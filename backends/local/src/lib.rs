//! # ak-backend-local
//!
//! A real, working local OS-sandbox [`Backend`] for macOS and Linux, used by
//! tests and examples. It executes [`ActionKind::Shell`], [`ActionKind::ReadFile`],
//! [`ActionKind::WriteFile`] and [`ActionKind::DeletePath`] inside a
//! **per-branch workspace directory**.
//!
//! ## Fail-closed sandbox enforcement (AK-001)
//!
//! Shell commands only ever run inside a **verified** OS sandbox:
//!
//! - **Linux** — bubblewrap (`bwrap`) with an unshared network + PID
//!   namespace, a read-only rootfs and the compiled readable/writable
//!   workspace prefixes bound in (everything else in the workspace shadowed
//!   by tmpfs when read confinement is requested);
//! - **macOS** — Seatbelt (`sandbox-exec`) with a generated deny-default
//!   profile: reads limited to the system paths needed to execute binaries
//!   plus the workspace's readable prefixes, writes limited to the writable
//!   prefixes, and **all network denied**.
//!
//! At construction the backend *probes* the host sandbox by executing a
//! canary inside it and verifying that a host file outside the workspace is
//! unreadable. [`BackendProfile::isolation_strength`] reports the **verified**
//! capability, never a declared one. When no sandbox passes the probe, shell
//! execution is **refused** (fail closed) unless the operator explicitly
//! constructs the backend with
//! [`LocalBackendConfig::dangerously_allow_unsandboxed`] — intended for
//! trusted-code development only.
//!
//! Because the local sandbox denies all direct network access, egress
//! happens exclusively through typed connectors ([`ActionKind::HttpRead`]
//! and effect proposals), where `egress_domains` are enforced on resolved
//! addresses. A shell step can therefore never bypass the domain policy.
//!
//! Additional confinement (all platforms):
//!
//! - a **scrubbed environment**: the child process environment is cleared and
//!   only `PATH` (host value), `HOME` (set to the workspace), `TMPDIR` (a
//!   workspace-internal scratch dir) and `LANG` are provided, plus any
//!   explicitly pre-authorized variables carried on the action itself;
//! - a **wall-clock timeout** derived from `budget.cpu_ms`, with
//!   kill-on-timeout of the child's whole **process group** (the child is
//!   spawned as a group leader, so the sandbox wrapper's descendants die
//!   with it);
//! - **honest resource metering** for shell steps: the child is reaped with
//!   `wait4`, so `usage.cpu_ms` is real user+system CPU time and
//!   `usage.memory_bytes` the real peak RSS — not wall-clock or byte-count
//!   proxies. (File actions and process-session operations, which reap no
//!   child, keep the proxies.) Egress bytes are counted at the proxy;
//! - **output capture with byte caps** (see [`LocalBackendConfig::max_capture_bytes`]);
//! - **in-process path confinement** for structured file actions: every path
//!   is verified to be inside the workspace (no absolute paths, no `..`,
//!   symlink escapes rejected by canonicalizing the deepest existing
//!   ancestor) and to match the request's readable/writable prefixes;
//! - **`paths_written` detection** via an mtime/size scan diff of the
//!   workspace before and after execution.
//!
//! Replay class: [`ReplayClass::FilesystemOnly`] — the workspace tree is the
//! only state this backend can faithfully restore.

use ak_core::action::ActionKind;
use ak_core::budget::ResourceBudget;
use ak_core::capability::Operation;
use ak_core::denial::{Denial, DenialCode};
use ak_core::error::{KernelError, KernelResult};
use ak_core::ids::BranchId;
use ak_core::replay::ReplayClass;
use ak_core::traits::{Backend, BackendProfile, ExecutionOutcome, ExecutionRequest};
use async_trait::async_trait;
use std::collections::BTreeMap;
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

pub mod b64;
pub mod egress;
pub mod process;
pub mod sandbox;

pub use egress::{EgressConfig, EgressGrant, EgressProxy};
pub use process::{ProcessRegistry, ProcessSession};
pub use sandbox::SandboxTech;

/// Configuration for [`LocalBackend`].
#[derive(Debug, Clone)]
pub struct LocalBackendConfig {
    /// Root directory under which per-branch workspaces are created.
    pub root: PathBuf,
    /// Maximum bytes of stdout/stderr retained per stream.
    pub max_capture_bytes: usize,
    /// Maximum bytes of combined output retained per **process session**
    /// (ring buffer; older bytes are evicted, offsets stay honest).
    pub max_log_buffer_bytes: usize,
    /// Timeout used when `budget.cpu_ms` is zero would otherwise mean
    /// "no time at all"; a zero budget is refused, this is only a hard upper
    /// clamp on very large budgets.
    pub max_wall_clock: Duration,
    /// Transparent egress proxy configuration (see [`egress`]). Only steps
    /// whose compiled confinement grants egress domains get proxy
    /// environment; everything else stays fully offline.
    pub egress: EgressConfig,
    /// When `false` (**default**), shell commands are refused unless a
    /// verified OS sandbox is available (fail closed). Setting this to
    /// `true` lets shell commands run as plain confined host processes and
    /// is **only** safe for fully trusted code on a development machine.
    pub dangerously_allow_unsandboxed: bool,
}

impl LocalBackendConfig {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            max_capture_bytes: 1 << 20,
            max_log_buffer_bytes: 1 << 20,
            max_wall_clock: Duration::from_secs(600),
            egress: EgressConfig::default(),
            dangerously_allow_unsandboxed: false,
        }
    }

    /// Opt out of fail-closed sandboxing. The name is deliberately loud:
    /// without an OS sandbox the workspace directory is **not** a security
    /// boundary for shell commands.
    pub fn dangerously_allow_unsandboxed(mut self) -> Self {
        self.dangerously_allow_unsandboxed = true;
        self
    }
}

/// Local OS-sandbox backend. See the crate docs for the confinement model.
pub struct LocalBackend {
    config: LocalBackendConfig,
    /// The sandbox technology that passed the construction-time probe.
    tech: SandboxTech,
    /// Persistent per-branch process sessions.
    processes: ProcessRegistry,
    /// Lazily started egress proxy (needs a tokio runtime).
    egress_proxy: tokio::sync::OnceCell<EgressProxy>,
}

impl LocalBackend {
    /// Create the backend, ensuring the workspace root exists and probing the
    /// host's sandbox capability (see [`sandbox::probe`]).
    pub fn new(config: LocalBackendConfig) -> KernelResult<Self> {
        std::fs::create_dir_all(&config.root)?;
        let tech = sandbox::probe();
        tracing::info!(?tech, "local backend sandbox probe");
        Ok(Self {
            config,
            tech,
            processes: ProcessRegistry::default(),
            egress_proxy: tokio::sync::OnceCell::new(),
        })
    }

    /// The process-session registry (tests and embedders).
    pub fn processes(&self) -> &ProcessRegistry {
        &self.processes
    }

    /// A per-step egress grant when the confinement allows any egress and
    /// the sandbox technology can actually confine traffic to the proxy.
    ///
    /// - Seatbelt: the generated profile opens **only** the proxy's loopback
    ///   port — the proxy is the sole route out.
    /// - No sandbox (explicit dev opt-out): the proxy env is still set so
    ///   tools work and the domain policy is enforced at the proxy.
    /// - bwrap: the unshared network namespace cannot reach host loopback;
    ///   egress stays **off** (fail closed, never a silent bypass) until an
    ///   in-namespace forwarder lands.
    async fn egress_grant(
        &self,
        domains: &[String],
        budget_network_bytes: u64,
    ) -> KernelResult<Option<EgressGrant>> {
        if !self.config.egress.enabled || domains.is_empty() || budget_network_bytes == 0 {
            return Ok(None);
        }
        if self.tech == SandboxTech::Bwrap {
            tracing::warn!(
                "egress domains granted but bwrap cannot reach the loopback proxy \
                 from an unshared netns; step runs without network (fail closed)"
            );
            return Ok(None);
        }
        let proxy = self
            .egress_proxy
            .get_or_try_init(|| EgressProxy::start(self.config.egress.clone()))
            .await
            .map_err(|e| KernelError::BackendUnavailable {
                backend: "local".into(),
                reason: format!("egress proxy failed to start: {e}"),
            })?;
        Ok(Some(proxy.grant(domains.to_vec(), budget_network_bytes)))
    }

    /// The verified sandbox technology for shell commands.
    pub fn sandbox_tech(&self) -> SandboxTech {
        self.tech
    }

    /// Whether shell commands will be wrapped in bubblewrap.
    pub fn uses_bwrap(&self) -> bool {
        self.tech == SandboxTech::Bwrap
    }

    /// The workspace directory for a branch, created on demand.
    pub fn workspace_for(&self, branch: &BranchId) -> KernelResult<PathBuf> {
        let dir = self.config.root.join(branch.as_str());
        std::fs::create_dir_all(&dir)?;
        Ok(dir)
    }
}

fn denial(code: DenialCode, op: &str, reason: impl Into<String>) -> KernelError {
    KernelError::Denied(Box::new(Denial {
        code,
        attempted_operation: Operation::new(op),
        reason: reason.into(),
        safe_alternatives: Vec::new(),
        requestable_scopes: Vec::new(),
        escalation_allowed: false,
    }))
}

/// Normalize a workspace-relative path: reject absolute paths, `..`
/// components, and empty paths. Returns the normalized relative `PathBuf`.
fn normalize_relative(op: &str, raw: &str) -> KernelResult<PathBuf> {
    let p = Path::new(raw);
    if p.as_os_str().is_empty() {
        return Err(denial(DenialCode::ConstraintViolated, op, "empty path"));
    }
    let mut out = PathBuf::new();
    for comp in p.components() {
        match comp {
            Component::Normal(c) => out.push(c),
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(denial(
                    DenialCode::ConstraintViolated,
                    op,
                    format!("path `{raw}` contains `..`"),
                ))
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(denial(
                    DenialCode::ConstraintViolated,
                    op,
                    format!("path `{raw}` is absolute; only workspace-relative paths are allowed"),
                ))
            }
        }
    }
    Ok(out)
}

/// Check a normalized relative path against allowed prefixes. An empty prefix
/// list means the whole workspace is allowed; an empty-string prefix likewise.
fn matches_prefixes(rel: &Path, prefixes: &[String]) -> bool {
    if prefixes.is_empty() {
        return true;
    }
    prefixes.iter().any(|p| {
        let p = p.trim_start_matches("./").trim_end_matches('/');
        if p.is_empty() {
            return true;
        }
        rel.starts_with(p)
    })
}

/// Resolve a workspace-relative path with full confinement:
/// normalization, prefix matching, and symlink-escape rejection by
/// canonicalizing the deepest *existing* ancestor and verifying it is still
/// under the canonicalized workspace.
fn resolve_confined(
    op: &str,
    workspace: &Path,
    raw: &str,
    prefixes: &[String],
) -> KernelResult<PathBuf> {
    let rel = normalize_relative(op, raw)?;
    if !matches_prefixes(&rel, prefixes) {
        return Err(denial(
            DenialCode::ConstraintViolated,
            op,
            format!("path `{raw}` is outside the allowed prefixes"),
        ));
    }
    let ws_canon = workspace.canonicalize()?;
    let full = ws_canon.join(&rel);
    // Find the deepest existing ancestor of `full` and canonicalize it: this
    // resolves any symlink placed inside the workspace that points outside.
    let mut probe: &Path = &full;
    let anchor = loop {
        if probe.exists() {
            break probe.canonicalize()?;
        }
        match probe.parent() {
            Some(parent) => probe = parent,
            None => {
                return Err(denial(
                    DenialCode::ConstraintViolated,
                    op,
                    format!("path `{raw}` has no resolvable ancestor"),
                ))
            }
        }
    };
    if !anchor.starts_with(&ws_canon) {
        return Err(denial(
            DenialCode::ConstraintViolated,
            op,
            format!("path `{raw}` escapes the workspace"),
        ));
    }
    // If the path itself exists, also verify its own canonical form.
    if full.exists() {
        let canon = full.canonicalize()?;
        if !canon.starts_with(&ws_canon) {
            return Err(denial(
                DenialCode::ConstraintViolated,
                op,
                format!("path `{raw}` escapes the workspace via a symlink"),
            ));
        }
    }
    Ok(full)
}

/// Snapshot of `(mtime, len)` per workspace-relative path, used to diff
/// written paths across an execution. Cache/scratch components
/// ([`ak_core::state::DEFAULT_SNAPSHOT_IGNORES`], which include the sandbox
/// scratch dir) are excluded — they are the cache tier, not step artifacts,
/// and skipping them keeps the scan proportional to the artifact tree.
fn scan_workspace(workspace: &Path) -> BTreeMap<String, (SystemTime, u64)> {
    let mut out = BTreeMap::new();
    let mut stack = vec![workspace.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if ak_core::state::is_ignored_component(&entry.file_name().to_string_lossy()) {
                continue;
            }
            let Ok(meta) = entry.metadata() else { continue };
            if meta.is_dir() {
                stack.push(path);
            } else {
                let rel = path
                    .strip_prefix(workspace)
                    .map(|p| p.to_string_lossy().into_owned())
                    .unwrap_or_else(|_| path.to_string_lossy().into_owned());
                let mtime = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
                out.insert(rel, (mtime, meta.len()));
            }
        }
    }
    out
}

fn diff_written(
    before: &BTreeMap<String, (SystemTime, u64)>,
    after: &BTreeMap<String, (SystemTime, u64)>,
) -> Vec<String> {
    after
        .iter()
        .filter(|(path, stat)| before.get(*path) != Some(stat))
        .map(|(path, _)| path.clone())
        .collect()
}

fn cap(mut bytes: Vec<u8>, max: usize) -> Vec<u8> {
    bytes.truncate(max);
    bytes
}

/// Honest child metering from `wait4` rusage: what the process actually
/// consumed, not a proxy.
#[derive(Debug, Clone, Copy)]
struct Meter {
    /// User + system CPU time, milliseconds.
    cpu_ms: u64,
    /// Peak resident set size, bytes (normalized: macOS reports bytes,
    /// Linux kilobytes).
    max_rss_bytes: u64,
}

struct ExecResult {
    exit_code: i32,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    /// Egress bytes transferred through the proxy during this execution.
    network_bytes: u64,
    /// Real reaped-child usage. `None` for paths that do not reap a child
    /// with rusage (file actions, process-session operations) — those fall
    /// back to the wall-clock / captured-bytes approximations.
    meter: Option<Meter>,
}

/// Result of spawning + reaping one shell child on the blocking pool.
struct Reaped {
    exit_code: i32,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    meter: Option<Meter>,
}

/// Spawn `cmd`, report its pid over `pid_tx`, drain both output pipes, and
/// reap the child with `wait4` so its rusage (real CPU time, peak RSS)
/// becomes the step's [`Meter`].
fn spawn_and_reap(
    mut cmd: std::process::Command,
    pid_tx: tokio::sync::oneshot::Sender<u32>,
) -> std::io::Result<Reaped> {
    use std::io::Read;
    let mut child = cmd.spawn()?;
    let _ = pid_tx.send(child.id());
    let mut stdout_pipe = child.stdout.take().expect("stdout piped");
    let mut stderr_pipe = child.stderr.take().expect("stderr piped");
    let stderr_thread = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stderr_pipe.read_to_end(&mut buf);
        buf
    });
    let mut stdout = Vec::new();
    let _ = stdout_pipe.read_to_end(&mut stdout);
    let stderr = stderr_thread.join().unwrap_or_default();

    #[cfg(unix)]
    {
        let pid = child.id() as libc::pid_t;
        let mut status: libc::c_int = 0;
        // SAFETY: a zeroed rusage is a valid out-parameter for wait4.
        let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
        loop {
            // SAFETY: pid is our own un-reaped child; pointers are valid for
            // the duration of the call. std's Child does not reap on drop
            // and `child.wait()` is never called, so this is the only reap.
            let r = unsafe { libc::wait4(pid, &mut status, 0, &mut usage) };
            if r == pid {
                break;
            }
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EINTR) {
                return Err(err);
            }
        }
        let exit_code = if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else {
            -1
        };
        let cpu_us = (usage.ru_utime.tv_sec.max(0) as u64)
            .saturating_mul(1_000_000)
            .saturating_add(usage.ru_utime.tv_usec.max(0) as u64)
            .saturating_add(
                (usage.ru_stime.tv_sec.max(0) as u64)
                    .saturating_mul(1_000_000)
                    .saturating_add(usage.ru_stime.tv_usec.max(0) as u64),
            );
        // ru_maxrss unit differs: bytes on macOS, kilobytes on Linux.
        #[cfg(target_os = "macos")]
        let max_rss_bytes = usage.ru_maxrss.max(0) as u64;
        #[cfg(not(target_os = "macos"))]
        let max_rss_bytes = (usage.ru_maxrss.max(0) as u64).saturating_mul(1024);
        Ok(Reaped {
            exit_code,
            stdout,
            stderr,
            meter: Some(Meter {
                cpu_ms: cpu_us / 1000,
                max_rss_bytes,
            }),
        })
    }
    #[cfg(not(unix))]
    {
        let code = child.wait()?.code().unwrap_or(-1);
        Ok(Reaped {
            exit_code: code,
            stdout,
            stderr,
            meter: None,
        })
    }
}

impl LocalBackend {
    /// Build a confined `/bin/sh -c` command under the verified sandbox tech
    /// with the scrubbed environment. Returns the command plus the Seatbelt
    /// profile file (which must outlive the child). Fails closed when no
    /// sandbox is verified and the operator did not opt out.
    #[allow(clippy::too_many_arguments)]
    fn build_confined_command(
        &self,
        op: &str,
        ws_canon: &Path,
        cwd: &Path,
        command: &str,
        env: &BTreeMap<String, String>,
        readable_prefixes: &[String],
        writable_prefixes: &[String],
        egress: Option<&EgressGrant>,
    ) -> KernelResult<(std::process::Command, Option<tempfile::NamedTempFile>)> {
        let host_path =
            std::env::var("PATH").unwrap_or_else(|_| "/usr/local/bin:/usr/bin:/bin".to_string());
        let scratch = ws_canon.join(sandbox::SCRATCH_DIR);
        std::fs::create_dir_all(&scratch)?;

        // Profile files live outside the workspace so a confined shell can
        // never rewrite its own sandbox rules.
        let mut profile_file: Option<tempfile::NamedTempFile> = None;

        let mut cmd = match self.tech {
            SandboxTech::Bwrap => {
                let mut c = std::process::Command::new("bwrap");
                c.args(sandbox::bwrap_args(
                    ws_canon,
                    readable_prefixes,
                    writable_prefixes,
                ));
                c.arg("--chdir")
                    .arg(cwd)
                    .arg("/bin/sh")
                    .arg("-c")
                    .arg(command);
                c
            }
            SandboxTech::SandboxExec => {
                let profile = sandbox::seatbelt_profile(
                    ws_canon,
                    readable_prefixes,
                    writable_prefixes,
                    egress.map(EgressGrant::port),
                );
                let file = tempfile::Builder::new()
                    .prefix("ak-seatbelt-")
                    .suffix(".sb")
                    .tempfile()
                    .map_err(KernelError::Io)?;
                std::fs::write(file.path(), profile)?;
                let mut c = std::process::Command::new("/usr/bin/sandbox-exec");
                c.arg("-f")
                    .arg(file.path())
                    .arg("/bin/sh")
                    .arg("-c")
                    .arg(command)
                    .current_dir(cwd);
                profile_file = Some(file);
                c
            }
            SandboxTech::None => {
                if !self.config.dangerously_allow_unsandboxed {
                    // Fail closed (AK-001): the workspace directory is not a
                    // security boundary and must never silently become one.
                    let _ = op;
                    return Err(KernelError::BackendUnavailable {
                        backend: "local".into(),
                        reason: "no verified OS sandbox on this host: install bubblewrap (Linux) \
                                 or ensure /usr/bin/sandbox-exec works (macOS). Shell execution \
                                 fails closed; route the step to a stronger backend, or opt in \
                                 to unsandboxed execution for trusted development code only via \
                                 LocalBackendConfig::dangerously_allow_unsandboxed."
                            .into(),
                    });
                }
                let mut c = std::process::Command::new("/bin/sh");
                c.arg("-c").arg(command).current_dir(cwd);
                c
            }
        };

        // Environment scrub: cleared, then a minimal safe set plus the
        // explicitly pre-authorized action environment. TMPDIR points at a
        // workspace-internal scratch dir the sandbox allows writes to.
        cmd.env_clear()
            .env("PATH", host_path)
            .env("HOME", ws_canon)
            .env("TMPDIR", &scratch)
            .env("LANG", "C.UTF-8");
        // Standard proxy environment: pip/cargo/npm/git/curl all speak it.
        // The token-bearing URL is the workload's only route out.
        if let Some(grant) = egress {
            let url = grant.proxy_url();
            cmd.env("HTTP_PROXY", &url)
                .env("HTTPS_PROXY", &url)
                .env("http_proxy", &url)
                .env("https_proxy", &url);
        }
        for (k, v) in env {
            cmd.env(k, v);
        }
        #[cfg(unix)]
        cmd.process_group(0);
        Ok((cmd, profile_file))
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_shell(
        &self,
        workspace: &Path,
        command: &str,
        cwd: Option<&str>,
        env: &BTreeMap<String, String>,
        budget: &ResourceBudget,
        readable_prefixes: &[String],
        writable_prefixes: &[String],
        egress_domains: &[String],
    ) -> KernelResult<ExecResult> {
        if budget.cpu_ms == 0 {
            return Err(denial(
                DenialCode::BudgetExhausted,
                "proc.shell",
                "cpu_ms budget is zero; refusing to start the process",
            ));
        }
        let timeout = Duration::from_millis(budget.cpu_ms).min(self.config.max_wall_clock);
        let cwd = match cwd {
            Some(c) => resolve_confined("proc.shell", workspace, c, &[])?,
            None => workspace.to_path_buf(),
        };
        if !cwd.is_dir() {
            return Err(denial(
                DenialCode::ConstraintViolated,
                "proc.shell",
                "cwd does not exist in the workspace",
            ));
        }
        let ws_canon = workspace.canonicalize()?;
        let egress = self
            .egress_grant(egress_domains, budget.network_bytes)
            .await?;
        let (mut cmd, profile_file) = self.build_confined_command(
            "proc.shell",
            &ws_canon,
            &cwd,
            command,
            env,
            readable_prefixes,
            writable_prefixes,
            egress.as_ref(),
        )?;
        cmd.stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());

        // Spawn and reap on the blocking pool: reaping with `wait4` is what
        // yields *honest* usage (real CPU time and peak RSS from the OS)
        // instead of wall-clock and byte-count proxies.
        let (pid_tx, pid_rx) = tokio::sync::oneshot::channel::<u32>();
        let mut worker = tokio::task::spawn_blocking(move || spawn_and_reap(cmd, pid_tx));
        let pid = pid_rx.await.ok();

        let network_bytes = |g: &Option<EgressGrant>| g.as_ref().map_or(0, EgressGrant::used_bytes);
        let join_err = |e: tokio::task::JoinError| KernelError::BackendUnavailable {
            backend: "local".into(),
            reason: format!("shell reaper task failed: {e}"),
        };
        let outcome = match tokio::time::timeout(timeout, &mut worker).await {
            Ok(joined) => match joined.map_err(join_err)? {
                Ok(reaped) => Ok(ExecResult {
                    meter: reaped.meter,
                    network_bytes: network_bytes(&egress),
                    exit_code: reaped.exit_code,
                    stdout: cap(reaped.stdout, self.config.max_capture_bytes),
                    stderr: cap(reaped.stderr, self.config.max_capture_bytes),
                }),
                Err(e) => Err(KernelError::BackendUnavailable {
                    backend: "local".into(),
                    reason: format!("failed to spawn: {e}"),
                }),
            },
            Err(_elapsed) => {
                // Kill the whole process group, then let the reaper finish:
                // even a killed run reports its real usage and partial output.
                #[cfg(unix)]
                if let Some(pid) = pid {
                    unsafe { libc::kill(-(pid as i32), libc::SIGKILL) };
                }
                let reaped = worker.await.map_err(join_err)?.unwrap_or(Reaped {
                    exit_code: -1,
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                    meter: None,
                });
                let mut stderr = format!(
                    "process killed: wall-clock timeout of {} ms exceeded",
                    timeout.as_millis()
                )
                .into_bytes();
                if !reaped.stderr.is_empty() {
                    stderr.push(b'\n');
                    stderr.extend_from_slice(&cap(reaped.stderr, self.config.max_capture_bytes));
                }
                Ok(ExecResult {
                    meter: reaped.meter,
                    network_bytes: network_bytes(&egress),
                    exit_code: -1,
                    stdout: cap(reaped.stdout, self.config.max_capture_bytes),
                    stderr,
                })
            }
        };
        drop(profile_file);
        // The grant drops here: the step's proxy token is revoked the moment
        // the step ends.
        outcome
    }

    // ------------------------------------------------- process sessions

    /// Start a persistent, sandboxed process session on the branch.
    #[allow(clippy::too_many_arguments)]
    async fn proc_start(
        &self,
        workspace: &Path,
        branch: &ak_core::ids::BranchId,
        command: &str,
        cwd: Option<&str>,
        env: &BTreeMap<String, String>,
        name: Option<String>,
        budget: &ResourceBudget,
        readable_prefixes: &[String],
        writable_prefixes: &[String],
        egress_domains: &[String],
    ) -> KernelResult<ExecResult> {
        let cwd = match cwd {
            Some(c) => resolve_confined("proc.start", workspace, c, &[])?,
            None => workspace.to_path_buf(),
        };
        if !cwd.is_dir() {
            return Err(denial(
                DenialCode::ConstraintViolated,
                "proc.start",
                "cwd does not exist in the workspace",
            ));
        }
        let ws_canon = workspace.canonicalize()?;
        // The grant lives as long as the process session: a dev server keeps
        // its (domain-scoped, byte-capped) egress until it exits or the
        // branch is discarded.
        let egress = self
            .egress_grant(egress_domains, budget.network_bytes)
            .await?;
        let (std_cmd, profile_file) = self.build_confined_command(
            "proc.start",
            &ws_canon,
            &cwd,
            command,
            env,
            readable_prefixes,
            writable_prefixes,
            egress.as_ref(),
        )?;
        let mut cmd = tokio::process::Command::from(std_cmd);
        cmd.stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);
        let child = cmd.spawn().map_err(|e| KernelError::BackendUnavailable {
            backend: "local".into(),
            reason: format!("failed to spawn: {e}"),
        })?;
        let session = self.processes.adopt(
            branch,
            name,
            command.to_string(),
            child,
            profile_file,
            egress,
            self.config.max_log_buffer_bytes,
        );
        Ok(ExecResult {
            meter: None,
            network_bytes: 0,
            exit_code: 0,
            stdout: serde_json::to_vec(&serde_json::json!({
                "process": session.id,
                "pid": session.pid,
                "name": session.name,
            }))
            .unwrap_or_default(),
            stderr: Vec::new(),
        })
    }

    fn proc_fail(msg: impl Into<String>) -> ExecResult {
        ExecResult {
            meter: None,
            network_bytes: 0,
            exit_code: 1,
            stdout: Vec::new(),
            stderr: msg.into().into_bytes(),
        }
    }

    fn session(
        &self,
        branch: &ak_core::ids::BranchId,
        process: &str,
    ) -> Result<ProcessSession, ExecResult> {
        self.processes.get(branch, process).ok_or_else(|| {
            Self::proc_fail(format!(
                "error: unknown process `{process}` on this branch (processes are branch-scoped \
                 and do not survive forks; use proc.status with an empty `process` to list)"
            ))
        })
    }

    async fn proc_stdin(
        &self,
        branch: &ak_core::ids::BranchId,
        process: &str,
        data_b64: &str,
        close: bool,
    ) -> KernelResult<ExecResult> {
        let data = b64::decode(data_b64).map_err(|e| {
            denial(
                DenialCode::ConstraintViolated,
                "proc.stdin",
                format!("invalid base64: {e}"),
            )
        })?;
        let session = match self.session(branch, process) {
            Ok(s) => s,
            Err(fail) => return Ok(fail),
        };
        let mut stdin = session.stdin.lock().await;
        let Some(handle) = stdin.as_mut() else {
            return Ok(Self::proc_fail("error: stdin is already closed"));
        };
        use tokio::io::AsyncWriteExt;
        if let Err(e) = handle.write_all(&data).await {
            return Ok(Self::proc_fail(format!("error: stdin write failed: {e}")));
        }
        if let Err(e) = handle.flush().await {
            return Ok(Self::proc_fail(format!("error: stdin flush failed: {e}")));
        }
        if close {
            *stdin = None; // dropping the handle closes the pipe
        }
        Ok(ExecResult {
            meter: None,
            network_bytes: 0,
            exit_code: 0,
            stdout: serde_json::to_vec(&serde_json::json!({
                "process": process,
                "bytes_written": data.len(),
                "stdin_closed": close,
            }))
            .unwrap_or_default(),
            stderr: Vec::new(),
        })
    }

    fn proc_logs(
        &self,
        branch: &ak_core::ids::BranchId,
        process: &str,
        from_offset: u64,
        max_bytes: Option<u64>,
    ) -> ExecResult {
        let session = match self.session(branch, process) {
            Ok(s) => s,
            Err(fail) => return fail,
        };
        let max = max_bytes
            .unwrap_or(64 * 1024)
            .min(self.config.max_capture_bytes as u64) as usize;
        let (effective, data, base, total) = {
            let logs = session.logs.lock().unwrap_or_else(|e| e.into_inner());
            let (eff, data) = logs.read_from(from_offset, max);
            (eff, data, logs.base_offset(), logs.total())
        };
        let exit_code = session.exit_code();
        let next_offset = effective + data.len() as u64;
        ExecResult {
            meter: None,
            network_bytes: 0,
            exit_code: 0,
            stdout: serde_json::to_vec(&serde_json::json!({
                "process": process,
                "requested_offset": from_offset,
                "effective_offset": effective,
                "dropped_bytes": effective.saturating_sub(from_offset),
                "next_offset": next_offset,
                "base_offset": base,
                "total_bytes": total,
                "running": exit_code.is_none(),
                "exit_code": exit_code,
                "eof": exit_code.is_some() && next_offset >= total,
                "data": String::from_utf8_lossy(&data),
            }))
            .unwrap_or_default(),
            stderr: Vec::new(),
        }
    }

    fn proc_signal(
        &self,
        branch: &ak_core::ids::BranchId,
        process: &str,
        signal: &str,
    ) -> KernelResult<ExecResult> {
        if !matches!(signal, "int" | "term" | "kill") {
            return Err(denial(
                DenialCode::ConstraintViolated,
                "proc.signal",
                format!("unknown signal `{signal}`: use int|term|kill"),
            ));
        }
        let session = match self.session(branch, process) {
            Ok(s) => s,
            Err(fail) => return Ok(fail),
        };
        Ok(match session.signal(signal) {
            Ok(()) => ExecResult {
                meter: None,
                network_bytes: 0,
                exit_code: 0,
                stdout: serde_json::to_vec(&serde_json::json!({
                    "process": process,
                    "signaled": signal,
                }))
                .unwrap_or_default(),
                stderr: Vec::new(),
            },
            Err(e) => Self::proc_fail(format!("error: {e}")),
        })
    }

    fn proc_status(&self, branch: &ak_core::ids::BranchId, process: &str) -> ExecResult {
        if process.is_empty() {
            let list: Vec<serde_json::Value> = self
                .processes
                .list(branch)
                .iter()
                .map(|s| s.status_json())
                .collect();
            return ExecResult {
                meter: None,
                network_bytes: 0,
                exit_code: 0,
                stdout: serde_json::to_vec(&serde_json::json!({ "processes": list }))
                    .unwrap_or_default(),
                stderr: Vec::new(),
            };
        }
        match self.session(branch, process) {
            Ok(s) => ExecResult {
                meter: None,
                network_bytes: 0,
                exit_code: 0,
                stdout: serde_json::to_vec(&s.status_json()).unwrap_or_default(),
                stderr: Vec::new(),
            },
            Err(fail) => fail,
        }
    }
}

#[async_trait]
impl Backend for LocalBackend {
    fn profile(&self) -> BackendProfile {
        BackendProfile {
            name: "local".into(),
            // Verified at construction by the sandbox probe — never declared.
            isolation_strength: self.tech.isolation_strength(),
            cold_start_ms: 5,
            replay_class: ReplayClass::FilesystemOnly,
            supports_fork: false,
            supports_gui: false,
            // Honest: only a Linux host runs arbitrary Linux binaries.
            full_linux: cfg!(target_os = "linux"),
            // Executes in the kernel's own workspace tree: snapshots see
            // every filesystem effect.
            shares_workspace: true,
        }
    }

    async fn execute(&self, req: ExecutionRequest) -> KernelResult<ExecutionOutcome> {
        let workspace = self.workspace_for(&req.branch)?;
        let before = scan_workspace(&workspace);
        let started = Instant::now();

        // Steps that only interact with a live process session cannot be
        // re-executed later; record them honestly as audit-only.
        let mut replay_class = ReplayClass::FilesystemOnly;

        let result = match &req.action {
            ActionKind::Shell { command, cwd, env } => {
                self.run_shell(
                    &workspace,
                    command,
                    cwd.as_deref(),
                    env,
                    &req.budget,
                    &req.readable_prefixes,
                    &req.writable_prefixes,
                    &req.egress_domains,
                )
                .await?
            }
            ActionKind::ProcessStart {
                command,
                cwd,
                env,
                name,
            } => {
                replay_class = ReplayClass::AuditOnly;
                self.proc_start(
                    &workspace,
                    &req.branch,
                    command,
                    cwd.as_deref(),
                    env,
                    name.clone(),
                    &req.budget,
                    &req.readable_prefixes,
                    &req.writable_prefixes,
                    &req.egress_domains,
                )
                .await?
            }
            ActionKind::ProcessStdin {
                process,
                data_b64,
                close,
            } => {
                replay_class = ReplayClass::AuditOnly;
                self.proc_stdin(&req.branch, process, data_b64, *close)
                    .await?
            }
            ActionKind::ProcessLogs {
                process,
                from_offset,
                max_bytes,
            } => {
                replay_class = ReplayClass::AuditOnly;
                self.proc_logs(&req.branch, process, *from_offset, *max_bytes)
            }
            ActionKind::ProcessSignal { process, signal } => {
                replay_class = ReplayClass::AuditOnly;
                self.proc_signal(&req.branch, process, signal)?
            }
            ActionKind::ProcessStatus { process } => {
                replay_class = ReplayClass::AuditOnly;
                self.proc_status(&req.branch, process)
            }
            ActionKind::ReadFile { path } => {
                let full = resolve_confined("fs.read", &workspace, path, &req.readable_prefixes)?;
                match std::fs::read(&full) {
                    Ok(bytes) => ExecResult {
                        meter: None,
                        network_bytes: 0,
                        exit_code: 0,
                        stdout: cap(bytes, self.config.max_capture_bytes),
                        stderr: Vec::new(),
                    },
                    Err(e) => ExecResult {
                        meter: None,
                        network_bytes: 0,
                        exit_code: 1,
                        stdout: Vec::new(),
                        stderr: format!("read failed: {e}").into_bytes(),
                    },
                }
            }
            ActionKind::WriteFile { path, contents_b64 } => {
                let full = resolve_confined("fs.write", &workspace, path, &req.writable_prefixes)?;
                let contents = b64::decode(contents_b64).map_err(|e| {
                    denial(
                        DenialCode::ConstraintViolated,
                        "fs.write",
                        format!("invalid base64: {e}"),
                    )
                })?;
                if let Some(parent) = full.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::write(&full, &contents)?;
                ExecResult {
                    meter: None,
                    network_bytes: 0,
                    exit_code: 0,
                    stdout: Vec::new(),
                    stderr: Vec::new(),
                }
            }
            ActionKind::DeletePath { path } => {
                let full = resolve_confined("fs.delete", &workspace, path, &req.writable_prefixes)?;
                let outcome = if full.is_dir() {
                    std::fs::remove_dir_all(&full)
                } else {
                    std::fs::remove_file(&full)
                };
                match outcome {
                    Ok(()) => ExecResult {
                        meter: None,
                        network_bytes: 0,
                        exit_code: 0,
                        stdout: Vec::new(),
                        stderr: Vec::new(),
                    },
                    Err(e) => ExecResult {
                        meter: None,
                        network_bytes: 0,
                        exit_code: 1,
                        stdout: Vec::new(),
                        stderr: format!("delete failed: {e}").into_bytes(),
                    },
                }
            }
            other => {
                return Err(denial(
                    DenialCode::PolicyForbidden,
                    &other.required_operation().0,
                    "the local backend executes shell, process-session and workspace file \
                     actions; HTTP reads, MCP invocations and connector operations run on the \
                     kernel's connector plane",
                ))
            }
        };

        let elapsed_ms = started.elapsed().as_millis().min(u64::MAX as u128) as u64;
        let after = scan_workspace(&workspace);
        let paths_written = diff_written(&before, &after);
        let captured = (result.stdout.len() + result.stderr.len()) as u64;

        Ok(ExecutionOutcome {
            exit_code: result.exit_code,
            stdout: result.stdout,
            stderr: result.stderr,
            // Shell steps carry *honest* metering: real CPU time (user+sys)
            // and peak RSS from reaping the child with wait4. Paths without
            // a reaped child (file actions, process-session ops) fall back
            // to wall-clock and captured-bytes proxies. Egress bytes are
            // always real, counted at the proxy.
            usage: ResourceBudget {
                cpu_ms: result.meter.map_or(elapsed_ms, |m| m.cpu_ms),
                memory_bytes: result.meter.map_or(captured, |m| m.max_rss_bytes),
                network_bytes: result.network_bytes,
                ..ResourceBudget::zero()
            },
            paths_written,
            replay_class,
        })
    }

    async fn discard(&self, branch: &BranchId) -> KernelResult<()> {
        // Kill the branch's process sessions before removing its workspace:
        // a discarded branch must leave no running side channel behind.
        let killed = self.processes.kill_branch(branch);
        if killed > 0 {
            tracing::info!(branch = %branch, killed, "killed process sessions on discard");
        }
        let dir = self.config.root.join(branch.as_str());
        if dir.exists() {
            std::fs::remove_dir_all(&dir)?;
        }
        Ok(())
    }
}

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
//!   kill-on-timeout via the child's process group where available;
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
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

pub mod b64;
mod sandbox;

pub use sandbox::SandboxTech;

/// Configuration for [`LocalBackend`].
#[derive(Debug, Clone)]
pub struct LocalBackendConfig {
    /// Root directory under which per-branch workspaces are created.
    pub root: PathBuf,
    /// Maximum bytes of stdout/stderr retained per stream.
    pub max_capture_bytes: usize,
    /// Timeout used when `budget.cpu_ms` is zero would otherwise mean
    /// "no time at all"; a zero budget is refused, this is only a hard upper
    /// clamp on very large budgets.
    pub max_wall_clock: Duration,
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
            max_wall_clock: Duration::from_secs(600),
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
}

impl LocalBackend {
    /// Create the backend, ensuring the workspace root exists and probing the
    /// host's sandbox capability (see [`sandbox::probe`]).
    pub fn new(config: LocalBackendConfig) -> KernelResult<Self> {
        std::fs::create_dir_all(&config.root)?;
        let tech = sandbox::probe();
        tracing::info!(?tech, "local backend sandbox probe");
        Ok(Self { config, tech })
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
/// written paths across an execution. The sandbox scratch dir
/// ([`sandbox::SCRATCH_DIR`]) is internal and excluded.
fn scan_workspace(workspace: &Path) -> BTreeMap<String, (SystemTime, u64)> {
    let mut out = BTreeMap::new();
    let mut stack = vec![workspace.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.file_name().is_some_and(|n| n == sandbox::SCRATCH_DIR)
                && path.parent() == Some(workspace)
            {
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

struct ExecResult {
    exit_code: i32,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

impl LocalBackend {
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

        let host_path =
            std::env::var("PATH").unwrap_or_else(|_| "/usr/local/bin:/usr/bin:/bin".to_string());
        let ws_canon = workspace.canonicalize()?;
        let scratch = ws_canon.join(sandbox::SCRATCH_DIR);
        std::fs::create_dir_all(&scratch)?;

        // Profile files live outside the workspace so a confined shell can
        // never rewrite its own sandbox rules.
        let mut profile_file: Option<tempfile::NamedTempFile> = None;

        let mut cmd = match self.tech {
            SandboxTech::Bwrap => {
                let mut c = tokio::process::Command::new("bwrap");
                c.args(sandbox::bwrap_args(&ws_canon, readable_prefixes, writable_prefixes));
                c.arg("--chdir").arg(&cwd).arg("/bin/sh").arg("-c").arg(command);
                c
            }
            SandboxTech::SandboxExec => {
                let profile =
                    sandbox::seatbelt_profile(&ws_canon, readable_prefixes, writable_prefixes);
                let file = tempfile::Builder::new()
                    .prefix("ak-seatbelt-")
                    .suffix(".sb")
                    .tempfile()
                    .map_err(KernelError::Io)?;
                std::fs::write(file.path(), profile)?;
                let mut c = tokio::process::Command::new("/usr/bin/sandbox-exec");
                c.arg("-f").arg(file.path()).arg("/bin/sh").arg("-c").arg(command).current_dir(&cwd);
                profile_file = Some(file);
                c
            }
            SandboxTech::None => {
                if !self.config.dangerously_allow_unsandboxed {
                    // Fail closed (AK-001): the workspace directory is not a
                    // security boundary and must never silently become one.
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
                let mut c = tokio::process::Command::new("/bin/sh");
                c.arg("-c").arg(command).current_dir(&cwd);
                c
            }
        };

        // Environment scrub: cleared, then a minimal safe set plus the
        // explicitly pre-authorized action environment. TMPDIR points at a
        // workspace-internal scratch dir the sandbox allows writes to.
        cmd.env_clear()
            .env("PATH", host_path)
            .env("HOME", &ws_canon)
            .env("TMPDIR", &scratch)
            .env("LANG", "C.UTF-8");
        for (k, v) in env {
            cmd.env(k, v);
        }
        cmd.stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);
        #[cfg(unix)]
        cmd.process_group(0);

        let child = cmd.spawn().map_err(|e| KernelError::BackendUnavailable {
            backend: "local".into(),
            reason: format!("failed to spawn: {e}"),
        })?;
        let pid = child.id();

        let outcome = match tokio::time::timeout(timeout, child.wait_with_output()).await {
            Ok(Ok(output)) => Ok(ExecResult {
                exit_code: output.status.code().unwrap_or(-1),
                stdout: cap(output.stdout, self.config.max_capture_bytes),
                stderr: cap(output.stderr, self.config.max_capture_bytes),
            }),
            Ok(Err(e)) => Err(KernelError::Io(e)),
            Err(_elapsed) => {
                // The dropped future killed the direct child (kill_on_drop);
                // also kill the whole process group where available.
                #[cfg(unix)]
                if let Some(pid) = pid {
                    let _ = std::process::Command::new("kill")
                        .arg("-KILL")
                        .arg("--")
                        .arg(format!("-{pid}"))
                        .status();
                }
                Ok(ExecResult {
                    exit_code: -1,
                    stdout: Vec::new(),
                    stderr: format!(
                        "process killed: wall-clock timeout of {} ms exceeded",
                        timeout.as_millis()
                    )
                    .into_bytes(),
                })
            }
        };
        drop(profile_file);
        outcome
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
        }
    }

    async fn execute(&self, req: ExecutionRequest) -> KernelResult<ExecutionOutcome> {
        let workspace = self.workspace_for(&req.branch)?;
        let before = scan_workspace(&workspace);
        let started = Instant::now();

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
                )
                .await?
            }
            ActionKind::ReadFile { path } => {
                let full = resolve_confined("fs.read", &workspace, path, &req.readable_prefixes)?;
                match std::fs::read(&full) {
                    Ok(bytes) => ExecResult {
                        exit_code: 0,
                        stdout: cap(bytes, self.config.max_capture_bytes),
                        stderr: Vec::new(),
                    },
                    Err(e) => ExecResult {
                        exit_code: 1,
                        stdout: Vec::new(),
                        stderr: format!("read failed: {e}").into_bytes(),
                    },
                }
            }
            ActionKind::WriteFile { path, contents_b64 } => {
                let full = resolve_confined("fs.write", &workspace, path, &req.writable_prefixes)?;
                let contents = b64::decode(contents_b64).map_err(|e| {
                    denial(DenialCode::ConstraintViolated, "fs.write", format!("invalid base64: {e}"))
                })?;
                if let Some(parent) = full.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::write(&full, &contents)?;
                ExecResult { exit_code: 0, stdout: Vec::new(), stderr: Vec::new() }
            }
            ActionKind::DeletePath { path } => {
                let full = resolve_confined("fs.delete", &workspace, path, &req.writable_prefixes)?;
                let outcome = if full.is_dir() {
                    std::fs::remove_dir_all(&full)
                } else {
                    std::fs::remove_file(&full)
                };
                match outcome {
                    Ok(()) => ExecResult { exit_code: 0, stdout: Vec::new(), stderr: Vec::new() },
                    Err(e) => ExecResult {
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
                    "the local backend only executes shell and workspace file actions",
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
            // Wall-clock elapsed as the CPU proxy; captured output bytes are
            // charged against the memory dimension as a proxy.
            usage: ResourceBudget {
                cpu_ms: elapsed_ms,
                memory_bytes: captured,
                ..ResourceBudget::zero()
            },
            paths_written,
            replay_class: ReplayClass::FilesystemOnly,
        })
    }

    async fn discard(&self, branch: &BranchId) -> KernelResult<()> {
        let dir = self.config.root.join(branch.as_str());
        if dir.exists() {
            std::fs::remove_dir_all(&dir)?;
        }
        Ok(())
    }
}

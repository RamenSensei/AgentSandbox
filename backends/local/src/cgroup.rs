//! cgroup v2 group-level enforcement: real tree-wide ceilings for shell
//! steps and process sessions.
//!
//! The rlimit backstops are **per-process**: a fork bomb or a tree of
//! processes each under the limit can still exhaust host memory or PIDs.
//! cgroup v2 enforces `memory.max`, `memory.swap.max = 0` and `pids.max` over the **whole
//! process tree**, exposes aggregate CPU usage for a lifetime-budget
//! monitor, and `cgroup.kill` reaps every member — including
//! processes that escaped the process group via `setsid`.
//!
//! Like every capability in this backend, group enforcement is **probed,
//! never declared**: at construction [`CgroupSupervisor::probe`] must
//! create a scratch group under a writable, controller-delegated parent,
//! set both limits, read CPU accounting and exercise `cgroup.kill`;
//! otherwise the backend honestly stays on the
//! rlimit backstops. The parent is found in order:
//!
//! 1. [`crate::LocalBackendConfig::cgroup_parent`],
//! 2. the `AK_CGROUP_PARENT` environment variable,
//! 3. the calling process's own cgroup (works only where the surrounding
//!    manager already delegated controllers and the no-internal-process
//!    rule permits children — typically it does **not** for a busy leaf,
//!    so production hosts should delegate an explicit parent).
//!
//! Attachment is race-free: the child writes itself into the group in
//! `pre_exec` (between `fork` and `exec`), so the very first instruction
//! of the workload already runs under the ceilings. The group also yields
//! **honest tree metering**: `cpu.stat:usage_usec`, `memory.peak`
//! (tree-wide peak, superseding the single-process RSS proxy),
//! `memory.events:oom_kill`, and `pids.events:max`.
//!
//! Everything here is Linux-only at runtime; on other platforms
//! [`CgroupSupervisor::probe`] returns `None` and compilation still
//! covers the module (probing a non-cgroupfs path fails cleanly).

use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// A probed, writable cgroup v2 parent under which per-step groups are
/// created.
#[derive(Debug)]
pub struct CgroupSupervisor {
    parent: PathBuf,
}

/// Read a cgroup control file into a trimmed string.
fn read_control(path: &Path) -> io::Result<String> {
    Ok(std::fs::read_to_string(path)?.trim().to_string())
}

fn event_value(path: &Path, key: &str) -> Option<u64> {
    let events = read_control(path).ok()?;
    events.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        let name = fields.next()?;
        let value = fields.next()?;
        (name == key).then(|| value.parse().ok()).flatten()
    })
}

/// Refuse lookalike ordinary directories before treating control-file writes
/// as kernel enforcement. Operator configuration is not itself proof that a
/// path lives on the unified cgroup hierarchy.
#[cfg(target_os = "linux")]
fn require_cgroup2fs(path: &Path) -> io::Result<()> {
    use std::os::unix::ffi::OsStrExt;

    const CGROUP2_SUPER_MAGIC: libc::c_long = 0x6367_7270;
    let path = std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "cgroup parent path contains a NUL byte",
        )
    })?;
    // SAFETY: `path` is NUL-terminated and `stat` points at writable,
    // correctly-sized storage for libc::statfs.
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statfs(path.as_ptr(), &mut stat) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if stat.f_type != CGROUP2_SUPER_MAGIC {
        return Err(io::Error::other(format!(
            "candidate is not on a cgroup v2 filesystem (statfs type {:#x})",
            stat.f_type
        )));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn require_cgroup2fs(_path: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "cgroup v2 is Linux-only",
    ))
}

/// Does this parent have both controllers available and delegated to
/// children (enabling them if needed)?
fn ensure_controllers(parent: &Path) -> io::Result<()> {
    let controllers = read_control(&parent.join("cgroup.controllers"))?;
    for needed in ["cpu", "memory", "pids"] {
        if !controllers.split_whitespace().any(|c| c == needed) {
            return Err(io::Error::other(format!(
                "cgroup parent lacks the `{needed}` controller (has: {controllers})"
            )));
        }
    }
    let subtree = parent.join("cgroup.subtree_control");
    let enabled = read_control(&subtree)?;
    let mut missing: Vec<&str> = Vec::new();
    for needed in ["cpu", "memory", "pids"] {
        if !enabled.split_whitespace().any(|c| c == needed) {
            missing.push(needed);
        }
    }
    if !missing.is_empty() {
        // May fail with EBUSY under the no-internal-process rule or
        // EACCES without delegation — the caller treats that as "no
        // group enforcement here".
        let line = missing
            .iter()
            .map(|c| format!("+{c}"))
            .collect::<Vec<_>>()
            .join(" ");
        std::fs::write(&subtree, line)?;
    }
    Ok(())
}

/// Prove that a child can enter the delegated subtree, not merely that its
/// control files are writable. cgroup v2 migration also checks write access
/// to the source/destination common ancestor, so limit-only probes can
/// otherwise produce a false positive for a process outside the delegation.
#[cfg(target_os = "linux")]
fn verify_process_attachment(group: &Path) -> io::Result<()> {
    use std::os::unix::process::CommandExt;

    let procs = group.join("cgroup.procs");
    let procs_c = std::ffi::CString::new(procs.as_os_str().as_encoded_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "cgroup path contains a NUL byte",
        )
    })?;
    let mut cmd = std::process::Command::new("/bin/sh");
    // `kill` is a shell builtin: the child stops itself without depending on
    // another executable and remains a stable cgroup member until killed.
    cmd.args(["-c", "kill -STOP $$"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    // SAFETY: only async-signal-safe raw syscalls run between fork and exec.
    unsafe {
        cmd.pre_exec(move || {
            let fd = libc::open(procs_c.as_ptr(), libc::O_WRONLY);
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            let wrote = libc::write(fd, b"0\n".as_ptr().cast(), 2);
            libc::close(fd);
            if wrote < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let mut child = cmd.spawn()?;
    let result = (|| {
        let members = read_control(&procs)?;
        if !members
            .lines()
            .any(|line| line.trim() == child.id().to_string())
        {
            return Err(io::Error::other(
                "probe child did not enter the delegated cgroup",
            ));
        }
        std::fs::write(group.join("cgroup.kill"), "1")?;
        let status = child.wait()?;
        if status.success() {
            return Err(io::Error::other("cgroup.kill did not kill the probe child"));
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
    }
    result
}

#[cfg(not(target_os = "linux"))]
fn verify_process_attachment(_group: &Path) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "cgroup process attachment is Linux-only",
    ))
}

impl CgroupSupervisor {
    /// Probe for a usable cgroup v2 parent (see the module docs for the
    /// candidate order). Returns `None` — with a log line naming the
    /// reason — when no candidate verifies; the backend then keeps the
    /// per-process rlimit backstops only.
    pub fn probe(configured: Option<&Path>) -> Option<Self> {
        if !cfg!(target_os = "linux") {
            return None;
        }
        let mut candidates: Vec<PathBuf> = Vec::new();
        if let Some(p) = configured {
            candidates.push(p.to_path_buf());
        }
        if let Some(p) = std::env::var_os("AK_CGROUP_PARENT") {
            candidates.push(PathBuf::from(p));
        }
        if let Some(own) = self_cgroup_dir() {
            candidates.push(own);
        }
        for candidate in candidates {
            match Self::verify(&candidate) {
                Ok(()) => {
                    tracing::info!(parent = %candidate.display(), "cgroup group enforcement verified");
                    return Some(Self { parent: candidate });
                }
                Err(e) => {
                    tracing::debug!(parent = %candidate.display(), error = %e,
                                    "cgroup candidate rejected");
                }
            }
        }
        tracing::info!(
            "no writable, delegated cgroup v2 parent verified; group-level \
             memory/pid ceilings stay off (per-process rlimit backstops only)"
        );
        None
    }

    /// Full end-to-end verification of one candidate: controllers
    /// delegated, a scratch child group creatable, both limit files
    /// writable, CPU accounting readable, a child process attachable, and
    /// atomic full-tree kill available.
    fn verify(parent: &Path) -> io::Result<()> {
        require_cgroup2fs(parent)?;
        ensure_controllers(parent)?;
        let probe = parent.join(format!("ak-probe-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir(&probe)?;
        let result = (|| {
            std::fs::write(probe.join("memory.max"), "1073741824")?;
            std::fs::write(probe.join("memory.swap.max"), "0")?;
            std::fs::write(probe.join("pids.max"), "64")?;
            let _ = read_control(&probe.join("cpu.stat"))?;
            // Attachment and full-tree teardown are part of the guarantee.
            // Requiring the kernel's atomic cgroup.kill avoids the PID-reuse
            // race inherent in userspace cgroup.procs enumeration fallbacks.
            verify_process_attachment(&probe)?;
            Ok(())
        })();
        let _ = std::fs::remove_dir(&probe);
        result
    }

    /// Create a per-step (or per-session) group with the given ceilings.
    /// `memory_bytes = None` (no declared budget dimension) sets no memory
    /// ceiling; `max_pids` always applies.
    pub fn create_group(
        &self,
        label: &str,
        memory_bytes: Option<u64>,
        max_pids: u64,
    ) -> io::Result<StepCgroup> {
        if max_pids == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "pids.max must be at least 1",
            ));
        }
        let dir = self.parent.join(format!("ak-{label}"));
        std::fs::create_dir(&dir)?;
        let group = StepCgroup {
            dir,
            cpu_exhausted: AtomicBool::new(false),
        };
        if let Some(bytes) = memory_bytes {
            std::fs::write(group.dir.join("memory.max"), bytes.to_string())?;
            // Without this, anonymous pages can leave memory.current and
            // consume unbudgeted swap beyond the declared memory ceiling.
            std::fs::write(group.dir.join("memory.swap.max"), "0")?;
        }
        std::fs::write(group.dir.join("pids.max"), max_pids.to_string())?;
        Ok(group)
    }
}

/// The calling process's own cgroup v2 directory, from `/proc/self/cgroup`
/// (`0::<path>` on the unified hierarchy).
fn self_cgroup_dir() -> Option<PathBuf> {
    let content = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    let path = content
        .lines()
        .find_map(|line| line.strip_prefix("0::"))?
        .trim();
    Some(PathBuf::from("/sys/fs/cgroup").join(path.trim_start_matches('/')))
}

/// One live per-step/per-session cgroup. Dropping it kills every member
/// (`cgroup.kill`) and removes the directory, with retries while the
/// kernel reaps.
#[derive(Debug)]
pub struct StepCgroup {
    dir: PathBuf,
    cpu_exhausted: AtomicBool,
}

impl StepCgroup {
    /// The `cgroup.procs` file a `pre_exec` hook writes `0` into: the
    /// child enters the group between `fork` and `exec`, so no workload
    /// instruction ever runs outside the ceilings.
    pub fn procs_file(&self) -> PathBuf {
        self.dir.join("cgroup.procs")
    }

    /// Kill **every** process in the group — including `setsid` escapees
    /// the process-group kill cannot reach. The construction probe requires
    /// the kernel's atomic `cgroup.kill` interface.
    pub fn kill_tree(&self) -> io::Result<()> {
        std::fs::write(self.dir.join("cgroup.kill"), "1")
    }

    /// Tree-wide peak memory (`memory.peak`), when the kernel exposes it.
    pub fn peak_memory(&self) -> Option<u64> {
        read_control(&self.dir.join("memory.peak"))
            .ok()?
            .parse()
            .ok()
    }

    /// How many processes the kernel OOM-killed under this group's
    /// `memory.max` (`memory.events:oom_kill`).
    pub fn oom_kills(&self) -> Option<u64> {
        event_value(&self.dir.join("memory.events"), "oom_kill")
    }

    /// Number of times `pids.max` rejected a task creation in this group.
    pub fn pid_limit_hits(&self) -> Option<u64> {
        event_value(&self.dir.join("pids.events"), "max")
    }

    /// Aggregate user+system CPU consumed by the whole group.
    pub fn cpu_usage_ms(&self) -> Option<u64> {
        event_value(&self.dir.join("cpu.stat"), "usage_usec").map(|us| us / 1000)
    }

    /// Whether any task remains in this cgroup. For process sessions this is
    /// the authoritative liveness bit: the original shell may exit while a
    /// daemonized descendant continues to run.
    pub fn populated(&self) -> Option<bool> {
        event_value(&self.dir.join("cgroup.events"), "populated").map(|n| n != 0)
    }

    /// Whether the group-level CPU monitor killed this workload.
    pub fn cpu_exhausted(&self) -> bool {
        self.cpu_exhausted.load(Ordering::SeqCst)
    }

    /// Enforce an aggregate CPU-time budget over every process/thread in the
    /// group. cgroup v2 exposes cumulative usage but no lifetime quota, so a
    /// small host-side monitor performs the terminal kill. `cpu.max` is not
    /// used: rate-limiting to one core would unnecessarily cripple parallel
    /// compilers and tests.
    pub fn enforce_cpu_budget(self: &Arc<Self>, cpu_ms: u64) {
        if cpu_ms == 0 {
            return;
        }
        let weak = Arc::downgrade(self);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_millis(5));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                let Some(group) = weak.upgrade() else {
                    break;
                };
                if group.cpu_usage_ms().is_some_and(|used| used >= cpu_ms) {
                    group.cpu_exhausted.store(true, Ordering::SeqCst);
                    if let Err(e) = group.kill_tree() {
                        tracing::error!(dir = %group.dir.display(), error = %e,
                                        "verified cgroup.kill failed at CPU limit");
                    }
                    break;
                }
                if group.populated() == Some(false) {
                    break;
                }
            }
        });
    }
}

impl Drop for StepCgroup {
    fn drop(&mut self) {
        if let Err(e) = self.kill_tree() {
            tracing::error!(dir = %self.dir.display(), error = %e,
                            "verified cgroup.kill failed during teardown");
        }
        // rmdir succeeds only once the kernel has reaped every member.
        for _ in 0..50 {
            match std::fs::remove_dir(&self.dir) {
                Ok(()) => return,
                Err(e) if e.kind() == io::ErrorKind::NotFound => return,
                Err(_) => std::thread::sleep(std::time::Duration::from_millis(10)),
            }
        }
        tracing::warn!(dir = %self.dir.display(), "step cgroup not removable after kill");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_rejects_non_cgroupfs_candidates() {
        // Even a lookalike directory containing plausible writable control
        // files is not enforcement. The filesystem type is part of the
        // capability proof (and this path also covers non-Linux hosts).
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("cgroup.controllers"), "cpu memory pids").unwrap();
        std::fs::write(dir.path().join("cgroup.subtree_control"), "cpu memory pids").unwrap();
        let error = CgroupSupervisor::verify(dir.path()).unwrap_err();
        assert!(
            error.to_string().contains("cgroup v2"),
            "unexpected rejection: {error}"
        );
    }

    #[test]
    fn probe_never_panics() {
        // Whatever the host: Some (delegated Linux) or None, no panic.
        let _ = CgroupSupervisor::probe(None);
    }

    #[test]
    fn parses_event_values_with_arbitrary_whitespace() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("events");
        std::fs::write(&path, "low 0\nmax    17\noom_kill 2\n").unwrap();
        assert_eq!(event_value(&path, "max"), Some(17));
        assert_eq!(event_value(&path, "oom_kill"), Some(2));
        assert_eq!(event_value(&path, "missing"), None);
    }

    /// On a Linux host with a delegated parent (CI exports
    /// `AK_CGROUP_PARENT`), the full lifecycle must work: create, limit,
    /// attach a real child, tree metering, kill, remove.
    #[cfg(target_os = "linux")]
    #[test]
    fn lifecycle_on_delegated_hosts() {
        let Some(sup) = CgroupSupervisor::probe(None) else {
            if std::env::var("AK_REQUIRE_CGROUP").as_deref() == Ok("1") {
                panic!("AK_REQUIRE_CGROUP=1 but the delegated cgroup v2 probe failed");
            }
            eprintln!("skipping: no delegated cgroup parent on this host");
            return;
        };
        let group = sup
            .create_group(&format!("test-{}", std::process::id()), Some(64 << 20), 16)
            .unwrap();
        assert_eq!(
            read_control(&group.dir.join("pids.max")).unwrap(),
            "16",
            "pids ceiling must be set"
        );

        // Attach a real child via pre_exec and verify membership.
        use std::os::unix::process::CommandExt;
        let procs = group.procs_file();
        let procs_c = std::ffi::CString::new(procs.to_str().unwrap()).unwrap();
        let mut cmd = std::process::Command::new("/bin/sh");
        cmd.args(["-c", "sleep 30"]);
        // SAFETY: only async-signal-safe raw syscalls in pre_exec.
        unsafe {
            cmd.pre_exec(move || {
                let fd = libc::open(procs_c.as_ptr(), libc::O_WRONLY);
                if fd < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                let r = libc::write(fd, b"0\n".as_ptr().cast(), 2);
                libc::close(fd);
                if r < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = cmd.spawn().unwrap();
        let members = read_control(&procs).unwrap();
        assert!(
            members.lines().any(|l| l.trim() == child.id().to_string()),
            "child must be inside the group: {members:?}"
        );

        // kill_tree must reap it (drop also does; exercise it explicitly).
        group.kill_tree().unwrap();
        drop(group);
        // The child was SIGKILLed by the cgroup, not by us.
        let mut child = child;
        let status = child.wait().unwrap();
        assert!(!status.success());
    }
}

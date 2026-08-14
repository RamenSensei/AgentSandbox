//! Persistent process sessions: long-running children owned by a branch.
//!
//! A [`ProcessSession`] outlives the step that started it. Its combined
//! stdout/stderr is pumped into a capped in-memory [`LogBuffer`] with a
//! monotonically increasing byte-offset space, so an agent can *tail* a dev
//! server, test run or REPL incrementally (`ProcessLogs { from_offset }`)
//! instead of waiting for termination.
//!
//! Sessions are branch-scoped:
//!
//! - a step may only address sessions of **its own** branch;
//! - discarding the branch kills every session in its process group;
//! - forks do **not** inherit sessions (files fork; live processes don't) —
//!   restart recipes are the agent's job, and honest `AuditOnly` replay
//!   classes record that these steps cannot be re-executed.

use ak_core::ids::BranchId;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Instant;
use tokio::io::AsyncReadExt;
use tokio::process::{Child, ChildStdin};

/// Combined stdout/stderr ring buffer. Offsets are *stream* offsets: the
/// total number of bytes ever produced, so an agent's `from_offset` cursor
/// stays valid as old bytes are evicted (it just observes `base_offset`
/// jumping forward and knows bytes were dropped).
#[derive(Debug)]
pub struct LogBuffer {
    data: Vec<u8>,
    base_offset: u64,
    cap: usize,
}

impl LogBuffer {
    fn new(cap: usize) -> Self {
        Self {
            data: Vec::new(),
            base_offset: 0,
            cap: cap.max(1),
        }
    }

    fn append(&mut self, chunk: &[u8]) {
        self.data.extend_from_slice(chunk);
        if self.data.len() > self.cap {
            let drop = self.data.len() - self.cap;
            self.data.drain(..drop);
            self.base_offset += drop as u64;
        }
    }

    /// First offset still held in the buffer.
    pub fn base_offset(&self) -> u64 {
        self.base_offset
    }

    /// Total bytes ever produced by the process.
    pub fn total(&self) -> u64 {
        self.base_offset + self.data.len() as u64
    }

    /// Read up to `max` bytes starting at stream offset `from` (clamped to
    /// what the buffer still holds). Returns `(effective_offset, bytes)`.
    pub fn read_from(&self, from: u64, max: usize) -> (u64, Vec<u8>) {
        let start = from.max(self.base_offset).min(self.total());
        let idx = (start - self.base_offset) as usize;
        let end = (idx + max).min(self.data.len());
        (start, self.data[idx..end].to_vec())
    }
}

/// A live (or exited but not yet reaped from the registry) process session.
#[derive(Clone)]
pub struct ProcessSession {
    pub id: String,
    pub branch: BranchId,
    pub name: Option<String>,
    pub command: String,
    pub pid: Option<u32>,
    pub started_at: Instant,
    /// Writable stdin; `None` once closed.
    pub stdin: Arc<tokio::sync::Mutex<Option<ChildStdin>>>,
    pub logs: Arc<Mutex<LogBuffer>>,
    /// Exit code once the process has terminated.
    pub exit: Arc<Mutex<Option<i32>>>,
    /// Keeps the Seatbelt profile file alive for the process lifetime.
    _profile: Option<Arc<tempfile::NamedTempFile>>,
    /// Keeps the egress proxy token alive for the process lifetime; dropped
    /// (revoked) when the session is removed.
    egress: Option<Arc<crate::egress::EgressGrant>>,
    /// The session's cgroup (group-level ceilings). Dropping the last
    /// clone kills every member — even setsid escapees — and removes it.
    cgroup: Option<Arc<crate::cgroup::StepCgroup>>,
}

impl ProcessSession {
    pub fn exit_code(&self) -> Option<i32> {
        *lock(&self.exit)
    }

    pub fn running(&self) -> bool {
        self.cgroup
            .as_ref()
            .and_then(|group| group.populated())
            .unwrap_or_else(|| self.exit_code().is_none())
    }

    /// Send a signal to the whole process group (the child is its own group
    /// leader). `signal` is `int`, `term` or `kill`.
    pub fn signal(&self, signal: &str) -> Result<(), String> {
        let sig = match signal {
            "int" => "INT",
            "term" => "TERM",
            "kill" => "KILL",
            other => return Err(format!("unknown signal `{other}`: use int|term|kill")),
        };
        let Some(pid) = self.pid else {
            return Err("process has no pid".into());
        };
        if !self.running() {
            return Err("process has already exited".into());
        }
        // SIGKILL is terminal, so use the cgroup's atomic full-tree kill
        // when available. Unlike a process-group signal this reaches
        // descendants that daemonized with setsid.
        if signal == "kill" {
            if let Some(group) = &self.cgroup {
                return group
                    .kill_tree()
                    .map_err(|e| format!("cgroup.kill failed: {e}"));
            }
        }
        let status = std::process::Command::new("kill")
            .arg(format!("-{sig}"))
            .arg("--")
            .arg(format!("-{pid}"))
            .status()
            .map_err(|e| format!("kill failed: {e}"))?;
        if status.success() {
            Ok(())
        } else {
            // The group may already be gone; try the single pid before
            // reporting failure.
            let single = std::process::Command::new("kill")
                .arg(format!("-{sig}"))
                .arg(pid.to_string())
                .status()
                .map_err(|e| format!("kill failed: {e}"))?;
            if single.success() {
                Ok(())
            } else {
                Err(format!("kill -{sig} {pid} failed"))
            }
        }
    }

    pub fn status_json(&self) -> serde_json::Value {
        let logs = lock(&self.logs);
        let cpu_ms = self.cgroup.as_ref().and_then(|g| g.cpu_usage_ms());
        let memory_peak_bytes = self.cgroup.as_ref().and_then(|g| g.peak_memory());
        let oom_kills = self.cgroup.as_ref().and_then(|g| g.oom_kills());
        let pid_limit_hits = self.cgroup.as_ref().and_then(|g| g.pid_limit_hits());
        let cpu_budget_exhausted = self.cgroup.as_ref().is_some_and(|g| g.cpu_exhausted());
        let network_bytes = self.egress.as_ref().map(|g| g.used_bytes()).unwrap_or(0);
        serde_json::json!({
            "process": self.id,
            "name": self.name,
            "command": self.command,
            "pid": self.pid,
            "running": self.running(),
            "exit_code": self.exit_code(),
            "uptime_ms": self.started_at.elapsed().as_millis() as u64,
            "log_total_bytes": logs.total(),
            "log_base_offset": logs.base_offset(),
            "cpu_ms": cpu_ms,
            "memory_peak_bytes": memory_peak_bytes,
            "oom_kills": oom_kills,
            "pid_limit_hits": pid_limit_hits,
            "cpu_budget_exhausted": cpu_budget_exhausted,
            "network_bytes": network_bytes,
        })
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Branch-scoped registry of process sessions.
#[derive(Default)]
pub struct ProcessRegistry {
    sessions: Mutex<HashMap<String, ProcessSession>>,
}

impl ProcessRegistry {
    /// Adopt a freshly spawned child: take its stdio, start the log pumps
    /// and the reaper task, and register the session.
    #[allow(clippy::too_many_arguments)]
    pub fn adopt(
        &self,
        branch: &BranchId,
        name: Option<String>,
        command: String,
        mut child: Child,
        profile: Option<tempfile::NamedTempFile>,
        egress: Option<crate::egress::EgressGrant>,
        cgroup: Option<Arc<crate::cgroup::StepCgroup>>,
        log_cap: usize,
    ) -> ProcessSession {
        let id = format!("proc-{}", uuid::Uuid::new_v4().simple());
        let logs = Arc::new(Mutex::new(LogBuffer::new(log_cap)));
        let exit = Arc::new(Mutex::new(None));
        let stdin = Arc::new(tokio::sync::Mutex::new(child.stdin.take()));
        let pid = child.id();
        if let Some(stdout) = child.stdout.take() {
            pump(stdout, Arc::clone(&logs));
        }
        if let Some(stderr) = child.stderr.take() {
            pump(stderr, Arc::clone(&logs));
        }
        {
            let exit = Arc::clone(&exit);
            tokio::spawn(async move {
                let code = child
                    .wait()
                    .await
                    .map(|s| s.code().unwrap_or(-1))
                    .unwrap_or(-1);
                *lock(&exit) = Some(code);
            });
        }
        let session = ProcessSession {
            id: id.clone(),
            branch: branch.clone(),
            name,
            command,
            pid,
            started_at: Instant::now(),
            stdin,
            logs,
            exit,
            _profile: profile.map(Arc::new),
            egress: egress.map(Arc::new),
            cgroup,
        };
        lock(&self.sessions).insert(id, session.clone());
        session
    }

    /// The session with `id`, **only** if it belongs to `branch` (a branch
    /// must never observe or signal another branch's processes).
    pub fn get(&self, branch: &BranchId, id: &str) -> Option<ProcessSession> {
        lock(&self.sessions)
            .get(id)
            .filter(|s| &s.branch == branch)
            .cloned()
    }

    /// All sessions of a branch (running and exited).
    pub fn list(&self, branch: &BranchId) -> Vec<ProcessSession> {
        let mut v: Vec<ProcessSession> = lock(&self.sessions)
            .values()
            .filter(|s| &s.branch == branch)
            .cloned()
            .collect();
        v.sort_by_key(|s| s.started_at);
        v
    }

    /// Kill and remove every session of a branch (branch discard).
    pub fn kill_branch(&self, branch: &BranchId) -> usize {
        let victims: Vec<ProcessSession> = {
            let mut map = lock(&self.sessions);
            let ids: Vec<String> = map
                .values()
                .filter(|s| &s.branch == branch)
                .map(|s| s.id.clone())
                .collect();
            ids.iter().filter_map(|id| map.remove(id)).collect()
        };
        let n = victims.len();
        for s in victims {
            let _ = s.signal("kill");
        }
        n
    }
}

fn pump(
    mut reader: impl tokio::io::AsyncRead + Unpin + Send + 'static,
    logs: Arc<Mutex<LogBuffer>>,
) {
    tokio::spawn(async move {
        let mut buf = [0u8; 8192];
        loop {
            match reader.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => lock(&logs).append(&buf[..n]),
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_buffer_caps_and_keeps_stream_offsets() {
        let mut b = LogBuffer::new(8);
        b.append(b"0123456789"); // 10 bytes into an 8-byte cap
        assert_eq!(b.base_offset(), 2);
        assert_eq!(b.total(), 10);
        let (off, data) = b.read_from(0, 100);
        assert_eq!(off, 2, "evicted bytes are skipped, honestly");
        assert_eq!(data, b"23456789");
        let (off, data) = b.read_from(4, 3);
        assert_eq!(off, 4);
        assert_eq!(data, b"456");
        // Reading past the end yields empty at the end offset.
        let (off, data) = b.read_from(99, 10);
        assert_eq!(off, 10);
        assert!(data.is_empty());
    }
}

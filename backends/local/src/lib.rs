//! # ak-backend-local
//!
//! A real, working local OS-sandbox [`Backend`] for macOS and Linux, used by
//! tests and examples. It executes [`ActionKind::Shell`], [`ActionKind::ReadFile`],
//! [`ActionKind::WriteFile`] and [`ActionKind::DeletePath`] inside a
//! **per-branch workspace directory** with:
//!
//! - a **scrubbed environment**: the child process environment is cleared and
//!   only `PATH` (host value), `HOME` (set to the workspace) and `LANG` are
//!   provided, plus any explicitly pre-authorized variables carried on the
//!   action itself;
//! - a **wall-clock timeout** derived from `budget.cpu_ms`, with
//!   kill-on-timeout via the child's process group where available;
//! - **output capture with byte caps** (see [`LocalBackendConfig::max_capture_bytes`]);
//! - **in-process path confinement**: every path is verified to be inside the
//!   workspace (no absolute paths, no `..`, symlink escapes rejected by
//!   canonicalizing the deepest existing ancestor) and to match the request's
//!   readable/writable prefixes;
//! - **`paths_written` detection** via an mtime/size scan diff of the
//!   workspace before and after execution.
//!
//! On Linux, if a `bwrap` (bubblewrap) binary is found at runtime, shell
//! commands are additionally wrapped in a bubblewrap sandbox with network and
//! PID namespaces unshared. This is feature-detected at *runtime*, not compile
//! time; without it the backend performs a plain confined exec.
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
}

impl LocalBackendConfig {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            max_capture_bytes: 1 << 20,
            max_wall_clock: Duration::from_secs(600),
        }
    }
}

/// Local OS-sandbox backend. See the crate docs for the confinement model.
pub struct LocalBackend {
    config: LocalBackendConfig,
    /// Whether `bwrap` was found on this host (Linux only, runtime-detected).
    bwrap: bool,
}

impl LocalBackend {
    /// Create the backend, ensuring the workspace root exists and probing for
    /// bubblewrap on Linux.
    pub fn new(config: LocalBackendConfig) -> KernelResult<Self> {
        std::fs::create_dir_all(&config.root)?;
        let bwrap = detect_bwrap();
        Ok(Self { config, bwrap })
    }

    /// Whether shell commands will be wrapped in bubblewrap.
    pub fn uses_bwrap(&self) -> bool {
        self.bwrap
    }

    /// The workspace directory for a branch, created on demand.
    pub fn workspace_for(&self, branch: &BranchId) -> KernelResult<PathBuf> {
        let dir = self.config.root.join(branch.as_str());
        std::fs::create_dir_all(&dir)?;
        Ok(dir)
    }
}

/// Runtime bubblewrap detection (Linux only; always `false` elsewhere).
fn detect_bwrap() -> bool {
    if !cfg!(target_os = "linux") {
        return false;
    }
    std::process::Command::new("bwrap")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
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
/// written paths across an execution.
fn scan_workspace(workspace: &Path) -> BTreeMap<String, (SystemTime, u64)> {
    let mut out = BTreeMap::new();
    let mut stack = vec![workspace.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        for entry in entries.flatten() {
            let path = entry.path();
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

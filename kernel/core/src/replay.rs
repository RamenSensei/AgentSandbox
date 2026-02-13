//! Replay classes: honest, per-backend statements of what "replay" guarantees.
//!
//! We deliberately refuse a single vague "supports snapshot" flag. A backend
//! declares exactly which layers of state it can capture and re-execute, and
//! the kernel classifies every step accordingly.

use serde::{Deserialize, Serialize};

/// What a backend can faithfully capture and replay.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayClass {
    /// Only the recorded observations can be played back; no re-execution.
    AuditOnly,
    /// Workspace files are content-addressed and restorable.
    FilesystemOnly,
    /// Filesystem plus process tree checkpoint/restore.
    ProcessAndFilesystem,
    /// Framework-level host calls (model, tools, HTTP) are recorded and can be
    /// replayed byte-identically under pinned time/randomness.
    FrameworkHostCalls,
    /// Browser profile and page state are restorable.
    BrowserProfile,
}

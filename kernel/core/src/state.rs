//! World-state DAG node and delta types.
//!
//! The sandbox is not a box; it is a versioned graph of immutable state nodes.
//! Each step appends a node whose delta records exactly what changed across
//! every state adapter (workspace, processes, tool sessions, policy, effects).

use crate::hash::ContentHash;
use crate::ids::{BranchId, EpisodeId, PrincipalId, StateId, StepId};
use crate::replay::ReplayClass;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// One file-level change in the workspace adapter.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "op")]
pub enum FileChange {
    Added { path: String, blob: ContentHash, mode: u32 },
    Modified { path: String, old_blob: ContentHash, new_blob: ContentHash },
    Deleted { path: String, old_blob: ContentHash },
}

impl FileChange {
    pub fn path(&self) -> &str {
        match self {
            FileChange::Added { path, .. }
            | FileChange::Modified { path, .. }
            | FileChange::Deleted { path, .. } => path,
        }
    }
}

/// The immutable delta produced by one step, spanning all adapters.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct StateDelta {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<FileChange>,
    /// Processes started (still running at step end), by command line digest.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub processes_started: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub processes_exited: Vec<String>,
    /// Tool/MCP sessions opened or mutated.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tool_sessions: Vec<String>,
    /// Policy epoch after this step (bumps when policy changed).
    pub policy_epoch: u64,
    /// Effects proposed during this step.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub effects_proposed: Vec<crate::ids::EffectId>,
    /// Effects committed during this step (receipts).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub effects_committed: Vec<crate::ids::ReceiptId>,
}

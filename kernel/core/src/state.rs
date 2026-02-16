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

impl StateDelta {
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
            && self.processes_started.is_empty()
            && self.processes_exited.is_empty()
            && self.tool_sessions.is_empty()
            && self.effects_proposed.is_empty()
            && self.effects_committed.is_empty()
    }
}

/// An immutable node in the world-state DAG.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StateNode {
    pub id: StateId,
    pub episode: EpisodeId,
    pub branch: BranchId,
    /// Parent state; `None` only for the episode root.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent: Option<StateId>,
    /// Step that produced this node; `None` for roots and merge nodes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub produced_by: Option<StepId>,
    /// Additional parent for merge nodes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub merge_parent: Option<StateId>,
    pub actor: PrincipalId,
    pub delta: StateDelta,
    /// Merkle root of the workspace tree at this node.
    pub workspace_root: ContentHash,
    pub replay_class: ReplayClass,
    pub created_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_delta_detection() {
        let mut d = StateDelta::default();
        assert!(d.is_empty());
        d.files.push(FileChange::Deleted {
            path: "a.txt".into(),
            old_blob: crate::hash::hash_bytes(b"x"),
        });
        assert!(!d.is_empty());
    }
}

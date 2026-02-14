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

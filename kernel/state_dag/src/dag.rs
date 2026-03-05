//! SQLite-backed world-state DAG store and its operations.
//!
//! Persists [`StateNode`] rows, branches and episodes; provides fork /
//! append / discard / diff / merge / GC on top of the [`Cas`] and the
//! snapshot layer.
//!
//! ## Merge semantics (read this)
//!
//! [`StateDag::merge`] is an **artifact merge only**: it three-way merges the
//! *workspace file trees* of two branches from their lowest common ancestor.
//! It never merges processes, tool sessions or capability leases — those are
//! runtime state owned by the isolation backend and the kernel respectively,
//! and "merging" them has no coherent semantics. Concurrent edits to the same
//! path fail with [`KernelError::MergeConflict`] listing every conflicting
//! path; nothing is written in that case.
//!
//! ## Discard semantics
//!
//! [`StateDag::discard_branch`] only flips the branch's status in the store.
//! Releasing backend-side resources (`Backend::discard`) is the caller's
//! responsibility; this crate has no backend handle by design.

use crate::cas::Cas;
use crate::snapshot::{self, Manifest};
use ak_core::hash::ContentHash;
use ak_core::ids::{BranchId, EpisodeId, PrincipalId, StateId, StepId};
use ak_core::replay::ReplayClass;
use ak_core::state::{FileChange, StateDelta, StateNode};
use ak_core::{KernelError, KernelResult};
use chrono::Utc;
use rusqlite::{params, Connection, OptionalExtension};
use std::collections::{BTreeMap, HashSet, VecDeque};
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

/// Lifecycle status of a branch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BranchStatus {
    /// The branch accepts new steps.
    Active,
    /// The branch was abandoned; its exclusive blobs are GC candidates.
    Discarded,
    /// The branch was merged into another branch.
    Merged,
}

impl BranchStatus {
    fn as_str(self) -> &'static str {
        match self {
            BranchStatus::Active => "active",
            BranchStatus::Discarded => "discarded",
            BranchStatus::Merged => "merged",
        }
    }

    fn parse(s: &str) -> KernelResult<Self> {
        match s {
            "active" => Ok(BranchStatus::Active),
            "discarded" => Ok(BranchStatus::Discarded),
            "merged" => Ok(BranchStatus::Merged),
            other => Err(KernelError::Storage(format!("unknown branch status `{other}`"))),
        }
    }
}

/// A branch row: a movable head pointer over immutable states.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Branch {
    pub id: BranchId,
    pub episode: EpisodeId,
    /// State this branch was forked from (the episode root for the initial branch).
    pub base_state: StateId,
    pub head: StateId,
    pub status: BranchStatus,
}

/// Result of [`StateDag::branch_compare`].
#[derive(Debug, Clone, PartialEq)]
pub struct BranchComparison {
    /// Lowest common ancestor of the two branch heads.
    pub base: StateId,
    /// Files changed on branch `a` since `base`.
    pub changed_in_a: Vec<FileChange>,
    /// Files changed on branch `b` since `base`.
    pub changed_in_b: Vec<FileChange>,
}

/// Everything created by [`StateDag::create_episode`].
#[derive(Debug, Clone)]
pub struct EpisodeHandle {
    pub episode: EpisodeId,
    /// The initial (main) branch of the episode.
    pub branch: BranchId,
    /// The root state node.
    pub root: StateNode,
}

/// Outcome of a garbage-collection pass.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GcReport {
    /// CAS blobs deleted.
    pub blobs_removed: usize,
    /// State rows deleted (states reachable only from discarded branches).
    pub states_removed: usize,
}

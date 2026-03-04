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

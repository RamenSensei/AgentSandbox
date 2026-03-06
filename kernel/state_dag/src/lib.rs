//! # ak-state-dag
//!
//! The branchable World State DAG service of AgentKernel.
//!
//! - [`Cas`]: content-addressed blob store on disk (sha256, prefix fan-out).
//! - [`snapshot`]: workspace snapshotting into the CAS ([`Manifest`],
//!   [`snapshot_dir`], [`materialize`], [`diff_manifests`]).
//! - [`StateDag`]: SQLite-backed (WAL, migrated schema) DAG of
//!   [`ak_core::StateNode`]s with episodes, branches, fork/append/discard,
//!   diff, lowest-common-ancestor branch comparison, three-way *artifact*
//!   merge, and mark-and-sweep garbage collection.
//!
//! Merges are file-tree merges only; processes and leases are never merged
//! (see [`dag`] module docs). `Backend::discard` is the caller's job after
//! [`StateDag::discard_branch`].

pub mod cas;
pub mod dag;
pub mod snapshot;

pub use cas::Cas;
pub use dag::{Branch, BranchComparison, BranchStatus, EpisodeHandle, GcReport, StateDag};
pub use snapshot::{diff_manifests, materialize, snapshot_dir, Manifest, ManifestEntry};

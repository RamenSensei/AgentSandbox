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

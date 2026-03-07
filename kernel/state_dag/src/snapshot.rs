//! Workspace snapshotting: directory trees → merkle manifests in the CAS.
//!
//! A snapshot walks a directory, stores every file's bytes as a CAS blob and
//! records `path → (blob, mode)` in a [`Manifest`]. The manifest is itself
//! serialized canonically and stored in the CAS; its content hash is the
//! node's `workspace_root`. Any state can therefore be re-materialized from
//! its `workspace_root` alone.

use crate::cas::Cas;
use ak_core::hash::ContentHash;
use ak_core::state::FileChange;
use ak_core::{KernelError, KernelResult};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

/// One file entry in a workspace manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestEntry {
    /// CAS hash of the file's bytes.
    pub blob: ContentHash,
    /// Unix permission bits (0o644 on platforms without a mode).
    pub mode: u32,
}

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

/// A full, sorted `path → entry` listing of a workspace tree.
///
/// Paths are workspace-relative and use `/` separators; the [`BTreeMap`]
/// keeps them sorted so the canonical encoding (and thus the merkle root)
/// is deterministic.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Manifest {
    pub files: BTreeMap<String, ManifestEntry>,
}

impl Manifest {
    /// Store this manifest in the CAS and return its content hash — the
    /// `workspace_root` for a state node with this tree.
    pub fn store(&self, cas: &Cas) -> KernelResult<ContentHash> {
        cas.put(ak_core::hash::canonical_json(self).as_bytes())
    }

    /// Load a manifest previously stored via [`Manifest::store`].
    pub fn load(cas: &Cas, workspace_root: &ContentHash) -> KernelResult<Self> {
        let bytes = cas.get(workspace_root)?;
        serde_json::from_slice(&bytes).map_err(KernelError::Serde)
    }
}

fn file_mode(meta: &fs::Metadata) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o7777
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        0o644
    }
}

/// Snapshot `dir` into the CAS, returning the workspace root hash and the
/// manifest. Symlinks and empty directories are ignored (artifact-level
/// snapshot only; process state is a backend concern).
#[tracing::instrument(level = "info", skip(cas), fields(dir = %dir.display()))]
pub fn snapshot_dir(cas: &Cas, dir: &Path) -> KernelResult<(ContentHash, Manifest)> {
    let mut manifest = Manifest::default();
    walk(cas, dir, dir, &mut manifest)?;
    let root = manifest.store(cas)?;
    tracing::debug!(files = manifest.files.len(), root = %root, "snapshot complete");
    Ok((root, manifest))
}

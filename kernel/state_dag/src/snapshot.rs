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

fn walk(cas: &Cas, base: &Path, dir: &Path, manifest: &mut Manifest) -> KernelResult<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let ft = entry.file_type()?;
        if ft.is_dir() {
            walk(cas, base, &path, manifest)?;
        } else if ft.is_file() {
            let bytes = fs::read(&path)?;
            let blob = cas.put(&bytes)?;
            let rel = path
                .strip_prefix(base)
                .map_err(|e| KernelError::Storage(format!("path outside snapshot root: {e}")))?;
            let rel = rel
                .components()
                .map(|c| c.as_os_str().to_string_lossy())
                .collect::<Vec<_>>()
                .join("/");
            let mode = file_mode(&entry.metadata()?);
            manifest.files.insert(rel, ManifestEntry { blob, mode });
        }
        // symlinks / other node types are intentionally skipped
    }
    Ok(())
}

/// Materialize the workspace identified by `workspace_root` into `target`,
/// replacing any files already present at manifest paths. `target` is
/// created if missing; files in `target` that are *not* in the manifest are
/// removed so the result exactly equals the snapshot.
#[tracing::instrument(level = "info", skip(cas), fields(root = %workspace_root, target = %target.display()))]
pub fn materialize(cas: &Cas, workspace_root: &ContentHash, target: &Path) -> KernelResult<()> {
    let manifest = Manifest::load(cas, workspace_root)?;
    if target.exists() {
        // Clear stale content so materialization is exact, not additive.
        fs::remove_dir_all(target)?;
    }
    fs::create_dir_all(target)?;
    for (path, entry) in &manifest.files {
        let dest = target.join(path);
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }
        let bytes = cas.get(&entry.blob)?;
        fs::write(&dest, bytes)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&dest, fs::Permissions::from_mode(entry.mode))?;
        }
    }
    Ok(())
}

/// Compute the file-level delta from `old` to `new`.
pub fn diff_manifests(old: &Manifest, new: &Manifest) -> Vec<FileChange> {
    let mut changes = Vec::new();
    for (path, e) in &new.files {
        match old.files.get(path) {
            None => changes.push(FileChange::Added {
                path: path.clone(),
                blob: e.blob.clone(),
                mode: e.mode,
            }),
            Some(o) if o.blob != e.blob => changes.push(FileChange::Modified {
                path: path.clone(),
                old_blob: o.blob.clone(),
                new_blob: e.blob.clone(),
            }),
            Some(_) => {}
        }
    }
    for (path, o) in &old.files {
        if !new.files.contains_key(path) {
            changes.push(FileChange::Deleted { path: path.clone(), old_blob: o.blob.clone() });
        }
    }
    changes
}
#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> (tempfile::TempDir, Cas) {
        let dir = tempfile::tempdir().unwrap();
        let cas = Cas::open(dir.path().join("cas")).unwrap();
        (dir, cas)
    }
    #[test]
    fn snapshot_materialize_roundtrip() {
        let (dir, cas) = setup();
        let ws = dir.path().join("ws");
        fs::create_dir_all(ws.join("sub")).unwrap();
        fs::write(ws.join("a.txt"), b"alpha").unwrap();
        fs::write(ws.join("sub/b.txt"), b"beta").unwrap();

        let (root, manifest) = snapshot_dir(&cas, &ws).unwrap();
        assert_eq!(manifest.files.len(), 2);
        assert!(manifest.files.contains_key("sub/b.txt"));

        let out = dir.path().join("out");
        materialize(&cas, &root, &out).unwrap();
        assert_eq!(fs::read(out.join("a.txt")).unwrap(), b"alpha");
        assert_eq!(fs::read(out.join("sub/b.txt")).unwrap(), b"beta");

        // Re-snapshotting the materialized tree yields the identical root.
        let (root2, _) = snapshot_dir(&cas, &out).unwrap();
        assert_eq!(root, root2);
    }
}

//! Workspace snapshotting: directory trees → merkle manifests in the CAS.
//!
//! A snapshot walks a directory, stores every file's bytes as a CAS blob and
//! records `path → (blob, mode)` in a [`Manifest`]. The manifest is itself
//! serialized canonically and stored in the CAS; its content hash is the
//! node's `workspace_root`. Any state can therefore be re-materialized from
//! its `workspace_root` alone.
//!
//! ## State tiers (AK cost model)
//!
//! Snapshots capture the **persistent artifact tier** only. Cache/scratch
//! components ([`ak_core::state::DEFAULT_SNAPSHOT_IGNORES`]: `node_modules`,
//! `target`, `.venv`, sandbox scratch, …) are excluded from manifests and
//! **preserved** by [`materialize`] — a branch keeps its warm build caches
//! while its semantic history stays proportional to real changes, not to
//! total workspace size.
//!
//! ## Incremental snapshots
//!
//! [`snapshot_dir_with_cache`] reuses blob hashes for files whose `(mtime, len)`
//! stat is unchanged since the previous snapshot of the same directory, so
//! the per-step cost is a stat walk plus reads of *changed* files only.
//! Entries are subject to a git-style racy-clean guard: a file whose mtime is
//! within the filesystem timestamp granularity of the cache write is never
//! trusted and gets re-read.

use crate::cas::Cas;
use ak_core::hash::ContentHash;
use ak_core::state::{is_ignored_component, FileChange};
use ak_core::{KernelError, KernelResult};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::Path;
use std::time::{Duration, SystemTime};

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

/// Filesystem timestamp granularity margin for the racy-clean guard.
const RACY_WINDOW: Duration = Duration::from_secs(2);

#[derive(Debug, Clone)]
struct StatEntry {
    mtime: SystemTime,
    len: u64,
    blob: ContentHash,
}

/// Per-workspace stat cache: `(mtime, len) → blob` from the previous
/// snapshot, letting unchanged files skip the read+hash entirely.
#[derive(Debug, Default)]
pub struct StatCache {
    entries: HashMap<String, StatEntry>,
    /// When the entries were recorded; the racy-clean fence.
    recorded_at: Option<SystemTime>,
}

impl StatCache {
    /// Can `entry` be trusted for a file currently statting `(mtime, len)`?
    fn trusted(&self, entry: &StatEntry, mtime: SystemTime, len: u64) -> bool {
        let Some(recorded_at) = self.recorded_at else {
            return false;
        };
        entry.len == len
            && entry.mtime == mtime
            // Racy-clean: a write in the same timestamp tick as the snapshot
            // may be invisible to (mtime, len). Only trust entries safely
            // older than the recording instant.
            && recorded_at
                .duration_since(mtime)
                .map(|age| age >= RACY_WINDOW)
                .unwrap_or(false)
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
/// snapshot only; process state is a backend concern), as are the default
/// cache/scratch components (see the module docs).
#[tracing::instrument(level = "info", skip(cas), fields(dir = %dir.display()))]
pub fn snapshot_dir(cas: &Cas, dir: &Path) -> KernelResult<(ContentHash, Manifest)> {
    let mut fresh = StatCache::default();
    snapshot_dir_with_cache(cas, dir, &mut fresh)
}

/// [`snapshot_dir`] with an incremental stat cache. The cache is consulted
/// to skip reads of stat-unchanged files, then replaced with the new state.
#[tracing::instrument(level = "info", skip(cas, cache), fields(dir = %dir.display()))]
pub fn snapshot_dir_with_cache(
    cas: &Cas,
    dir: &Path,
    cache: &mut StatCache,
) -> KernelResult<(ContentHash, Manifest)> {
    let started = SystemTime::now();
    let mut manifest = Manifest::default();
    let mut next = HashMap::new();
    let mut reused = 0usize;
    walk(cas, dir, dir, &mut manifest, cache, &mut next, &mut reused)?;
    let root = manifest.store(cas)?;
    tracing::debug!(
        files = manifest.files.len(),
        reused,
        root = %root,
        "snapshot complete"
    );
    cache.entries = next;
    cache.recorded_at = Some(started);
    Ok((root, manifest))
}

#[allow(clippy::too_many_arguments)]
fn walk(
    cas: &Cas,
    base: &Path,
    dir: &Path,
    manifest: &mut Manifest,
    cache: &StatCache,
    next: &mut HashMap<String, StatEntry>,
    reused: &mut usize,
) -> KernelResult<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name();
        if is_ignored_component(&name.to_string_lossy()) {
            continue;
        }
        let ft = entry.file_type()?;
        if ft.is_dir() {
            walk(cas, base, &path, manifest, cache, next, reused)?;
        } else if ft.is_file() {
            let rel = path
                .strip_prefix(base)
                .map_err(|e| KernelError::Storage(format!("path outside snapshot root: {e}")))?
                .components()
                .map(|c| c.as_os_str().to_string_lossy())
                .collect::<Vec<_>>()
                .join("/");
            let meta = entry.metadata()?;
            let mtime = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
            let len = meta.len();
            let blob = match cache.entries.get(&rel) {
                Some(e) if cache.trusted(e, mtime, len) => {
                    *reused += 1;
                    e.blob.clone()
                }
                _ => cas.put(&fs::read(&path)?)?,
            };
            next.insert(
                rel.clone(),
                StatEntry {
                    mtime,
                    len,
                    blob: blob.clone(),
                },
            );
            let mode = file_mode(&meta);
            manifest.files.insert(rel, ManifestEntry { blob, mode });
        }
        // symlinks / other node types are intentionally skipped
    }
    Ok(())
}

/// Materialize the workspace identified by `workspace_root` into `target`,
/// replacing any files already present at manifest paths. `target` is
/// created if missing; non-ignored files in `target` that are *not* in the
/// manifest are removed so the artifact tier exactly equals the snapshot.
/// Ignored cache/scratch components are **preserved** — materializing over a
/// warm workspace keeps its build caches.
#[tracing::instrument(level = "info", skip(cas), fields(root = %workspace_root, target = %target.display()))]
pub fn materialize(cas: &Cas, workspace_root: &ContentHash, target: &Path) -> KernelResult<()> {
    materialize_with_cache(cas, workspace_root, target, &mut StatCache::default())
}

/// [`materialize`] that also (re)builds the incremental stat cache for the
/// target directory, so the first snapshot after a fork/merge does not have
/// to re-read the whole tree.
pub fn materialize_with_cache(
    cas: &Cas,
    workspace_root: &ContentHash,
    target: &Path,
    cache: &mut StatCache,
) -> KernelResult<()> {
    let started = SystemTime::now();
    let manifest = Manifest::load(cas, workspace_root)?;
    if target.exists() {
        remove_stale(target, target, &manifest)?;
    }
    fs::create_dir_all(target)?;
    let mut next = HashMap::new();
    for (path, entry) in &manifest.files {
        let dest = target.join(path);
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }
        // Skip rewrites of files whose cached stat already maps to this
        // exact blob (warm branch re-materialization).
        let unchanged = cache
            .entries
            .get(path)
            .filter(|e| e.blob == entry.blob)
            .and_then(|e| {
                let meta = fs::metadata(&dest).ok()?;
                let mtime = meta.modified().ok()?;
                Some(cache.trusted(e, mtime, meta.len()))
            })
            .unwrap_or(false);
        if !unchanged {
            let bytes = cas.get(&entry.blob)?;
            fs::write(&dest, bytes)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&dest, fs::Permissions::from_mode(entry.mode))?;
            }
        }
        let meta = fs::metadata(&dest)?;
        next.insert(
            path.clone(),
            StatEntry {
                mtime: meta.modified().unwrap_or(SystemTime::UNIX_EPOCH),
                len: meta.len(),
                blob: entry.blob.clone(),
            },
        );
    }
    cache.entries = next;
    cache.recorded_at = Some(started);
    Ok(())
}

/// Remove files under `dir` that are not manifest paths, preserving ignored
/// cache/scratch components. Directories left empty are removed too (unless
/// they are ancestors of manifest paths — those get recreated as needed).
fn remove_stale(base: &Path, dir: &Path, manifest: &Manifest) -> KernelResult<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if is_ignored_component(&entry.file_name().to_string_lossy()) {
            continue;
        }
        let ft = entry.file_type()?;
        if ft.is_dir() {
            remove_stale(base, &path, manifest)?;
            // Prune the directory when nothing (not even ignored content)
            // remains inside it.
            if fs::read_dir(&path)?.next().is_none() {
                fs::remove_dir(&path)?;
            }
        } else {
            let rel = path
                .strip_prefix(base)
                .map_err(|e| KernelError::Storage(format!("path outside target root: {e}")))?
                .components()
                .map(|c| c.as_os_str().to_string_lossy())
                .collect::<Vec<_>>()
                .join("/");
            if !manifest.files.contains_key(&rel) {
                fs::remove_file(&path)?;
            }
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
            // A chmod is a real artifact change even when the bytes are
            // identical.  Keep the existing wire shape: equal old/new blob
            // hashes mean this `modified` record is metadata-only.
            Some(o) if o != e => changes.push(FileChange::Modified {
                path: path.clone(),
                old_blob: o.blob.clone(),
                new_blob: e.blob.clone(),
            }),
            Some(_) => {}
        }
    }
    for (path, o) in &old.files {
        if !new.files.contains_key(path) {
            changes.push(FileChange::Deleted {
                path: path.clone(),
                old_blob: o.blob.clone(),
            });
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

    #[test]
    fn materialize_removes_stale_files() {
        let (dir, cas) = setup();
        let ws = dir.path().join("ws");
        fs::create_dir_all(&ws).unwrap();
        fs::write(ws.join("keep.txt"), b"k").unwrap();
        let (root, _) = snapshot_dir(&cas, &ws).unwrap();

        let out = dir.path().join("out");
        fs::create_dir_all(out.join("stale-dir")).unwrap();
        fs::write(out.join("stale.txt"), b"s").unwrap();
        fs::write(out.join("stale-dir/inner.txt"), b"s").unwrap();
        materialize(&cas, &root, &out).unwrap();
        assert!(out.join("keep.txt").exists());
        assert!(!out.join("stale.txt").exists());
        assert!(!out.join("stale-dir").exists());
    }

    #[test]
    fn diff_detects_add_modify_delete() {
        let (dir, cas) = setup();
        let ws = dir.path().join("ws");
        fs::create_dir_all(&ws).unwrap();
        fs::write(ws.join("a.txt"), b"one").unwrap();
        fs::write(ws.join("b.txt"), b"two").unwrap();
        let (_, m1) = snapshot_dir(&cas, &ws).unwrap();

        fs::write(ws.join("a.txt"), b"one-changed").unwrap();
        fs::remove_file(ws.join("b.txt")).unwrap();
        fs::write(ws.join("c.txt"), b"three").unwrap();
        let (_, m2) = snapshot_dir(&cas, &ws).unwrap();

        let changes = diff_manifests(&m1, &m2);
        assert_eq!(changes.len(), 3);
        assert!(changes
            .iter()
            .any(|c| matches!(c, FileChange::Modified { path, .. } if path == "a.txt")));
        assert!(changes
            .iter()
            .any(|c| matches!(c, FileChange::Deleted { path, .. } if path == "b.txt")));
        assert!(changes
            .iter()
            .any(|c| matches!(c, FileChange::Added { path, .. } if path == "c.txt")));

        assert!(diff_manifests(&m2, &m2).is_empty());
    }

    #[test]
    fn diff_records_mode_only_changes() {
        let blob = ak_core::hash::hash_bytes(b"same bytes");
        let old = Manifest {
            files: BTreeMap::from([(
                "run.sh".into(),
                ManifestEntry {
                    blob: blob.clone(),
                    mode: 0o644,
                },
            )]),
        };
        let new = Manifest {
            files: BTreeMap::from([(
                "run.sh".into(),
                ManifestEntry {
                    blob: blob.clone(),
                    mode: 0o755,
                },
            )]),
        };

        assert_eq!(
            diff_manifests(&old, &new),
            vec![FileChange::Modified {
                path: "run.sh".into(),
                old_blob: blob.clone(),
                new_blob: blob,
            }]
        );
    }

    #[test]
    fn cache_and_scratch_components_are_ignored_and_preserved() {
        let (dir, cas) = setup();
        let ws = dir.path().join("ws");
        fs::create_dir_all(ws.join("node_modules/pkg")).unwrap();
        fs::create_dir_all(ws.join("src")).unwrap();
        fs::create_dir_all(ws.join(".aktmp")).unwrap();
        fs::write(ws.join("node_modules/pkg/index.js"), b"huge").unwrap();
        fs::write(ws.join(".aktmp/tmp"), b"x").unwrap();
        fs::write(ws.join("src/main.rs"), b"fn main() {}").unwrap();

        let (root, manifest) = snapshot_dir(&cas, &ws).unwrap();
        assert_eq!(manifest.files.len(), 1, "only src/main.rs is an artifact");

        // Materializing over the same tree preserves the caches.
        materialize(&cas, &root, &ws).unwrap();
        assert!(ws.join("node_modules/pkg/index.js").exists());
        assert!(ws.join(".aktmp/tmp").exists());
        assert!(ws.join("src/main.rs").exists());
    }

    #[test]
    fn incremental_snapshot_reuses_unchanged_blobs_and_sees_changes() {
        let (dir, cas) = setup();
        let ws = dir.path().join("ws");
        fs::create_dir_all(&ws).unwrap();
        fs::write(ws.join("a.txt"), b"aaa").unwrap();
        fs::write(ws.join("b.txt"), b"bbb").unwrap();

        let mut cache = StatCache::default();
        let (root1, _) = snapshot_dir_with_cache(&cas, &ws, &mut cache).unwrap();

        // Same tree → same root through the cache path.
        // Backdate the recording fence so entries pass the racy-clean guard
        // (in real usage steps are seconds apart; tests run in one tick).
        cache.recorded_at = Some(SystemTime::now() + RACY_WINDOW + RACY_WINDOW);
        let (root2, _) = snapshot_dir_with_cache(&cas, &ws, &mut cache).unwrap();
        assert_eq!(root1, root2);

        // A content change with a *bumped* mtime is always seen.
        fs::write(ws.join("b.txt"), b"BBB-changed").unwrap();
        cache.recorded_at = Some(SystemTime::now() + RACY_WINDOW + RACY_WINDOW);
        let (root3, m3) = snapshot_dir_with_cache(&cas, &ws, &mut cache).unwrap();
        assert_ne!(root2, root3);
        let blob = &m3.files["b.txt"].blob;
        assert_eq!(cas.get(blob).unwrap(), b"BBB-changed");
    }

    #[test]
    fn racy_clean_guard_rereads_recent_files() {
        let (dir, cas) = setup();
        let ws = dir.path().join("ws");
        fs::create_dir_all(&ws).unwrap();
        fs::write(ws.join("a.txt"), b"v1").unwrap();

        let mut cache = StatCache::default();
        snapshot_dir_with_cache(&cas, &ws, &mut cache).unwrap();

        // Change the content but force identical (mtime, len): same-length
        // write plus restored mtime — exactly the racy case.
        let meta = fs::metadata(ws.join("a.txt")).unwrap();
        let mtime = meta.modified().unwrap();
        fs::write(ws.join("a.txt"), b"v2").unwrap();
        let f = fs::File::options()
            .append(true)
            .open(ws.join("a.txt"))
            .unwrap();
        f.set_modified(mtime).unwrap();
        drop(f);

        // recorded_at is within RACY_WINDOW of mtime → entry untrusted →
        // the file is re-read and the change is captured.
        let (_, m) = snapshot_dir_with_cache(&cas, &ws, &mut cache).unwrap();
        assert_eq!(cas.get(&m.files["a.txt"].blob).unwrap(), b"v2");
    }

    #[test]
    fn materialize_with_cache_primes_next_snapshot() {
        let (dir, cas) = setup();
        let ws = dir.path().join("ws");
        fs::create_dir_all(&ws).unwrap();
        fs::write(ws.join("a.txt"), b"alpha").unwrap();
        let (root, _) = snapshot_dir(&cas, &ws).unwrap();

        let out = dir.path().join("out");
        let mut cache = StatCache::default();
        materialize_with_cache(&cas, &root, &out, &mut cache).unwrap();
        assert_eq!(cache.entries.len(), 1);

        // The primed cache round-trips to the identical root.
        cache.recorded_at = Some(SystemTime::now() + RACY_WINDOW + RACY_WINDOW);
        let (root2, _) = snapshot_dir_with_cache(&cas, &out, &mut cache).unwrap();
        assert_eq!(root, root2);
    }
}

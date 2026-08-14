//! Remote state sync: the pure planning half, shared by every remote
//! adapter that materializes kernel state in its own sandbox.
//!
//! Before executing a step, a syncing backend lists the live remote tree and
//! diffs it against the base state's manifest (from the
//! [`crate::traits::StateProvider`]), pushing only the difference. After
//! execution it lists again, pulls only files changed from the committed base,
//! and reports a [`crate::traits::WorkspaceDelta`] for the kernel to apply and
//! snapshot. A per-sandbox manifest cache remains a transfer/index hint, never
//! the authority for mutable remote state. The functions here compute those
//! diffs; adapters own transport.

use crate::hash::ContentHash;
use crate::path::normalize_relative;
use crate::state::is_ignored_component;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// One file in a synced workspace tree: content identity plus mode.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncEntry {
    /// Hash of the file's bytes ([`crate::hash::hash_bytes`] format).
    pub blob: ContentHash,
    /// Unix permission bits.
    pub mode: u32,
}

/// A `path → entry` view of a workspace tree, as used for sync planning.
pub type SyncManifest = BTreeMap<String, SyncEntry>;

/// What must be transferred to bring a remote tree from `current` to
/// `target`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PushPlan {
    /// Paths to write (create or overwrite), with their target entry.
    pub upserts: Vec<(String, SyncEntry)>,
    /// Paths to remove.
    pub deletes: Vec<String>,
}

impl PushPlan {
    pub fn is_empty(&self) -> bool {
        self.upserts.is_empty() && self.deletes.is_empty()
    }
}

/// Diff two sync manifests into the transfer plan from `current` to
/// `target`. A path is upserted when its blob *or* mode differs.
pub fn push_plan(current: &SyncManifest, target: &SyncManifest) -> PushPlan {
    let mut plan = PushPlan::default();
    for (path, entry) in target {
        if current.get(path) != Some(entry) {
            plan.upserts.push((path.clone(), entry.clone()));
        }
    }
    for path in current.keys() {
        if !target.contains_key(path) {
            plan.deletes.push(path.clone());
        }
    }
    plan
}

/// Reject a manifest that claims both a file and a descendant beneath that
/// file (for example `a` and `a/b`). No real filesystem tree can have that
/// shape; accepting it would make sync order determine the resulting state.
pub fn validate_manifest_shape(manifest: &SyncManifest) -> Result<(), String> {
    for path in manifest.keys() {
        for (separator, _) in path.match_indices('/') {
            let ancestor = &path[..separator];
            if manifest.contains_key(ancestor) {
                return Err(format!(
                    "manifest contains both file `{ancestor}` and descendant `{path}`"
                ));
            }
        }
    }
    Ok(())
}

/// Is `path` eligible for state sync? It must normalize to a clean relative
/// file path whose components are all outside the snapshot-ignore set (the
/// cache/scratch tier never travels). Returns the normalized path string.
pub fn syncable_path(path: &str) -> Result<String, String> {
    let rel = normalize_relative(path)?;
    if rel.as_os_str().is_empty() {
        return Err(format!(
            "path `{path}` names the workspace root, not a file"
        ));
    }
    let parts: Vec<String> = rel
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect();
    for part in &parts {
        if is_ignored_component(part) {
            return Err(format!(
                "path `{path}` is in the cache/scratch tier (`{part}`), which never syncs"
            ));
        }
    }
    Ok(parts.join("/"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::hash_bytes;

    fn entry(bytes: &[u8], mode: u32) -> SyncEntry {
        SyncEntry {
            blob: hash_bytes(bytes),
            mode,
        }
    }

    #[test]
    fn plan_covers_add_modify_chmod_delete() {
        let mut current = SyncManifest::new();
        current.insert("keep.txt".into(), entry(b"same", 0o644));
        current.insert("edit.txt".into(), entry(b"old", 0o644));
        current.insert("chmod.sh".into(), entry(b"run", 0o644));
        current.insert("gone.txt".into(), entry(b"bye", 0o644));

        let mut target = SyncManifest::new();
        target.insert("keep.txt".into(), entry(b"same", 0o644));
        target.insert("edit.txt".into(), entry(b"new", 0o644));
        target.insert("chmod.sh".into(), entry(b"run", 0o755));
        target.insert("fresh.txt".into(), entry(b"hi", 0o644));

        let plan = push_plan(&current, &target);
        let upserted: Vec<&str> = plan.upserts.iter().map(|(p, _)| p.as_str()).collect();
        assert_eq!(upserted, vec!["chmod.sh", "edit.txt", "fresh.txt"]);
        assert_eq!(plan.deletes, vec!["gone.txt"]);

        assert!(push_plan(&target, &target).is_empty());
    }

    #[test]
    fn syncable_path_filters_hostile_and_cache_paths() {
        assert_eq!(syncable_path("./src/main.rs").unwrap(), "src/main.rs");
        assert!(syncable_path("../escape").is_err());
        assert!(syncable_path("/abs").is_err());
        assert!(syncable_path(".").is_err());
        assert!(syncable_path("node_modules/pkg/index.js").is_err());
        assert!(syncable_path("src/target").is_err());
    }

    #[test]
    fn manifest_shape_rejects_file_ancestor_conflicts() {
        let mut manifest = SyncManifest::new();
        manifest.insert("a".into(), entry(b"file", 0o644));
        manifest.insert("a-b".into(), entry(b"unrelated", 0o644));
        manifest.insert("a/b/c".into(), entry(b"child", 0o644));
        assert!(validate_manifest_shape(&manifest).is_err());

        manifest.remove("a");
        validate_manifest_shape(&manifest).unwrap();
    }
}

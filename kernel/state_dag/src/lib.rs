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
#[cfg(test)]
mod tests {
    use super::*;
    use ak_core::ids::{PrincipalId, StepId};
    use ak_core::replay::ReplayClass;
    use ak_core::state::FileChange;
    use ak_core::KernelError;
    use std::fs;
    use std::path::PathBuf;

    struct Fixture {
        _tmp: tempfile::TempDir,
        dag: StateDag,
        ws: PathBuf,
        actor: PrincipalId,
    }

    fn fixture() -> Fixture {
        let tmp = tempfile::tempdir().unwrap();
        let dag = StateDag::open(&tmp.path().join("dag.db"), &tmp.path().join("cas")).unwrap();
        let ws = tmp.path().join("ws");
        fs::create_dir_all(&ws).unwrap();
        Fixture { dag, ws, actor: PrincipalId::generate(), _tmp: tmp }
    }

    fn write(f: &Fixture, path: &str, content: &str) {
        let p = f.ws.join(path);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, content).unwrap();
    }



    /// Build: root(base.txt) -> fork two branches, edit disjoint files, merge.
    #[test]
    fn episode_append_and_materialize() {
        let f = fixture();
        write(&f, "a.txt", "v1");
        let ep = f
            .dag
            .create_episode(&f.actor, Some(&f.ws), ReplayClass::FilesystemOnly)
            .unwrap();
        assert!(ep.root.parent.is_none());

        write(&f, "a.txt", "v2");
        write(&f, "b.txt", "new");
        let n1 = f
            .dag
            .snapshot_and_append(&ep.branch, &StepId::generate(), &f.actor, &f.ws, ReplayClass::FilesystemOnly)
            .unwrap();
        assert_eq!(n1.parent.as_ref(), Some(&ep.root.id));
        assert_eq!(n1.delta.files.len(), 2);

        // Diff root -> n1
        let d = f.dag.diff(&ep.root.id, &n1.id).unwrap();
        assert_eq!(d.len(), 2);

        // Materialize root back out.
        let out = f._tmp.path().join("out");
        f.dag.materialize(&ep.root.id, &out).unwrap();
        assert_eq!(fs::read_to_string(out.join("a.txt")).unwrap(), "v1");
        assert!(!out.join("b.txt").exists());
    }

    #[test]
    fn discarded_branch_rejects_appends_and_double_discard() {
        let f = fixture();
        let ep = f.dag.create_episode(&f.actor, None, ReplayClass::FilesystemOnly).unwrap();
        let br = f.dag.fork(&ep.root.id).unwrap();
        f.dag.discard_branch(&br.id).unwrap();
        assert!(matches!(
            f.dag.discard_branch(&br.id),
            Err(KernelError::BranchDiscarded { .. })
        ));
        write(&f, "x.txt", "x");
        assert!(matches!(
            f.dag.snapshot_and_append(&br.id, &StepId::generate(), &f.actor, &f.ws, ReplayClass::FilesystemOnly),
            Err(KernelError::BranchDiscarded { .. })
        ));
    }

    #[test]
    fn lca_branch_compare_and_clean_merge() {
        let f = fixture();
        write(&f, "base.txt", "base");
        let ep = f
            .dag
            .create_episode(&f.actor, Some(&f.ws), ReplayClass::FilesystemOnly)
            .unwrap();

        let br_a = f.dag.fork(&ep.root.id).unwrap();
        let br_b = f.dag.fork(&ep.root.id).unwrap();

        write(&f, "a-only.txt", "A");
        let ha = f
            .dag
            .snapshot_and_append(&br_a.id, &StepId::generate(), &f.actor, &f.ws, ReplayClass::FilesystemOnly)
            .unwrap();

        fs::remove_file(f.ws.join("a-only.txt")).unwrap();
        write(&f, "b-only.txt", "B");
        let hb = f
            .dag
            .snapshot_and_append(&br_b.id, &StepId::generate(), &f.actor, &f.ws, ReplayClass::FilesystemOnly)
            .unwrap();

        assert_eq!(f.dag.lca(&ha.id, &hb.id).unwrap(), ep.root.id);

        let cmp = f.dag.branch_compare(&br_a.id, &br_b.id).unwrap();
        assert_eq!(cmp.base, ep.root.id);
        assert_eq!(cmp.changed_in_a.len(), 1);
        assert_eq!(cmp.changed_in_b.len(), 1);
        assert!(matches!(&cmp.changed_in_a[0], FileChange::Added { path, .. } if path == "a-only.txt"));

        let merged = f.dag.merge(&br_a.id, &br_b.id, &f.actor).unwrap();
        assert_eq!(merged.parent.as_ref(), Some(&ha.id));
        assert_eq!(merged.merge_parent.as_ref(), Some(&hb.id));
        assert_eq!(f.dag.get_branch(&br_b.id).unwrap().status, BranchStatus::Merged);

        let out = f._tmp.path().join("merged");
        f.dag.materialize(&merged.id, &out).unwrap();
        assert_eq!(fs::read_to_string(out.join("a-only.txt")).unwrap(), "A");
        assert_eq!(fs::read_to_string(out.join("b-only.txt")).unwrap(), "B");
        assert_eq!(fs::read_to_string(out.join("base.txt")).unwrap(), "base");

        // LCA through the merge node still resolves.
        assert_eq!(f.dag.lca(&merged.id, &hb.id).unwrap(), hb.id);
    }

    #[test]
    fn conflicting_merge_reports_paths_and_writes_nothing() {
        let f = fixture();
        write(&f, "shared.txt", "base");
        let ep = f
            .dag
            .create_episode(&f.actor, Some(&f.ws), ReplayClass::FilesystemOnly)
            .unwrap();
        let br_a = f.dag.fork(&ep.root.id).unwrap();
        let br_b = f.dag.fork(&ep.root.id).unwrap();

        write(&f, "shared.txt", "edit-A");
        let ha = f
            .dag
            .snapshot_and_append(&br_a.id, &StepId::generate(), &f.actor, &f.ws, ReplayClass::FilesystemOnly)
            .unwrap();
        write(&f, "shared.txt", "edit-B");
        f.dag
            .snapshot_and_append(&br_b.id, &StepId::generate(), &f.actor, &f.ws, ReplayClass::FilesystemOnly)
            .unwrap();

        match f.dag.merge(&br_a.id, &br_b.id, &f.actor) {
            Err(KernelError::MergeConflict { paths }) => {
                assert_eq!(paths, vec!["shared.txt".to_string()])
            }
            other => panic!("expected MergeConflict, got {other:?}"),
        }
        // Nothing written: heads unchanged, both branches still active.
        assert_eq!(f.dag.get_branch(&br_a.id).unwrap().head, ha.id);
        assert_eq!(f.dag.get_branch(&br_b.id).unwrap().status, BranchStatus::Active);
    }
}

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
}

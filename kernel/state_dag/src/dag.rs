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

impl BranchStatus {
    fn as_str(self) -> &'static str {
        match self {
            BranchStatus::Active => "active",
            BranchStatus::Discarded => "discarded",
            BranchStatus::Merged => "merged",
        }
    }

    fn parse(s: &str) -> KernelResult<Self> {
        match s {
            "active" => Ok(BranchStatus::Active),
            "discarded" => Ok(BranchStatus::Discarded),
            "merged" => Ok(BranchStatus::Merged),
            other => Err(KernelError::Storage(format!("unknown branch status `{other}`"))),
        }
    }
}

/// A branch row: a movable head pointer over immutable states.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Branch {
    pub id: BranchId,
    pub episode: EpisodeId,
    /// State this branch was forked from (the episode root for the initial branch).
    pub base_state: StateId,
    pub head: StateId,
    pub status: BranchStatus,
}

/// Result of [`StateDag::branch_compare`].
#[derive(Debug, Clone, PartialEq)]
pub struct BranchComparison {
    /// Lowest common ancestor of the two branch heads.
    pub base: StateId,
    /// Files changed on branch `a` since `base`.
    pub changed_in_a: Vec<FileChange>,
    /// Files changed on branch `b` since `base`.
    pub changed_in_b: Vec<FileChange>,
}

/// Everything created by [`StateDag::create_episode`].
#[derive(Debug, Clone)]
pub struct EpisodeHandle {
    pub episode: EpisodeId,
    /// The initial (main) branch of the episode.
    pub branch: BranchId,
    /// The root state node.
    pub root: StateNode,
}

/// Outcome of a garbage-collection pass.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GcReport {
    /// CAS blobs deleted.
    pub blobs_removed: usize,
    /// State rows deleted (states reachable only from discarded branches).
    pub states_removed: usize,
}

const MIGRATIONS: &[(&str, &str)] = &[(
    "0001_initial",
    "CREATE TABLE episodes (
         id TEXT PRIMARY KEY,
         root_state TEXT NOT NULL,
         created_at TEXT NOT NULL
     );
     CREATE TABLE states (
         id TEXT PRIMARY KEY,
         episode TEXT NOT NULL,
         branch TEXT NOT NULL,
         parent TEXT,
         merge_parent TEXT,
         workspace_root TEXT NOT NULL,
         node_json TEXT NOT NULL,
         created_at TEXT NOT NULL
     );
     CREATE INDEX idx_states_episode ON states(episode);
     CREATE INDEX idx_states_branch ON states(branch);
     CREATE TABLE branches (
         id TEXT PRIMARY KEY,
         episode TEXT NOT NULL,
         base_state TEXT NOT NULL,
         head TEXT NOT NULL,
         status TEXT NOT NULL,
         created_at TEXT NOT NULL
     );",
)];

/// The branchable world-state DAG service: CAS + SQLite DAG store.
///
/// Thread-safe (`Send + Sync`): the SQLite connection is serialized behind a
/// mutex; the CAS is naturally concurrent.
pub struct StateDag {
    conn: Mutex<Connection>,
    cas: Cas,
}

impl StateDag {
    /// Open (creating if necessary) the DAG database at `db_path` with the
    /// CAS rooted at `cas_root`. Enables WAL mode and runs schema migrations.
    #[tracing::instrument(level = "info", skip_all)]
    pub fn open(db_path: &Path, cas_root: &Path) -> KernelResult<Self> {
        let conn = Connection::open(db_path).map_err(sql_err)?;
        Self::init(conn, Cas::open(cas_root)?)
    }

    /// In-memory database (tests / ephemeral kernels); CAS still on disk.
    pub fn open_in_memory(cas_root: &Path) -> KernelResult<Self> {
        let conn = Connection::open_in_memory().map_err(sql_err)?;
        Self::init(conn, Cas::open(cas_root)?)
    }

    fn init(conn: Connection, cas: Cas) -> KernelResult<Self> {
        conn.pragma_update(None, "journal_mode", "WAL").map_err(sql_err)?;
        conn.pragma_update(None, "foreign_keys", "ON").map_err(sql_err)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS migrations (
                 name TEXT PRIMARY KEY, applied_at TEXT NOT NULL
             );",
        )
        .map_err(sql_err)?;
        for (name, sql) in MIGRATIONS {
            let applied: Option<String> = conn
                .query_row("SELECT name FROM migrations WHERE name = ?1", [name], |r| r.get(0))
                .optional()
                .map_err(sql_err)?;
            if applied.is_none() {
                conn.execute_batch(sql).map_err(sql_err)?;
                conn.execute(
                    "INSERT INTO migrations (name, applied_at) VALUES (?1, ?2)",
                    params![name, Utc::now().to_rfc3339()],
                )
                .map_err(sql_err)?;
            }
        }
        Ok(Self { conn: Mutex::new(conn), cas })
    }

    /// The underlying content-addressed store.
    pub fn cas(&self) -> &Cas {
        &self.cas
    }

    fn conn(&self) -> KernelResult<MutexGuard<'_, Connection>> {
        self.conn
            .lock()
            .map_err(|_| KernelError::Storage("state DAG mutex poisoned".into()))
    }

    // ---------------------------------------------------------------- episodes

    /// Create a new episode with a root state and an initial active branch.
    ///
    /// If `workspace` is given, the directory is snapshotted as the root
    /// workspace; otherwise the root workspace is empty.
    #[tracing::instrument(level = "info", skip(self, workspace), fields(actor = %actor))]
    pub fn create_episode(
        &self,
        actor: &PrincipalId,
        workspace: Option<&Path>,
        replay_class: ReplayClass,
    ) -> KernelResult<EpisodeHandle> {
        let (workspace_root, _) = match workspace {
            Some(dir) => snapshot::snapshot_dir(&self.cas, dir)?,
            None => {
                let m = Manifest::default();
                (m.store(&self.cas)?, m)
            }
        };
        let episode = EpisodeId::generate();
        let branch = BranchId::generate();
        let root = StateNode {
            id: StateId::generate(),
            episode: episode.clone(),
            branch: branch.clone(),
            parent: None,
            produced_by: None,
            merge_parent: None,
            actor: actor.clone(),
            delta: StateDelta::default(),
            workspace_root,
            replay_class,
            created_at: Utc::now(),
        };
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO episodes (id, root_state, created_at) VALUES (?1, ?2, ?3)",
            params![episode.as_str(), root.id.as_str(), root.created_at.to_rfc3339()],
        )
        .map_err(sql_err)?;
        insert_state(&conn, &root)?;
        conn.execute(
            "INSERT INTO branches (id, episode, base_state, head, status, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                branch.as_str(),
                episode.as_str(),
                root.id.as_str(),
                root.id.as_str(),
                BranchStatus::Active.as_str(),
                root.created_at.to_rfc3339()
            ],
        )
        .map_err(sql_err)?;
        Ok(EpisodeHandle { episode, branch, root })
    }

    // ------------------------------------------------------------------ states

    /// Fetch a state node by id.
    pub fn get_state(&self, id: &StateId) -> KernelResult<StateNode> {
        let conn = self.conn()?;
        load_state(&conn, id)
    }

    /// Fetch a branch row by id.
    pub fn get_branch(&self, id: &BranchId) -> KernelResult<Branch> {
        let conn = self.conn()?;
        load_branch(&conn, id)
    }

    /// The current head state of a branch.
    pub fn head(&self, branch: &BranchId) -> KernelResult<StateNode> {
        let b = self.get_branch(branch)?;
        self.get_state(&b.head)
    }

    /// Append a new state to an active branch from an explicit delta and a
    /// pre-computed workspace root (the root must already be in the CAS).
    #[tracing::instrument(level = "info", skip(self, delta), fields(branch = %branch, step = %step))]
    pub fn append_step(
        &self,
        branch: &BranchId,
        step: &StepId,
        actor: &PrincipalId,
        delta: StateDelta,
        workspace_root: ContentHash,
        replay_class: ReplayClass,
    ) -> KernelResult<StateNode> {
        if !self.cas.contains(&workspace_root)? {
            return Err(KernelError::Storage(format!(
                "workspace root {workspace_root} is not in the CAS"
            )));
        }
        let conn = self.conn()?;
        let b = load_branch(&conn, branch)?;
        ensure_active(&b)?;
        let node = StateNode {
            id: StateId::generate(),
            episode: b.episode.clone(),
            branch: branch.clone(),
            parent: Some(b.head.clone()),
            produced_by: Some(step.clone()),
            merge_parent: None,
            actor: actor.clone(),
            delta,
            workspace_root,
            replay_class,
            created_at: Utc::now(),
        };
        insert_state(&conn, &node)?;
        set_head(&conn, branch, &node.id)?;
        Ok(node)
    }

    /// Convenience: snapshot `dir`, compute the file delta against the
    /// branch head automatically, and append the resulting state.
    pub fn snapshot_and_append(
        &self,
        branch: &BranchId,
        step: &StepId,
        actor: &PrincipalId,
        dir: &Path,
        replay_class: ReplayClass,
    ) -> KernelResult<StateNode> {
        let head = self.head(branch)?;
        let (new_root, new_manifest) = snapshot::snapshot_dir(&self.cas, dir)?;
        let old_manifest = Manifest::load(&self.cas, &head.workspace_root)?;
        let delta = StateDelta {
            files: snapshot::diff_manifests(&old_manifest, &new_manifest),
            policy_epoch: head.delta.policy_epoch,
            ..StateDelta::default()
        };
        self.append_step(branch, step, actor, delta, new_root, replay_class)
    }

    /// Materialize a state's workspace into `target`.
    pub fn materialize(&self, state: &StateId, target: &Path) -> KernelResult<()> {
        let node = self.get_state(state)?;
        snapshot::materialize(&self.cas, &node.workspace_root, target)
    }

    // ---------------------------------------------------------------- branches

    /// Fork a new active branch whose head is `from` (any existing state).
    #[tracing::instrument(level = "info", skip(self), fields(from = %from))]
    pub fn fork(&self, from: &StateId) -> KernelResult<Branch> {
        let conn = self.conn()?;
        let base = load_state(&conn, from)?;
        let branch = Branch {
            id: BranchId::generate(),
            episode: base.episode,
            base_state: from.clone(),
            head: from.clone(),
            status: BranchStatus::Active,
        };
        conn.execute(
            "INSERT INTO branches (id, episode, base_state, head, status, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                branch.id.as_str(),
                branch.episode.as_str(),
                branch.base_state.as_str(),
                branch.head.as_str(),
                branch.status.as_str(),
                Utc::now().to_rfc3339()
            ],
        )
        .map_err(sql_err)?;
        Ok(branch)
    }

    /// Mark a branch discarded. Idempotent errors: discarding twice fails
    /// with [`KernelError::BranchDiscarded`]. Backend-side teardown
    /// (`Backend::discard`) is the caller's responsibility.
    #[tracing::instrument(level = "info", skip(self), fields(branch = %branch))]
    pub fn discard_branch(&self, branch: &BranchId) -> KernelResult<()> {
        let conn = self.conn()?;
        let b = load_branch(&conn, branch)?;
        if b.status == BranchStatus::Discarded {
            return Err(KernelError::BranchDiscarded { branch: branch.to_string() });
        }
        conn.execute(
            "UPDATE branches SET status = ?1 WHERE id = ?2",
            params![BranchStatus::Discarded.as_str(), branch.as_str()],
        )
        .map_err(sql_err)?;
        Ok(())
    }

    // ------------------------------------------------------------- diff / merge

    /// File-level diff between two arbitrary states (`a` → `b`).
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn diff(&self, a: &StateId, b: &StateId) -> KernelResult<Vec<FileChange>> {
        let (na, nb) = (self.get_state(a)?, self.get_state(b)?);
        let ma = Manifest::load(&self.cas, &na.workspace_root)?;
        let mb = Manifest::load(&self.cas, &nb.workspace_root)?;
        Ok(snapshot::diff_manifests(&ma, &mb))
    }

    /// Lowest common ancestor of two states, walking `parent` and
    /// `merge_parent` edges.
    pub fn lca(&self, a: &StateId, b: &StateId) -> KernelResult<StateId> {
        let conn = self.conn()?;
        let mut ancestors_a = HashSet::new();
        let mut queue = VecDeque::from([a.clone()]);
        while let Some(id) = queue.pop_front() {
            if !ancestors_a.insert(id.clone()) {
                continue;
            }
            let n = load_state(&conn, &id)?;
            queue.extend(n.parent.into_iter().chain(n.merge_parent));
        }
        let mut seen_b = HashSet::new();
        let mut queue = VecDeque::from([b.clone()]);
        while let Some(id) = queue.pop_front() {
            if ancestors_a.contains(&id) {
                return Ok(id);
            }
            if !seen_b.insert(id.clone()) {
                continue;
            }
            let n = load_state(&conn, &id)?;
            queue.extend(n.parent.into_iter().chain(n.merge_parent));
        }
        Err(KernelError::Storage(format!("states {a} and {b} share no common ancestor")))
    }

    /// Compare two branches: files changed in each since their lowest
    /// common ancestor.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn branch_compare(&self, a: &BranchId, b: &BranchId) -> KernelResult<BranchComparison> {
        let (ha, hb) = (self.get_branch(a)?.head, self.get_branch(b)?.head);
        let base = self.lca(&ha, &hb)?;
        Ok(BranchComparison {
            changed_in_a: self.diff(&base, &ha)?,
            changed_in_b: self.diff(&base, &hb)?,
            base,
        })
    }

    /// Three-way **artifact-only** merge of `source` into `target` from
    /// their lowest common ancestor. See the module docs: processes, tool
    /// sessions and leases are never merged. On success the merge node is
    /// appended to `target` (with `merge_parent` = source head) and `source`
    /// is marked [`BranchStatus::Merged`]. Conflicting paths abort with
    /// [`KernelError::MergeConflict`] and write nothing.
    #[tracing::instrument(level = "info", skip(self), fields(target = %target, source = %source))]
    pub fn merge(
        &self,
        target: &BranchId,
        source: &BranchId,
        actor: &PrincipalId,
    ) -> KernelResult<StateNode> {
        let tb = self.get_branch(target)?;
        let sb = self.get_branch(source)?;
        ensure_active(&tb)?;
        ensure_active(&sb)?;
        let base = self.lca(&tb.head, &sb.head)?;

        let base_m = Manifest::load(&self.cas, &self.get_state(&base)?.workspace_root)?;
        let tgt_node = self.get_state(&tb.head)?;
        let src_node = self.get_state(&sb.head)?;
        let tgt_m = Manifest::load(&self.cas, &tgt_node.workspace_root)?;
        let src_m = Manifest::load(&self.cas, &src_node.workspace_root)?;

        let mut merged = BTreeMap::new();
        let mut conflicts = Vec::new();
        let all_paths: std::collections::BTreeSet<&String> = base_m
            .files
            .keys()
            .chain(tgt_m.files.keys())
            .chain(src_m.files.keys())
            .collect();
        for path in all_paths {
            let b = base_m.files.get(path);
            let t = tgt_m.files.get(path);
            let s = src_m.files.get(path);
            let chosen = match (b, t, s) {
                // unchanged on both sides
                (_, t, s) if t == s => t,
                // changed only on target
                (b, t, s) if s == b => t,
                // changed only on source
                (b, t, s) if t == b => s,
                // both changed, differently (incl. modify/delete)
                _ => {
                    conflicts.push(path.clone());
                    continue;
                }
            };
            if let Some(entry) = chosen {
                merged.insert(path.clone(), entry.clone());
            }
        }
        if !conflicts.is_empty() {
            tracing::warn!(?conflicts, "merge aborted with conflicts");
            return Err(KernelError::MergeConflict { paths: conflicts });
        }

        let merged_manifest = Manifest { files: merged };
        let workspace_root = merged_manifest.store(&self.cas)?;
        let delta = StateDelta {
            files: snapshot::diff_manifests(&tgt_m, &merged_manifest),
            policy_epoch: tgt_node.delta.policy_epoch,
            ..StateDelta::default()
        };
        let node = StateNode {
            id: StateId::generate(),
            episode: tb.episode.clone(),
            branch: target.clone(),
            parent: Some(tb.head.clone()),
            produced_by: None,
            merge_parent: Some(sb.head.clone()),
            actor: actor.clone(),
            delta,
            workspace_root,
            replay_class: tgt_node.replay_class.min(src_node.replay_class),
            created_at: Utc::now(),
        };
        let conn = self.conn()?;
        insert_state(&conn, &node)?;
        set_head(&conn, target, &node.id)?;
        conn.execute(
            "UPDATE branches SET status = ?1 WHERE id = ?2",
            params![BranchStatus::Merged.as_str(), source.as_str()],
        )
        .map_err(sql_err)?;
        Ok(node)
    }

    // ---------------------------------------------------------------------- GC

    /// Mark-and-sweep garbage collection.
    ///
    /// Marks every blob (manifests + file contents) reachable from the heads
    /// of non-discarded branches (walking all parent edges), then sweeps
    /// unreferenced CAS blobs and state rows that are reachable only from
    /// discarded branches. Branch rows are kept for audit.
    #[tracing::instrument(level = "info", skip(self))]
    pub fn gc(&self) -> KernelResult<GcReport> {
        let conn = self.conn()?;
        let heads: Vec<String> = {
            let mut stmt = conn
                .prepare("SELECT head FROM branches WHERE status != 'discarded'")
                .map_err(sql_err)?;
            let rows = stmt
                .query_map([], |r| r.get::<_, String>(0))
                .map_err(sql_err)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(sql_err)?;
            rows
        };

        // Mark: reachable states and blobs.
        let mut live_states = HashSet::new();
        let mut live_blobs: HashSet<ContentHash> = HashSet::new();
        let mut queue: VecDeque<StateId> = heads.into_iter().map(StateId).collect();
        while let Some(id) = queue.pop_front() {
            if !live_states.insert(id.clone()) {
                continue;
            }
            let n = load_state(&conn, &id)?;
            let manifest = Manifest::load(&self.cas, &n.workspace_root)?;
            live_blobs.insert(n.workspace_root.clone());
            live_blobs.extend(manifest.files.values().map(|e| e.blob.clone()));
            queue.extend(n.parent.into_iter().chain(n.merge_parent));
        }

        // Sweep state rows.
        let all_states: Vec<String> = {
            let mut stmt = conn.prepare("SELECT id FROM states").map_err(sql_err)?;
            let rows = stmt
                .query_map([], |r| r.get::<_, String>(0))
                .map_err(sql_err)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(sql_err)?;
            rows
        };
        let mut states_removed = 0;
        for id in all_states {
            if !live_states.contains(&StateId(id.clone())) {
                conn.execute("DELETE FROM states WHERE id = ?1", [&id]).map_err(sql_err)?;
                states_removed += 1;
            }
        }

        // Sweep blobs.
        let mut blobs_removed = 0;
        for blob in self.cas.list()? {
            if !live_blobs.contains(&blob) {
                self.cas.remove(&blob)?;
                blobs_removed += 1;
            }
        }
        let report = GcReport { blobs_removed, states_removed };
        tracing::info!(?report, "gc complete");
        Ok(report)
    }
}

// ------------------------------------------------------------------- helpers

fn sql_err(e: rusqlite::Error) -> KernelError {
    KernelError::Storage(format!("sqlite: {e}"))
}

fn ensure_active(b: &Branch) -> KernelResult<()> {
    match b.status {
        BranchStatus::Active => Ok(()),
        BranchStatus::Discarded | BranchStatus::Merged => {
            Err(KernelError::BranchDiscarded { branch: b.id.to_string() })
        }
    }
}

fn insert_state(conn: &Connection, node: &StateNode) -> KernelResult<()> {
    let json = serde_json::to_string(node)?;
    conn.execute(
        "INSERT INTO states (id, episode, branch, parent, merge_parent, workspace_root, node_json, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            node.id.as_str(),
            node.episode.as_str(),
            node.branch.as_str(),
            node.parent.as_ref().map(|p| p.as_str()),
            node.merge_parent.as_ref().map(|p| p.as_str()),
            node.workspace_root.as_str(),
            json,
            node.created_at.to_rfc3339()
        ],
    )
    .map_err(sql_err)?;
    Ok(())
}

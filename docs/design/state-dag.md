# The World State DAG

Status: Living document · Applies to: v0.6 · Last updated: 2026-08-12

## 1. Overview

The sandbox is not a box; it is a state-transition graph. A VM, container, or
process tree is only the physical mechanism that carries execution. The object
AgentKernel actually manages is a **World State DAG**: a versioned graph of
immutable state nodes in which every step appends a node whose delta records
exactly what changed, across every layer of agent-relevant state. This is the
concrete realization of invariant 2: *no invisible state transition*.

Types referenced here are defined in `kernel/core/src/state.rs`,
`ids.rs`, and `replay.rs`; the DAG service itself lives in
`kernel/state_dag`.

## 2. State adapters

What needs versioning is far more than a filesystem. The DAG service MUST
decompose world state into adapters, each responsible for capturing,
diffing, and restoring one layer:

```text
WorkspaceState        working directory (content-addressed files)
ProcessState          processes and runtime state
BrowserState          browser profile, cookies, open pages
ToolSessionState      tool / MCP sessions
PolicyState           active policy and its epoch
ObservationState      externally-read facts and their freshness
EffectLedgerState     pending effects and committed receipts
```

Each adapter declares what it can faithfully capture; the composite fidelity
of a node is summarized by its `ReplayClass` (see `replay.md`). An adapter
MUST NOT claim fidelity it cannot restore — e.g. a backend without process
checkpointing MUST NOT report `ProcessAndFilesystem`.

## 3. Node and delta semantics

### 3.1 StateNode

A node is immutable and content-addressed (`StateId`, prefix `st-`):

```rust
pub struct StateNode {
    pub id: StateId,
    pub episode: EpisodeId,
    pub branch: BranchId,
    pub parent: Option<StateId>,        // None only for the episode root
    pub produced_by: Option<StepId>,    // None for roots and merge nodes
    pub merge_parent: Option<StateId>,  // second parent, merge nodes only
    pub actor: PrincipalId,
    pub delta: StateDelta,
    pub workspace_root: ContentHash,    // Merkle root of the workspace tree
    pub replay_class: ReplayClass,
    pub created_at: DateTime<Utc>,
}
```

Rules:

- Every node except the episode root MUST have a `parent`. A node with a
  `merge_parent` is a merge node and MUST have `produced_by: None`.
- `actor` records which `Principal` produced the transition; a delta with no
  attributable actor MUST NOT be admitted.
- Nodes are append-only. Rollback and discard never mutate or delete nodes
  (garbage collection of unreachable nodes is a storage concern, §7).

### 3.2 StateDelta and FileChange

The delta spans all adapters:

```rust
pub struct StateDelta {
    pub files: Vec<FileChange>,
    pub processes_started: Vec<String>,   // command-line digests, still running
    pub processes_exited: Vec<String>,
    pub tool_sessions: Vec<String>,       // sessions opened or mutated
    pub policy_epoch: u64,                // bumps when policy changed
    pub effects_proposed: Vec<EffectId>,
    pub effects_committed: Vec<ReceiptId>,
}
```

File changes are typed, not textual:

```rust
pub enum FileChange {
    Added    { path: String, blob: ContentHash, mode: u32 },
    Modified { path: String, old_blob: ContentHash, new_blob: ContentHash },
    Deleted  { path: String, old_blob: ContentHash },
}
```

`Modified` and `Deleted` carry `old_blob` so that a delta is invertible for
files and so that three-way merge (§6) can detect concurrent modification
without re-reading parents. `StateDelta::is_empty()` identifies steps that
changed nothing; the DAG MAY collapse empty-delta steps into ledger-only
entries instead of full nodes (a checkpoint policy — most agent turns contain
no state worth snapshotting, so per-turn full snapshots are wasteful).

### 3.3 Content-addressed workspace

The workspace adapter MUST store file contents in a content-addressed store
(CAS) keyed by `ContentHash`, and MUST summarize each node's tree as a Merkle
root in `workspace_root`. Consequences:

- Two branches with identical trees share all blobs and have equal
  `workspace_root`; equality of roots is a constant-time branch comparison.
- Fork is O(1) metadata; materialization is lazy.
- `branch.diff` between any two nodes reduces to a Merkle tree walk.

## 4. Fork, diff, rollback, discard

- **`branch.fork(from: StateId) -> BranchId`** creates a new branch whose
  first node has `parent = from`. The kernel asks the selected `Backend` to
  `fork(&from, &to_branch)`; backends with native CoW (forkd-class) return
  `Ok(true)`, others return `Ok(false)` and the kernel re-materializes the
  workspace from the CAS. Fork MUST NOT copy capability leases: leases are
  branch-bound (`bound_branch`) and authority does not follow the agent across
  speculative branches unless explicitly rebound.
- **`branch.diff(a, b)`** returns the typed delta between two nodes per
  adapter (files as `FileChange` lists, plus process/session/effect diffs).
- **Rollback** is repointing a branch head to an ancestor node and resuming
  execution from there. Nothing is destroyed; the abandoned suffix remains in
  the ledger.
- **`branch.discard(branch)`** marks a branch dead and calls
  `Backend::discard` to release backend-side resources. Discard MUST revoke
  all leases bound to the branch and MUST abort all its
  `PendingEffect`s that have not been committed. Committed receipts are
  never discarded — they are facts about the external world.

## 5. Branch fan-out

Fork/search is a first-class agent tool. An agent MAY:

```text
fork 3 branches from one checkpoint
attempt a different fix in each
run tests in parallel
compare correctness, performance, complexity, risk (branch.compare)
merge the best branch; discard the rest
```

Fan-out is budgeted: the scheduler enforces a branch fan-out budget per
episode (see `scheduling.md` §6), and each child branch runs under its own
attenuated leases and its own `ResourceBudget`.

## 6. Merge semantics: artifact-merge-only

Branch merge is not just Git merge. The normative rule is:

> **Merge artifacts and verified local state. Never merge processes or
> authority.**

Per adapter:

| Layer | Merge behavior |
|---|---|
| Workspace files | Three-way merge against the nearest common ancestor's tree, using `old_blob`/`new_blob`. Conflicts are surfaced to the agent as structured observations, never auto-resolved by the model without a recorded decision. |
| Processes | MUST NOT be merged. Process memory from two branches has no defined union; processes are restarted on the merge result. |
| Browser sessions | MUST NOT be merged. |
| Capabilities | MUST NOT be merged. Leases are not unioned across branches; the merged branch starts with explicitly (re)issued or rebound leases. |
| External effects | MUST NOT be duplicated or unioned. Pending effects of the losing branch are aborted; receipts from either branch remain immutable ledger facts referenced by, not copied into, the merge. |
| Observations | Carried with freshness metadata; stale external reads MAY be flagged for re-validation. |

A merge produces a merge node with `parent` = the surviving branch head,
`merge_parent` = the merged-in head, and `produced_by: None`. The merge
node's `workspace_root` is the merged tree's Merkle root.

## 7. Storage amplification

Branch fan-out multiplies state. Mitigations, in order of importance:

1. Content addressing: unchanged blobs are shared across all branches;
   amplification is proportional to *changed* bytes, not tree size.
2. Empty-delta collapse (§3.2): skip node creation for no-op steps.
3. Semantic checkpoint policy: full adapter capture only at
   scheduler-designated checkpoints; intermediate steps keep deltas only.
4. GC of nodes unreachable from any live branch head, pinned checkpoint, or
   receipt reference. Ledger entries are never GC'd.

**Branch storage amplification** (bytes stored / bytes of a single-branch
baseline) is a tracked metric with targets in `metrics.md`.

## 8. Deliberate MVP exclusions

The v0.6 DAG deliberately does not attempt arbitrary process-memory
checkpointing (CRIU-class capture of sockets, GPU state, FUSE mounts,
kernel-version-sensitive state, multi-process browsers, Unix domain sockets,
external service sessions). Instead the MVP guarantees semantic correctness
first:

- content-addressed workspace;
- file and tool-call logs;
- pinned images and dependencies;
- process restart (not restore) on rollback;
- recorded model responses;
- observation receipts for external reads.

Backends that do support process snapshotting declare it via
`ReplayClass::ProcessAndFilesystem`; the DAG accepts higher-fidelity nodes
without requiring them. This is why `ReplayClass` exists: honest per-node
guarantees instead of a vague "supports snapshot" flag.

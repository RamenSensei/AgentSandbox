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

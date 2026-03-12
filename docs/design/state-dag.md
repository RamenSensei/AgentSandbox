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

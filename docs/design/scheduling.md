# Scheduling and Backend Selection

Status: Living document · Applies to: v0.6 · Last updated: 2026-08-12

## 1. Overview

Not every action deserves a full microVM, and no task should be bound for its
lifetime to one maximum-privilege VM. AgentKernel schedules **per action**:
the Backend Router picks an isolation backend for each step, and the
Scheduler allocates resources at step boundaries. Both live in
`kernel/scheduler`; the contract types (`Backend`, `BackendProfile`,
`ExecutionRequest`, `ExecutionOutcome`, `ResourceBudget`) are in
`kernel/core/src/traits.rs` and `budget.rs`. Backends live under
`backends/{local,cube,forkd,gvisor,kubernetes}`.

## 2. Per-action backend selection

| Action type | Appropriate backend |
|---|---|
| Pure compute, code transformation | WASI / language isolate |
| Low-risk local CLI | OS sandbox: Landlock, bubblewrap (srt/nono class) — `backends/local` |
| General Linux, third-party dependencies | gVisor — `backends/gvisor` |
| Arbitrary binaries, root, higher-risk workloads | microVM / Kata — `backends/cube`, `backends/forkd` |
| GUI, desktop, browser automation | full GUI VM |
| GitHub, cloud platforms, databases, payments | **never enters a guest** — trusted Effect Broker + connector |

The last row is normative and absolute: credentialed external operations are
not a backend-selection problem. They route to the Effect Broker regardless
of what backend the step otherwise uses.

### 2.1 The selection rule

> The router MUST select the **cheapest backend that satisfies the risk,
> compatibility, and reproducibility requirements** of the action.

Inputs to the decision, all from `BackendProfile`:

```rust
pub struct BackendProfile {
    pub name: String,
    pub isolation_strength: u8,   // 0 = in-process, 100 = hardware-virtualized
    pub cold_start_ms: u64,       // self-reported typical cold start
    pub replay_class: ReplayClass,
    pub supports_fork: bool,
    pub supports_gui: bool,
    pub full_linux: bool,         // arbitrary Linux binaries vs. e.g. WASI-only
}
```

- **Risk**: the action's operation namespace, the lease's `risk_units`, and
  policy floors map to a minimum `isolation_strength`. Untrusted or
  quarantined principals raise the floor.
- **Compatibility**: does the action need `full_linux`, `supports_gui`,
  `supports_fork`?
- **Reproducibility**: does the episode's replay policy require a minimum
  `ReplayClass` for this step?

Among backends clearing all three floors, choose the lowest expected cost
(cold/warm start latency plus resource footprint). Ties break toward higher
`isolation_strength`.

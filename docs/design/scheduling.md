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

## 3. Step-level resource allocation

Measurements on coding-agent workloads show OS execution/initialization can
dominate end-to-end latency and memory peak/average ratios can exceed an
order of magnitude. Static per-container limits waste both. The scheduler
therefore operates at step and tool-call boundaries:

- **Step-level cgroups**: each `ExecutionRequest` carries a `ResourceBudget`
  (`cpu_ms`, `memory_bytes`, `network_bytes`, `tokens`, `cost_micro_usd`,
  `risk_units`); the Capability Compiler renders it as cgroup limits for that
  step, not a static container ceiling.
- **Burst memory budgets**: short bursts above steady-state MAY be granted
  from a shared burst pool, reclaimed at step end; peak/avg ratio is tracked
  per action type to size the pool.
- **Idle pause**: a guest waiting on model inference or human approval SHOULD
  be paused (frozen cgroup or suspended VM) and its memory reclaimed;
  tool-call idle time is a tracked metric.
- **Semantic checkpoint policy**: full state capture happens at
  scheduler-designated checkpoints (before risky actions, before fan-out, at
  episode milestones), not every turn — most turns carry no state worth a
  snapshot (cf. `state-dag.md` §7).
- **Backend promotion/demotion**: a step MAY be promoted to a stronger
  backend mid-episode (an action's risk grew) or demoted to a cheaper one
  (pure-compute stretch). Promotion re-materializes the workspace from the
  CAS on the new backend; process state does not migrate across backends.

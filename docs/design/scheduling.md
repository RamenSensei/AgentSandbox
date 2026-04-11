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

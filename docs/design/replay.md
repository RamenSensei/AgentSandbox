# Replay: Three Modes, Not One

Status: Living document · Applies to: v0.6 · Last updated: 2026-08-12

## 1. Overview

"Replayable" is a claim that hides three very different guarantees. AgentKernel
refuses a single vague "supports snapshot" flag and instead defines **three
replay modes** with distinct semantics, plus per-backend **replay classes**
that state honestly which modes each recorded step can honor. Types are in
`kernel/core/src/replay.rs` (`ReplayMode`, `ReplayClass`); the replay engine
spans `kernel/causal_ledger` and `kernel/state_dag`; the protocol verbs are
`replay.audit`, `replay.sandbox`, and `replay.live`.

## 2. The three modes

```rust
pub enum ReplayMode { Audit, Sandbox, Live }
```

### 2.1 Audit replay (`replay.audit`)

Plays back the recorded stream: model responses, tool results, observations,
and receipts, in causal order from the ledger. **Never re-executes
anything** — no process runs, no network flows, no state mutates. Use cases:
auditing, debugging, post-incident review, demonstrating to a human exactly
what happened and under what authority. Audit replay is universal: every
recorded step supports it (`ReplayClass::supports(Audit)` is `true` for all
classes).

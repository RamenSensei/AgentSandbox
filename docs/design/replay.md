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

### 2.2 Sandbox replay (`replay.sandbox`)

Restores internal state from the State DAG and **re-executes local code**,
substituting recorded inputs where they were captured: time, randomness, DNS
answers, and model responses are fed from the recording instead of the live
world. Use cases: reproducing a bug, verifying a fix against the original
conditions, regression-testing kernel changes against recorded episodes.
Fidelity is bounded by the recording backend's `ReplayClass` (§3): a
`FilesystemOnly` recording restores files and restarts processes; only
`FrameworkHostCalls` recordings can promise byte-identical re-execution at
the host-call boundary.

### 2.3 Live replay (`replay.live`)

Reconnects to the **real external world** and re-executes the same effect
contracts. The guarantee is deliberately narrow:

> Live replay guarantees the same `EffectContract`, not the same outcome.

The base branch may have moved, the API may respond differently, preconditions
may fail — in which case commit-time revalidation aborts exactly as it would
in a first run. Live replay of a committed effect with an unchanged
`idempotency_key` MUST hit duplicate-commit protection and return the
existing receipt rather than acting twice.

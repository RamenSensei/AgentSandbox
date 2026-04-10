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

### 2.4 Committed effects are never re-executed in audit/sandbox

In Audit and Sandbox modes, effects that were committed are represented by
their receipts and recorded response digests. The replay engine MUST NOT call
`Connector::commit` (or `prepare`) in these modes under any circumstances;
connectors are simply not wired into the audit/sandbox replay path. Only Live
mode touches connectors, and only through the full transaction pipeline.

## 3. ReplayClass: per-backend honesty

Each backend declares in its `BackendProfile`, and each `StateNode` records,
what was faithfully captured:

```rust
pub enum ReplayClass {
    AuditOnly,             // only recorded observations; no re-execution
    FilesystemOnly,        // workspace content-addressed and restorable
    ProcessAndFilesystem,  // + process tree checkpoint/restore
    FrameworkHostCalls,    // host calls (model, tools, HTTP) recorded; byte-identical
                           //   replay under pinned time/randomness
    BrowserProfile,        // browser profile and page state restorable
}
```

A backend MUST declare the weakest class describing what it actually
guarantees. Full process checkpointing collides with sockets, GPUs, FUSE,
kernel versions, device state, multi-process browsers, Unix domain sockets,
and external service sessions — classes exist so those limits are stated, not
papered over.

### 3.1 The supports() matrix

`ReplayClass::supports(mode)`:

| ReplayClass | Audit | Sandbox | Live |
|---|---|---|---|
| `AuditOnly` | yes | no | no |
| `FilesystemOnly` | yes | yes | yes |
| `ProcessAndFilesystem` | yes | yes | yes |
| `FrameworkHostCalls` | yes | yes | yes |
| `BrowserProfile` | yes | yes | yes |

In code: Audit is always supported; Sandbox and Live require `*self >=
ReplayClass::FilesystemOnly` (the `Ord` on the enum is meaningful). A replay
request over a range of steps is honored at the *weakest* class in the range;
the kernel MUST report which steps limited fidelity rather than silently
degrading.

## 4. Divergence detection and classification

Sandbox and Live replay compare re-execution against the recording at every
step boundary. A divergence is any mismatch in: workspace Merkle root
(`workspace_root`), `StateDelta` contents, observation summaries/exit codes,
proposed effect contract hashes, or resource usage beyond tolerance.

Divergences MUST be detected, classified, and reported — never silently
absorbed. The classification dimensions:

- **layer**: which state adapter diverged (workspace, process, tool session,
  effect, observation);
- **cause category**: uncaptured input (time, randomness, DNS, network),
  external world change (Live), backend fidelity gap (class too weak),
  nondeterministic guest code, kernel regression;
- **severity**: cosmetic (log noise), semantic (different delta), effectual
  (different proposed contract — always terminates a Live replay before
  commit).

**Divergence classification completeness** — the fraction of observed
divergences the engine can attribute to a cause category — is a tracked
metric (`metrics.md` §4). An unclassified divergence is a bug in the recorder
or classifier, not an acceptable residue.

## 5. Why "fully deterministic replay" is not claimed

Recording host calls under pinned time and randomness can achieve
byte-identical replay at the framework boundary (`FrameworkHostCalls`), and
AgentKernel supports that class where a backend provides it. But the open
network, live websites, and external SaaS are not deterministic systems:
their state advances independently, their responses embed clocks and nonces,
and their side effects cannot be rolled back or replayed into existence.

Claiming "fully deterministic replay" of an episode that touched the open
world would be marketing, not engineering. AgentKernel's position:

- determinism claims are scoped to a `ReplayClass` and a mode;
- everything external is captured as recorded observations (replayable in
  Audit/Sandbox) or re-negotiated as contracts (Live);
- the honest unit of cross-run comparability for external actions is the
  `EffectContract` hash plus the receipt, not the bytes of the outcome.

## 6. Interaction with the ledger and DAG

Replay is a read path over two stores: the causal ledger (ordered events,
observations, full outputs by `ContentHash`, receipts) and the State DAG
(restorable nodes). Consequently:

- any step is replayable in Audit mode forever, as long as its ledger entries
  exist — ledger entries are never garbage collected;
- Sandbox replay requires the node's blobs to still be materializable from
  the CAS; GC MUST NOT collect blobs pinned by replay-retention policy;
- `replay.*` verbs accept a step range within one episode and MUST refuse
  ranges crossing a fidelity boundary unless the caller opts into degraded
  (Audit-only) playback for the weaker segment.

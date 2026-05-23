# ADR-0008: Three Replay Modes with Per-Backend ReplayClass

## Status

Accepted

## Date

2026-05-13

## Context

"Deterministic replay" is the most over-claimed feature in this space. Systems
that pin time and randomness at a host-call boundary (Chidori-style) achieve
byte-identical replay of framework calls; filesystem-versioning systems replay
files but not processes; process-checkpoint systems hit sockets, GPUs, FUSE and
kernel-version compatibility walls; and nothing replays the open network — DNS
answers change, external SaaS state moves, a replayed request is a new request.
DeltaBox's own paper is explicit that network I/O and external effects do not
roll back with the VM. A single "supports snapshot" flag would let every backend
claim replay while guaranteeing different, incomparable things, and would let us
market a determinism we cannot deliver.

Alternatives considered: one best-effort replay mode with divergence warnings
(rejected: users cannot reason about what a divergence means without knowing
what was guaranteed); requiring full determinism and dropping backends that
cannot provide it (rejected: it excludes every real backend the moment a
browser or the network is involved).

## Decision

The protocol exposes three deliberately distinct replay modes:

- `audit` — play back recorded model responses, tool results, Observations and
  Receipts. Never re-executes anything. Always available.
- `sandbox` — restore internal state and re-execute local code, substituting
  recorded inputs (time, randomness, DNS, model responses) where captured.
- `live` — reconnect to the current external world and re-execute the same
  effect contracts. Guarantees the *contract*, not the outcome.

Every backend declares a `ReplayClass` per step — `audit_only`,
`filesystem_only`, `process_and_filesystem`, `framework_host_calls`,
`browser_profile` — recorded on each `StateNode`. The kernel answers "can this
step honor mode M" mechanically from the recorded class (`supports()`); a
replay request beyond a step's class is refused, not approximated silently.
Documentation and marketing must not claim determinism beyond what a step's
recorded class supports; the open network is never claimed deterministic.

## Consequences

Positive:

- Replay guarantees are honest, per-step and machine-checkable; an auditor can
  see exactly which segments of an Episode are re-executable and at what fidelity.
- Backends can join with weak replay (audit_only) and strengthen incrementally
  without protocol changes.
- `live` replay composes with commit-time revalidation (ADR-0007): re-executing
  a contract against a changed world aborts on preconditions instead of
  silently doing something different.

Negative:

- Three modes and five classes are more surface for SDK users to learn than
  one `replay()` call.
- Mixed-class episodes replay unevenly; tooling must render per-step class so
  gaps are visible rather than surprising.

Follow-ups:

- Divergence classification for sandbox replay (which uncaptured input diverged).
- Conformance suite: a backend's declared class is tested, not trusted.

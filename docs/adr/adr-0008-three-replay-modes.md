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

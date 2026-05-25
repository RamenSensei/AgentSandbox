# AgentKernel Architecture

Status: Living document · Applies to: v0.6 · Last updated: 2026-08-12

## 1. Overview

AgentKernel is an open-source transactional execution kernel for AI agents. It
models agent execution as a branchable, replayable, authorizable,
transactionally-committed world state machine. The slogan is:

> **Speculate locally, commit globally.**

The local world lets an agent explore boldly, fork parallel branches, and roll
back automatically; actions that affect the real world MUST pass through
precise authorization, commit-time revalidation, and MUST produce a
non-repudiable execution receipt.

AgentKernel is not another container platform. It is closer to a combination
of Git (managing execution state and branches), a database transaction manager
(managing external side effects), a capability OS (managing the authority of
agents, sub-agents, and tools), CPU speculative execution (parallel attempts
with discarded failures), and a flight recorder (the complete causal chain from
intent to OS change to external effect).

This document is normative. The key words MUST, MUST NOT, SHOULD, and MAY are
to be interpreted as in RFC 2119. The semantic source of truth is the `ak-core`
crate at `kernel/core/src/`; the protocol version implemented by this tree is
`PROTOCOL_VERSION = "0.6"` (pre-1.0; breaking changes MAY occur before 1.0).

## 2. Workspace invariants

Every layer of the system MUST uphold four invariants (declared in
`kernel/core/src/lib.rs`):

1. **No ambient authority.** Every action carries an explicit
   `CapabilityLease`.
2. **No invisible state transition.** Every step produces a `StateDelta` and a
   causal-ledger entry.
3. **No irreversible effect before commit.** External effects go through the
   Effect Broker.
4. **No denial without a machine-readable explanation.** Every refusal is a
   structured `Denial`.

An implementation that violates any of these is non-conformant, regardless of
which optional features it supports.

## 3. Layered architecture

```text
┌─────────────────────────────────────────────────────────┐
│              Agent / Harness / Human                     │
│ objective · action · intent hint · approval              │
└──────────────────────────┬──────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────┐
│              Agent Execution Protocol                    │
│ Episode · Step · Branch · Principal · Capability         │
│ Observation · Effect · Receipt · ReplayClass             │
└──────────────────────────┬──────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────┐
│             Trusted Semantic Kernel                      │
│                                                         │
│ Identity & Policy       State DAG       Effect Broker    │
│ Capability Compiler     Causal Ledger   Secret Broker    │
│ Backend Router          Scheduler       Replay Engine    │
└───────────────┬────────────────┬────────────────┬────────┘
                │                │                │
┌───────────────▼──────┐ ┌───────▼────────┐ ┌────▼───────────┐
│ Local OS Sandboxes   │ │ gVisor/microVM │ │ World Connectors│
│ WASI/srt/nono class  │ │ Kata/GUI VM    │ │ GitHub/DB/Cloud │
└──────────────────────┘ └────────────────┘ └────────────────┘
```

Three properties of this layering are normative:

- The **protocol** is the primary public asset. It MUST remain independent of
  any particular VMM, cloud, or orchestrator (Firecracker, E2B, Cube,
  Kubernetes, ...). Protocol schemas, event formats, state formats, and the
  conformance suite MUST stay open and backend-neutral.
- The **Trusted Semantic Kernel** is the only trusted computing base. Guests,
  backends, and agent models are untrusted.
- **Backends and connectors are pluggable.** They implement the `Backend` and
  `Connector` traits from `ak-core::traits` and carry no policy authority of
  their own.

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

## 4. Agent Execution Protocol

The protocol's core nouns are not containers, processes and files, but:

```text
Episode          one long-running task
Step             one decision-and-execution unit
Branch           one speculative world branch
Principal        an agent, sub-agent, tool, or human identity
CapabilityLease  time-bound, budgeted, attenuable authority
Observation      a structured observation
Effect           a proposed change to the external world
Receipt          proof of a committed effect
```

### 4.1 Verb families

Conformant kernels MUST expose the following verb families:

```text
episode.create        episode.describe

step.execute          step.explain          step.retry

branch.fork           branch.diff           branch.compare
branch.merge          branch.discard

capability.describe   capability.request
capability.delegate   capability.revoke

effect.propose        effect.prepare
effect.commit         effect.compensate

trace.query

replay.audit          replay.sandbox        replay.live
```

`step.explain` and `trace.query` exist because agents SHOULD NOT have to guess
their environment with `git status`, `find`, `ps`, and `netstat`; the causal
ledger is directly queryable. `replay.*` is three distinct verbs because the
three replay modes make deliberately different guarantees (see `replay.md`).

### 4.2 The execute() state transition

The minimal execution abstraction is not `create_container()` / `exec()` /
`kill()`, but a controlled state transition:

```text
execute(
    state_id,
    principal,
    action,
    capability_lease,
    resource_budget
) -> {
    new_state_id,
    observation,
    local_delta,
    pending_effects,
    committed_receipts,
    policy_decisions,
    resource_usage,
    replay_class
}
```

Formally: `T(S_t, P, A_t, C_t, B_t) → (S_{t+1}, O_t, Δ_t, E_t^pending, R_t,
K_t)`, where `S_t` is versioned world state, `P` the principal, `A_t` the
structured action, `C_t` the current capability lease, `B_t` the
CPU/memory/token/network/cost/risk budget, `Δ_t` the local delta,
`E_t^pending` uncommitted external effects, `R_t` committed receipts, and
`K_t` cost and causal record. In code, the request/response pair is
`ExecutionRequest` / `ExecutionOutcome` (`ak-core::traits`), with the
kernel-level result carrying `StateNode`, `StateDelta`, `Observation`,
`PendingEffect`, `Receipt`, `ResourceBudget` usage, and `ReplayClass`.

## 5. Trusted Semantic Kernel components

| Component | Responsibility | Crate |
|---|---|---|
| Identity & Policy | `Principal` registry, `TrustLevel`, deterministic typed policy rules, policy epochs | `kernel/identity`, `kernel/policy` |
| Capability Compiler | Compiles semantic capability requests into concrete enforcement (Landlock, seccomp, cgroups, netns/egress proxy, connector constraints, secret-broker token exchange) | `kernel/policy` |
| State DAG | Versioned world state: `StateNode`, `StateDelta`, fork/diff/merge/discard | `kernel/state_dag` |
| Causal Ledger | Append-only record from objective → model response → intent → capability → policy decision → invocation → delta → observation → effect → receipt → next decision | `kernel/causal_ledger` |
| Effect Broker | External-effect transaction pipeline and commit-time revalidation | `kernel/effect_broker` |
| Secret Broker | Credential mediation; raw credentials never enter guests | `kernel/effect_broker` (broker side) + connectors |
| Backend Router | Selects the cheapest `Backend` satisfying risk, compatibility, and reproducibility requirements | `kernel/scheduler` |
| Scheduler | Step-level resource allocation, prewarming, fan-out budgets | `kernel/scheduler` |
| Replay Engine | Audit/sandbox/live replay over the ledger and state DAG | `kernel/causal_ledger` + `kernel/state_dag` |
| API surface | Protocol endpoint exposing the verb families | `kernel/api` |

Shared semantic types live in `kernel/core` (`ak-core`), which performs no
I/O. Backends live under `backends/{local,cube,forkd,gvisor,kubernetes}`;
connectors under `connectors/{github,http,mcp}`. `conformance/` and
`adversarial-bench/` validate protocol conformance and security behavior;
`examples/coding-agent-github` is the reference MVP scenario.

## 6. Design principles

Derived from first principles in the founding design discussion; all normative.

1. **The sandbox is not a box; it is a state-transition graph.** A VM is only
   the physical carrier. What MUST be versioned is harness state, workspace,
   process/runtime state, browser profile, tool/MCP sessions, externally-read
   facts and their freshness, current capabilities, pending effects, and
   committed receipts — the World State DAG (see `state-dag.md`).
2. **Local change and external effect MUST be separated.** OS snapshots are
   not a transaction for the external world; emails, PRs, deletions, and
   payments cannot be undone by rolling back a VM (see
   `effect-transactions.md`).
3. **Authority is a lease, not a boolean.** Not `allow network` but a
   principal-, operation-, parameter-, count-, time-, budget-, and
   branch-bound `CapabilityLease` with preconditions (see
   `capability-model.md`).
4. **Failures and denials MUST be high-quality observations.** Not
   `Permission denied`, but a structured `Denial` with a code, reason, safe
   alternatives, and requestable scopes, so agents self-repair instead of
   interrupting humans.
5. **Each action selects its appropriate isolation backend.** The scheduler
   chooses the cheapest backend satisfying risk, compatibility, and
   reproducibility requirements — never "one maximum-privilege VM per task"
   (see `scheduling.md`).
6. **Multiple agents share evidence, not a mutable world.** Each agent is a
   distinct `Principal` on its own branch; delegation is attenuation; agents
   exchange provenance-carrying artifacts, and merges combine artifacts, never
   process state or authority.

## 7. Trust and non-goals

The kernel trusts: its own code, the policy configuration, connectors (which
hold credentials), and the receipt signing key. It does not trust: guest code,
model outputs, intent hints (hints MAY optimize scheduling, MUST NOT
authorize), backends beyond their declared `BackendProfile`, or any skill/MCP
server prior to quarantine and promotion (see `threat-model.md`).

Out of scope for v0.6: a new hypervisor, arbitrary full process-memory
checkpointing, generic transactions over arbitrary SaaS, payment connectors,
multi-cloud scheduling, and any marketing claim of fully deterministic replay
of the open network.

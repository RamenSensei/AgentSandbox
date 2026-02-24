# AgentKernel Execution Protocol — Specification

Version: 1.0.0 (`agentkernel.v1`)
Status: Stable
Canonical machine definitions: `protocol/*.proto` (proto3),
`protocol/openapi.yaml` (JSON/HTTP binding).
Reference implementation of the wire types: `kernel/core/src/*.rs` (ak-core).

The protocol treats an AI agent's execution the way a database treats a
transaction: every action is authorized against explicit capability leases,
every state transition is recorded in an immutable causal ledger, and every
externally visible effect passes through a two-phase, receipt-producing
commit. The result is an execution substrate that can be branched, diffed,
merged, audited and replayed.

---

## 1. The four invariants

Everything else in the protocol is machinery for enforcing these:

1. **No ambient authority.**
   A principal has exactly the authority carried by the capability leases it
   presents — nothing more. There is no implicit inheritance: sub-agents,
   tools and skills are distinct principals and begin with zero leases.
   Delegation is only ever *attenuation* (`capability.delegate`): a child
   lease can never exceed its parent in operations, constraints, uses,
   expiry or budget. Every `Action` carries the `lease` it presents; the
   free-text `intent_hint` is used only for scheduling and narration, never
   for authorization.

2. **No invisible state transition.**
   Every step either produces an immutable `StateNode` in the world-state
   DAG (with a `StateDelta` recording exactly what changed across every
   adapter: files, processes, tool sessions, policy epoch, effects) or
   produces no transition at all. `StepExecuteResponse.produced_state` is
   absent precisely when nothing changed. There is no third possibility.

3. **No irreversible effect before commit.**
   Anything that leaves the sandbox is an *effect* and follows the pipeline
   in section 5. Effects classified `compensatable` or worse cannot happen
   as a side channel of a step; the step yields `effect_pending` and the
   world is untouched until an explicit, revalidated `effect.commit`.
   `prepare` is guaranteed side-effect free.

4. **No denial without a machine-readable explanation.**
   A policy rejection is a first-class observation, not an error string.
   Every `Denial` carries a stable `DenialCode`, the canonical
   `attempted_operation`, a repair-oriented `reason`, `safe_alternatives`
   the caller may already use, `requestable_scopes` it could ask for, and
   whether `escalation_allowed`. Detail is calibrated by the principal's
   trust level (quarantined principals get codes and safe alternatives, not
   a map of the policy surface) — but a code and alternatives are always
   present.

---

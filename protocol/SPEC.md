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

## 2. Objects and identifiers

All identifiers are opaque strings with a fixed prefix:

| Prefix   | Object            | Description |
|----------|-------------------|-------------|
| `ep-`    | Episode           | A long-running task; root of a state DAG. |
| `step-`  | Step              | One decision-and-execution unit. |
| `br-`    | Branch            | A speculative world line forked from a state. |
| `st-`    | StateNode         | Immutable, content-addressed world state. |
| `pr-`    | Principal         | Agent, sub-agent, tool, human or kernel. |
| `lease-` | CapabilityLease   | Time-bound, budgeted, attenuable authority. |
| `fx-`    | PendingEffect     | Proposed-but-uncommitted external effect. |
| `rcpt-`  | Receipt           | Signed proof of a committed effect. |

Content hashes are strings of the form `sha256:<hex>` computed over
*canonical JSON*: object keys sorted lexicographically, compact separators,
UTF-8. Contract hashes and receipt signatures depend on this encoding being
stable across implementations.

JSON encoding rules (mirroring ak-core serde):

- Field names are `snake_case`.
- Sum types are internally tagged: `ActionKind` and `Observation` by
  `"kind"`, `EffectPhase` by `"phase"`, `FileChange` by `"op"`,
  `Constraint` by `"kind"` — with `snake_case` variant names.
- `DenialCode` values are `SCREAMING_SNAKE_CASE` (e.g.
  `CAPABILITY_DENIED`).
- `EffectClass`, `ReplayClass`, `ReplayMode`, `TrustLevel`,
  `PrincipalKind` values are `snake_case` strings.
- Optional fields are omitted when absent, never `null`-filled by servers.

### 2.1 Errors

Every non-2xx HTTP response is an `ErrorEnvelope`:

```json
{ "code": "STALE_AUTHORIZATION", "message": "...", "denial": { ... } }
```

`denial` is present exactly when `code` is `DENIED`; denials are served as
HTTP **403** with the full structured `Denial`. Merge conflicts are `409
MERGE_CONFLICT`; failed commit-time revalidation is `409
STALE_AUTHORIZATION` / `PRECONDITION_FAILED`; unknown objects are `404
NOT_FOUND`.

---

## 3. The world-state DAG

```
                    ep-1 (episode)
                      |
    root  st-0 ───────┼──────────────────────────────
            \         |            main branch br-0
             st-1 ── st-2 ─────────── st-6 ── st-7(M)
                       \                       /
                        \  fork               / merge
                br-1:    st-3 ── st-4 ── st-5
```

- An **episode** is created with a root state and a main branch.
- Each successful **step** appends one `StateNode` whose `StateDelta` is
  the complete, adapter-spanning record of what changed.
- A **branch** is a mutable head pointer into the DAG; `branch.fork` (with
  `count > 1` for parallel speculation) creates siblings that share history
  by construction. Nodes are immutable; branches never rewrite them.
- `branch.diff` returns the accumulated delta since a state (default: the
  fork point). `branch.compare` diffs two branches against their common
  ancestor and lists `conflicting_paths`. `branch.merge` creates a merge
  node (with `merge_parent`) or reports a conflict. `branch.discard` marks
  the branch dead and releases backend resources; the nodes remain in the
  ledger for audit.
- Leases may be **branch-bound** (`bound_branch`): authority does not
  follow an agent across speculative branches unless explicitly rebound.

## 4. Steps and observations

`step.execute` takes `{branch, actor, action}`. The kernel — never the
agent — selects the isolation backend. The response's `Observation` is one
of:

| kind               | Meaning |
|--------------------|---------|
| `success`          | Ran; distilled summary + `full_output` hash in the ledger. |
| `failure`          | Ran and failed; includes `first_causal_failure` when derivable. |
| `denied`           | Refused; carries the full structured `Denial`. |
| `effect_pending`   | A connector op became a proposed effect (`fx-...`). |
| `effect_committed` | An auto-committable effect committed; receipt id. |

`step.explain` returns the full authorization narrative for any recorded
step: the trace entry, the lease as presented, per-parameter constraint
check outcomes, and the backend selection rationale. `step.retry`
re-executes a step, optionally on a different branch or with a new budget.

Authorization of a step is deterministic: lease revocation, expiry,
remaining uses, principal, operation, branch binding, and per-parameter
`Constraint` checks (`equals`, `one_of`, `glob` (`*`-only), `prefix`,
`max`, `forbidden`), in that order. The first failure becomes the denial.

## 5. Effect lifecycle

OS snapshots are not a transaction for the external world. Anything that
leaves the sandbox goes through:

```
            propose ──> canonicalize ──> PROPOSED
                                            │ effect.prepare (dry-run,
                                            │  never a side effect)
                                            v
                                        PREPARED ──preview──> human/policy
                                            │ effect.approve
                                            │  (approves exactly the
                                            │   contract_hash, nothing else)
                                            v
                                        APPROVED
                                            │ effect.commit:
                                            │  revalidate lease + policy
                                            │  epoch + preconditions +
                                            │  expected_contract_hash
                            ┌───────────────┴───────────────┐
                     stale/failed                       revalidated
                            v                                v
                        ABORTED                         COMMITTED ──> signed
                                                            │         Receipt
                                                            │ effect.compensate
                                                            v
                                                       COMPENSATED
```

Key rules:

- The `EffectContract` (`operation`, `resource`, canonical `arguments`,
  `preconditions`, `idempotency_key`, `class`) is immutable once proposed.
  Its canonical-JSON hash is what gets approved; **approving an effect
  means approving exactly that hash**. Any drift fails commit with
  `STALE_AUTHORIZATION`.
- `EffectClass` is the honest reversibility scale, ordered by severity:
  `pure < local_reversible < remote_reversible < compensatable <
  irreversible < opaque_external`. Unknown semantics are `opaque_external`
  and treated as irreversible and maximally restricted.
- Commit is exactly-once: a duplicate `idempotency_key` returns the
  original receipt instead of re-executing.
- The `Receipt` is non-repudiable: an Ed25519 signature over
  `canonical_json(body)`, where the body binds effect, principal,
  operation, resource, contract hash, branch, step, policy epoch, an
  `authorization_witness` (hash of who approved what, when) and the digest
  of the external system's response.
- `effect.compensate` runs the connector's compensating action (e.g. close
  the PR) and yields a second receipt; it never pretends compensation is
  undo.

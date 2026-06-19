# Effect Transactions

Status: Living document · Applies to: v0.6 · Last updated: 2026-08-12

## 1. Overview

Installing dependencies, editing files, and starting processes can usually be
rolled back. Sending an email, pushing a commit, creating or merging a PR,
deleting a cloud resource, mutating a production database, initiating a
payment, or leaking a secret cannot be undone by a VM snapshot. **An OS
snapshot is not a transaction for the external world.** AgentKernel therefore
separates local change (managed by the State DAG) from external effects, which
pass through the Effect Broker's transaction pipeline and end in a signed,
non-repudiable receipt (invariant 3: *no irreversible effect before commit*).

Types are defined in `kernel/core/src/effect.rs` and `traits.rs`; the broker
lives in `kernel/effect_broker`; connectors under `connectors/`.

## 2. EffectClass taxonomy

Not every SaaS supports prepare/commit; the honest answer is classification,
not pretending everything is reversible. `EffectClass` is ordered by severity:

| Class | Definition | Default handling |
|---|---|---|
| `Pure` | No observable side effect. | May execute freely under its lease. |
| `LocalReversible` | Reversible by rolling back local state. | State DAG handles it; no broker transaction required. |
| `RemoteReversible` | The remote system offers a true undo. | Broker transaction; auto-approvable under policy. |
| `Compensatable` | Reversible only via a compensating action (e.g. close the PR). | Broker transaction; compensation contract MUST be registered before commit. |
| `Irreversible` | Cannot be undone (e.g. an email that has been read). | Broker transaction; approval policy is strictest short of refusal; MUST be explicitly labeled. |
| `OpaqueExternal` | Semantics unknown. | Treated as irreversible and **maximally restricted**: MUST NOT auto-approve, SHOULD require a human, highest risk cost. |

The `Ord` derive is semantic: `Pure < ... < Irreversible < OpaqueExternal`,
so policy can express "auto-approve up to `RemoteReversible`" as a comparison.
Each `Connector` declares `operations() -> Vec<(String, EffectClass)>`; an
operation without a declared class is `OpaqueExternal`.

## 3. EffectContract and the contract hash

The canonical, immutable description of what will be done to the world:

```rust
pub struct EffectContract {
    pub operation: String,               // "github.create_pull_request"
    pub resource: String,                // "org/repo"
    pub arguments: serde_json::Value,    // full canonical arguments
    pub preconditions: serde_json::Value,// e.g. {"base_head_sha": "abc123"}
    pub idempotency_key: String,         // "episode-<n>-step-<m>" by convention
    pub class: EffectClass,
}
```

`EffectContract::contract_hash()` is `hash_canonical(self)` — a hash over the
canonical JSON serialization. **The contract hash is the unit of approval.**
Approving an effect means approving *exactly this* contract; any change to
arguments, resource, or preconditions changes the hash and invalidates the
approval. Arguments MUST first pass `Connector::canonicalize`, so
semantically-equal requests hash equally and constraint checks see canonical
parameter names.

## 4. Lifecycle

```text
propose → canonicalize → prepare → approve → commit-time revalidation → commit → signed receipt
                                     │                    │
                                     └── abort ◄──────────┘        compensate (post-commit)
```

Tracked by `EffectPhase` on the `PendingEffect`:

```rust
pub enum EffectPhase {
    Proposed,
    Prepared    { preview: serde_json::Value },
    Approved    { approver: PrincipalId, approved_at: DateTime<Utc>, policy_epoch: u64 },
    Committed   { receipt: ReceiptId },
    Aborted     { reason: String },
    Compensated { compensating_receipt: ReceiptId },
}
```

A `PendingEffect` binds the contract to its provenance: `id`, `contract`,
`contract_hash`, `proposer: PrincipalId`, `branch: BranchId`, `step: StepId`,
`lease: LeaseId`, `phase`, `proposed_at`.

Stage semantics:

1. **propose** (`effect.propose`): the agent submits operation + arguments
   under a lease. The lease `check()` runs here; failure yields a `Denial`.
2. **canonicalize**: the connector validates and canonicalizes arguments; the
   contract and its hash are fixed.
3. **prepare** (`effect.prepare` → `Connector::prepare`): a dry-run against
   the live external system producing a `PreparedEffect { preview,
   observed_preconditions }`. Prepare MUST NOT cause any external side effect.
4. **approve**: policy auto-approval or human approval of the contract hash.
   The decision records the approver, timestamp, and `policy_epoch`.
5. **commit-time revalidation** (§5): immediately before commit, the broker
   re-checks everything. Any failure aborts with a machine-readable reason
   (`StaleAuthorization`, `PreconditionFailed`, `DuplicateCommit`, ...).
6. **commit** (`effect.commit` → `Connector::commit`): the single point where
   the world changes. Produces a `CommitResult { response }` and a signed
   `Receipt`.
7. **abort**: allowed from any pre-commit phase; records a reason.
8. **compensate** (`effect.compensate` → `Connector::compensate`): best-effort
   post-commit reversal for `Compensatable` effects, producing its own
   receipt (`Compensated { compensating_receipt }`). Connectors without
   compensation return `KernelError::Connector("operation is not
   compensatable")`.

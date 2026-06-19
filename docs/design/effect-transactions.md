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

## 5. Commit-time revalidation checklist

Approval decays; the world moves. Immediately before commit the broker MUST
verify all of the following, aborting on any failure:

1. **Contract unchanged**: the `contract_hash` equals the approved hash.
2. **Preconditions hold**: each entry in `contract.preconditions` (e.g.
   `base_head_sha == "abc123"`) matches the live world, re-observed now.
3. **Lease still valid**: not expired, not revoked, uses remaining, branch
   still live — the full `CapabilityLease::check` at commit time.
4. **Policy epoch unchanged**: the current epoch equals the
   `Approved.policy_epoch`; a policy change since approval voids it.
5. **Idempotency key not already committed**: the ledger contains no receipt
   for this `idempotency_key`. Retries of a committed effect MUST return the
   existing receipt, not re-execute (duplicate-commit protection).

## 6. Receipts

```rust
pub struct Receipt {
    pub id: ReceiptId,
    pub body: ReceiptBody,
    pub signature: String,   // Ed25519 over canonical_json(body), hex-encoded
    pub key_id: String,
}

pub struct ReceiptBody {
    pub effect: EffectId,
    pub who: PrincipalId,
    pub operation: String,
    pub resource: String,
    pub contract_hash: ContentHash,
    pub branch: BranchId,
    pub step: StepId,
    pub policy_epoch: u64,
    pub authorization_witness: ContentHash,     // hash of the approval decision
    pub external_response_digest: ContentHash,  // digest of the external response
    pub committed_at: DateTime<Utc>,
}
```

The signature is Ed25519 over the canonical JSON of `body`, signed with the
kernel's receipt key (identified by `key_id`). `authorization_witness` hashes
the approval decision — who approved what, when — making the receipt a proof
of *authorized* execution, not merely execution. Receipts are immutable ledger
facts: they survive branch discard, are never merged or copied, and their
completeness rate is a security metric.

## 7. APIs without a real prepare

Many external APIs cannot dry-run. Strategies, in order of preference:

1. **Draft**: create in a draft/unpublished state; publishing is the commit
   (GitHub draft PRs).
2. **Shadow resource**: create a parallel resource and swap on commit.
3. **Temporary branch**: stage on a scratch branch; the merge/rename is the
   commit.
4. **Escrow**: hand the effect to a holding system that releases on commit.
5. **Single call + idempotency key**: when the API is one-shot, collapse
   prepare/commit into one guarded, deduplicated call.
6. **Explicit `Irreversible` label**: when none of the above applies, the
   contract MUST carry `class: Irreversible` (or `OpaqueExternal`) and clear
   the corresponding stricter approval bar. Pretending is forbidden.

## 8. GET is not automatically pure

HTTP method is not effect semantics: a GET can trigger side effects
(analytics, one-time links, state machines behind "read" endpoints). The
kernel MUST NOT infer `EffectClass` from HTTP verbs. The unit of trust is the
**connector's semantic contract**: each operation's declared class in
`Connector::operations()`. The generic `connectors/http` connector classifies
reads through its proxy conservatively; anything it cannot vouch for is
`OpaqueExternal`.

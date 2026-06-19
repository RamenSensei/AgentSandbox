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

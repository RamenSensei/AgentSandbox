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

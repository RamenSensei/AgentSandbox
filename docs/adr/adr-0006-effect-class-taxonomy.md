# ADR-0006: Six-Class Effect Reversibility Taxonomy

## Status

Accepted

## Date

2026-04-15

## Context

The effect broker must decide, per effect, what safeguards apply: can it run
speculatively on a branch, does it need prepare/preview, does it require
approval, can a failed branch be cleaned up automatically. The naive model is a
boolean: `reversible` or `irreversible`. It collapses distinctions the broker
actually needs. "Reversible" by whom? Rolling back a local file write, invoking
a remote system's true undo, and closing a PR you opened are three different
guarantees with three different failure modes (the compensation itself can
fail; the undo can race with external changes). And a boolean forces a labeling
decision for operations whose semantics nobody knows — the long tail of
arbitrary SaaS APIs — which in practice get optimistically labeled "reversible".

A related trap: inferring purity from HTTP method. GET requests trigger side
effects in the wild constantly (analytics, one-click actions, cache-busting
endpoints, tracking pixels — an email being read is itself irreversible). HTTP
method is not evidence of purity; only a connector's declared semantic contract is.

Alternatives considered: boolean (rejected above); a continuous risk score
(rejected: not deterministic policy input, invites threshold gaming); per-effect
free-text annotations (rejected: not machine-decidable).

## Decision

Every `EffectContract` carries an `EffectClass`, one of six ordered values:

- `pure` — no observable side effect;
- `local_reversible` — undone by rolling back local state;
- `remote_reversible` — the remote system offers a true undo;
- `compensatable` — reversible only via a compensating action (e.g. close the PR);
- `irreversible` — cannot be undone;
- `opaque_external` — semantics unknown; treated as irreversible and maximally
  restricted. This is the mandatory default for any operation without a typed
  connector contract, including all raw HTTP regardless of method.

Classification comes from the connector's contract, never from transport-level
heuristics. The broker keys its lifecycle on the class: `pure`/`local_reversible`
may execute inside a branch; `compensatable` must register its compensation
before commit; `irreversible` and `opaque_external` require the full
propose/prepare/approve/commit path with commit-time revalidation (ADR-0007).

## Consequences

Positive:

- Policy can be written honestly: "sub-agents may commit up to compensatable,
  never irreversible" is expressible and enforceable.
- The `opaque_external` default makes the unknown-API long tail fail closed
  instead of fail open.
- Compensation is a first-class phase (`Compensated { compensating_receipt }`),
  so "undo" leaves its own Receipt.

Negative:

- Connector authors must classify every operation; misclassification is now a
  connector bug with security impact, so connector review must check contracts,
  not just code.
- Six classes still simplify reality (compensation can fail); the broker must
  surface compensation failures rather than report clean rollback.

Follow-ups:

- Conformance tests asserting `opaque_external` for uncontracted operations.
- A connector contract lint that flags GET-implies-pure assumptions.

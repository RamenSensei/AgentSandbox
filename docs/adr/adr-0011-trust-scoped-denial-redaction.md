# ADR-0011: Trust-Scoped Redaction of Machine-Readable Denials

## Status

Accepted

## Date

2026-06-24

## Context

The fourth invariant — no denial without a machine-readable explanation —
exists because `Permission denied, exit code 1` forces an agent to either give
up or interrupt a human. A structured `Denial` (code, attempted operation,
reason, safe alternatives, requestable scopes, escalation flag) lets a benign
agent self-repair: switch to the typed connector, or request a narrower
temporary lease. Autonomous denial recovery rate is a headline metric for the
project.

But rich denials are also an oracle. A quarantined skill or an injected
sub-agent can probe operations systematically and use reasons and requestable-
scope sketches to map the policy surface: which repositories exist, which
constraints are checked, where the enforcement edges are. Full transparency to
every principal converts our best DX feature into reconnaissance tooling.

Alternatives considered: uniform rich denials for all principals (rejected:
policy-map reconnaissance as above); uniform minimal denials (rejected: kills
self-repair, the invariant's whole point); rate-limiting denial detail under
probing (kept as a complement, but rejected as the primary mechanism — it is
heuristic where the principal model is already precise).

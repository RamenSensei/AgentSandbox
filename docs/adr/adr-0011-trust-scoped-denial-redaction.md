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

## Decision

Every denial is machine-readable, and its detail level is a deterministic
function of the requesting principal's `TrustLevel`
(quarantined / untrusted / limited / standard / elevated):

1. All principals, including quarantined ones, receive the `DenialCode`, the
   canonical `attempted_operation`, and `safe_alternatives` — typed operations
   they are *already* allowed to use. Self-redirection is never withheld.
2. Principals below `limited` (quarantined, untrusted) receive a generic
   reason ("operation not permitted for this principal"), no
   `requestable_scopes`, and `escalation_allowed: false`. They learn what they
   may do, not why they may not or what they could request.
3. Principals at `limited` and above receive the full denial: specific reason,
   requestable scope sketches, and the branch's escalation flag.
4. Redaction (`Denial::redact_for`) happens in the kernel before serialization;
   no unredacted denial crosses the boundary to a low-trust principal. Reasons
   must never leak host paths or the policy map at any trust level.

## Consequences

Positive:

- Standard agents keep full self-repair capability; quarantined skills get a
  useful-but-opaque wall, and probing yields near-constant responses.
- The redaction rule is deterministic and unit-testable per trust level, not a
  judgment call per denial site.

Negative:

- Benign code running quarantined (e.g. a new skill in its promotion pipeline)
  recovers less autonomously; that friction is the price of the quarantine and
  an incentive to complete promotion.
- Two-tier responses complicate SDK ergonomics and documentation ("why does my
  denial lack a reason?").

Follow-ups:

- Ledger-based probe detection: dense denial sequences from one principal flag
  for review and can demote trust.
- Audit that every `reason` string in connectors and policy passes the
  no-host-path, no-policy-map lint.

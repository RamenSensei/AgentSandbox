# ADR-0004: Capability Leases, Not Boolean Allow-Lists

## Status

Accepted

## Date

2026-03-24

## Context

Traditional sandbox permissions are boolean and ambient: `allow network`,
`allow /workspace write`, `inject GITHUB_TOKEN` into the environment. For agent
workloads this fails in predictable ways. An injected token is ambient authority —
any process in the guest, including a malicious dependency, can use it for any
operation the token allows, forever. Booleans cannot express "one draft PR
against `main`, from a `sandbox/` head, no merge, within ten minutes". And when
a parent agent spawns a sub-agent or tool, boolean models either duplicate the
full grant or invent ad-hoc inheritance — both violate least privilege, and
neither leaves an audit trail of who delegated what.

Alternatives considered: static allow-lists with wildcards (OpenShell-style
declarative policy) — expressive for paths and domains but stateless, so no use
counting, no expiry, no delegation lineage; OAuth-style scoped tokens per
operation — pushes semantics into each external provider's scope language and
gives us nothing for local operations like `fs.write`.

## Decision

All authority in AgentKernel is carried by `CapabilityLease` objects, checked
deterministically by the kernel. A lease binds:

- a `Principal` and a single namespaced `Operation` (e.g. `github.create_pull_request`);
- parameter `Constraint`s (Equals/OneOf/Glob/Prefix/Max/Forbidden) keyed by
  canonical parameter name;
- a `remaining_uses` count and an `expires_at` time;
- a `ResourceBudget` (CPU, tokens, network, cost);
- optionally a `bound_branch`: authority does not follow the agent across
  speculative branches unless explicitly rebound;
- deterministic `preconditions` revalidated at commit time (ADR-0007).

Delegation is only ever attenuation: `attenuate()` produces a child lease that
must be no broader than the parent on every dimension (constraints must
`narrows()`, uses/expiry/budget must fit), recording `parent_lease` for the
audit chain. There is no ambient authority: no long-lived environment
credentials in the guest (ADR-0010), and every action carries an explicit lease.

## Consequences

Positive:

- Leases are the mechanical form of the "no ambient authority" invariant; a
  stolen lease is worth one constrained operation for a few minutes, not an
  organization-wide token.
- Sub-agent and tool permissions are explicit, attenuated, time-bound,
  branch-bound, revocable and auditable by construction.
- Deterministic `check()` makes every policy decision replayable and testable.

Negative:

- The constraint language is deliberately small; some real policies ("total PR
  count across all leases this episode") need policy-layer aggregation above leases.
- `narrows()` is conservative and rejects unprovable relationships, which can
  force humans to restate constraints in a comparable form.

Follow-ups:

- Lease revocation propagation to attenuated children.
- A capability compiler from semantic requests ("run the tests") to lease sets
  plus backend enforcement (Landlock, seccomp, egress proxy).

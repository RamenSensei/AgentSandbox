# ADR-0009: Branch Merge Is Artifact Merge Only

## Status

Accepted

## Date

2026-05-27

## Context

Branch fork/compare/merge is a core workflow: fork three branches, attempt
three fixes, keep the best. Fork and compare are well-defined over the
content-addressed workspace (ADR-0003). Merge is where a Git analogy becomes
dangerous. Files three-way-merge; almost nothing else in a Branch does:

- **Process memory** from two divergent executions has no meaningful union;
  "merging" heaps or interpreter state is undefined.
- **Browser sessions** carry cookies, auth state and server-side session
  entanglement; combining two profiles is neither safe nor coherent.
- **Capabilities** must not union: a merge that combined each branch's leases
  would be a privilege-escalation primitive — fork twice, get narrow grants on
  each side, merge, hold both. This would break attenuation-only delegation
  (ADR-0004).
- **External effects** must not duplicate: if both branches proposed "create
  the PR", the merged branch must not carry two pending effects for one
  real-world action, and committed Receipts belong to history, not to a
  mergeable set.
- **Observations** may be stale: a fact read on branch A ("CI is green") was
  true in A's timeline at read time, not necessarily at merge time.

Alternatives considered: full-state merge with conflict resolution (rejected:
undefined for memory/sessions, unsafe for authority); forbidding merge entirely
and only allowing "pick one branch, discard the rest" (rejected as the only
option: cherry-picking artifacts from multiple branches is genuinely useful).

## Decision

`branch.merge` merges artifacts and verified local state only:

1. Workspace files merge via three-way Merkle merge from the common ancestor;
   conflicts surface to the agent as structured Observations, never auto-resolved
   silently.
2. Process state, tool sessions and browser state are *not* merged; the merged
   branch starts these fresh (process restart semantics), recorded as such in
   its `ReplayClass`.
3. Capabilities never union. The merged branch's leases are issued anew (or
   explicitly rebound); branch-bound leases from source branches die with them.
4. Pending effects are not copied across a merge; they must be re-proposed on
   the merged branch. Idempotency keys (ADR-0007) guard against duplication of
   anything already committed.
5. Observations carried over are marked with their originating branch and
   timestamp; freshness-sensitive consumers must treat them as potentially stale.

The merge produces a `StateNode` with `parent` and `merge_parent`, keeping the
DAG honest about ancestry.

## Consequences

Positive:

- Merge cannot escalate authority or double-fire external effects by
  construction; the invariants survive N-way search.
- Merge semantics are simple enough to explain and test: files plus provenance,
  nothing else.

Negative:

- Losing process/session state at merge costs warm state (caches, running dev
  servers) and forces re-initialization.
- Re-proposing effects after merge adds a step for agents; SDKs should make
  this ergonomic.

Follow-ups:

- Structured conflict Observations with per-file ancestor/ours/theirs hashes.
- A staleness policy hook so connectors can declare observation TTLs.

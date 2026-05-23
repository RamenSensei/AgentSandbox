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

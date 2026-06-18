# The Capability Model: Leases, Not Booleans

Status: Living document · Applies to: v0.6 · Last updated: 2026-08-12

## 1. Overview

Traditional sandbox permissions are booleans and ambient grants: `allow
network`, `allow /workspace write`, `inject GITHUB_TOKEN`. AgentKernel
replaces them with **capability leases**: time-bound, use-counted, budgeted,
branch-bound, attenuable grants of a single operation to a single principal.
This gives an agent a large autonomous envelope with *zero ambient authority*
(invariant 1). Types are defined in `kernel/core/src/capability.rs`,
`principal.rs`, and `budget.rs`; issuance and policy live in
`kernel/identity` and `kernel/policy`.

## 2. CapabilityLease

```rust
pub struct CapabilityLease {
    pub id: LeaseId,
    pub principal: PrincipalId,
    pub operation: Operation,                       // e.g. "github.create_pull_request"
    pub constraints: IndexMap<String, Constraint>,  // by canonical parameter name
    pub remaining_uses: u32,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub bound_branch: Option<BranchId>,
    pub budget: ResourceBudget,
    pub parent_lease: Option<LeaseId>,              // attenuation lineage
    pub preconditions: IndexMap<String, serde_json::Value>,
    pub revoked: bool,
}
```

- `Operation` is a namespaced string (`fs.write`, `net.http_get`,
  `github.create_pull_request`, `mcp.invoke`); `Operation::namespace()`
  returns the prefix before the first `.`.
- `constraints` uses an `IndexMap` deliberately: iteration order is insertion
  order, so checks and serialization are deterministic.
- `bound_branch`: authority does not follow the agent across speculative
  branches unless explicitly rebound.
- `preconditions` are deterministic assertions about the external world (e.g.
  `{"repo_head_sha": "abc123"}`) revalidated at effect commit time.
- `budget` is a `ResourceBudget` (cpu_ms, memory_bytes, network_bytes,
  tokens, cost_micro_usd, risk_units).

### 2.1 Canonical example: one GitHub PR

The lease that authorizes "create exactly one draft-able PR" and nothing more:

```text
principal:       pr-agent
operation:       github.create_pull_request
constraints:
  repository:    Equals "org/repo"
  base:          Equals "main"
  head:          Prefix "sandbox/"
  merge:         Forbidden
remaining_uses:  1
expires_at:      issued_at + 10 minutes
bound_branch:    br-42
budget:          $0 (cost_micro_usd = 0)
preconditions:   { "repo_head_sha": "abc123" }
```

This is the shape used by `capability.rs`'s own tests: the lease authorizes
`{"repository":"org/repo","base":"main","head":"sandbox/fix-1"}`, and rejects
the same call with `"merge": true` (`ConstraintViolated {parameter:
"merge"}`), on the wrong branch (`WrongBranch`), or one minute late
(`Expired`).

## 3. Constraints and attenuation proof

### 3.1 Constraint kinds

```rust
pub enum Constraint {
    Equals   { value: serde_json::Value }, // exact JSON equality
    OneOf    { values: Vec<serde_json::Value> },
    Glob     { pattern: String },          // '*'-only globs, no regex engine
    Prefix   { prefix: String },           // path/branch scoping
    Max      { max: f64 },                 // numeric upper bound
    Forbidden,                             // absent or JSON false
}
```

`Constraint::allows(value: Option<&Value>) -> bool` evaluates one candidate.
A missing parameter (`None`) satisfies only `Forbidden`. The glob matcher
(`glob_match`) is deterministic and supports only `*` — no regex, no
backtracking surprises.

### 3.2 narrows(): the attenuation relation

`child.narrows(parent)` answers: *is the child at least as restrictive as the
parent for every possible value?* It is conservative — when the relationship
cannot be proven, it MUST return `false`. Provable narrowings:

- identical constraints;
- `Equals{v}` narrows `OneOf`/`Glob`/`Prefix`/`Max` iff `v` satisfies the
  parent;
- `OneOf{values}` narrows any parent iff *every* value satisfies the parent;
- `Prefix{child}` narrows `Prefix{parent}` iff `child` starts with `parent`;
- `Max{child}` narrows `Max{parent}` iff `child <= parent`;
- `Forbidden` narrows everything.

All other pairs (e.g. `Glob` vs `Glob`) are unproven and rejected. This is a
soundness-over-completeness choice: delegation MAY be refused for a
technically-safe narrowing, but MUST NOT be accepted for a widening.

## 4. Deterministic check()

`CapabilityLease::check(principal, operation, params, branch, now)` evaluates
in a fixed order and returns the *first* failure as a `LeaseCheckFailure`:

1. `Revoked`
2. `Expired { expired_at }` (`now >= expires_at`)
3. `Exhausted` (`remaining_uses == 0`)
4. `WrongPrincipal`
5. `WrongOperation { granted }`
6. `WrongBranch { bound }` (only if `bound_branch` is set)
7. `ConstraintViolated { parameter }` — constraints checked in insertion order

The order is normative: implementations MUST report the same failure for the
same inputs, so denials are reproducible and testable. `LeaseCheckFailure`
values map to `DenialCode`s in the structured `Denial` returned to the agent.

## 5. Delegation is attenuation only

`CapabilityLease::attenuate(child, constraints, uses, expires_at, budget,
now)` derives a child lease and fails with a typed `AttenuationError` unless
every dimension is no broader than the parent:

- `ParentUnusable` — parent revoked or expired;
- `UsesExceedParent` — `uses > remaining_uses`;
- `ExpiryExceedsParent`;
- `BudgetExceedsParent` — checked via `ResourceBudget::fits_within`
  (dimension-wise `<=`);
- `ConstraintWidened { parameter }` — every parent constraint MUST be present
  in the child and MUST `narrows()` it.

The child records `parent_lease: Some(parent.id)`, forming an auditable
attenuation chain. Delegation is therefore, by construction:

```text
explicit · attenuated · time-bound · branch-bound · revocable · auditable
```

There is no other delegation path. Sub-agents and tools never implicitly
inherit parental authority.

## 6. Principals and trust

```rust
pub enum PrincipalKind { Agent, SubAgent, Tool, Human, Kernel }
pub enum TrustLevel   { Quarantined, Untrusted, Limited, Standard, Elevated }
```

A `Principal` has `id`, `kind`, `display_name`, optional `parent`, and
`trust`. `Principal::spawn_child(kind, name)` creates a child with `trust =
parent.trust.min(TrustLevel::Limited)` — children are capped at `Limited`
regardless of the parent — and with **no leases**; authority arrives only via
`attenuate`. `TrustLevel` controls the *granularity of policy explanations*
(`Denial::redact_for`, see `threat-model.md`), never whether enforcement
applies.

## 7. The Capability Compiler

Agents request semantic capabilities ("read this repo", "run tests", "create
one PR", "let this sub-agent query prod logs read-only"). The Capability
Compiler (`kernel/policy`) compiles a granted lease into concrete,
deterministic enforcement:

| Semantic dimension | Enforcement mechanism |
|---|---|
| File paths | Landlock/LSM policies; `writable_prefixes` / `readable_prefixes` in `ExecutionRequest` |
| Syscalls | seccomp profiles |
| CPU/memory | cgroup limits from `ResourceBudget` |
| Network | network namespace + egress proxy; `egress_domains` in `ExecutionRequest` |
| Tools/MCP | tool RBAC on `mcp.invoke` constraints |
| External APIs | connector parameter constraints (`Connector::canonicalize` + lease check) |
| Credentials | Secret-broker token exchange (see `secret-broker.md`) |
| Counts, time, budget, risk | `remaining_uses`, `expires_at`, `budget`, `risk_units` |

Backends receive only the compiled confinement — `ExecutionRequest` carries
prefixes, egress domains, and a budget, never leases or secrets.

Normative rule: **intent hints never authorize.** An agent-declared intent MAY
inform scheduling and prewarming; final enforcement MUST be the deterministic
lease check plus compiled confinement. The LLM may explain, request, and
recommend; it MUST NOT issue, self-clear, or bypass.

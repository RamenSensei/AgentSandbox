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

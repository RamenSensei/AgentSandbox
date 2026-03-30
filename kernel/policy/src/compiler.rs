//! The capability compiler: approved semantic grants → lease + confinement.

use crate::document::{PolicyDocument, PolicyRule, RuleEffect};
use crate::error::{PolicyError, PolicyResult};
use ak_core::budget::ResourceBudget;
use ak_core::capability::{CapabilityLease, Constraint, Operation};
use ak_core::ids::{BranchId, LeaseId};
use ak_core::principal::{Principal, TrustLevel};
use chrono::{DateTime, Duration, Utc};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

/// Syscall confinement profile a backend should apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyscallProfile {
    /// Default seccomp profile for trusted workloads.
    Standard,
    /// Tightened profile (no ptrace, no raw sockets, no user namespaces).
    Restricted,
    /// Restricted profile plus all network syscalls blocked.
    Networkless,
}

/// The compiled, backend-facing half of a grant. The fields mirror
/// [`ak_core::traits::ExecutionRequest`]: the scheduler copies
/// `writable_prefixes`, `readable_prefixes` and `egress_domains` straight into
/// the request it hands to a backend.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompiledConfinement {
    /// Workspace-relative prefixes the workload may write.
    pub writable_prefixes: Vec<String>,
    /// Workspace-relative prefixes the workload may read.
    pub readable_prefixes: Vec<String>,
    /// Egress domain allowlist (empty = no network).
    pub egress_domains: Vec<String>,
    /// Whether the backend must scrub the ambient environment (secrets never
    /// reach guests anyway; this removes even innocuous host env).
    pub env_scrub: bool,
    /// Syscall profile the backend applies.
    pub syscall_profile: SyscallProfile,
}

/// A fully compiled grant: the lease (authority) plus the confinement
/// (mechanism). Policy semantics live in the lease; backends only ever see
/// the confinement.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompiledGrant {
    pub lease: CapabilityLease,
    pub confinement: CompiledConfinement,
}

/// Compile the confinement for `principal` under `doc`.
///
/// Deterministic mapping:
/// - path prefixes come from the document's [`crate::PathPolicy`];
/// - egress domains come from the allowlist, except for operations outside
///   the `net`/network-using namespaces on quarantined principals;
/// - `env_scrub` is on for everything below [`TrustLevel::Standard`] and for
///   every non-`Elevated` principal by default;
/// - the syscall profile is [`SyscallProfile::Networkless`] when the egress
///   allowlist is empty, [`SyscallProfile::Restricted`] for principals below
///   [`TrustLevel::Standard`], and [`SyscallProfile::Standard`] otherwise.
pub fn compile_confinement(doc: &PolicyDocument, principal: &Principal) -> CompiledConfinement {
    let egress_domains = if principal.trust <= TrustLevel::Quarantined {
        Vec::new()
    } else {
        doc.egress_domains.clone()
    };
    let syscall_profile = if egress_domains.is_empty() {
        SyscallProfile::Networkless
    } else if principal.trust < TrustLevel::Standard {
        SyscallProfile::Restricted
    } else {
        SyscallProfile::Standard
    };
    CompiledConfinement {
        writable_prefixes: doc.paths.writable_prefixes.clone(),
        readable_prefixes: doc.paths.readable_prefixes.clone(),
        egress_domains,
        env_scrub: principal.trust < TrustLevel::Elevated,
        syscall_profile,
    }
}

/// Compile an approved semantic grant into a [`CompiledGrant`].
///
/// `rule` is the (already matched) policy rule that authorized the grant;
/// `extra_constraints` lets the approver narrow further (e.g. pin the exact
/// repository). Extra constraints may only *add* parameters or replace a rule
/// constraint with one that [`Constraint::narrows`] it — widening is rejected.
pub fn compile_grant(
    doc: &PolicyDocument,
    principal: &Principal,
    operation: &Operation,
    rule: &PolicyRule,
    extra_constraints: &IndexMap<String, Constraint>,
    branch: Option<BranchId>,
    now: DateTime<Utc>,
) -> PolicyResult<CompiledGrant> {
    if rule.effect == RuleEffect::Deny {
        return Err(PolicyError::GrantRejected(format!(
            "rule `{}` is a deny rule and cannot be compiled into a grant",
            rule.id
        )));
    }
    if !rule.matches_operation(&operation.0) {
        return Err(PolicyError::GrantRejected(format!(
            "rule `{}` does not cover operation `{}`",
            rule.id, operation.0
        )));
    }
    let mut constraints = rule.constraints.clone();
    for (param, c) in extra_constraints {
        match rule.constraints.get(param) {
            Some(parent) if !c.narrows(parent) => {
                return Err(PolicyError::GrantRejected(format!(
                    "extra constraint on `{param}` widens the rule constraint"
                )));
            }
            _ => {
                constraints.insert(param.clone(), c.clone());
            }
        }
    }
    let mut budget = rule.budget.unwrap_or_else(ResourceBudget::step_default);
    budget.risk_units = budget.risk_units.max(rule.risk_weight);
    let ttl = Duration::seconds(i64::try_from(rule.ttl_seconds).unwrap_or(i64::MAX));
    let lease = CapabilityLease {
        id: LeaseId::generate(),
        principal: principal.id.clone(),
        operation: operation.clone(),
        constraints,
        remaining_uses: rule.max_uses,
        issued_at: now,
        expires_at: now + ttl,
        bound_branch: branch,
        budget,
        parent_lease: None,
        preconditions: IndexMap::new(),
        revoked: false,
    };
    Ok(CompiledGrant { lease, confinement: compile_confinement(doc, principal) })
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::document::{PathPolicy, PrincipalSelector};
    use serde_json::json;

    fn doc() -> PolicyDocument {
        let mut d = PolicyDocument::default();
        d.set_paths(PathPolicy {
            readable_prefixes: vec!["".into()],
            writable_prefixes: vec!["src/".into(), "tests/".into()],
        });
        d.set_egress_domains(vec!["api.github.com".into()]);
        d
    }

    fn pr_rule() -> PolicyRule {
        let mut constraints = IndexMap::new();
        constraints.insert("repository".into(), Constraint::Equals { value: json!("org/repo") });
        constraints.insert("head".into(), Constraint::Prefix { prefix: "sandbox/".into() });
        PolicyRule {
            id: "pr".into(),
            principals: PrincipalSelector::default(),
            operations: vec!["github.create_pull_request".into()],
            effect: RuleEffect::Allow,
            constraints,
            max_uses: 2,
            ttl_seconds: 900,
            budget: None,
            risk_weight: 5,
            note: None,
        }
    }
    #[test]
    fn compiles_lease_and_confinement_from_rule() {
        let d = doc();
        let p = Principal::new_agent("agent");
        let op = Operation::new("github.create_pull_request");
        let now = Utc::now();
        let grant =
            compile_grant(&d, &p, &op, &pr_rule(), &IndexMap::new(), None, now).unwrap();
        assert_eq!(grant.lease.principal, p.id);
        assert_eq!(grant.lease.operation, op);
        assert_eq!(grant.lease.remaining_uses, 2);
        assert_eq!(grant.lease.expires_at, now + Duration::seconds(900));
        assert_eq!(grant.lease.budget.risk_units, 10); // step_default max risk_weight
        assert_eq!(grant.confinement.writable_prefixes, vec!["src/", "tests/"]);
        assert_eq!(grant.confinement.egress_domains, vec!["api.github.com"]);
        assert_eq!(grant.confinement.syscall_profile, SyscallProfile::Standard);
        assert!(grant.confinement.env_scrub);
    }
}

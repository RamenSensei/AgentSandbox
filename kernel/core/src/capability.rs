//! Capability leases: time-bound, budgeted, attenuable authority.
//!
//! A lease binds a principal to a set of operations on constrained resources,
//! with an expiry, a use count, a budget, and optional preconditions on the
//! external world. Delegation is only ever *attenuation*: a child lease can
//! never grant more than its parent.

use crate::budget::ResourceBudget;
use crate::ids::{BranchId, LeaseId, PrincipalId};
use chrono::{DateTime, Utc};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

/// A namespaced operation, e.g. `fs.write`, `net.http_get`,
/// `github.create_pull_request`, `mcp.invoke`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Operation(pub String);

impl Operation {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
    pub fn namespace(&self) -> &str {
        self.0.split('.').next().unwrap_or("")
    }
}

/// A deterministic constraint on one parameter of an operation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum Constraint {
    /// Parameter must equal this JSON value exactly.
    Equals { value: serde_json::Value },
    /// Parameter must be one of these values.
    OneOf { values: Vec<serde_json::Value> },
    /// String parameter must match this glob (only `*` wildcards).
    Glob { pattern: String },
    /// String parameter must start with this prefix (e.g. path scoping).
    Prefix { prefix: String },
    /// Numeric parameter must be `<= max`.
    Max { max: f64 },
    /// Parameter must be absent or JSON `false`.
    Forbidden,
}

impl Constraint {
    /// Check a candidate value against this constraint. `None` means the
    /// parameter was not supplied.
    pub fn allows(&self, value: Option<&serde_json::Value>) -> bool {
        match self {
            Constraint::Equals { value: want } => value == Some(want),
            Constraint::OneOf { values } => value.map(|v| values.contains(v)).unwrap_or(false),
            Constraint::Glob { pattern } => value
                .and_then(|v| v.as_str())
                .map(|s| glob_match(pattern, s))
                .unwrap_or(false),
            Constraint::Prefix { prefix } => value
                .and_then(|v| v.as_str())
                .map(|s| s.starts_with(prefix.as_str()))
                .unwrap_or(false),
            Constraint::Max { max } => value
                .and_then(|v| v.as_f64())
                .map(|n| n <= *max)
                .unwrap_or(false),
            Constraint::Forbidden => {
                matches!(value, None | Some(serde_json::Value::Bool(false)))
            }
        }
    }

    /// Is `self` at least as restrictive as `parent` for every possible value?
    /// Used to verify attenuation. Conservative: returns `false` when the
    /// relationship cannot be proven.
    pub fn narrows(&self, parent: &Constraint) -> bool {
        use Constraint::*;
        match (self, parent) {
            (a, b) if a == b => true,
            (Equals { value }, OneOf { values }) => values.contains(value),
            (Equals { value }, Glob { pattern }) => value
                .as_str()
                .map(|s| glob_match(pattern, s))
                .unwrap_or(false),
            (Equals { value }, Prefix { prefix }) => value
                .as_str()
                .map(|s| s.starts_with(prefix.as_str()))
                .unwrap_or(false),
            (Equals { value }, Max { max }) => value.as_f64().map(|n| n <= *max).unwrap_or(false),
            (OneOf { values }, parent) => values
                .iter()
                .all(|v| parent.allows(Some(v))),
            (Prefix { prefix: child }, Prefix { prefix: parent_p }) => child.starts_with(parent_p.as_str()),
            (Max { max: child }, Max { max: parent_m }) => child <= parent_m,
            (Forbidden, _) => true,
            _ => false,
        }
    }
}

/// Simple `*`-only glob matcher (deterministic, no regex engine).
pub fn glob_match(pattern: &str, input: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return pattern == input;
    }
    let mut rest = input;
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        if i == 0 {
            match rest.strip_prefix(part) {
                Some(r) => rest = r,
                None => return false,
            }
        } else if i == parts.len() - 1 {
            return rest.ends_with(part);
        } else {
            match rest.find(part) {
                Some(pos) => rest = &rest[pos + part.len()..],
                None => return false,
            }
        }
    }
    parts.last().map(|p| p.is_empty()).unwrap_or(false) || parts.len() == 1
}

/// A grant of bounded authority to one principal.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CapabilityLease {
    pub id: LeaseId,
    pub principal: PrincipalId,
    pub operation: Operation,
    /// Constraints keyed by canonical parameter name.
    pub constraints: IndexMap<String, Constraint>,
    /// Remaining invocation count.
    pub remaining_uses: u32,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    /// Branch this lease is bound to, if any: authority does not follow the
    /// agent across speculative branches unless explicitly rebound.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bound_branch: Option<BranchId>,
    pub budget: ResourceBudget,
    /// Lease this one was attenuated from, for the audit chain.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_lease: Option<LeaseId>,
    /// Deterministic preconditions revalidated at commit time,
    /// e.g. `{"repo_head_sha": "abc123"}`.
    #[serde(default, skip_serializing_if = "IndexMap::is_empty")]
    pub preconditions: IndexMap<String, serde_json::Value>,
    pub revoked: bool,
}

/// Why a lease does not authorize a given invocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "reason")]
pub enum LeaseCheckFailure {
    Revoked,
    Expired { expired_at: DateTime<Utc> },
    Exhausted,
    WrongPrincipal,
    WrongOperation { granted: Operation },
    WrongBranch { bound: BranchId },
    ConstraintViolated { parameter: String },
}

impl CapabilityLease {
    /// Deterministically check whether this lease authorizes `principal` to
    /// invoke `operation` with `params` on `branch` at time `now`.
    pub fn check(
        &self,
        principal: &PrincipalId,
        operation: &Operation,
        params: &serde_json::Value,
        branch: Option<&BranchId>,
        now: DateTime<Utc>,
    ) -> Result<(), LeaseCheckFailure> {
        if self.revoked {
            return Err(LeaseCheckFailure::Revoked);
        }
        if now >= self.expires_at {
            return Err(LeaseCheckFailure::Expired { expired_at: self.expires_at });
        }
        if self.remaining_uses == 0 {
            return Err(LeaseCheckFailure::Exhausted);
        }
        if &self.principal != principal {
            return Err(LeaseCheckFailure::WrongPrincipal);
        }
        if &self.operation != operation {
            return Err(LeaseCheckFailure::WrongOperation { granted: self.operation.clone() });
        }
        if let Some(bound) = &self.bound_branch {
            if branch != Some(bound) {
                return Err(LeaseCheckFailure::WrongBranch { bound: bound.clone() });
            }
        }
        for (param, constraint) in &self.constraints {
            if !constraint.allows(params.get(param)) {
                return Err(LeaseCheckFailure::ConstraintViolated { parameter: param.clone() });
            }
        }
        Ok(())
    }

    /// Derive an attenuated lease for a child principal. Fails unless every
    /// dimension (constraints, uses, expiry, budget) is no broader than the
    /// parent's. Delegation is explicit, attenuated, time-bound and auditable.
    pub fn attenuate(
        &self,
        child: PrincipalId,
        constraints: IndexMap<String, Constraint>,
        uses: u32,
        expires_at: DateTime<Utc>,
        budget: ResourceBudget,
        now: DateTime<Utc>,
    ) -> Result<CapabilityLease, AttenuationError> {
        if self.revoked || now >= self.expires_at {
            return Err(AttenuationError::ParentUnusable);
        }
        if uses > self.remaining_uses {
            return Err(AttenuationError::UsesExceedParent);
        }
        if expires_at > self.expires_at {
            return Err(AttenuationError::ExpiryExceedsParent);
        }
        if !budget.fits_within(&self.budget) {
            return Err(AttenuationError::BudgetExceedsParent);
        }
        // Every parent constraint must be present and narrowed (or identical).
        for (param, parent_c) in &self.constraints {
            match constraints.get(param) {
                Some(child_c) if child_c.narrows(parent_c) => {}
                _ => {
                    return Err(AttenuationError::ConstraintWidened { parameter: param.clone() })
                }
            }
        }
        Ok(CapabilityLease {
            id: LeaseId::generate(),
            principal: child,
            operation: self.operation.clone(),
            constraints,
            remaining_uses: uses,
            issued_at: now,
            expires_at,
            bound_branch: self.bound_branch.clone(),
            budget,
            parent_lease: Some(self.id.clone()),
            preconditions: self.preconditions.clone(),
            revoked: false,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "error")]
pub enum AttenuationError {
    #[error("parent lease is revoked or expired")]
    ParentUnusable,
    #[error("child use count exceeds parent's remaining uses")]
    UsesExceedParent,
    #[error("child expiry exceeds parent expiry")]
    ExpiryExceedsParent,
    #[error("child budget exceeds parent budget")]
    BudgetExceedsParent,
    #[error("constraint on `{parameter}` is wider than the parent's")]
    ConstraintWidened { parameter: String },
}
#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use serde_json::json;

    fn lease(now: DateTime<Utc>) -> CapabilityLease {
        let mut constraints = IndexMap::new();
        constraints.insert("repository".into(), Constraint::Equals { value: json!("org/repo") });
        constraints.insert("base".into(), Constraint::Equals { value: json!("main") });
        constraints.insert(
            "head".into(),
            Constraint::Prefix { prefix: "sandbox/".into() },
        );
        constraints.insert("merge".into(), Constraint::Forbidden);
        CapabilityLease {
            id: LeaseId::generate(),
            principal: PrincipalId("pr-agent".into()),
            operation: Operation::new("github.create_pull_request"),
            constraints,
            remaining_uses: 1,
            issued_at: now,
            expires_at: now + Duration::minutes(10),
            bound_branch: Some(BranchId("br-42".into())),
            budget: ResourceBudget::default(),
            parent_lease: None,
            preconditions: IndexMap::new(),
            revoked: false,
        }
    }
    #[test]
    fn lease_authorizes_exact_pr_and_nothing_wider() {
        let now = Utc::now();
        let l = lease(now);
        let ok = json!({"repository": "org/repo", "base": "main", "head": "sandbox/fix-1"});
        assert!(l
            .check(&l.principal, &l.operation, &ok, Some(&BranchId("br-42".into())), now)
            .is_ok());

        let merge = json!({"repository": "org/repo", "base": "main", "head": "sandbox/fix-1", "merge": true});
        assert_eq!(
            l.check(&l.principal, &l.operation, &merge, Some(&BranchId("br-42".into())), now),
            Err(LeaseCheckFailure::ConstraintViolated { parameter: "merge".into() })
        );

        let wrong_branch = l.check(&l.principal, &l.operation, &ok, Some(&BranchId("br-7".into())), now);
        assert!(matches!(wrong_branch, Err(LeaseCheckFailure::WrongBranch { .. })));

        let expired = l.check(&l.principal, &l.operation, &ok, Some(&BranchId("br-42".into())), now + Duration::minutes(11));
        assert!(matches!(expired, Err(LeaseCheckFailure::Expired { .. })));
    }
}

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

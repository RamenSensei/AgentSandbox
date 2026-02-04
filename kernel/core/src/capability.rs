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

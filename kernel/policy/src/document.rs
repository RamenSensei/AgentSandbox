//! The typed, declarative [`PolicyDocument`] and its YAML representation.

use crate::error::{PolicyError, PolicyResult};
use ak_core::budget::ResourceBudget;
use ak_core::capability::{glob_match, Constraint};
use ak_core::ids::PrincipalId;
use ak_core::principal::{Principal, PrincipalKind, TrustLevel};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Selects which principals a rule applies to. All present fields must match
/// (conjunctive); an empty selector matches every principal.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrincipalSelector {
    /// Match by exact principal ids.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ids: Vec<PrincipalId>,
    /// Match by principal kind.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub kinds: Vec<PrincipalKind>,
    /// Minimum trust level (inclusive).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_trust: Option<TrustLevel>,
    /// Maximum trust level (inclusive); used to target low-trust principals.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_trust: Option<TrustLevel>,
}

impl PrincipalSelector {
    /// Whether this selector matches `principal`.
    pub fn matches(&self, principal: &Principal) -> bool {
        if !self.ids.is_empty() && !self.ids.contains(&principal.id) {
            return false;
        }
        if !self.kinds.is_empty() && !self.kinds.contains(&principal.kind) {
            return false;
        }
        if let Some(min) = self.min_trust {
            if principal.trust < min {
                return false;
            }
        }
        if let Some(max) = self.max_trust {
            if principal.trust > max {
                return false;
            }
        }
        true
    }
}

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

/// The outcome a matching rule produces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleEffect {
    /// Grant, subject to the rule's constraints, uses, TTL and budget.
    Allow,
    /// Refuse outright.
    Deny,
    /// Grant only after out-of-band approval (usually human).
    RequireApproval,
}

/// One declarative policy rule. Rules are evaluated **in document order**;
/// the first rule whose selector and operation glob match decides.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRule {
    /// Stable rule id, referenced in audit records.
    pub id: String,
    /// Which principals this rule applies to.
    #[serde(default)]
    pub principals: PrincipalSelector,
    /// Operation globs (`*` wildcards, matched with
    /// [`ak_core::capability::glob_match`]), e.g. `fs.*` or
    /// `github.create_pull_request`.
    pub operations: Vec<String>,
    /// What happens when this rule matches.
    pub effect: RuleEffect,
    /// Parameter constraints applied to the invocation and copied into
    /// compiled leases. Keyed by canonical parameter name.
    #[serde(default, skip_serializing_if = "IndexMap::is_empty")]
    pub constraints: IndexMap<String, Constraint>,
    /// Use count for leases compiled from this rule (default 1).
    #[serde(default = "default_max_uses")]
    pub max_uses: u32,
    /// Lease TTL in seconds (default 600).
    #[serde(default = "default_ttl_seconds")]
    pub ttl_seconds: u64,
    /// Budget cap for compiled leases; defaults to
    /// [`ResourceBudget::step_default`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget: Option<ResourceBudget>,
    /// Abstract risk weight charged per use (informs `risk_units`).
    #[serde(default)]
    pub risk_weight: u32,
    /// Optional human-facing note; never used in evaluation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

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

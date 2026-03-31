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

fn default_max_uses() -> u32 {
    1
}
fn default_ttl_seconds() -> u64 {
    600
}

impl PolicyRule {
    /// Whether this rule's operation globs cover `operation`.
    pub fn matches_operation(&self, operation: &str) -> bool {
        self.operations.iter().any(|g| glob_match(g, operation))
    }
}

/// Workspace-relative path prefixes the branch may touch.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathPolicy {
    #[serde(default)]
    pub readable_prefixes: Vec<String>,
    #[serde(default)]
    pub writable_prefixes: Vec<String>,
}

/// Which MCP servers/tools may be invoked (glob patterns on
/// `server` and `tool` names). Empty lists mean "none".
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolPolicy {
    #[serde(default)]
    pub allowed_servers: Vec<String>,
    #[serde(default)]
    pub allowed_tools: Vec<String>,
}

/// A scope principals may *request* when denied, sketching the constraints
/// policy would consider.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestableScopeSpec {
    /// Operation glob this scope covers.
    pub operation: String,
    /// Constraint sketch shown to the requester.
    #[serde(default)]
    pub constraints: serde_json::Value,
    /// Whether granting requires a human in the loop.
    #[serde(default)]
    pub requires_human: bool,
}

/// Whether and how principals may request capability escalation.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EscalationPolicy {
    /// Master switch: when false, denials advertise no requestable scopes.
    #[serde(default)]
    pub allow_requests: bool,
    /// Scopes that may be requested.
    #[serde(default)]
    pub requestable: Vec<RequestableScopeSpec>,
}

/// The complete declarative policy for a kernel instance.
///
/// The document is deterministic data: evaluation depends only on it and the
/// five explicit inputs of [`crate::PolicyEngine::evaluate`]. `policy_epoch`
/// bumps on **every** mutation, so approvals pinned to an epoch are invalidated
/// by any policy change.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyDocument {
    /// Monotonic epoch, bumped by every mutating call.
    #[serde(default)]
    pub policy_epoch: u64,
    /// Ordered rules; first match wins.
    #[serde(default)]
    pub rules: Vec<PolicyRule>,
    /// Path confinement compiled into every grant.
    #[serde(default)]
    pub paths: PathPolicy,
    /// Egress domain allowlist (glob patterns, e.g. `*.github.com`).
    #[serde(default)]
    pub egress_domains: Vec<String>,
    /// MCP tool policy.
    #[serde(default)]
    pub tools: ToolPolicy,
    /// Escalation policy.
    #[serde(default)]
    pub escalation: EscalationPolicy,
}

impl Default for PolicyDocument {
    fn default() -> Self {
        Self {
            policy_epoch: 0,
            rules: Vec::new(),
            paths: PathPolicy::default(),
            egress_domains: Vec::new(),
            tools: ToolPolicy::default(),
            escalation: EscalationPolicy::default(),
        }
    }
}

impl PolicyDocument {
    /// Parse a document from YAML text and validate it.
    pub fn from_yaml_str(yaml: &str) -> PolicyResult<Self> {
        let doc: PolicyDocument = serde_yaml::from_str(yaml)?;
        doc.validate()?;
        Ok(doc)
    }

    /// Load and validate a document from a YAML file.
    pub fn from_yaml_file(path: impl AsRef<Path>) -> PolicyResult<Self> {
        Self::from_yaml_str(&std::fs::read_to_string(path)?)
    }

    /// Serialize back to YAML.
    pub fn to_yaml(&self) -> PolicyResult<String> {
        Ok(serde_yaml::to_string(self)?)
    }

    /// Semantic validation beyond what serde enforces.
    pub fn validate(&self) -> PolicyResult<()> {
        let mut seen = std::collections::HashSet::new();
        for rule in &self.rules {
            if rule.operations.is_empty() {
                return Err(PolicyError::Invalid(format!(
                    "rule `{}` has no operation globs",
                    rule.id
                )));
            }
            if !seen.insert(rule.id.as_str()) {
                return Err(PolicyError::Invalid(format!("duplicate rule id `{}`", rule.id)));
            }
        }
        Ok(())
    }

    /// Append a rule, bumping the epoch.
    pub fn add_rule(&mut self, rule: PolicyRule) -> PolicyResult<()> {
        if self.rules.iter().any(|r| r.id == rule.id) {
            return Err(PolicyError::Invalid(format!("duplicate rule id `{}`", rule.id)));
        }
        self.rules.push(rule);
        self.bump_epoch();
        Ok(())
    }

    /// Remove a rule by id, bumping the epoch. Returns whether it existed.
    pub fn remove_rule(&mut self, id: &str) -> bool {
        let before = self.rules.len();
        self.rules.retain(|r| r.id != id);
        let removed = self.rules.len() != before;
        if removed {
            self.bump_epoch();
        }
        removed
    }

    /// Replace the path policy, bumping the epoch.
    pub fn set_paths(&mut self, paths: PathPolicy) {
        self.paths = paths;
        self.bump_epoch();
    }

    /// Replace the egress allowlist, bumping the epoch.
    pub fn set_egress_domains(&mut self, domains: Vec<String>) {
        self.egress_domains = domains;
        self.bump_epoch();
    }

    /// Replace the escalation policy, bumping the epoch.
    pub fn set_escalation(&mut self, escalation: EscalationPolicy) {
        self.escalation = escalation;
        self.bump_epoch();
    }

    fn bump_epoch(&mut self) {
        self.policy_epoch += 1;
    }

    /// Whether `domain` is covered by the egress allowlist.
    pub fn egress_allows(&self, domain: &str) -> bool {
        self.egress_domains.iter().any(|g| glob_match(g, domain))
    }
}

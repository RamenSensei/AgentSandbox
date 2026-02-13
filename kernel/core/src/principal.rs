//! Principals: agents, sub-agents, tools and humans as first-class identities.
//!
//! A principal is the unit of authorization. Sub-agents and delegated tools are
//! *distinct* principals; they never implicitly inherit their parent's
//! authority (invariant: no ambient authority).

use crate::ids::PrincipalId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalKind {
    /// A top-level agent driven by a harness.
    Agent,
    /// A sub-agent spawned by another agent.
    SubAgent,
    /// A tool or MCP server invoked on behalf of an agent.
    Tool,
    /// A human operator (approvals, overrides).
    Human,
    /// The kernel itself (system maintenance actions).
    Kernel,
}

/// How much the kernel trusts a principal. Trust controls the *granularity of
/// policy explanations* (a quarantined skill gets less detail than the primary
/// agent) — never whether enforcement applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustLevel {
    Quarantined,
    Untrusted,
    Limited,
    Standard,
    Elevated,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Principal {
    pub id: PrincipalId,
    pub kind: PrincipalKind,
    /// Human-readable name, e.g. `coding-agent/fix-issue-42`.
    pub display_name: String,
    /// Parent principal, if this principal was spawned by another.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent: Option<PrincipalId>,
    pub trust: TrustLevel,
}

impl Principal {
    pub fn new_agent(display_name: impl Into<String>) -> Self {
        Self {
            id: PrincipalId::generate(),
            kind: PrincipalKind::Agent,
            display_name: display_name.into(),
            parent: None,
            trust: TrustLevel::Standard,
        }
    }

    /// Spawn a child principal. The child starts at a trust level no higher
    /// than its parent and with *no* leases; authority must be delegated
    /// explicitly via [`crate::capability::CapabilityLease::attenuate`].
    pub fn spawn_child(&self, kind: PrincipalKind, display_name: impl Into<String>) -> Self {
        Self {
            id: PrincipalId::generate(),
            kind,
            display_name: display_name.into(),
            parent: Some(self.id.clone()),
            trust: self.trust.min(TrustLevel::Limited),
        }
    }
}

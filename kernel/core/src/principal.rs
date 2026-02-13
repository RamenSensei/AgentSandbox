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

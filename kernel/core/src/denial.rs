//! Machine-readable denials: a policy rejection is a high-quality observation
//! that a well-behaved agent can recover from without human interruption.

use crate::capability::Operation;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DenialCode {
    CapabilityDenied,
    CapabilityExpired,
    CapabilityExhausted,
    BudgetExhausted,
    ConstraintViolated,
    BranchMismatch,
    EffectRequiresApproval,
    StaleAuthorization,
    PreconditionFailed,
    DuplicateCommit,
    BackendUnavailable,
    PolicyForbidden,
}

/// A scope the agent may request to unblock itself.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RequestableScope {
    pub operation: Operation,
    /// Constraint sketch the policy would consider, e.g.
    /// `{"repository": "org/repo", "max_count": 1}`.
    pub constraints: serde_json::Value,
    /// Whether granting this requires a human in the loop.
    pub requires_human: bool,
}

/// The structured denial returned instead of a bare `Permission denied`.
///
/// The level of detail is calibrated by the caller's
/// [`crate::principal::TrustLevel`]: quarantined principals receive the code
/// and safe alternatives but not scope sketches or reasons that would map the
/// policy surface.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Denial {
    pub code: DenialCode,
    /// What the principal attempted, in canonical operation form.
    pub attempted_operation: Operation,
    /// Human- and agent-readable reason. Must help a benign agent repair
    /// itself without leaking host paths or the full policy map.
    pub reason: String,
    /// Typed operations the agent is *already* allowed to use instead.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub safe_alternatives: Vec<Operation>,
    /// Narrow scopes the agent could request.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requestable_scopes: Vec<RequestableScope>,
    /// Whether this branch permits capability escalation requests at all.
    pub escalation_allowed: bool,
}

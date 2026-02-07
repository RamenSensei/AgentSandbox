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

impl Denial {
    /// Redact details not appropriate for low-trust principals.
    pub fn redact_for(&self, trust: crate::principal::TrustLevel) -> Denial {
        use crate::principal::TrustLevel;
        if trust >= TrustLevel::Limited {
            return self.clone();
        }
        Denial {
            code: self.code,
            attempted_operation: self.attempted_operation.clone(),
            reason: "operation not permitted for this principal".into(),
            safe_alternatives: self.safe_alternatives.clone(),
            requestable_scopes: Vec::new(),
            escalation_allowed: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::principal::TrustLevel;

    fn denial() -> Denial {
        Denial {
            code: DenialCode::CapabilityDenied,
            attempted_operation: Operation::new("net.raw_socket"),
            reason: "credential may only be used by the typed GitHub connector".into(),
            safe_alternatives: vec![Operation::new("github.create_pull_request")],
            requestable_scopes: vec![RequestableScope {
                operation: Operation::new("net.http_read"),
                constraints: serde_json::json!({"domain": "api.github.com"}),
                requires_human: false,
            }],
            escalation_allowed: true,
        }
    }

    #[test]
    fn quarantined_principals_get_redacted_denials() {
        let d = denial();
        let r = d.redact_for(TrustLevel::Quarantined);
        assert!(r.requestable_scopes.is_empty());
        assert!(!r.escalation_allowed);
        assert_eq!(r.safe_alternatives, d.safe_alternatives);
        // Standard principals see everything.
        assert_eq!(d.redact_for(TrustLevel::Standard), d);
    }
}

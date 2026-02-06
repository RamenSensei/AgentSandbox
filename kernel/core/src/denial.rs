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

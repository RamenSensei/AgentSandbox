//! The deterministic [`PolicyEngine`].

use crate::compiler::{compile_grant, CompiledGrant};
use crate::document::{PolicyDocument, RuleEffect};
use ak_core::capability::{glob_match, Operation};
use ak_core::denial::{Denial, DenialCode, RequestableScope};
use ak_core::ids::BranchId;
use ak_core::principal::Principal;
use chrono::{DateTime, Utc};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

/// The outcome of a policy evaluation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "decision")]
pub enum Decision {
    /// The operation is allowed. Carries the compiled lease + confinement,
    /// ready for the scheduler.
    Allow {
        /// Id of the rule that granted.
        rule_id: String,
        /// Compiled grant (lease + backend confinement).
        grant: CompiledGrant,
    },
    /// The operation is allowed only with out-of-band approval. The caller
    /// should surface the sketch to an approver, then call
    /// [`crate::compile_grant`] with the approved rule.
    RequireApproval {
        /// Id of the rule that requires approval.
        rule_id: String,
        /// The operation awaiting approval.
        operation: Operation,
        /// The constraint sketch the approver is signing off on.
        constraints: serde_json::Value,
        /// Policy epoch at evaluation time; approvals are pinned to it.
        policy_epoch: u64,
    },
    /// The operation is denied. The [`Denial`] is already redacted for the
    /// requesting principal's trust level.
    Deny {
        /// Machine-readable, trust-redacted denial.
        denial: Denial,
    },
}

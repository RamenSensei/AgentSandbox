//! External effects: proposed changes to the real world, their transaction
//! lifecycle, and non-repudiable receipts.
//!
//! OS snapshots are not a transaction for the external world. Anything that
//! leaves the sandbox goes through: propose → canonicalize → prepare →
//! authorize → commit-time revalidation → commit → signed receipt.

use crate::hash::{hash_canonical, ContentHash};
use crate::ids::{BranchId, EffectId, LeaseId, PrincipalId, ReceiptId, StepId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Honest classification of an effect's reversibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectClass {
    /// No observable side effect.
    Pure,
    /// Reversible by rolling back local state.
    LocalReversible,
    /// The remote system offers a true undo.
    RemoteReversible,
    /// Reversible only via a compensating action (e.g. close the PR).
    Compensatable,
    /// Cannot be undone (e.g. an email that has been read).
    Irreversible,
    /// Semantics unknown; treated as irreversible and maximally restricted.
    OpaqueExternal,
}

/// Lifecycle of a pending effect.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "phase")]
pub enum EffectPhase {
    Proposed,
    Prepared { preview: serde_json::Value },
    Approved { approver: PrincipalId, approved_at: DateTime<Utc>, policy_epoch: u64 },
    /// Claimed by exactly one committer; the external call is (or may be)
    /// in flight. An effect stuck here after a crash is **in doubt** until
    /// the connector's idempotency protocol resolves what really happened.
    Committing { claimed_at: DateTime<Utc> },
    Committed { receipt: ReceiptId },
    Aborted { reason: String },
    Compensated { compensating_receipt: ReceiptId },
}

/// The canonical, immutable description of what will be done to the world.
/// The hash of this structure is what humans approve and what commit-time
/// revalidation re-checks — approving an effect means approving *exactly* this.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EffectContract {
    /// e.g. `github.create_pull_request`.
    pub operation: String,
    /// Target resource, e.g. `org/repo`.
    pub resource: String,
    /// Full canonical arguments.
    pub arguments: serde_json::Value,
    /// Deterministic preconditions on the external world, revalidated at
    /// commit, e.g. `{"base_head_sha": "abc123"}`.
    pub preconditions: serde_json::Value,
    /// Exactly-once key: `episode-<n>-step-<m>` by convention.
    pub idempotency_key: String,
    pub class: EffectClass,
}

impl EffectContract {
    pub fn contract_hash(&self) -> ContentHash {
        hash_canonical(self)
    }
}

/// A pending (not yet committed) external effect.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PendingEffect {
    pub id: EffectId,
    pub contract: EffectContract,
    pub contract_hash: ContentHash,
    pub proposer: PrincipalId,
    pub branch: BranchId,
    pub step: StepId,
    pub lease: LeaseId,
    pub phase: EffectPhase,
    pub proposed_at: DateTime<Utc>,
}

impl PendingEffect {
    pub fn new(
        contract: EffectContract,
        proposer: PrincipalId,
        branch: BranchId,
        step: StepId,
        lease: LeaseId,
        now: DateTime<Utc>,
    ) -> Self {
        let contract_hash = contract.contract_hash();
        Self {
            id: EffectId::generate(),
            contract,
            contract_hash,
            proposer,
            branch,
            step,
            lease,
            phase: EffectPhase::Proposed,
            proposed_at: now,
        }
    }
}

/// A non-repudiable record of a committed effect. Signed by the kernel's
/// receipt key; the signature covers the canonical JSON of `body`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Receipt {
    pub id: ReceiptId,
    pub body: ReceiptBody,
    /// Ed25519 signature over `canonical_json(body)`, hex-encoded.
    pub signature: String,
    /// Identifier of the signing key.
    pub key_id: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReceiptBody {
    pub effect: EffectId,
    pub who: PrincipalId,
    pub operation: String,
    pub resource: String,
    pub contract_hash: ContentHash,
    pub branch: BranchId,
    pub step: StepId,
    pub policy_epoch: u64,
    /// Hash of the approval decision (who approved what, when).
    pub authorization_witness: ContentHash,
    /// Digest of the external system's response.
    pub external_response_digest: ContentHash,
    pub committed_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn contract() -> EffectContract {
        EffectContract {
            operation: "github.create_pull_request".into(),
            resource: "org/repo".into(),
            arguments: json!({"base": "main", "head": "sandbox/fix", "draft": true}),
            preconditions: json!({"base_head_sha": "abc123"}),
            idempotency_key: "ep-7-step-98".into(),
            class: EffectClass::Compensatable,
        }
    }

    #[test]
    fn contract_hash_is_stable_and_content_sensitive() {
        let a = contract();
        let mut b = contract();
        assert_eq!(a.contract_hash(), b.contract_hash());
        b.arguments = json!({"base": "main", "head": "sandbox/fix", "draft": false});
        assert_ne!(a.contract_hash(), b.contract_hash());
    }

    #[test]
    fn effect_class_orders_by_severity() {
        assert!(EffectClass::Pure < EffectClass::Irreversible);
        assert!(EffectClass::Irreversible < EffectClass::OpaqueExternal);
    }
}

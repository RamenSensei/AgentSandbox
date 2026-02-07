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

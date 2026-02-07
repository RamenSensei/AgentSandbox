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

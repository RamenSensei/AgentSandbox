//! The [`EffectBroker`]: registry of connectors, durable store of pending
//! effects and receipts, and enforcer of the commit-time revalidation rules.

use ak_core::effect::{EffectContract, EffectPhase, PendingEffect, Receipt, ReceiptBody};
use ak_core::hash::{canonical_json, hash_canonical, ContentHash};
use ak_core::ids::{BranchId, EffectId, LeaseId, PrincipalId, ReceiptId, StepId};
use ak_core::traits::{CommitResult, Connector, PreparedEffect};
use ak_core::{EffectClass, KernelError, KernelResult};
use chrono::Utc;
use rusqlite::{params, Connection, OptionalExtension};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tracing::{info, instrument, warn};

/// Signs the canonical JSON of a [`ReceiptBody`]. Implemented by the
/// kernel-identity crate's Ed25519 keypair (or a test signer) without this
/// crate depending on it.
pub trait ReceiptSigner: Send + Sync {
    /// Sign `message`, returning `(signature_hex, key_id)`.
    fn sign(&self, message: &[u8]) -> (String, String);
}

impl<F> ReceiptSigner for F
where
    F: Fn(&[u8]) -> (String, String) + Send + Sync,
{
    fn sign(&self, message: &[u8]) -> (String, String) {
        self(message)
    }
}

/// Approval record stored alongside an effect; hashed into the receipt as the
/// `authorization_witness`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct ApprovalRecord {
    approver: PrincipalId,
    approved_at: chrono::DateTime<chrono::Utc>,
    policy_epoch: u64,
    /// Contract hash the approver saw. Commit refuses if the effect's hash
    /// has changed since.
    contract_hash: ContentHash,
}

/// The transactional effect broker. See the crate-level docs for the
/// lifecycle it enforces.
pub struct EffectBroker {
    connectors: Mutex<HashMap<String, Arc<dyn Connector>>>,
    store: Mutex<Connection>,
    signer: Box<dyn ReceiptSigner>,
}

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

impl std::fmt::Debug for EffectBroker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EffectBroker").finish_non_exhaustive()
    }
}

fn storage_err(e: rusqlite::Error) -> KernelError {
    KernelError::Storage(e.to_string())
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS effects (
    id TEXT PRIMARY KEY,
    idempotency_key TEXT NOT NULL,
    json TEXT NOT NULL,
    observed_preconditions TEXT,
    approval TEXT
);
CREATE INDEX IF NOT EXISTS idx_effects_idem ON effects(idempotency_key);
CREATE TABLE IF NOT EXISTS receipts (
    id TEXT PRIMARY KEY,
    effect_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    compensating INTEGER NOT NULL DEFAULT 0,
    json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_receipts_idem ON receipts(idempotency_key);
";

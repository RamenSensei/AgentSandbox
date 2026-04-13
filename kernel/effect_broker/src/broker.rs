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

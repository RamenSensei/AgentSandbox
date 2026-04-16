//! The secret broker: named credentials that are readable **only** on
//! host-side connector code paths.
//!
//! ## Invariant: no raw credential ever enters the guest
//!
//! - [`SecretVault`] implements neither `Serialize` nor `Clone`-into-guest
//!   paths; its `Debug` output is redacted.
//! - The only read API is [`SecretVault::with_secret`], which lends the
//!   secret to a closure and never returns an owned handle that could be
//!   stored in a `PendingEffect`, `Receipt`, observation, or ledger entry.
//! - For tools that genuinely need a network credential, mint a *single-use
//!   scoped token* ([`SecretVault::mint_scoped_token`]): a random opaque
//!   token with a TTL and exactly one redemption. The guest sees only the
//!   opaque token, never the underlying credential; the host connector
//!   redeems it once via [`SecretVault::redeem_scoped_token`].

use ak_core::{KernelError, KernelResult};
use chrono::{DateTime, Duration, Utc};
use rand::RngCore;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;
use tracing::{info, instrument};

/// A minted single-use token: guest-visible handle to a vault secret.
#[derive(Debug, Clone)]
pub struct ScopedToken {
    /// The opaque random token string handed to the guest.
    pub token: String,
    /// When the token stops being redeemable.
    pub expires_at: DateTime<Utc>,
}

struct TokenState {
    secret_name: String,
    expires_at: DateTime<Utc>,
}

/// In-memory (optionally file-backed) store of named secrets.
///
/// File-backed vaults persist as JSON with `0600` permissions. See the module
/// docs for the exposure invariant.
pub struct SecretVault {
    secrets: Mutex<HashMap<String, String>>,
    tokens: Mutex<HashMap<String, TokenState>>,
    path: Option<PathBuf>,
}

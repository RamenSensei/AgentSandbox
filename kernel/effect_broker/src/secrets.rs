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

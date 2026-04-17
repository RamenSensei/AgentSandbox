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

impl std::fmt::Debug for SecretVault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let n = self.secrets.lock().map(|m| m.len()).unwrap_or(0);
        f.debug_struct("SecretVault")
            .field("secrets", &format!("<{n} redacted>"))
            .finish()
    }
}

fn poisoned() -> KernelError {
    KernelError::Storage("secret vault lock poisoned".into())
}

impl SecretVault {
    /// A purely in-memory vault.
    pub fn in_memory() -> Self {
        Self { secrets: Mutex::new(HashMap::new()), tokens: Mutex::new(HashMap::new()), path: None }
    }

    /// Open (or create) a file-backed vault. The file is created with `0600`
    /// permissions on Unix.
    #[instrument(skip_all, fields(path = %path.display()))]
    pub fn open(path: PathBuf) -> KernelResult<Self> {
        let secrets: HashMap<String, String> = if path.exists() {
            let raw = std::fs::read_to_string(&path)?;
            serde_json::from_str(&raw)?
        } else {
            HashMap::new()
        };
        let vault = Self {
            secrets: Mutex::new(secrets),
            tokens: Mutex::new(HashMap::new()),
            path: Some(path),
        };
        vault.persist()?;
        Ok(vault)
    }

    fn persist(&self) -> KernelResult<()> {
        let Some(path) = &self.path else { return Ok(()) };
        let map = self.secrets.lock().map_err(|_| poisoned())?;
        let json = serde_json::to_string(&*map)?;
        drop(map);
        std::fs::write(path, json)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }

    /// Store (or replace) a named secret.
    pub fn insert(&self, name: &str, value: &str) -> KernelResult<()> {
        self.secrets
            .lock()
            .map_err(|_| poisoned())?
            .insert(name.to_string(), value.to_string());
        self.persist()
    }

    /// Remove a named secret.
    pub fn remove(&self, name: &str) -> KernelResult<()> {
        self.secrets.lock().map_err(|_| poisoned())?.remove(name);
        self.persist()
    }

    /// Lend the named secret to `f`. This is the **only** way to read a
    /// secret; connector code paths call this and must not persist the value.
    pub fn with_secret<R>(&self, name: &str, f: impl FnOnce(&str) -> R) -> KernelResult<R> {
        let map = self.secrets.lock().map_err(|_| poisoned())?;
        let value = map
            .get(name)
            .ok_or_else(|| KernelError::NotFound { kind: "secret", id: name.to_string() })?;
        Ok(f(value))
    }

    /// Mint a single-use token bound to `secret_name`, valid for `ttl`.
    /// The returned token is safe to hand to a guest: it reveals nothing
    /// about the credential and can be redeemed exactly once, by the host.
    #[instrument(skip(self))]
    pub fn mint_scoped_token(&self, secret_name: &str, ttl: Duration) -> KernelResult<ScopedToken> {
        // Verify the secret exists without exposing it.
        self.with_secret(secret_name, |_| ())?;
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        let token = format!("akst-{}", hex::encode(bytes));
        let expires_at = Utc::now() + ttl;
        self.tokens.lock().map_err(|_| poisoned())?.insert(
            token.clone(),
            TokenState { secret_name: secret_name.to_string(), expires_at },
        );
        info!(secret = secret_name, "minted scoped token");
        Ok(ScopedToken { token, expires_at })
    }

    /// Redeem a scoped token exactly once, lending the underlying secret to
    /// `f`. Expired, unknown, or already-redeemed tokens are refused.
    pub fn redeem_scoped_token<R>(&self, token: &str, f: impl FnOnce(&str) -> R) -> KernelResult<R> {
        let state = self
            .tokens
            .lock()
            .map_err(|_| poisoned())?
            .remove(token)
            .ok_or_else(|| KernelError::NotFound { kind: "scoped_token", id: "<redacted>".into() })?;
        if Utc::now() > state.expires_at {
            return Err(KernelError::StaleAuthorization {
                reason: "scoped token expired before redemption".into(),
            });
        }
        self.with_secret(&state.secret_name, f)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn with_secret_lends_value() {
        let v = SecretVault::in_memory();
        v.insert("gh", "tok-123").expect("insert");
        let len = v.with_secret("gh", |s| s.len()).expect("read");
        assert_eq!(len, 7);
        assert!(v.with_secret("missing", |_| ()).is_err());
    }
}

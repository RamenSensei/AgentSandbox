//! At-rest sealing for kernel secret files (AK-012).
//!
//! Small AEAD envelope shared by the secret vault and the receipt-signing
//! seed: ChaCha20-Poly1305 with a fresh random nonce per encryption, stored
//! alongside the ciphertext behind a magic header so legacy plaintext files
//! can be detected and transparently migrated.
//!
//! ## Key sourcing (in order)
//!
//! 1. `AK_VAULT_KEY` environment variable: base64-encoded 32 bytes.
//! 2. A key file at a caller-configured path (kept **outside** the data
//!    dir), created with `0600` permissions on Unix.
//! 3. On first run, a fresh random key is generated and persisted to that
//!    key file.

use crate::error::{IdentityError, IdentityResult};
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::RngCore;
use std::path::Path;

/// Environment variable holding the base64-encoded 32-byte sealing key.
pub const KEY_ENV_VAR: &str = "AK_VAULT_KEY";

/// Header identifying a sealed file: magic + format version.
const MAGIC: &[u8; 8] = b"AKSEAL1\n";
/// ChaCha20-Poly1305 nonce length in bytes.
const NONCE_LEN: usize = 12;

/// A 32-byte symmetric key used to seal secret files at rest.
///
/// `Debug` output is redacted; the raw bytes never leave this module except
/// through the AEAD.
pub struct SealKey([u8; 32]);

impl std::fmt::Debug for SealKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SealKey(<redacted>)")
    }
}

impl SealKey {
    /// Wrap raw key bytes (mainly for tests).
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Resolve the sealing key: `AK_VAULT_KEY` env var first, then the key
    /// file at `key_file`, else generate and persist a new key there.
    pub fn resolve(key_file: &Path) -> IdentityResult<Self> {
        Self::resolve_with_env(std::env::var(KEY_ENV_VAR).ok().as_deref(), key_file)
    }

    /// [`SealKey::resolve`] with the env var value passed explicitly, so the
    /// env branch is testable without mutating process environment.
    pub fn resolve_with_env(env_value: Option<&str>, key_file: &Path) -> IdentityResult<Self> {
        if let Some(b64) = env_value {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(b64.trim())
                .map_err(|e| {
                    IdentityError::Key(format!("{KEY_ENV_VAR} is not valid base64: {e}"))
                })?;
            let key: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
                IdentityError::Key(format!("{KEY_ENV_VAR} must decode to exactly 32 bytes"))
            })?;
            return Ok(Self(key));
        }
        if key_file.exists() {
            let bytes = std::fs::read(key_file)?;
            let key: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
                IdentityError::Key(format!(
                    "key file {} must contain exactly 32 bytes",
                    key_file.display()
                ))
            })?;
            return Ok(Self(key));
        }
        // First run: generate and persist.
        let mut key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut key);
        if let Some(parent) = key_file.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        std::fs::write(key_file, key)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(key_file, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(Self(key))
    }

    fn cipher(&self) -> ChaCha20Poly1305 {
        ChaCha20Poly1305::new(Key::from_slice(&self.0))
    }
}

/// Whether `bytes` carry the sealed-file header (vs. legacy plaintext).
pub fn is_sealed(bytes: &[u8]) -> bool {
    bytes.starts_with(MAGIC)
}

/// Seal `plaintext`: `MAGIC || nonce (12 bytes) || ciphertext+tag`.
/// A fresh random nonce is drawn for every call.
pub fn seal(key: &SealKey, plaintext: &[u8]) -> IdentityResult<Vec<u8>> {
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = key
        .cipher()
        .encrypt(nonce, plaintext)
        .map_err(|_| IdentityError::Key("sealing failed".into()))?;
    let mut out = Vec::with_capacity(MAGIC.len() + NONCE_LEN + ciphertext.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Unseal bytes produced by [`seal`]. Fails on a wrong key, tampering, or a
/// malformed envelope.
pub fn unseal(key: &SealKey, bytes: &[u8]) -> IdentityResult<Vec<u8>> {
    let body = bytes
        .strip_prefix(MAGIC.as_slice())
        .ok_or_else(|| IdentityError::Key("not a sealed file (missing header)".into()))?;
    if body.len() < NONCE_LEN {
        return Err(IdentityError::Key("sealed file is truncated".into()));
    }
    let (nonce_bytes, ciphertext) = body.split_at(NONCE_LEN);
    key.cipher()
        .decrypt(Nonce::from_slice(nonce_bytes), ciphertext)
        .map_err(|_| IdentityError::Key("unsealing failed: wrong key or corrupted file".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_unseal_round_trip_with_fresh_nonces() {
        let dir = tempfile::tempdir().unwrap();
        let key = SealKey::resolve(&dir.path().join("k.key")).unwrap();
        let a = seal(&key, b"top-secret").unwrap();
        let b = seal(&key, b"top-secret").unwrap();
        assert!(is_sealed(&a));
        assert_ne!(a, b, "nonce must be random per encryption");
        assert_eq!(unseal(&key, &a).unwrap(), b"top-secret");
        assert_eq!(unseal(&key, &b).unwrap(), b"top-secret");
    }

    #[test]
    fn wrong_key_fails_to_unseal() {
        let sealed = seal(&SealKey::from_bytes([1u8; 32]), b"top-secret").unwrap();
        assert!(matches!(
            unseal(&SealKey::from_bytes([2u8; 32]), &sealed),
            Err(IdentityError::Key(_))
        ));
    }

    #[test]
    fn key_file_is_created_persisted_and_0600() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys").join("seal.key");
        let k1 = SealKey::resolve_with_env(None, &path).unwrap();
        assert!(path.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let k2 = SealKey::resolve_with_env(None, &path).unwrap();
        let sealed = seal(&k1, b"x").unwrap();
        assert_eq!(unseal(&k2, &sealed).unwrap(), b"x");
    }

    #[test]
    fn env_var_takes_precedence_and_is_validated() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("unused.key");
        let b64 = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        let key = SealKey::resolve_with_env(Some(&b64), &path).unwrap();
        assert!(!path.exists(), "env key must not touch the key file");
        let sealed = seal(&key, b"x").unwrap();
        assert_eq!(
            unseal(&SealKey::from_bytes([7u8; 32]), &sealed).unwrap(),
            b"x"
        );
        assert!(SealKey::resolve_with_env(Some("!!"), &path).is_err());
        let short = base64::engine::general_purpose::STANDARD.encode([7u8; 16]);
        assert!(SealKey::resolve_with_env(Some(&short), &path).is_err());
    }

    #[test]
    fn plaintext_is_not_sealed() {
        assert!(!is_sealed(b"{\"gh\":\"tok\"}"));
        assert!(unseal(&SealKey::from_bytes([0u8; 32]), b"plaintext").is_err());
    }
}

//! The kernel's Ed25519 signing identity, used for effect receipts.

use crate::error::{IdentityError, IdentityResult};
use crate::sealing::{self, SealKey};
use ak_core::hash::canonical_json;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::path::Path;

/// The kernel's Ed25519 keypair.
///
/// Receipts (and any other kernel attestations) are signed over the
/// **canonical JSON** encoding of the value ([`ak_core::hash::canonical_json`]):
/// keys sorted, compact separators. This makes signatures stable across
/// serializer implementations and field ordering.
///
/// The key id is `ed25519:<sha256-hex-of-public-key-bytes>`, so verifiers can
/// address keys without ever shipping the private half.
pub struct KernelKeypair {
    signing: SigningKey,
}

impl KernelKeypair {
    /// Generate a fresh random keypair.
    pub fn generate() -> Self {
        let mut rng = rand::rngs::OsRng;
        Self {
            signing: SigningKey::generate(&mut rng),
        }
    }

    /// Load a keypair from a file holding the 32-byte secret seed, sealed at
    /// rest with `key` (see [`crate::sealing`]). Legacy files containing the
    /// seed as plaintext lowercase hex are accepted and transparently
    /// re-saved sealed.
    pub fn load(path: impl AsRef<Path>, key: &SealKey) -> IdentityResult<Self> {
        let raw = std::fs::read(path.as_ref())?;
        let was_sealed = sealing::is_sealed(&raw);
        let hex_text = if was_sealed {
            String::from_utf8(sealing::unseal(key, &raw)?)
                .map_err(|_| IdentityError::Key("sealed key file is not valid UTF-8".into()))?
        } else {
            String::from_utf8(raw)
                .map_err(|_| IdentityError::Key("key file is not valid UTF-8".into()))?
        };
        let bytes = hex::decode(hex_text.trim())
            .map_err(|e| IdentityError::Key(format!("key file is not valid hex: {e}")))?;
        let seed: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| IdentityError::Key("key file must contain exactly 32 bytes".into()))?;
        let kp = Self {
            signing: SigningKey::from_bytes(&seed),
        };
        if !was_sealed {
            // Legacy plaintext seed on disk: migrate to the sealed format.
            kp.save(path, key)?;
        }
        Ok(kp)
    }

    /// Persist the secret seed (hex-encoded, then sealed with `key`). On
    /// Unix the file is created with owner-only (0600) permissions.
    pub fn save(&self, path: impl AsRef<Path>, key: &SealKey) -> IdentityResult<()> {
        let hex_seed = hex::encode(self.signing.to_bytes());
        let sealed = sealing::seal(key, hex_seed.as_bytes())?;
        std::fs::write(&path, sealed)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }

    /// Load from `path` if it exists, otherwise generate and save a new key.
    pub fn load_or_generate(path: impl AsRef<Path>, key: &SealKey) -> IdentityResult<Self> {
        if path.as_ref().exists() {
            Self::load(path, key)
        } else {
            let kp = Self::generate();
            kp.save(path, key)?;
            Ok(kp)
        }
    }

    /// The public verifying key.
    pub fn public_key(&self) -> VerifyingKey {
        self.signing.verifying_key()
    }

    /// Stable key id: `ed25519:<sha256(public key bytes)>` in lowercase hex.
    pub fn key_id(&self) -> String {
        let digest = Sha256::digest(self.public_key().as_bytes());
        format!("ed25519:{}", hex::encode(digest))
    }

    /// Sign the canonical JSON encoding of `value`. Returns the 64-byte
    /// signature as lowercase hex.
    pub fn sign_canonical<T: Serialize>(&self, value: &T) -> String {
        let payload = canonical_json(value);
        hex::encode(self.signing.sign(payload.as_bytes()).to_bytes())
    }

    /// Verify a hex signature produced by [`KernelKeypair::sign_canonical`]
    /// against `public_key`.
    pub fn verify_canonical<T: Serialize>(
        public_key: &VerifyingKey,
        value: &T,
        signature_hex: &str,
    ) -> IdentityResult<bool> {
        let sig_bytes = hex::decode(signature_hex)
            .map_err(|e| IdentityError::Key(format!("signature is not valid hex: {e}")))?;
        let sig_arr: [u8; 64] = sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| IdentityError::Key("signature must be 64 bytes".into()))?;
        let sig = Signature::from_bytes(&sig_arr);
        let payload = canonical_json(value);
        Ok(public_key.verify(payload.as_bytes(), &sig).is_ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sign_verify_roundtrip_over_canonical_json() {
        let kp = KernelKeypair::generate();
        // Key order must not matter: both encode to the same canonical JSON.
        let a = json!({"x": 1, "y": {"b": 2, "a": 3}});
        let b = json!({"y": {"a": 3, "b": 2}, "x": 1});
        let sig = kp.sign_canonical(&a);
        assert!(KernelKeypair::verify_canonical(&kp.public_key(), &b, &sig).unwrap());
        assert!(
            !KernelKeypair::verify_canonical(&kp.public_key(), &json!({"x": 2}), &sig).unwrap()
        );
    }

    #[test]
    fn key_id_is_sha256_of_public_key() {
        let kp = KernelKeypair::generate();
        let id = kp.key_id();
        assert!(id.starts_with("ed25519:"));
        assert_eq!(id.len(), "ed25519:".len() + 64);
        assert_eq!(id, kp.key_id());
    }

    #[test]
    fn save_load_roundtrip_sealed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kernel.key");
        let seal_key = SealKey::from_bytes([9u8; 32]);
        let kp = KernelKeypair::generate();
        kp.save(&path, &seal_key).unwrap();
        // On-disk bytes are sealed and never contain the hex seed.
        let raw = std::fs::read(&path).unwrap();
        assert!(sealing::is_sealed(&raw));
        let hex_seed = hex::encode(kp.signing.to_bytes());
        assert!(!String::from_utf8_lossy(&raw).contains(&hex_seed));
        let loaded = KernelKeypair::load(&path, &seal_key).unwrap();
        assert_eq!(kp.key_id(), loaded.key_id());
        // load_or_generate keeps an existing key…
        let again = KernelKeypair::load_or_generate(&path, &seal_key).unwrap();
        assert_eq!(again.key_id(), kp.key_id());
        // …and creates one when missing.
        let fresh_path = dir.path().join("fresh.key");
        let fresh = KernelKeypair::load_or_generate(&fresh_path, &seal_key).unwrap();
        assert!(fresh_path.exists());
        assert_ne!(fresh.key_id(), kp.key_id());
    }

    #[test]
    fn wrong_seal_key_fails_to_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kernel.key");
        let kp = KernelKeypair::generate();
        kp.save(&path, &SealKey::from_bytes([1u8; 32])).unwrap();
        assert!(matches!(
            KernelKeypair::load(&path, &SealKey::from_bytes([2u8; 32])),
            Err(IdentityError::Key(_))
        ));
    }

    #[test]
    fn legacy_plaintext_hex_seed_migrates_to_sealed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("legacy.key");
        let kp = KernelKeypair::generate();
        let hex_seed = hex::encode(kp.signing.to_bytes());
        std::fs::write(&path, format!("{hex_seed}\n")).unwrap();
        let seal_key = SealKey::from_bytes([9u8; 32]);
        let loaded = KernelKeypair::load(&path, &seal_key).unwrap();
        assert_eq!(loaded.key_id(), kp.key_id());
        // The file was re-saved sealed and no longer leaks the seed.
        let raw = std::fs::read(&path).unwrap();
        assert!(sealing::is_sealed(&raw));
        assert!(!String::from_utf8_lossy(&raw).contains(&hex_seed));
        let reloaded = KernelKeypair::load(&path, &seal_key).unwrap();
        assert_eq!(reloaded.key_id(), kp.key_id());
    }

    #[test]
    fn bad_key_files_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.key");
        let seal_key = SealKey::from_bytes([9u8; 32]);
        std::fs::write(&path, "not-hex!").unwrap();
        assert!(matches!(
            KernelKeypair::load(&path, &seal_key),
            Err(IdentityError::Key(_))
        ));
        std::fs::write(&path, hex::encode([0u8; 16])).unwrap();
        assert!(matches!(
            KernelKeypair::load(&path, &seal_key),
            Err(IdentityError::Key(_))
        ));
    }
}

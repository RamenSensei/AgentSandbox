//! The kernel's Ed25519 signing identity, used for effect receipts.

use crate::error::{IdentityError, IdentityResult};
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

    /// Load a keypair from a file containing the 32-byte secret seed encoded
    /// as lowercase hex (optionally with trailing whitespace).
    pub fn load(path: impl AsRef<Path>) -> IdentityResult<Self> {
        let text = std::fs::read_to_string(path)?;
        let bytes = hex::decode(text.trim())
            .map_err(|e| IdentityError::Key(format!("key file is not valid hex: {e}")))?;
        let seed: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| IdentityError::Key("key file must contain exactly 32 bytes".into()))?;
        Ok(Self {
            signing: SigningKey::from_bytes(&seed),
        })
    }

    /// Persist the secret seed as hex. On Unix the file is created with
    /// owner-only (0600) permissions.
    pub fn save(&self, path: impl AsRef<Path>) -> IdentityResult<()> {
        let hex_seed = hex::encode(self.signing.to_bytes());
        std::fs::write(&path, hex_seed)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }

    /// Load from `path` if it exists, otherwise generate and save a new key.
    pub fn load_or_generate(path: impl AsRef<Path>) -> IdentityResult<Self> {
        if path.as_ref().exists() {
            Self::load(path)
        } else {
            let kp = Self::generate();
            kp.save(path)?;
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
    fn save_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kernel.key");
        let kp = KernelKeypair::generate();
        kp.save(&path).unwrap();
        let loaded = KernelKeypair::load(&path).unwrap();
        assert_eq!(kp.key_id(), loaded.key_id());
        // load_or_generate keeps an existing key…
        let again = KernelKeypair::load_or_generate(&path).unwrap();
        assert_eq!(again.key_id(), kp.key_id());
        // …and creates one when missing.
        let fresh_path = dir.path().join("fresh.key");
        let fresh = KernelKeypair::load_or_generate(&fresh_path).unwrap();
        assert!(fresh_path.exists());
        assert_ne!(fresh.key_id(), kp.key_id());
    }

    #[test]
    fn bad_key_files_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.key");
        std::fs::write(&path, "not-hex!").unwrap();
        assert!(matches!(
            KernelKeypair::load(&path),
            Err(IdentityError::Key(_))
        ));
        std::fs::write(&path, hex::encode([0u8; 16])).unwrap();
        assert!(matches!(
            KernelKeypair::load(&path),
            Err(IdentityError::Key(_))
        ));
    }
}

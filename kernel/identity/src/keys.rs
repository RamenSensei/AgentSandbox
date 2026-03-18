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
        Self { signing: SigningKey::generate(&mut rng) }
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
        Ok(Self { signing: SigningKey::from_bytes(&seed) })
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

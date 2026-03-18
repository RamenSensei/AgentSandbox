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

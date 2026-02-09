//! Canonical hashing utilities.
//!
//! Every artifact that participates in authorization (effect contracts, policy
//! documents, receipts) is hashed over a *canonical JSON* encoding: object keys
//! sorted lexicographically, no insignificant whitespace, UTF-8. Commit-time
//! revalidation compares these hashes, so canonicalization must be stable.

use serde::Serialize;
use sha2::{Digest, Sha256};

/// A lowercase hex-encoded SHA-256 digest, prefixed with the algorithm.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Deserialize, Serialize)]
#[serde(transparent)]
pub struct ContentHash(pub String);

impl ContentHash {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ContentHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

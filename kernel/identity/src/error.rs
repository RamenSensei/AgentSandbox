//! Error type for the identity crate.

use ak_core::KernelError;
use thiserror::Error;

/// Convenience alias for identity-crate results.
pub type IdentityResult<T> = Result<T, IdentityError>;

/// Everything that can go wrong in the identity layer.
#[derive(Debug, Error)]
pub enum IdentityError {
    /// A principal id was not found in the registry.
    #[error("unknown principal `{0}`")]
    UnknownPrincipal(String),

    /// A lease id was not found in the store.
    #[error("unknown lease `{0}`")]
    UnknownLease(String),

    /// A principal with this id is already registered.
    #[error("principal `{0}` is already registered")]
    DuplicatePrincipal(String),

    /// The declared parent of a principal is not registered.
    #[error("parent principal `{0}` is not registered")]
    UnknownParent(String),

    /// The lease exists but cannot be used (revoked / expired / exhausted).
    #[error("lease `{lease}` is unusable: {reason}")]
    LeaseUnusable { lease: String, reason: String },

    /// Delegation was rejected by registry-level checks.
    #[error("delegation rejected: {0}")]
    DelegationRejected(String),

    /// Attenuation was rejected by the core lease algebra.
    #[error("attenuation rejected: {0}")]
    Attenuation(#[from] ak_core::capability::AttenuationError),

    /// Underlying SQLite failure.
    #[error("storage error: {0}")]
    Storage(#[from] rusqlite::Error),

    /// JSON (de)serialization failure for a persisted row.
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    /// Key material could not be loaded or parsed.
    #[error("key error: {0}")]
    Key(String),

    /// Filesystem failure while loading/saving key material.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

impl From<IdentityError> for KernelError {
    fn from(e: IdentityError) -> Self {
        match e {
            IdentityError::UnknownPrincipal(id) => {
                KernelError::NotFound { kind: "principal", id }
            }
            IdentityError::UnknownLease(id) => KernelError::NotFound { kind: "lease", id },
            IdentityError::Storage(err) => KernelError::Storage(err.to_string()),
            IdentityError::Serde(err) => KernelError::Serde(err),
            IdentityError::Io(err) => KernelError::Io(err),
            other => KernelError::Other(other.to_string()),
        }
    }
}

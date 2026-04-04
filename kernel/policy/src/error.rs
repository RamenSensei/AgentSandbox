//! Error type for the policy crate.

use thiserror::Error;

/// Convenience alias for policy-crate results.
pub type PolicyResult<T> = Result<T, PolicyError>;

/// Everything that can go wrong while loading or compiling policy.
#[derive(Debug, Error)]
pub enum PolicyError {
    /// The YAML document could not be parsed into a [`crate::PolicyDocument`]
    /// or [`crate::AutonomyEnvelope`].
    #[error("invalid policy yaml: {0}")]
    Yaml(#[from] serde_yaml::Error),

    /// A document failed semantic validation after parsing.
    #[error("invalid policy document: {0}")]
    Invalid(String),

    /// A grant could not be compiled into a lease + confinement.
    #[error("grant rejected: {0}")]
    GrantRejected(String),

    /// An envelope entry was rejected (e.g. it collides with a forbid rule).
    #[error("envelope rejected: {0}")]
    EnvelopeRejected(String),

    /// Filesystem failure while loading a policy file.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON conversion failure.
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
}

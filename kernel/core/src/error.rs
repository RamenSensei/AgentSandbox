//! Kernel-wide error type.

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub type KernelResult<T> = Result<T, KernelError>;

#[derive(Debug, Error)]
pub enum KernelError {
    #[error("invalid id: expected prefix `{expected_prefix}`, got `{got}`")]
    InvalidId {
        expected_prefix: &'static str,
        got: String,
    },

    #[error("unknown object: {kind} `{id}`")]
    NotFound { kind: &'static str, id: String },

    #[error("action denied: {}", .0.reason)]
    Denied(Box<crate::denial::Denial>),

    #[error("effect `{effect}` is in phase {phase} but `{expected}` was required")]
    WrongEffectPhase {
        effect: String,
        phase: String,
        expected: &'static str,
    },

    #[error("commit-time revalidation failed: {reason}")]
    StaleAuthorization { reason: String },

    #[error("idempotency key `{key}` was already committed as receipt `{receipt}`")]
    DuplicateCommit { key: String, receipt: String },

    #[error(
        "effect `{effect}` is in doubt: a commit attempt failed indeterminately ({reason}); \
         the connector could not confirm whether the external effect happened. \
         Resolve via recovery or operator decision — do NOT blindly retry."
    )]
    CommitInDoubt { effect: String, reason: String },

    #[error("backend `{backend}` unavailable: {reason}")]
    BackendUnavailable { backend: String, reason: String },

    #[error("branch `{branch}` was already discarded")]
    BranchDiscarded { branch: String },

    #[error("merge conflict on {paths:?}")]
    MergeConflict { paths: Vec<String> },

    #[error("storage error: {0}")]
    Storage(String),

    #[error("connector error: {0}")]
    Connector(String),

    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Other(String),
}

impl KernelError {
    /// Stable machine-readable code for the wire protocol.
    pub fn code(&self) -> &'static str {
        match self {
            KernelError::InvalidId { .. } => "INVALID_ID",
            KernelError::NotFound { .. } => "NOT_FOUND",
            KernelError::Denied(_) => "DENIED",
            KernelError::WrongEffectPhase { .. } => "WRONG_EFFECT_PHASE",
            KernelError::StaleAuthorization { .. } => "STALE_AUTHORIZATION",
            KernelError::DuplicateCommit { .. } => "DUPLICATE_COMMIT",
            KernelError::CommitInDoubt { .. } => "COMMIT_IN_DOUBT",
            KernelError::BackendUnavailable { .. } => "BACKEND_UNAVAILABLE",
            KernelError::BranchDiscarded { .. } => "BRANCH_DISCARDED",
            KernelError::MergeConflict { .. } => "MERGE_CONFLICT",
            KernelError::Storage(_) => "STORAGE",
            KernelError::Connector(_) => "CONNECTOR",
            KernelError::Serde(_) => "SERDE",
            KernelError::Io(_) => "IO",
            KernelError::Other(_) => "OTHER",
        }
    }
}

/// Wire-serializable error envelope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorEnvelope {
    pub code: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub denial: Option<crate::denial::Denial>,
}

impl From<&KernelError> for ErrorEnvelope {
    fn from(e: &KernelError) -> Self {
        let denial = match e {
            KernelError::Denied(d) => Some((**d).clone()),
            _ => None,
        };
        ErrorEnvelope {
            code: e.code().to_string(),
            message: e.to_string(),
            denial,
        }
    }
}
impl From<crate::denial::Denial> for KernelError {
    fn from(d: crate::denial::Denial) -> Self {
        KernelError::Denied(Box::new(d))
    }
}

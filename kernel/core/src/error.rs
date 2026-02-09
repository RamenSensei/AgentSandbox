//! Kernel-wide error type.

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub type KernelResult<T> = Result<T, KernelError>;

#[derive(Debug, Error)]
pub enum KernelError {
    #[error("invalid id: expected prefix `{expected_prefix}`, got `{got}`")]
    InvalidId { expected_prefix: &'static str, got: String },

    #[error("unknown object: {kind} `{id}`")]
    NotFound { kind: &'static str, id: String },

    #[error("action denied: {}", .0.reason)]
    Denied(Box<crate::denial::Denial>),

    #[error("effect `{effect}` is in phase {phase} but `{expected}` was required")]
    WrongEffectPhase { effect: String, phase: String, expected: &'static str },

    #[error("commit-time revalidation failed: {reason}")]
    StaleAuthorization { reason: String },

    #[error("idempotency key `{key}` was already committed as receipt `{receipt}`")]
    DuplicateCommit { key: String, receipt: String },

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

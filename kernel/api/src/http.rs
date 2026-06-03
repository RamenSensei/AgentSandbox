//! JSON/HTTP binding of the Agent Execution Protocol (see
//! `protocol/openapi.yaml`).
//!
//! Errors are returned as [`ak_core::error::ErrorEnvelope`]; policy denials
//! are HTTP 403 carrying the full machine-readable [`ak_core::Denial`].

use crate::kernel::Kernel;
use ak_causal_ledger::{EventKind, TraceQuery};
use ak_core::action::Action;
use ak_core::budget::ResourceBudget;
use ak_core::capability::{Constraint, Operation};
use ak_core::error::{ErrorEnvelope, KernelError};
use ak_core::ids::{BranchId, EffectId, EpisodeId, LeaseId, PrincipalId, ReceiptId, StateId};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use indexmap::IndexMap;
use serde::Deserialize;
use std::sync::Arc;

/// Kernel error → HTTP response with an [`ErrorEnvelope`].
struct ApiError(KernelError);

impl From<KernelError> for ApiError {
    fn from(e: KernelError) -> Self {
        Self(e)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match &self.0 {
            KernelError::Denied(_) => StatusCode::FORBIDDEN,
            KernelError::NotFound { .. } => StatusCode::NOT_FOUND,
            KernelError::InvalidId { .. } | KernelError::Serde(_) => StatusCode::BAD_REQUEST,
            KernelError::StaleAuthorization { .. }
            | KernelError::DuplicateCommit { .. }
            | KernelError::WrongEffectPhase { .. }
            | KernelError::BranchDiscarded { .. }
            | KernelError::MergeConflict { .. } => StatusCode::CONFLICT,
            KernelError::BackendUnavailable { .. } => StatusCode::SERVICE_UNAVAILABLE,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (status, Json(ErrorEnvelope::from(&self.0))).into_response()
    }
}

type ApiResult<T> = Result<T, ApiError>;

/// Build the kernel HTTP router.
pub fn router(kernel: Arc<Kernel>) -> Router {
    Router::new()
        .route("/v1/episodes", post(create_episode))
        .route("/v1/episodes/:id", get(describe_episode))
        .route("/v1/steps/execute", post(execute_step))
        .route("/v1/branches/:id/fork", post(fork_branch))
        .route("/v1/branches/:id/diff", post(diff_branch))
        .route("/v1/branches/:id/merge", post(merge_branch))
        .route("/v1/branches/:id/discard", post(discard_branch))
        .route("/v1/branches/:id/compare/:other", get(compare_branches))
        .route("/v1/capabilities/request", post(request_capability))
        .route("/v1/capabilities/delegate", post(delegate_capability))
        .route("/v1/capabilities/revoke", post(revoke_capability))
        .route("/v1/capabilities/:principal", get(list_capabilities))
        .route("/v1/effects/:id", get(get_effect))
        .route("/v1/effects/:id/prepare", post(prepare_effect))
        .route("/v1/effects/:id/approve", post(approve_effect))
        .route("/v1/effects/:id/commit", post(commit_effect))
        .route("/v1/effects/:id/compensate", post(compensate_effect))
        .route("/v1/trace/query", get(trace_query))
        .route("/v1/receipts/:id", get(get_receipt))
        .with_state(kernel)
}

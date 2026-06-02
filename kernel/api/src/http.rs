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

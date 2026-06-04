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

#[derive(Deserialize)]
struct CreateEpisodeRequest {
    principal: PrincipalId,
    #[serde(default)]
    objective: String,
    #[serde(default)]
    workspace: Option<std::path::PathBuf>,
}

async fn create_episode(
    State(k): State<Arc<Kernel>>,
    Json(req): Json<CreateEpisodeRequest>,
) -> ApiResult<impl IntoResponse> {
    let handle = k.create_episode(&req.principal, req.workspace.as_deref(), &req.objective)?;
    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({
            "episode": handle.episode,
            "branch": handle.branch,
            "root_state": handle.root.id,
        })),
    ))
}

async fn describe_episode(
    State(k): State<Arc<Kernel>>,
    Path(id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    let desc = k.describe_episode(&EpisodeId::parse(&id)?).await?;
    Ok(Json(serde_json::to_value(&desc).map_err(KernelError::from)?))
}

#[derive(Deserialize)]
struct ExecuteStepRequest {
    principal: PrincipalId,
    branch: BranchId,
    action: Action,
}

async fn execute_step(
    State(k): State<Arc<Kernel>>,
    Json(req): Json<ExecuteStepRequest>,
) -> ApiResult<Response> {
    let result = k.execute_step(&req.principal, &req.branch, req.action).await?;
    // Denials are full observations *and* HTTP 403 with the structured
    // denial, per the protocol.
    if let ak_core::Observation::Denied { denial } = &result.observation {
        let envelope = ErrorEnvelope {
            code: "DENIED".into(),
            message: denial.reason.clone(),
            denial: Some(denial.clone()),
        };
        return Ok((StatusCode::FORBIDDEN, Json(serde_json::json!({
            "step": result.step,
            "state": result.state,
            "observation": result.observation,
            "error": envelope,
        })))
        .into_response());
    }
    Ok(Json(serde_json::to_value(&result).map_err(KernelError::from)?).into_response())
}

async fn fork_branch(
    State(k): State<Arc<Kernel>>,
    Path(id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    let branch = k.fork_branch(&BranchId::parse(&id)?)?;
    Ok(Json(serde_json::to_value(&branch).map_err(KernelError::from)?))
}

#[derive(Deserialize, Default)]
struct DiffRequest {
    #[serde(default)]
    since: Option<StateId>,
}

async fn diff_branch(
    State(k): State<Arc<Kernel>>,
    Path(id): Path<String>,
    Json(req): Json<DiffRequest>,
) -> ApiResult<impl IntoResponse> {
    let changes = k.branch_diff(&BranchId::parse(&id)?, req.since.as_ref())?;
    Ok(Json(serde_json::to_value(&changes).map_err(KernelError::from)?))
}

#[derive(Deserialize)]
struct MergeRequest {
    source: BranchId,
    actor: PrincipalId,
}

async fn merge_branch(
    State(k): State<Arc<Kernel>>,
    Path(id): Path<String>,
    Json(req): Json<MergeRequest>,
) -> ApiResult<impl IntoResponse> {
    let node = k.merge_branch(&BranchId::parse(&id)?, &req.source, &req.actor)?;
    Ok(Json(serde_json::to_value(&node).map_err(KernelError::from)?))
}

async fn discard_branch(
    State(k): State<Arc<Kernel>>,
    Path(id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    k.discard_branch(&BranchId::parse(&id)?).await?;
    Ok(Json(serde_json::json!({ "discarded": id })))
}

async fn compare_branches(
    State(k): State<Arc<Kernel>>,
    Path((a, b)): Path<(String, String)>,
) -> ApiResult<impl IntoResponse> {
    let cmp = k.branch_compare(&BranchId::parse(&a)?, &BranchId::parse(&b)?)?;
    Ok(Json(serde_json::json!({
        "base": cmp.base,
        "changed_in_a": cmp.changed_in_a,
        "changed_in_b": cmp.changed_in_b,
    })))
}

#[derive(Deserialize)]
struct CapabilityRequest {
    principal: PrincipalId,
    operation: String,
    #[serde(default)]
    params: serde_json::Value,
    #[serde(default)]
    branch: Option<BranchId>,
}

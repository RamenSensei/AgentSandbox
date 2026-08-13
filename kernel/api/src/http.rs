//! JSON/HTTP binding of the Agent Execution Protocol (see
//! `protocol/openapi.yaml`).
//!
//! Errors are returned as [`ak_core::error::ErrorEnvelope`]; policy denials
//! are HTTP 403 carrying the full machine-readable [`ak_core::Denial`].

use crate::auth::{require_auth, AuthConfig, AuthContext, AuthError, Role};
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
use axum::{Extension, Json, Router};
use indexmap::IndexMap;
use serde::Deserialize;
use std::sync::Arc;

/// Kernel or authorization error → HTTP response with an
/// [`ErrorEnvelope`].
enum ApiError {
    Kernel(KernelError),
    Auth(AuthError),
}

impl From<KernelError> for ApiError {
    fn from(e: KernelError) -> Self {
        Self::Kernel(e)
    }
}

impl From<AuthError> for ApiError {
    fn from(e: AuthError) -> Self {
        Self::Auth(e)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let e = match self {
            ApiError::Auth(a) => return a.into_response(),
            ApiError::Kernel(e) => e,
        };
        let status = match &e {
            KernelError::Denied(_) => StatusCode::FORBIDDEN,
            KernelError::NotFound { .. } => StatusCode::NOT_FOUND,
            KernelError::InvalidId { .. } | KernelError::Serde(_) => StatusCode::BAD_REQUEST,
            KernelError::StaleAuthorization { .. }
            | KernelError::DuplicateCommit { .. }
            | KernelError::CommitInDoubt { .. }
            | KernelError::WrongEffectPhase { .. }
            | KernelError::BranchDiscarded { .. }
            | KernelError::MergeConflict { .. } => StatusCode::CONFLICT,
            KernelError::BackendUnavailable { .. } => StatusCode::SERVICE_UNAVAILABLE,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (status, Json(ErrorEnvelope::from(&e))).into_response()
    }
}

type ApiResult<T> = Result<T, ApiError>;

/// Build the kernel HTTP router with auth disabled (loopback/dev/tests).
pub fn router(kernel: Arc<Kernel>) -> Router {
    router_with_auth(kernel, AuthConfig::disabled())
}

/// Build the kernel HTTP router enforcing `auth` on every route except
/// `/healthz`.
pub fn router_with_auth(kernel: Arc<Kernel>, auth: AuthConfig) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/episodes", post(create_episode))
        .route("/v1/episodes/:id", get(describe_episode))
        .route("/v1/steps/execute", post(execute_step))
        .route("/v1/steps/execute_auto", post(execute_step_auto))
        .route("/v1/steps/:id/explain", get(explain_step))
        .route("/v1/steps/:id/retry", post(retry_step))
        .route("/v1/branches/:id/fork", post(fork_branch))
        .route("/v1/branches/:id/diff", post(diff_branch))
        .route("/v1/branches/:id/merge", post(merge_branch))
        .route("/v1/branches/:id/discard", post(discard_branch))
        .route("/v1/branches/:id/explore", post(explore_branch))
        .route("/v1/branches/:id/compare/:other", get(compare_branches))
        .route("/v1/raw/:hash", get(fetch_raw))
        .route("/v1/capabilities/request", post(request_capability))
        .route("/v1/capabilities/delegate", post(delegate_capability))
        .route("/v1/capabilities/revoke", post(revoke_capability))
        .route("/v1/capabilities/:principal", get(list_capabilities))
        .route("/v1/effects", get(list_effects))
        .route("/v1/effects/recover", post(recover_effects))
        .route("/v1/effects/:id", get(get_effect))
        .route("/v1/effects/:id/prepare", post(prepare_effect))
        .route("/v1/effects/:id/approve", post(approve_effect))
        .route("/v1/effects/:id/commit", post(commit_effect))
        .route("/v1/effects/:id/compensate", post(compensate_effect))
        .route("/v1/effects/:id/resolve", post(resolve_effect))
        .route("/v1/replay/:mode", post(replay))
        .route("/v1/trace/query", get(trace_query))
        .route("/v1/receipts/:id", get(get_receipt))
        .layer(axum::middleware::from_fn_with_state(
            Arc::new(auth),
            require_auth,
        ))
        .with_state(kernel)
}

async fn healthz() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok", "version": env!("CARGO_PKG_VERSION") }))
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
    Extension(auth): Extension<AuthContext>,
    Json(req): Json<CreateEpisodeRequest>,
) -> ApiResult<impl IntoResponse> {
    let principal = auth.act_as(&req.principal)?;
    let handle = k.create_episode(&principal, req.workspace.as_deref(), &req.objective)?;
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
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    let id = EpisodeId::parse(&id)?;
    auth.require_owner(&k.episode_owner(&id)?)?;
    let desc = k.describe_episode(&id).await?;
    Ok(Json(
        serde_json::to_value(&desc).map_err(KernelError::from)?,
    ))
}

#[derive(Deserialize)]
struct ExecuteStepRequest {
    principal: PrincipalId,
    branch: BranchId,
    action: Action,
}

async fn execute_step(
    State(k): State<Arc<Kernel>>,
    Extension(auth): Extension<AuthContext>,
    Json(req): Json<ExecuteStepRequest>,
) -> ApiResult<Response> {
    let principal = auth.act_as(&req.principal)?;
    auth.require_owner(&k.branch_owner(&req.branch)?)?;
    let result = k.execute_step(&principal, &req.branch, req.action).await?;
    // Denials are full observations *and* HTTP 403 with the structured
    // denial, per the protocol.
    if let ak_core::Observation::Denied { denial } = &result.observation {
        let envelope = ErrorEnvelope {
            code: "DENIED".into(),
            message: denial.reason.clone(),
            denial: Some(denial.clone()),
        };
        return Ok((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "step": result.step,
                "state": result.state,
                "observation": result.observation,
                "error": envelope,
            })),
        )
            .into_response());
    }
    Ok(Json(serde_json::to_value(&result).map_err(KernelError::from)?).into_response())
}

#[derive(Deserialize)]
struct ExecuteStepAutoRequest {
    principal: PrincipalId,
    branch: BranchId,
    /// The action kind alone — the kernel resolves the lease and budget.
    kind: ak_core::action::ActionKind,
    #[serde(default)]
    intent_hint: Option<String>,
    #[serde(default)]
    budget: Option<ResourceBudget>,
}

/// `steps/execute_auto`: execute with automatic lease resolution. The
/// response carries the step result plus the lease that authorized it.
async fn execute_step_auto(
    State(k): State<Arc<Kernel>>,
    Extension(auth): Extension<AuthContext>,
    Json(req): Json<ExecuteStepAutoRequest>,
) -> ApiResult<Response> {
    let principal = auth.act_as(&req.principal)?;
    auth.require_owner(&k.branch_owner(&req.branch)?)?;
    let auto = k
        .execute_step_auto(
            &principal,
            &req.branch,
            req.kind,
            req.intent_hint,
            req.budget,
        )
        .await?;
    if let ak_core::Observation::Denied { denial } = &auto.result.observation {
        let envelope = ErrorEnvelope {
            code: "DENIED".into(),
            message: denial.reason.clone(),
            denial: Some(denial.clone()),
        };
        return Ok((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "step": auto.result.step,
                "state": auto.result.state,
                "observation": auto.result.observation,
                "lease": auto.lease,
                "lease_minted": auto.lease_minted,
                "error": envelope,
            })),
        )
            .into_response());
    }
    Ok(Json(serde_json::to_value(&auto).map_err(KernelError::from)?).into_response())
}

#[derive(Deserialize)]
struct ExploreRequest {
    principal: PrincipalId,
    #[serde(flatten)]
    options: crate::kernel::ExploreOptions,
}

/// `branches/{id}/explore`: server-side parallel candidate exploration.
async fn explore_branch(
    State(k): State<Arc<Kernel>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
    Json(req): Json<ExploreRequest>,
) -> ApiResult<impl IntoResponse> {
    let id = BranchId::parse(&id)?;
    auth.require_owner(&k.branch_owner(&id)?)?;
    let principal = auth.act_as(&req.principal)?;
    let report = k.explore(&principal, &id, req.options).await?;
    Ok(Json(
        serde_json::to_value(&report).map_err(KernelError::from)?,
    ))
}

#[derive(Deserialize, Default)]
struct RawParams {
    #[serde(default)]
    offset: Option<u64>,
    #[serde(default)]
    limit: Option<u64>,
    /// Case-sensitive substring search over the blob's lines.
    #[serde(default)]
    grep: Option<String>,
}

/// `GET /v1/raw/{hash}`: paginated access to a full recorded output blob.
/// Observations reference these blobs by content hash; this route closes the
/// loop so an agent can actually read past the distilled head/tail (compiler
/// errors in the middle, test summaries at the end) without a human pulling
/// files off the server. Content hashes are unguessable (SHA-256), and every
/// caller is authenticated by the surrounding middleware.
async fn fetch_raw(
    State(k): State<Arc<Kernel>>,
    Extension(_auth): Extension<AuthContext>,
    Path(hash): Path<String>,
    Query(p): Query<RawParams>,
) -> ApiResult<impl IntoResponse> {
    const MAX_SLICE: u64 = 1 << 20;
    const MAX_GREP_MATCHES: usize = 200;
    let bytes = k.fetch_raw(&ak_core::hash::ContentHash(hash.clone()))?;
    let total = bytes.len() as u64;
    if let Some(pattern) = &p.grep {
        // Line-oriented search with byte offsets, so an agent can grep a big
        // log and then page precisely around the hits.
        let mut matches = Vec::new();
        let mut truncated = false;
        let mut offset: u64 = 0;
        for line in String::from_utf8_lossy(&bytes).split_inclusive('\n') {
            if line.contains(pattern.as_str()) {
                if matches.len() >= MAX_GREP_MATCHES {
                    truncated = true;
                    break;
                }
                matches.push(serde_json::json!({
                    "offset": offset,
                    "line": line.trim_end_matches('\n'),
                }));
            }
            offset += line.len() as u64;
        }
        return Ok(Json(serde_json::json!({
            "hash": hash,
            "total_bytes": total,
            "grep": pattern,
            "matches": matches,
            "matches_truncated": truncated,
        })));
    }
    let offset = p.offset.unwrap_or(0).min(total);
    let limit = p.limit.unwrap_or(64 * 1024).min(MAX_SLICE);
    let end = offset.saturating_add(limit).min(total);
    let slice = &bytes[offset as usize..end as usize];
    Ok(Json(serde_json::json!({
        "hash": hash,
        "total_bytes": total,
        "offset": offset,
        "returned_bytes": slice.len(),
        "next_offset": if end < total { Some(end) } else { None },
        "data": String::from_utf8_lossy(slice),
    })))
}

async fn fork_branch(
    State(k): State<Arc<Kernel>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    let id = BranchId::parse(&id)?;
    auth.require_owner(&k.branch_owner(&id)?)?;
    let branch = k.fork_branch(&id)?;
    Ok(Json(
        serde_json::to_value(&branch).map_err(KernelError::from)?,
    ))
}

#[derive(Deserialize, Default)]
struct DiffRequest {
    #[serde(default)]
    since: Option<StateId>,
}

async fn diff_branch(
    State(k): State<Arc<Kernel>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
    Json(req): Json<DiffRequest>,
) -> ApiResult<impl IntoResponse> {
    let id = BranchId::parse(&id)?;
    auth.require_owner(&k.branch_owner(&id)?)?;
    let changes = k.branch_diff(&id, req.since.as_ref())?;
    Ok(Json(
        serde_json::to_value(&changes).map_err(KernelError::from)?,
    ))
}

#[derive(Deserialize)]
struct MergeRequest {
    source: BranchId,
    actor: PrincipalId,
}

async fn merge_branch(
    State(k): State<Arc<Kernel>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
    Json(req): Json<MergeRequest>,
) -> ApiResult<impl IntoResponse> {
    let id = BranchId::parse(&id)?;
    auth.require_owner(&k.branch_owner(&id)?)?;
    let actor = auth.act_as(&req.actor)?;
    let node = k.merge_branch(&id, &req.source, &actor)?;
    Ok(Json(
        serde_json::to_value(&node).map_err(KernelError::from)?,
    ))
}

async fn discard_branch(
    State(k): State<Arc<Kernel>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    let branch = BranchId::parse(&id)?;
    auth.require_owner(&k.branch_owner(&branch)?)?;
    k.discard_branch(&branch).await?;
    Ok(Json(serde_json::json!({ "discarded": id })))
}

async fn compare_branches(
    State(k): State<Arc<Kernel>>,
    Extension(auth): Extension<AuthContext>,
    Path((a, b)): Path<(String, String)>,
) -> ApiResult<impl IntoResponse> {
    let (a, b) = (BranchId::parse(&a)?, BranchId::parse(&b)?);
    auth.require_owner(&k.branch_owner(&a)?)?;
    auth.require_owner(&k.branch_owner(&b)?)?;
    let cmp = k.branch_compare(&a, &b)?;
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

async fn request_capability(
    State(k): State<Arc<Kernel>>,
    Extension(auth): Extension<AuthContext>,
    Json(req): Json<CapabilityRequest>,
) -> ApiResult<impl IntoResponse> {
    let principal = auth.act_as(&req.principal)?;
    let lease = k.request_capability(
        &principal,
        &Operation::new(req.operation),
        &req.params,
        req.branch.as_ref(),
    )?;
    Ok((
        StatusCode::CREATED,
        Json(serde_json::to_value(&lease).map_err(KernelError::from)?),
    ))
}

#[derive(Deserialize)]
struct DelegateRequest {
    delegator: PrincipalId,
    parent_lease: LeaseId,
    delegatee: PrincipalId,
    #[serde(default)]
    constraints: IndexMap<String, Constraint>,
    uses: u32,
    expires_at: chrono::DateTime<chrono::Utc>,
    #[serde(default = "ResourceBudget::zero")]
    budget: ResourceBudget,
}

async fn delegate_capability(
    State(k): State<Arc<Kernel>>,
    Extension(auth): Extension<AuthContext>,
    Json(req): Json<DelegateRequest>,
) -> ApiResult<impl IntoResponse> {
    let delegator = auth.act_as(&req.delegator)?;
    let lease = k.delegate(
        &delegator,
        &req.parent_lease,
        &req.delegatee,
        req.constraints,
        req.uses,
        req.expires_at,
        req.budget,
    )?;
    Ok((
        StatusCode::CREATED,
        Json(serde_json::to_value(&lease).map_err(KernelError::from)?),
    ))
}

#[derive(Deserialize)]
struct RevokeRequest {
    lease: LeaseId,
}

async fn revoke_capability(
    State(k): State<Arc<Kernel>>,
    Extension(auth): Extension<AuthContext>,
    Json(req): Json<RevokeRequest>,
) -> ApiResult<impl IntoResponse> {
    auth.require_role(Role::Admin)?;
    let revoked = k.revoke(&req.lease)?;
    Ok(Json(serde_json::json!({ "revoked": revoked })))
}

async fn list_capabilities(
    State(k): State<Arc<Kernel>>,
    Extension(auth): Extension<AuthContext>,
    Path(principal): Path<String>,
) -> ApiResult<impl IntoResponse> {
    let principal = PrincipalId::parse(&principal)?;
    auth.require_owner(&principal)?;
    let leases = k
        .leases()
        .active_for_principal(&principal, chrono::Utc::now())
        .map_err(KernelError::from)?;
    Ok(Json(
        serde_json::to_value(&leases).map_err(KernelError::from)?,
    ))
}

async fn get_effect(
    State(k): State<Arc<Kernel>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    let effect = k.effect(&EffectId::parse(&id)?)?;
    auth.require_owner(&k.branch_owner(&effect.branch)?)?;
    Ok(Json(
        serde_json::to_value(&effect).map_err(KernelError::from)?,
    ))
}

async fn prepare_effect(
    State(k): State<Arc<Kernel>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    let id = EffectId::parse(&id)?;
    auth.require_owner(&k.branch_owner(&k.effect(&id)?.branch)?)?;
    let prepared = k.prepare_effect(&id).await?;
    Ok(Json(serde_json::json!({
        "preview": prepared.preview,
        "observed_preconditions": prepared.observed_preconditions,
    })))
}

#[derive(Deserialize)]
struct ApproveRequest {
    approver: PrincipalId,
}

async fn approve_effect(
    State(k): State<Arc<Kernel>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
    Json(req): Json<ApproveRequest>,
) -> ApiResult<impl IntoResponse> {
    auth.require_role(Role::Approver)?;
    // The recorded approver is the authenticated principal, never a
    // body-supplied one (in disabled mode the body is trusted).
    let approver = auth.principal.clone().unwrap_or(req.approver);
    k.approve_effect(&EffectId::parse(&id)?, &approver)?;
    Ok(Json(serde_json::json!({ "approved": id })))
}

async fn commit_effect(
    State(k): State<Arc<Kernel>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    let id = EffectId::parse(&id)?;
    auth.require_owner(&k.branch_owner(&k.effect(&id)?.branch)?)?;
    let receipt = k.commit_effect(&id).await?;
    Ok(Json(
        serde_json::to_value(&receipt).map_err(KernelError::from)?,
    ))
}

async fn compensate_effect(
    State(k): State<Arc<Kernel>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    let id = EffectId::parse(&id)?;
    auth.require_owner(&k.branch_owner(&k.effect(&id)?.branch)?)?;
    let receipt = k.compensate_effect(&id).await?;
    Ok(Json(
        serde_json::to_value(&receipt).map_err(KernelError::from)?,
    ))
}

/// Run in-doubt recovery: resolve effects parked in phase `committing`
/// through each connector's idempotency probe.
async fn recover_effects(
    State(k): State<Arc<Kernel>>,
    Extension(auth): Extension<AuthContext>,
) -> ApiResult<impl IntoResponse> {
    auth.require_role(Role::Admin)?;
    let resolutions = k.recover_in_doubt_effects().await?;
    Ok(Json(serde_json::json!({
        "resolutions": resolutions
            .into_iter()
            .map(|(effect, resolution)| serde_json::json!({
                "effect": effect, "resolution": resolution,
            }))
            .collect::<Vec<_>>(),
    })))
}

/// Operator verdict on an in-doubt effect: `{"outcome": "committed",
/// "response": {...}}` or `{"outcome": "aborted", "reason": "..."}`.
async fn resolve_effect(
    State(k): State<Arc<Kernel>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
    Json(req): Json<ak_effect_broker::OperatorResolution>,
) -> ApiResult<impl IntoResponse> {
    auth.require_role(Role::Admin)?;
    let receipt = k.resolve_in_doubt_effect(&EffectId::parse(&id)?, req)?;
    Ok(Json(
        serde_json::json!({ "resolved": id, "receipt": receipt }),
    ))
}

#[derive(Deserialize, Default)]
struct TraceParams {
    #[serde(default)]
    episode: Option<String>,
    #[serde(default)]
    branch: Option<String>,
    #[serde(default)]
    step: Option<String>,
    #[serde(default)]
    principal: Option<String>,
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
}

async fn trace_query(
    State(k): State<Arc<Kernel>>,
    Extension(auth): Extension<AuthContext>,
    Query(p): Query<TraceParams>,
) -> ApiResult<impl IntoResponse> {
    match &p.episode {
        Some(e) => auth.require_owner(&k.episode_owner(&EpisodeId::parse(e)?)?)?,
        None => auth.require_role(Role::Admin)?,
    }
    let q = TraceQuery {
        episode: p.episode.as_deref().map(EpisodeId::parse).transpose()?,
        branch: p.branch.as_deref().map(BranchId::parse).transpose()?,
        step: p
            .step
            .as_deref()
            .map(ak_core::ids::StepId::parse)
            .transpose()?,
        principal: p.principal.as_deref().map(PrincipalId::parse).transpose()?,
        kinds: p
            .kind
            .as_deref()
            .and_then(EventKind::parse)
            .into_iter()
            .collect(),
        limit: p.limit,
        ..TraceQuery::default()
    };
    let events = k.trace_query(&q)?;
    Ok(Json(
        serde_json::to_value(&events).map_err(KernelError::from)?,
    ))
}

async fn explain_step(
    State(k): State<Arc<Kernel>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    let explanation = k.step_explain(&ak_core::ids::StepId::parse(&id)?)?;
    auth.require_owner(&explanation.principal)?;
    Ok(Json(
        serde_json::to_value(&explanation).map_err(KernelError::from)?,
    ))
}

async fn retry_step(
    State(k): State<Arc<Kernel>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
) -> ApiResult<Response> {
    let id = ak_core::ids::StepId::parse(&id)?;
    auth.require_owner(&k.step_explain(&id)?.principal)?;
    let result = k.step_retry(&id).await?;
    if let ak_core::Observation::Denied { denial } = &result.observation {
        let envelope = ErrorEnvelope {
            code: "DENIED".into(),
            message: denial.reason.clone(),
            denial: Some(denial.clone()),
        };
        return Ok((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "step": result.step,
                "state": result.state,
                "observation": result.observation,
                "error": envelope,
            })),
        )
            .into_response());
    }
    Ok(Json(serde_json::to_value(&result).map_err(KernelError::from)?).into_response())
}

#[derive(Deserialize, Default)]
struct ListEffectsParams {
    #[serde(default)]
    phase: Option<String>,
}

async fn list_effects(
    State(k): State<Arc<Kernel>>,
    Extension(auth): Extension<AuthContext>,
    Query(p): Query<ListEffectsParams>,
) -> ApiResult<impl IntoResponse> {
    auth.require_role(Role::Admin)?;
    let effects = k.list_effects(p.phase.as_deref())?;
    Ok(Json(
        serde_json::to_value(&effects).map_err(KernelError::from)?,
    ))
}

#[derive(Deserialize, Default)]
struct ReplayRequestBody {
    /// `audit`: inclusive ledger sequence range.
    #[serde(default)]
    seq_from: Option<i64>,
    #[serde(default)]
    seq_to: Option<i64>,
    /// `sandbox`: the recorded step to re-execute.
    #[serde(default)]
    step: Option<String>,
    /// `live`: the recorded effect whose contract is re-committed, and the
    /// principal approving the new commit.
    #[serde(default)]
    effect: Option<String>,
    #[serde(default)]
    approver: Option<String>,
}

async fn replay(
    State(k): State<Arc<Kernel>>,
    Extension(auth): Extension<AuthContext>,
    Path(mode): Path<String>,
    Json(req): Json<ReplayRequestBody>,
) -> ApiResult<Response> {
    match mode.as_str() {
        "audit" => {
            auth.require_role(Role::Admin)?;
            let (from, to) = (req.seq_from.unwrap_or(1), req.seq_to.unwrap_or(i64::MAX));
            let events = k.replay_audit(from, to)?;
            Ok(Json(serde_json::json!({ "mode": "audit", "events": events })).into_response())
        }
        "sandbox" => {
            let step = req.step.as_deref().ok_or_else(|| {
                ApiError::Kernel(KernelError::Other("sandbox replay requires `step`".into()))
            })?;
            let step = ak_core::ids::StepId::parse(step)?;
            auth.require_owner(&k.step_explain(&step)?.principal)?;
            let report = k.replay_sandbox(&step).await?;
            Ok(Json(serde_json::to_value(&report).map_err(KernelError::from)?).into_response())
        }
        "live" => {
            auth.require_role(Role::Approver)?;
            let effect = req.effect.as_deref().ok_or_else(|| {
                ApiError::Kernel(KernelError::Other("live replay requires `effect`".into()))
            })?;
            let approver = req.approver.as_deref().ok_or_else(|| {
                ApiError::Kernel(KernelError::Other("live replay requires `approver`".into()))
            })?;
            let approver = auth.act_as(&PrincipalId::parse(approver)?)?;
            let receipt = k.replay_live(&EffectId::parse(effect)?, &approver).await?;
            Ok(Json(serde_json::to_value(&receipt).map_err(KernelError::from)?).into_response())
        }
        other => Err(ApiError::Kernel(KernelError::InvalidId {
            expected_prefix: "audit|sandbox|live",
            got: other.to_string(),
        })),
    }
}

async fn get_receipt(
    State(k): State<Arc<Kernel>>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    auth.require_role(Role::Admin)?;
    let receipt = k.receipt(&ReceiptId::parse(&id)?)?;
    Ok(Json(
        serde_json::to_value(&receipt).map_err(KernelError::from)?,
    ))
}

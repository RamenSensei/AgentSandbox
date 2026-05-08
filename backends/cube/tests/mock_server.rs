//! Unit tests for the cube adapter against an in-process axum mock server.

use ak_backend_cube::{CubeBackend, CubeConfig};
use ak_core::action::ActionKind;
use ak_core::budget::ResourceBudget;
use ak_core::error::KernelError;
use ak_core::ids::{BranchId, PrincipalId, StateId};
use ak_core::traits::{Backend, ExecutionRequest};
use axum::extract::Path;
use axum::routing::{delete, post};
use axum::{Json, Router};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

static SANDBOX_SEQ: AtomicUsize = AtomicUsize::new(0);

async fn spawn_mock() -> String {
    let app = Router::new()
        .route(
            "/v1/sandboxes",
            post(|Json(_body): Json<serde_json::Value>| async {
                let n = SANDBOX_SEQ.fetch_add(1, Ordering::SeqCst);
                Json(serde_json::json!({"sandbox_id": format!("sb-{n}")}))
            }),
        )
        .route(
            "/v1/sandboxes/:id/exec",
            post(|Path(id): Path<String>, Json(body): Json<serde_json::Value>| async move {
                let cmd = body["command"].as_str().unwrap_or_default().to_string();
                Json(serde_json::json!({
                    "exit_code": 0,
                    "stdout": format!("{id}:{cmd}"),
                    "stderr": "",
                    "duration_ms": 42
                }))
            }),
        )
        .route(
            "/v1/sandboxes/:id/snapshot",
            post(|Path(id): Path<String>| async move {
                Json(serde_json::json!({"snapshot_id": format!("snap-of-{id}")}))
            }),
        )
        .route(
            "/v1/snapshots/:id/clone",
            post(|Path(id): Path<String>| async move {
                Json(serde_json::json!({"sandbox_id": format!("clone-from-{id}")}))
            }),
        )
        .route("/v1/sandboxes/:id", delete(|| async { Json(serde_json::json!({})) }));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}")
}

fn shell_req(branch: &str, state: &str, cmd: &str) -> ExecutionRequest {
    ExecutionRequest {
        branch: BranchId(branch.into()),
        base_state: StateId(state.into()),
        actor: PrincipalId("pr-t".into()),
        action: ActionKind::Shell { command: cmd.into(), cwd: None, env: BTreeMap::new() },
        budget: ResourceBudget::step_default(),
        writable_prefixes: vec![],
        readable_prefixes: vec![],
        egress_domains: vec![],
    }
}

#[tokio::test]
async fn exec_happy_path() {
    let endpoint = spawn_mock().await;
    let backend = CubeBackend::new(CubeConfig::new(endpoint)).unwrap();
    let out = backend.execute(shell_req("br-1", "st-1", "echo hi")).await.unwrap();
    assert_eq!(out.exit_code, 0);
    assert!(String::from_utf8_lossy(&out.stdout).ends_with(":echo hi"));
    assert_eq!(out.usage.cpu_ms, 42);
}

#[tokio::test]
async fn fork_snapshots_and_clones() {
    let endpoint = spawn_mock().await;
    let backend = Arc::new(CubeBackend::new(CubeConfig::new(endpoint)).unwrap());
    // Unknown state: honest "no native fork" answer.
    assert!(!backend.fork(&StateId("st-unknown".into()), &BranchId("br-x".into())).await.unwrap());
    // Execute to register the state, then fork it.
    backend.execute(shell_req("br-1", "st-42", "true")).await.unwrap();
    let forked = backend.fork(&StateId("st-42".into()), &BranchId("br-2".into())).await.unwrap();
    assert!(forked);
    // The forked branch executes in the cloned sandbox.
    let out = backend.execute(shell_req("br-2", "st-43", "pwd")).await.unwrap();
    assert!(String::from_utf8_lossy(&out.stdout).starts_with("clone-from-snap-of-"));
}

#[tokio::test]
async fn unreachable_endpoint_maps_to_backend_unavailable() {
    let backend = CubeBackend::new(CubeConfig::new("http://127.0.0.1:1")).unwrap();
    let err = backend.execute(shell_req("br-1", "st-1", "true")).await.unwrap_err();
    match err {
        KernelError::BackendUnavailable { backend, .. } => assert_eq!(backend, "cube"),
        other => panic!("expected BackendUnavailable, got {other:?}"),
    }
}

#[tokio::test]
async fn http_error_status_maps_to_backend_unavailable() {
    // Mock that always answers 500.
    let app = Router::new().route(
        "/v1/sandboxes",
        post(|| async {
            (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "boom")
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let backend = CubeBackend::new(CubeConfig::new(format!("http://{addr}"))).unwrap();
    let err = backend.execute(shell_req("br-1", "st-1", "true")).await.unwrap_err();
    match err {
        KernelError::BackendUnavailable { reason, .. } => assert!(reason.contains("500")),
        other => panic!("expected BackendUnavailable, got {other:?}"),
    }
}

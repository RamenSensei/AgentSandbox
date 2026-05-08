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

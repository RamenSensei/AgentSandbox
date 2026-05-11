//! Unit tests for the forkd adapter against an in-process axum mock server.

use ak_backend_forkd::{ForkdBackend, ForkdConfig};
use ak_core::action::ActionKind;
use ak_core::budget::ResourceBudget;
use ak_core::error::KernelError;
use ak_core::ids::{BranchId, PrincipalId, StateId};
use ak_core::traits::{Backend, ExecutionRequest};
use axum::extract::Path;
use axum::routing::post;
use axum::{Json, Router};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};

static CHILD_SEQ: AtomicUsize = AtomicUsize::new(0);

async fn spawn_mock() -> String {
    let app = Router::new()
        .route(
            "/v1/parents",
            post(|| async { Json(serde_json::json!({"parent_id": "p-warm"})) }),
        )
        .route(
            "/v1/parents/:id/fork",
            post(|Path(id): Path<String>| async move {
                let n = CHILD_SEQ.fetch_add(1, Ordering::SeqCst);
                Json(serde_json::json!({"child_id": format!("c-{n}-of-{id}")}))
            }),
        )
        .route(
            "/v1/children/:id/fork",
            post(|Path(id): Path<String>| async move {
                Json(serde_json::json!({"child_id": format!("cow-of-{id}")}))
            }),
        )
        .route(
            "/v1/children/:id/exec",
            post(|Path(id): Path<String>, Json(body): Json<serde_json::Value>| async move {
                let cmd = body["command"].as_str().unwrap_or_default().to_string();
                Json(serde_json::json!({
                    "exit_code": 0,
                    "stdout": format!("{id}|{cmd}"),
                    "stderr": "",
                    "duration_ms": 7
                }))
            }),
        );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}")
}

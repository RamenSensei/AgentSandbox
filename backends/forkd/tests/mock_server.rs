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
            post(
                |Path(id): Path<String>, Json(body): Json<serde_json::Value>| async move {
                    let cmd = body["command"].as_str().unwrap_or_default().to_string();
                    Json(serde_json::json!({
                        "exit_code": 0,
                        "stdout": format!("{id}|{cmd}"),
                        "stderr": "",
                        "duration_ms": 7
                    }))
                },
            ),
        );

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
        action: ActionKind::Shell {
            command: cmd.into(),
            cwd: None,
            env: BTreeMap::new(),
        },
        budget: ResourceBudget::step_default(),
        writable_prefixes: vec![],
        readable_prefixes: vec![],
        egress_domains: vec![],
    }
}

#[tokio::test]
async fn exec_forks_a_child_from_the_warm_parent() {
    let backend = ForkdBackend::new(ForkdConfig::new(spawn_mock().await)).unwrap();
    let out = backend
        .execute(shell_req("br-1", "st-1", "uname"))
        .await
        .unwrap();
    assert_eq!(out.exit_code, 0);
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        stdout.contains("of-p-warm") && stdout.ends_with("|uname"),
        "{stdout}"
    );
    assert_eq!(out.usage.cpu_ms, 7);
    // Same branch reuses the same child.
    let again = backend
        .execute(shell_req("br-1", "st-2", "id"))
        .await
        .unwrap();
    let stdout2 = String::from_utf8_lossy(&again.stdout).into_owned();
    assert_eq!(stdout.split('|').next(), stdout2.split('|').next());
}

#[tokio::test]
async fn fork_fans_out_a_live_child() {
    let backend = ForkdBackend::new(ForkdConfig::new(spawn_mock().await)).unwrap();
    assert!(!backend
        .fork(&StateId("st-nope".into()), &BranchId("br-b".into()))
        .await
        .unwrap());
    backend
        .execute(shell_req("br-a", "st-9", "true"))
        .await
        .unwrap();
    assert!(backend
        .fork(&StateId("st-9".into()), &BranchId("br-b".into()))
        .await
        .unwrap());
    let out = backend
        .execute(shell_req("br-b", "st-10", "hostname"))
        .await
        .unwrap();
    assert!(String::from_utf8_lossy(&out.stdout).starts_with("cow-of-c-"));
}

#[tokio::test]
async fn write_file_is_translated_to_a_shell_exec() {
    let backend = ForkdBackend::new(ForkdConfig::new(spawn_mock().await)).unwrap();
    let mut r = shell_req("br-1", "st-1", "");
    r.action = ActionKind::WriteFile {
        path: "a/b.txt".into(),
        contents_b64: "aGk=".into(),
    };
    let out = backend.execute(r).await.unwrap();
    assert_eq!(out.exit_code, 0);
    assert_eq!(out.paths_written, vec!["a/b.txt".to_string()]);
    assert!(String::from_utf8_lossy(&out.stdout).contains("base64 -d"));
}

#[tokio::test]
async fn unreachable_endpoint_maps_to_backend_unavailable() {
    let backend = ForkdBackend::new(ForkdConfig::new("http://127.0.0.1:1")).unwrap();
    let err = backend
        .execute(shell_req("br-1", "st-1", "true"))
        .await
        .unwrap_err();
    match err {
        KernelError::BackendUnavailable { backend, .. } => assert_eq!(backend, "forkd"),
        other => panic!("expected BackendUnavailable, got {other:?}"),
    }
}

#[tokio::test]
async fn exec_wire_request_carries_confinement_and_budget() {
    // Mock that echoes the received exec body back as stdout.
    let app = Router::new()
        .route(
            "/v1/parents",
            post(|| async { Json(serde_json::json!({"parent_id": "p-echo"})) }),
        )
        .route(
            "/v1/parents/:id/fork",
            post(|| async { Json(serde_json::json!({"child_id": "c-echo"})) }),
        )
        .route(
            "/v1/children/:id/exec",
            post(|Json(body): Json<serde_json::Value>| async move {
                Json(serde_json::json!({
                    "exit_code": 0,
                    "stdout": body.to_string(),
                    "stderr": "",
                    "duration_ms": 1
                }))
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let backend = ForkdBackend::new(ForkdConfig::new(format!("http://{addr}"))).unwrap();
    let mut req = shell_req("br-1", "st-1", "true");
    req.writable_prefixes = vec!["src/".into()];
    req.readable_prefixes = vec!["docs/".into()];
    req.egress_domains = vec!["example.com".into()];
    let out = backend.execute(req).await.unwrap();
    let body: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("stdout is echoed wire body");
    assert_eq!(body["writable_prefixes"], serde_json::json!(["src/"]));
    assert_eq!(body["readable_prefixes"], serde_json::json!(["docs/"]));
    assert_eq!(body["egress_domains"], serde_json::json!(["example.com"]));
    assert!(body["budget"]["cpu_ms"].as_u64().unwrap() > 0);
}

#[tokio::test]
async fn invalid_remote_id_is_rejected() {
    let app = Router::new().route(
        "/v1/parents",
        post(|| async { Json(serde_json::json!({"parent_id": "p/../evil"})) }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let backend = ForkdBackend::new(ForkdConfig::new(format!("http://{addr}"))).unwrap();
    let err = backend
        .execute(shell_req("br-1", "st-1", "true"))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("invalid id"), "{err}");
}

#[test]
fn non_loopback_http_endpoint_is_rejected() {
    let err = ForkdBackend::new(ForkdConfig::new("http://forkd.example.com"))
        .err()
        .expect("expected config error");
    assert!(err.to_string().contains("https"), "{err}");
    ForkdBackend::new(ForkdConfig::new("http://127.0.0.1:9")).unwrap();
    ForkdBackend::new(ForkdConfig::new("https://forkd.example.com")).unwrap();
}

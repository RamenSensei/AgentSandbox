//! Unit tests for the cube adapter against an in-process axum mock server.

use ak_backend_cube::{CubeBackend, CubeConfig};
use ak_core::action::ActionKind;
use ak_core::budget::ResourceBudget;
use ak_core::error::{KernelError, KernelResult};
use ak_core::hash::{hash_bytes, ContentHash};
use ak_core::ids::{BranchId, PrincipalId, StateId};
use ak_core::sync::{SyncEntry, SyncManifest};
use ak_core::traits::{Backend, ExecutionRequest, StateProvider};
use axum::extract::Path;
use axum::routing::{delete, post};
use axum::{Json, Router};
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

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
            post(
                |Path(id): Path<String>, Json(body): Json<serde_json::Value>| async move {
                    let cmd = body["command"].as_str().unwrap_or_default().to_string();
                    Json(serde_json::json!({
                        "exit_code": 0,
                        "stdout": format!("{id}:{cmd}"),
                        "stderr": "",
                        "duration_ms": 42
                    }))
                },
            ),
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
        .route(
            "/v1/sandboxes/:id",
            delete(|| async { Json(serde_json::json!({})) }),
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
async fn exec_happy_path() {
    let endpoint = spawn_mock().await;
    let backend = CubeBackend::new(CubeConfig::new(endpoint)).unwrap();
    let out = backend
        .execute(shell_req("br-1", "st-1", "echo hi"))
        .await
        .unwrap();
    assert_eq!(out.exit_code, 0);
    assert!(String::from_utf8_lossy(&out.stdout).ends_with(":echo hi"));
    assert_eq!(out.usage.cpu_ms, 42);
}

#[tokio::test]
async fn fork_snapshots_and_clones() {
    let endpoint = spawn_mock().await;
    let backend = Arc::new(CubeBackend::new(CubeConfig::new(endpoint)).unwrap());
    // Unknown state: honest "no native fork" answer.
    assert!(!backend
        .fork(&StateId("st-unknown".into()), &BranchId("br-x".into()))
        .await
        .unwrap());
    // Execute to register the state, then fork it.
    backend
        .execute(shell_req("br-1", "st-42", "true"))
        .await
        .unwrap();
    let forked = backend
        .fork(&StateId("st-42".into()), &BranchId("br-2".into()))
        .await
        .unwrap();
    assert!(forked);
    // The forked branch executes in the cloned sandbox.
    let out = backend
        .execute(shell_req("br-2", "st-43", "pwd"))
        .await
        .unwrap();
    assert!(String::from_utf8_lossy(&out.stdout).starts_with("clone-from-snap-of-"));
}

#[tokio::test]
async fn unreachable_endpoint_maps_to_backend_unavailable() {
    let backend = CubeBackend::new(CubeConfig::new("http://127.0.0.1:1")).unwrap();
    let err = backend
        .execute(shell_req("br-1", "st-1", "true"))
        .await
        .unwrap_err();
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
        post(|| async { (axum::http::StatusCode::INTERNAL_SERVER_ERROR, "boom") }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let backend = CubeBackend::new(CubeConfig::new(format!("http://{addr}"))).unwrap();
    let err = backend
        .execute(shell_req("br-1", "st-1", "true"))
        .await
        .unwrap_err();
    match err {
        KernelError::BackendUnavailable { reason, .. } => assert!(reason.contains("500")),
        other => panic!("expected BackendUnavailable, got {other:?}"),
    }
}

#[tokio::test]
async fn exec_wire_request_carries_confinement_and_budget() {
    // Mock that echoes the received exec body back as stdout.
    let app = Router::new()
        .route(
            "/v1/sandboxes",
            post(|| async { Json(serde_json::json!({"sandbox_id": "sb-echo"})) }),
        )
        .route(
            "/v1/sandboxes/:id/exec",
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

    let backend = CubeBackend::new(CubeConfig::new(format!("http://{addr}"))).unwrap();
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
    // Service returns an id containing a path traversal.
    let app = Router::new().route(
        "/v1/sandboxes",
        post(|| async { Json(serde_json::json!({"sandbox_id": "../evil"})) }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let backend = CubeBackend::new(CubeConfig::new(format!("http://{addr}"))).unwrap();
    let err = backend
        .execute(shell_req("br-1", "st-1", "true"))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("invalid id"), "{err}");
}

#[test]
fn non_loopback_http_endpoint_is_rejected() {
    let err = CubeBackend::new(CubeConfig::new("http://cube.example.com"))
        .err()
        .expect("expected config error");
    assert!(err.to_string().contains("https"), "{err}");
    // Loopback http and any https are fine.
    CubeBackend::new(CubeConfig::new("http://127.0.0.1:9")).unwrap();
    CubeBackend::new(CubeConfig::new("http://localhost:9")).unwrap();
    CubeBackend::new(CubeConfig::new("https://cube.example.com")).unwrap();
}

// ---- State-sync tests against a stateful mock ------------------------------

/// Shared state of the sync-capable mock: an in-memory FS per sandbox.
/// path → (bytes, mode)
type Tree = BTreeMap<String, (Vec<u8>, u32)>;

#[derive(Default)]
struct SyncMockState {
    /// sandbox → tree
    fs: Mutex<HashMap<String, Tree>>,
    writes: AtomicUsize,
    fail_next_write: AtomicBool,
}

/// Mock implementing the full files API plus an exec that mutates the FS:
/// `put <path> <contents>` writes a file, `del <path>` removes one,
/// anything else is a no-op.
async fn spawn_sync_mock() -> (String, Arc<SyncMockState>) {
    let state = Arc::new(SyncMockState::default());
    let app = Router::new()
        .route(
            "/v1/sandboxes",
            post({
                let state = Arc::clone(&state);
                move |Json(_): Json<serde_json::Value>| {
                    let state = Arc::clone(&state);
                    async move {
                        let n = SANDBOX_SEQ.fetch_add(1, Ordering::SeqCst);
                        let id = format!("sb-{n}");
                        state.fs.lock().unwrap().insert(id.clone(), BTreeMap::new());
                        Json(serde_json::json!({"sandbox_id": id}))
                    }
                }
            }),
        )
        .route(
            "/v1/sandboxes/:id/exec",
            post({
                let state = Arc::clone(&state);
                move |Path(id): Path<String>, Json(body): Json<serde_json::Value>| {
                    let state = Arc::clone(&state);
                    async move {
                        let cmd = body["command"].as_str().unwrap_or_default().to_string();
                        let mut fs = state.fs.lock().unwrap();
                        let tree = fs.entry(id).or_default();
                        if let Some(rest) = cmd.strip_prefix("put ") {
                            let (path, contents) = rest.split_once(' ').unwrap();
                            tree.insert(path.into(), (contents.as_bytes().to_vec(), 0o644));
                        } else if let Some(path) = cmd.strip_prefix("del ") {
                            tree.remove(path);
                        }
                        Json(serde_json::json!({
                            "exit_code": 0, "stdout": "", "stderr": "", "duration_ms": 7
                        }))
                    }
                }
            }),
        )
        .route(
            "/v1/sandboxes/:id/files/write",
            post({
                let state = Arc::clone(&state);
                move |Path(id): Path<String>, Json(body): Json<serde_json::Value>| {
                    let state = Arc::clone(&state);
                    async move {
                        if state.fail_next_write.swap(false, Ordering::SeqCst) {
                            return Err(axum::http::StatusCode::INTERNAL_SERVER_ERROR);
                        }
                        state.writes.fetch_add(1, Ordering::SeqCst);
                        let bytes =
                            ak_core::b64::decode(body["contents_b64"].as_str().unwrap()).unwrap();
                        let mode = body["mode"].as_u64().unwrap_or(0o644) as u32;
                        state
                            .fs
                            .lock()
                            .unwrap()
                            .entry(id)
                            .or_default()
                            .insert(body["path"].as_str().unwrap().to_string(), (bytes, mode));
                        Ok(Json(serde_json::json!({})))
                    }
                }
            }),
        )
        .route(
            "/v1/sandboxes/:id/files/read",
            post({
                let state = Arc::clone(&state);
                move |Path(id): Path<String>, Json(body): Json<serde_json::Value>| {
                    let state = Arc::clone(&state);
                    async move {
                        let fs = state.fs.lock().unwrap();
                        let (bytes, _) = fs
                            .get(&id)
                            .and_then(|t| t.get(body["path"].as_str().unwrap()))
                            .cloned()
                            .unwrap_or_default();
                        Json(serde_json::json!({"contents_b64": ak_core::b64::encode(&bytes)}))
                    }
                }
            }),
        )
        .route(
            "/v1/sandboxes/:id/files/delete",
            post({
                let state = Arc::clone(&state);
                move |Path(id): Path<String>, Json(body): Json<serde_json::Value>| {
                    let state = Arc::clone(&state);
                    async move {
                        state
                            .fs
                            .lock()
                            .unwrap()
                            .entry(id)
                            .or_default()
                            .remove(body["path"].as_str().unwrap());
                        Json(serde_json::json!({}))
                    }
                }
            }),
        )
        .route(
            "/v1/sandboxes/:id/files/list",
            post({
                let state = Arc::clone(&state);
                move |Path(id): Path<String>| {
                    let state = Arc::clone(&state);
                    async move {
                        let fs = state.fs.lock().unwrap();
                        let files: Vec<serde_json::Value> = fs
                            .get(&id)
                            .map(|tree| {
                                tree.iter()
                                    .map(|(path, (bytes, mode))| {
                                        let hex = hash_bytes(bytes)
                                            .as_str()
                                            .trim_start_matches("sha256:")
                                            .to_string();
                                        serde_json::json!({
                                            "path": path, "sha256": hex, "mode": mode
                                        })
                                    })
                                    .collect()
                            })
                            .unwrap_or_default();
                        Json(serde_json::json!({ "files": files }))
                    }
                }
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
            post({
                let state = Arc::clone(&state);
                move |Path(id): Path<String>, Json(_): Json<serde_json::Value>| {
                    let state = Arc::clone(&state);
                    async move {
                        // Clone the source sandbox's tree byte-for-byte.
                        let source = id.trim_start_matches("snap-of-").to_string();
                        let clone_id = format!("clone-from-{id}");
                        let mut fs = state.fs.lock().unwrap();
                        let tree = fs.get(&source).cloned().unwrap_or_default();
                        fs.insert(clone_id.clone(), tree);
                        Json(serde_json::json!({"sandbox_id": clone_id}))
                    }
                }
            }),
        )
        .route(
            "/v1/sandboxes/:id",
            delete(|| async { Json(serde_json::json!({})) }),
        );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{addr}"), state)
}

/// In-memory [`StateProvider`]: states and blobs registered by the test.
#[derive(Default)]
struct MapProvider {
    manifests: Mutex<HashMap<StateId, SyncManifest>>,
    blobs: Mutex<HashMap<ContentHash, Vec<u8>>>,
}

impl MapProvider {
    fn add_state(&self, state: &str, files: &[(&str, &[u8], u32)]) {
        let mut manifest = SyncManifest::new();
        for (path, bytes, mode) in files {
            let blob = hash_bytes(bytes);
            self.blobs
                .lock()
                .unwrap()
                .insert(blob.clone(), bytes.to_vec());
            manifest.insert(path.to_string(), SyncEntry { blob, mode: *mode });
        }
        self.manifests
            .lock()
            .unwrap()
            .insert(StateId(state.into()), manifest);
    }
}

impl StateProvider for MapProvider {
    fn manifest(&self, state: &StateId) -> KernelResult<SyncManifest> {
        self.manifests
            .lock()
            .unwrap()
            .get(state)
            .cloned()
            .ok_or_else(|| KernelError::Other(format!("unknown state {state}")))
    }
    fn blob(&self, hash: &ContentHash) -> KernelResult<Vec<u8>> {
        self.blobs
            .lock()
            .unwrap()
            .get(hash)
            .cloned()
            .ok_or_else(|| KernelError::Other(format!("unknown blob {hash}")))
    }
}

fn sync_backend(endpoint: String, provider: Arc<MapProvider>) -> CubeBackend {
    CubeBackend::new(CubeConfig::new(endpoint))
        .unwrap()
        .with_state_provider(provider)
}

#[tokio::test]
async fn sync_pushes_base_state_and_pulls_the_delta() {
    let (endpoint, mock) = spawn_sync_mock().await;
    let provider = Arc::new(MapProvider::default());
    provider.add_state("st-base", &[("src/main.rs", b"fn main() {}", 0o644)]);
    let backend = sync_backend(endpoint, Arc::clone(&provider));

    let out = backend
        .execute(shell_req("br-1", "st-base", "put out.txt built"))
        .await
        .unwrap();

    // Push happened: the sandbox received the base tree before the command.
    assert_eq!(mock.writes.load(Ordering::SeqCst), 1, "one pushed file");
    // Pull happened: the delta carries exactly the file the command wrote.
    let delta = out.workspace_delta.expect("sync backends return a delta");
    assert_eq!(delta.upserts.len(), 1);
    assert_eq!(delta.upserts[0].path, "out.txt");
    assert_eq!(delta.upserts[0].contents, b"built");
    assert!(delta.deletes.is_empty());
    assert_eq!(out.paths_written, vec!["out.txt".to_string()]);
}

#[tokio::test]
async fn sync_is_content_addressed_across_steps() {
    let (endpoint, mock) = spawn_sync_mock().await;
    let provider = Arc::new(MapProvider::default());
    provider.add_state("st-0", &[("a.txt", b"alpha", 0o644)]);
    let backend = sync_backend(endpoint, Arc::clone(&provider));

    let out = backend
        .execute(shell_req("br-1", "st-0", "put b.txt beta"))
        .await
        .unwrap();
    assert_eq!(mock.writes.load(Ordering::SeqCst), 1);
    assert_eq!(out.workspace_delta.unwrap().upserts[0].path, "b.txt");

    // The kernel appends st-1 (= st-0 plus the pulled b.txt) and executes
    // the next step from it: the sandbox already holds exactly that tree,
    // so nothing is pushed again — sync-in is a no-op diff.
    provider.add_state(
        "st-1",
        &[("a.txt", b"alpha", 0o644), ("b.txt", b"beta", 0o644)],
    );
    let out2 = backend
        .execute(shell_req("br-1", "st-1", "del a.txt"))
        .await
        .unwrap();
    assert_eq!(
        mock.writes.load(Ordering::SeqCst),
        1,
        "an already-synced tree must push nothing"
    );
    let delta2 = out2.workspace_delta.unwrap();
    assert!(delta2.upserts.is_empty());
    assert_eq!(delta2.deletes, vec!["a.txt".to_string()]);
}

#[tokio::test]
async fn push_failure_poisons_the_sandbox_and_the_next_step_recreates_it() {
    let (endpoint, mock) = spawn_sync_mock().await;
    let provider = Arc::new(MapProvider::default());
    provider.add_state("st-0", &[("a.txt", b"alpha", 0o644)]);
    let backend = sync_backend(endpoint, Arc::clone(&provider));

    mock.fail_next_write.store(true, Ordering::SeqCst);
    let err = backend
        .execute(shell_req("br-1", "st-0", "true"))
        .await
        .unwrap_err();
    assert!(matches!(err, KernelError::BackendUnavailable { .. }));
    let poisoned_count = mock.fs.lock().unwrap().len();

    // The next step gets a fresh sandbox and a full re-push from base.
    let out = backend
        .execute(shell_req("br-1", "st-0", "noop"))
        .await
        .unwrap();
    assert!(out.workspace_delta.unwrap().is_empty());
    assert!(
        mock.fs.lock().unwrap().len() > poisoned_count,
        "a fresh sandbox must have been created after poisoning"
    );
    assert_eq!(
        mock.writes.load(Ordering::SeqCst),
        1,
        "full re-push of one file"
    );
}

#[tokio::test]
async fn fork_inherits_the_sync_view_and_reverse_diffs_to_the_base() {
    let (endpoint, mock) = spawn_sync_mock().await;
    let provider = Arc::new(MapProvider::default());
    provider.add_state("st-0", &[("a.txt", b"alpha", 0o644)]);
    let backend = sync_backend(endpoint, Arc::clone(&provider));

    // Step on br-1 from st-0 writes extra.txt; the sandbox tree is now past
    // st-0, and st-0 maps to this sandbox for forking.
    backend
        .execute(shell_req("br-1", "st-0", "put extra.txt data"))
        .await
        .unwrap();
    let writes_before = mock.writes.load(Ordering::SeqCst);

    assert!(backend
        .fork(&StateId("st-0".into()), &BranchId("br-2".into()))
        .await
        .unwrap());

    // The forked branch executes from st-0: the clone inherited the source
    // tree (with extra.txt), so sync-in must *reverse-diff* — delete the
    // file that st-0 does not contain, push nothing.
    let out = backend
        .execute(shell_req("br-2", "st-0", "noop"))
        .await
        .unwrap();
    assert_eq!(
        mock.writes.load(Ordering::SeqCst),
        writes_before,
        "a CoW clone of a shared tree must not re-push shared files"
    );
    assert!(out.workspace_delta.unwrap().is_empty());
    let fs = mock.fs.lock().unwrap();
    let clone_tree = fs
        .values()
        .find(|t| t.contains_key("a.txt") && !t.contains_key("extra.txt"))
        .expect("the clone must have been reverse-diffed back to st-0");
    assert_eq!(clone_tree.len(), 1);
}

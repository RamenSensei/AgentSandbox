//! Unit tests for the forkd adapter against an in-process axum mock server.

use ak_backend_forkd::{ForkdBackend, ForkdConfig};
use ak_core::action::ActionKind;
use ak_core::budget::ResourceBudget;
use ak_core::error::{KernelError, KernelResult};
use ak_core::hash::{hash_bytes, ContentHash};
use ak_core::ids::{BranchId, PrincipalId, StateId};
use ak_core::sync::{SyncEntry, SyncManifest};
use ak_core::traits::{Backend, ExecutionRequest, StateProvider};
use axum::extract::Path;
use axum::routing::post;
use axum::{Json, Router};
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

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
async fn fork_without_a_state_provider_falls_back() {
    let backend = ForkdBackend::new(ForkdConfig::new(spawn_mock().await)).unwrap();
    assert!(!backend
        .fork(&StateId("st-nope".into()), &BranchId("br-b".into()))
        .await
        .unwrap());
    backend
        .execute(shell_req("br-a", "st-9", "true"))
        .await
        .unwrap();
    assert!(!backend
        .fork(&StateId("st-9".into()), &BranchId("br-b".into()))
        .await
        .unwrap());
    assert!(!backend.profile().supports_fork);
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

// ---- State-sync tests against a stateful mock ------------------------------
//
// forkd syncs over the shell transport, so this mock interprets exactly the
// command shapes the adapter generates (`mkdir … | base64 -d`, `rm -rf`,
// `find … | sha256sum`, `stat -c`, `base64 --`) against an in-memory FS —
// the honest wire-level contract, without needing a GNU userland on the
// test host.

type Tree = BTreeMap<String, (Vec<u8>, u32)>;

#[derive(Default)]
struct ShellMockState {
    /// child → tree
    fs: Mutex<HashMap<String, Tree>>,
    push_writes: AtomicUsize,
    fail_ambiguous_exec: std::sync::atomic::AtomicBool,
    corrupt_next_read: AtomicBool,
    mutate_after_next_read: AtomicBool,
    mutate_next_clone: AtomicBool,
    block_next_exec: AtomicBool,
    exec_started: tokio::sync::Notify,
    release_exec: tokio::sync::Notify,
}

/// Strip one layer of POSIX single quoting (`'…'` with `'\''` escapes).
fn unq(s: &str) -> String {
    let s = s.trim();
    let inner = s
        .strip_prefix('\'')
        .and_then(|x| x.strip_suffix('\''))
        .unwrap_or(s);
    inner.replace(r"'\''", "'")
}

/// Interpret one adapter-generated sync command (or `put`/`del` test
/// mutations) against a child's tree. Returns (exit_code, stdout).
fn interpret(state: &ShellMockState, tree: &mut Tree, cmd: &str) -> (i32, String) {
    if let Some(rest) = cmd.strip_prefix("put ") {
        let (path, contents) = rest.split_once(' ').unwrap();
        tree.insert(path.into(), (contents.as_bytes().to_vec(), 0o644));
        return (0, String::new());
    }
    if let Some(path) = cmd.strip_prefix("del ") {
        tree.remove(path);
        return (0, String::new());
    }
    if let Some(rest) = cmd.strip_prefix("chmod ") {
        let (path, mode) = rest.split_once(' ').unwrap();
        if let Some((_, current_mode)) = tree.get_mut(path) {
            *current_mode = u32::from_str_radix(mode, 8).unwrap();
        }
        return (0, String::new());
    }
    if cmd.contains("| base64 -d > ") {
        // rm -rf 'P' && mkdir -p "$(dirname 'P')" && printf %s 'B64'
        // | base64 -d > 'P' && chmod M 'P'
        let (left, right) = cmd.split_once(" | base64 -d > ").unwrap();
        let b64 = unq(left.rsplit_once("printf %s ").unwrap().1);
        let (path_q, chmod) = right.split_once(" && chmod ").unwrap();
        let (mode, _) = chmod.split_once(' ').unwrap();
        let bytes = ak_core::b64::decode(&b64).unwrap();
        let mode = u32::from_str_radix(mode, 8).unwrap();
        state.push_writes.fetch_add(1, Ordering::SeqCst);
        tree.insert(unq(path_q), (bytes, mode));
        return (0, String::new());
    }
    if let Some(rest) = cmd.strip_prefix("rm -rf -- ") {
        for q in rest.split_whitespace() {
            tree.remove(&unq(q));
        }
        return (0, String::new());
    }
    if cmd.starts_with("find . ") && cmd.ends_with("| xargs -0 -r sha256sum --") {
        let out: String = tree
            .iter()
            .map(|(path, (bytes, _))| {
                let hex = hash_bytes(bytes)
                    .as_str()
                    .trim_start_matches("sha256:")
                    .to_string();
                format!("{hex}  ./{path}\n")
            })
            .collect();
        return (0, out);
    }
    if let Some(rest) = cmd.strip_prefix("stat -c '%a %n' -- ") {
        let mut out = String::new();
        for q in rest.split_whitespace() {
            let path = unq(q);
            let bare = path.strip_prefix("./").unwrap_or(&path);
            match tree.get(bare) {
                Some((_, mode)) => out.push_str(&format!("{mode:o} {path}\n")),
                None => return (1, String::new()),
            }
        }
        return (0, out);
    }
    if let Some(q) = cmd.strip_prefix("base64 -- ") {
        let path = unq(q);
        let bare = path.strip_prefix("./").unwrap_or(&path);
        let Some((mut bytes, _)) = tree.get(bare).cloned() else {
            return (1, String::new());
        };
        if state.corrupt_next_read.swap(false, Ordering::SeqCst) {
            bytes = b"different-from-listing".to_vec();
        }
        if state.mutate_after_next_read.swap(false, Ordering::SeqCst) {
            // The returned file remains self-consistent, but the tree has
            // moved after the first listing.
            tree.insert("late-drift.txt".into(), (b"late".to_vec(), 0o644));
        }
        return (0, ak_core::b64::encode(&bytes));
    }
    (0, String::new())
}

async fn spawn_shell_mock() -> (String, Arc<ShellMockState>) {
    let state = Arc::new(ShellMockState::default());
    let app = Router::new()
        .route(
            "/v1/parents",
            post(|| async { Json(serde_json::json!({"parent_id": "p-warm"})) }),
        )
        .route(
            "/v1/parents/:id/fork",
            post({
                let state = Arc::clone(&state);
                move |_: Path<String>| {
                    let state = Arc::clone(&state);
                    async move {
                        let n = CHILD_SEQ.fetch_add(1, Ordering::SeqCst);
                        let id = format!("c-{n}");
                        state.fs.lock().unwrap().insert(id.clone(), Tree::new());
                        Json(serde_json::json!({"child_id": id}))
                    }
                }
            }),
        )
        .route(
            "/v1/children/:id/fork",
            post({
                let state = Arc::clone(&state);
                move |Path(id): Path<String>| {
                    let state = Arc::clone(&state);
                    async move {
                        let clone_id = format!("cow-of-{id}");
                        let mut fs = state.fs.lock().unwrap();
                        let mut tree = fs.get(&id).cloned().unwrap_or_default();
                        if state.mutate_next_clone.swap(false, Ordering::SeqCst) {
                            tree.insert("clone-drift.txt".into(), (b"late".to_vec(), 0o644));
                        }
                        fs.insert(clone_id.clone(), tree);
                        Json(serde_json::json!({"child_id": clone_id}))
                    }
                }
            }),
        )
        .route(
            "/v1/children/:id/exec",
            post({
                let state = Arc::clone(&state);
                move |Path(id): Path<String>, Json(body): Json<serde_json::Value>| {
                    let state = Arc::clone(&state);
                    async move {
                        let cmd = body["command"].as_str().unwrap_or_default().to_string();
                        if cmd == "block" && state.block_next_exec.swap(false, Ordering::SeqCst) {
                            state.exec_started.notify_one();
                            state.release_exec.notified().await;
                        }
                        let mut fs = state.fs.lock().unwrap();
                        let tree = fs.entry(id).or_default();
                        if cmd == "mutate-then-fail"
                            && state.fail_ambiguous_exec.swap(false, Ordering::SeqCst)
                        {
                            tree.insert("ambiguous.txt".into(), (b"maybe".to_vec(), 0o644));
                            return Err(axum::http::StatusCode::INTERNAL_SERVER_ERROR);
                        }
                        let (exit_code, stdout) = interpret(&state, tree, &cmd);
                        Ok(Json(serde_json::json!({
                            "exit_code": exit_code, "stdout": stdout,
                            "stderr": "", "duration_ms": 3
                        })))
                    }
                }
            }),
        )
        .route(
            "/v1/children/:id",
            axum::routing::delete(|| async { Json(serde_json::json!({})) }),
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

#[tokio::test]
async fn shell_transport_sync_pushes_base_and_pulls_the_delta() {
    let (endpoint, mock) = spawn_shell_mock().await;
    let provider = Arc::new(MapProvider::default());
    provider.add_state(
        "st-base",
        &[
            ("src/main.rs", b"fn main() {}", 0o644),
            ("run.sh", b"#!/bin/sh", 0o755),
        ],
    );
    let backend = ForkdBackend::new(ForkdConfig::new(endpoint))
        .unwrap()
        .with_state_provider(Arc::clone(&provider) as Arc<dyn StateProvider>);

    let out = backend
        .execute(shell_req("br-1", "st-base", "put out.txt built"))
        .await
        .unwrap();

    assert_eq!(
        mock.push_writes.load(Ordering::SeqCst),
        2,
        "two pushed files"
    );
    let delta = out.workspace_delta.expect("sync returns a delta");
    assert_eq!(delta.upserts.len(), 1);
    assert_eq!(delta.upserts[0].path, "out.txt");
    assert_eq!(delta.upserts[0].contents, b"built");
    // The pushed executable kept its mode in the child.
    let fs = mock.fs.lock().unwrap();
    let tree = fs.values().next().unwrap();
    assert_eq!(tree.get("run.sh").unwrap().1, 0o755);
}

#[tokio::test]
async fn shell_transport_sync_is_content_addressed_across_steps() {
    let (endpoint, mock) = spawn_shell_mock().await;
    let provider = Arc::new(MapProvider::default());
    provider.add_state("st-0", &[("a.txt", b"alpha", 0o644)]);
    let backend = ForkdBackend::new(ForkdConfig::new(endpoint))
        .unwrap()
        .with_state_provider(Arc::clone(&provider) as Arc<dyn StateProvider>);

    backend
        .execute(shell_req("br-1", "st-0", "put b.txt beta"))
        .await
        .unwrap();
    assert_eq!(mock.push_writes.load(Ordering::SeqCst), 1);

    provider.add_state(
        "st-1",
        &[("a.txt", b"alpha", 0o644), ("b.txt", b"beta", 0o644)],
    );
    let out2 = backend
        .execute(shell_req("br-1", "st-1", "del a.txt"))
        .await
        .unwrap();
    assert_eq!(
        mock.push_writes.load(Ordering::SeqCst),
        1,
        "an already-synced tree must push nothing"
    );
    let delta2 = out2.workspace_delta.unwrap();
    assert!(delta2.upserts.is_empty());
    assert_eq!(delta2.deletes, vec!["a.txt".to_string()]);
}

#[tokio::test]
async fn live_child_drift_is_repaired_before_execution_and_never_cow_forked() {
    let (endpoint, mock) = spawn_shell_mock().await;
    let provider = Arc::new(MapProvider::default());
    provider.add_state("st-0", &[("a.txt", b"alpha", 0o644)]);
    let backend = ForkdBackend::new(ForkdConfig::new(endpoint))
        .unwrap()
        .with_state_provider(Arc::clone(&provider) as Arc<dyn StateProvider>);

    backend
        .execute(shell_req("br-1", "st-0", "noop"))
        .await
        .unwrap();
    let child = mock.fs.lock().unwrap().keys().next().unwrap().clone();
    mock.fs
        .lock()
        .unwrap()
        .get_mut(&child)
        .unwrap()
        .insert("a.txt".into(), (b"background-drift".to_vec(), 0o600));

    assert!(
        !backend
            .fork(&StateId("st-0".into()), &BranchId("br-drift".into()))
            .await
            .unwrap(),
        "a stale cache entry must not make a drifted child a CoW source"
    );
    let writes_before = mock.push_writes.load(Ordering::SeqCst);
    let out = backend
        .execute(shell_req("br-1", "st-0", "noop"))
        .await
        .unwrap();
    assert!(out.workspace_delta.unwrap().is_empty());
    assert_eq!(mock.push_writes.load(Ordering::SeqCst), writes_before + 1);
    assert_eq!(
        mock.fs.lock().unwrap()[&child]["a.txt"],
        (b"alpha".to_vec(), 0o644)
    );
}

#[tokio::test]
async fn list_read_hash_race_poisons_the_child() {
    let (endpoint, mock) = spawn_shell_mock().await;
    let provider = Arc::new(MapProvider::default());
    provider.add_state("st-0", &[]);
    let backend = ForkdBackend::new(ForkdConfig::new(endpoint))
        .unwrap()
        .with_state_provider(Arc::clone(&provider) as Arc<dyn StateProvider>);

    mock.corrupt_next_read.store(true, Ordering::SeqCst);
    let error = backend
        .execute(shell_req("br-1", "st-0", "put out.txt value"))
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("changed between list and read"),
        "unexpected error: {error}"
    );
}

#[tokio::test]
async fn post_read_tree_drift_poisons_the_child() {
    let (endpoint, mock) = spawn_shell_mock().await;
    let provider = Arc::new(MapProvider::default());
    provider.add_state("st-0", &[]);
    let backend = ForkdBackend::new(ForkdConfig::new(endpoint))
        .unwrap()
        .with_state_provider(Arc::clone(&provider) as Arc<dyn StateProvider>);

    mock.mutate_after_next_read.store(true, Ordering::SeqCst);
    let error = backend
        .execute(shell_req("br-1", "st-0", "put out.txt value"))
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("changed while its state delta was being pulled"),
        "unexpected error: {error}"
    );
    let poisoned_count = mock.fs.lock().unwrap().len();

    let out = backend
        .execute(shell_req("br-1", "st-0", "noop"))
        .await
        .unwrap();
    assert!(out.workspace_delta.unwrap().is_empty());
    assert!(
        mock.fs.lock().unwrap().len() > poisoned_count,
        "the drifted child must never be reused"
    );
}

#[tokio::test]
async fn ambiguous_exec_failure_poisons_the_child() {
    let (endpoint, mock) = spawn_shell_mock().await;
    let provider = Arc::new(MapProvider::default());
    provider.add_state("st-0", &[("a.txt", b"alpha", 0o644)]);
    let backend = ForkdBackend::new(ForkdConfig::new(endpoint))
        .unwrap()
        .with_state_provider(Arc::clone(&provider) as Arc<dyn StateProvider>);

    mock.fail_ambiguous_exec.store(true, Ordering::SeqCst);
    assert!(backend
        .execute(shell_req("br-1", "st-0", "mutate-then-fail"))
        .await
        .is_err());
    let poisoned_count = mock.fs.lock().unwrap().len();
    let out = backend
        .execute(shell_req("br-1", "st-0", "noop"))
        .await
        .unwrap();
    assert!(out.workspace_delta.unwrap().is_empty());
    assert!(mock.fs.lock().unwrap().len() > poisoned_count);
}

#[tokio::test]
async fn mode_only_change_is_pulled() {
    let (endpoint, _mock) = spawn_shell_mock().await;
    let provider = Arc::new(MapProvider::default());
    provider.add_state("st-0", &[("run.sh", b"#!/bin/sh\n", 0o644)]);
    let backend = ForkdBackend::new(ForkdConfig::new(endpoint))
        .unwrap()
        .with_state_provider(Arc::clone(&provider) as Arc<dyn StateProvider>);

    let out = backend
        .execute(shell_req("br-1", "st-0", "chmod run.sh 755"))
        .await
        .unwrap();
    let delta = out.workspace_delta.unwrap();
    assert_eq!(delta.upserts.len(), 1);
    assert_eq!(delta.upserts[0].path, "run.sh");
    assert_eq!(delta.upserts[0].contents, b"#!/bin/sh\n");
    assert_eq!(delta.upserts[0].mode, 0o755);
}

#[tokio::test]
async fn fork_uses_only_an_exact_current_manifest() {
    let (endpoint, mock) = spawn_shell_mock().await;
    let provider = Arc::new(MapProvider::default());
    provider.add_state("st-0", &[("a.txt", b"alpha", 0o644)]);
    let backend = ForkdBackend::new(ForkdConfig::new(endpoint))
        .unwrap()
        .with_state_provider(Arc::clone(&provider) as Arc<dyn StateProvider>);

    backend
        .execute(shell_req("br-1", "st-0", "put extra.txt data"))
        .await
        .unwrap();
    provider.add_state(
        "st-1",
        &[("a.txt", b"alpha", 0o644), ("extra.txt", b"data", 0o644)],
    );
    let writes_before = mock.push_writes.load(Ordering::SeqCst);

    assert!(backend
        .fork(&StateId("st-1".into()), &BranchId("br-2".into()))
        .await
        .unwrap());

    let out = backend
        .execute(shell_req("br-2", "st-1", "noop"))
        .await
        .unwrap();
    assert_eq!(
        mock.push_writes.load(Ordering::SeqCst),
        writes_before,
        "an exact CoW clone must not re-push shared files"
    );
    assert!(out.workspace_delta.unwrap().is_empty());
    let fs = mock.fs.lock().unwrap();
    let clone = fs.get("cow-of-c-0").or_else(|| {
        fs.iter()
            .find(|(k, _)| k.starts_with("cow-of-"))
            .map(|(_, v)| v)
    });
    let clone_tree = clone.expect("forked child exists");
    assert!(clone_tree.contains_key("a.txt") && clone_tree.contains_key("extra.txt"));
}

#[tokio::test]
async fn fork_reports_false_when_the_child_itself_is_not_exact() {
    let (endpoint, mock) = spawn_shell_mock().await;
    let provider = Arc::new(MapProvider::default());
    provider.add_state("st-0", &[("a.txt", b"alpha", 0o644)]);
    let backend = ForkdBackend::new(ForkdConfig::new(endpoint))
        .unwrap()
        .with_state_provider(Arc::clone(&provider) as Arc<dyn StateProvider>);
    backend
        .execute(shell_req("br-1", "st-0", "noop"))
        .await
        .unwrap();

    mock.mutate_next_clone.store(true, Ordering::SeqCst);
    assert!(
        !backend
            .fork(&StateId("st-0".into()), &BranchId("br-raced".into()))
            .await
            .unwrap(),
        "native CoW success requires the child itself to be exact"
    );

    let out = backend
        .execute(shell_req("br-raced", "st-0", "noop"))
        .await
        .unwrap();
    assert!(out.workspace_delta.unwrap().is_empty());
    let fs = mock.fs.lock().unwrap();
    let clone = fs
        .iter()
        .find(|(id, _)| id.starts_with("cow-of-"))
        .map(|(_, tree)| tree)
        .expect("forked child exists");
    assert!(!clone.contains_key("clone-drift.txt"));
}

#[tokio::test]
async fn fork_never_clones_a_matching_but_busy_child() {
    let (endpoint, mock) = spawn_shell_mock().await;
    let provider = Arc::new(MapProvider::default());
    provider.add_state("st-0", &[("a.txt", b"alpha", 0o644)]);
    let backend = Arc::new(
        ForkdBackend::new(ForkdConfig::new(endpoint))
            .unwrap()
            .with_state_provider(Arc::clone(&provider) as Arc<dyn StateProvider>),
    );
    backend
        .execute(shell_req("br-1", "st-0", "noop"))
        .await
        .unwrap();

    mock.block_next_exec.store(true, Ordering::SeqCst);
    let running = {
        let backend = Arc::clone(&backend);
        tokio::spawn(async move { backend.execute(shell_req("br-1", "st-0", "block")).await })
    };
    mock.exec_started.notified().await;
    assert!(!backend
        .fork(&StateId("st-0".into()), &BranchId("br-busy".into()))
        .await
        .unwrap());

    mock.release_exec.notify_one();
    running.await.unwrap().unwrap();
    assert!(backend
        .fork(&StateId("st-0".into()), &BranchId("br-idle".into()))
        .await
        .unwrap());
}

#[tokio::test]
async fn hostile_listing_lines_fail_the_step_loudly() {
    // A child whose listing contains an escaped (newline) filename or a
    // traversal path must fail the sync, never smuggle a file through.
    for stdout in [
        "\\abc123  ./evil\\nname\n",
        "0000000000000000000000000000000000000000000000000000000000000000  ../escape\n",
        "not-a-hash-line\n",
    ] {
        let stdout = stdout.to_string();
        let app = Router::new()
            .route(
                "/v1/parents",
                post(|| async { Json(serde_json::json!({"parent_id": "p"})) }),
            )
            .route(
                "/v1/parents/:id/fork",
                post(|_: Path<String>| async { Json(serde_json::json!({"child_id": "c-h"})) }),
            )
            .route(
                "/v1/children/:id/exec",
                post(move |Json(body): Json<serde_json::Value>| {
                    let stdout = stdout.clone();
                    async move {
                        let cmd = body["command"].as_str().unwrap_or_default();
                        let out = if cmd.starts_with("find . ") {
                            stdout.clone()
                        } else {
                            String::new()
                        };
                        Json(serde_json::json!({
                            "exit_code": 0, "stdout": out, "stderr": "", "duration_ms": 1
                        }))
                    }
                }),
            )
            .route(
                "/v1/children/:id",
                axum::routing::delete(|| async { Json(serde_json::json!({})) }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let provider = Arc::new(MapProvider::default());
        provider.add_state("st-0", &[]);
        let backend = ForkdBackend::new(ForkdConfig::new(format!("http://{addr}")))
            .unwrap()
            .with_state_provider(provider);
        let err = backend
            .execute(shell_req("br-1", "st-0", "noop"))
            .await
            .unwrap_err();
        assert!(
            matches!(err, KernelError::BackendUnavailable { .. }),
            "hostile listing must fail the step: {err:?}"
        );
    }
}

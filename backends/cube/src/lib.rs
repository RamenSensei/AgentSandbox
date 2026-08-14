//! # ak-backend-cube
//!
//! Remote adapter [`Backend`] for a **Cube** sandbox service exposing an
//! E2B-compatible HTTP control API with snapshot + clone (fork) support.
//! This is an *honest adapter*: it performs real HTTP calls via `reqwest` and
//! returns [`KernelError::BackendUnavailable`] when the control plane is
//! unreachable or answers with an error — there is no pretend-success path.
//!
//! ## Assumed control API (documented here because these APIs evolve)
//!
//! All requests carry `Authorization: Bearer <token>` when a token is set.
//!
//! | Method & path | Body | Response |
//! |---|---|---|
//! | `POST /v1/sandboxes` | `{"metadata": {"branch": "..."}}` | `{"sandbox_id": "sb-..."}` |
//! | `POST /v1/sandboxes/{id}/exec` | `{"command","cwd?","env","timeout_ms"}` | `{"exit_code","stdout","stderr","duration_ms"}` |
//! | `POST /v1/sandboxes/{id}/files/write` | `{"path","contents_b64","mode?"}` | `{}` |
//! | `POST /v1/sandboxes/{id}/files/read` | `{"path"}` | `{"contents_b64"}` |
//! | `POST /v1/sandboxes/{id}/files/delete` | `{"path"}` | `{}` |
//! | `POST /v1/sandboxes/{id}/files/list` | `{}` | `{"files":[{"path","sha256","mode"}]}` |
//! | `POST /v1/sandboxes/{id}/snapshot` | `{}` | `{"snapshot_id"}` |
//! | `POST /v1/snapshots/{id}/clone` | `{"metadata": {"branch": "..."}}` | `{"sandbox_id"}` |
//! | `DELETE /v1/sandboxes/{id}` | — | `{}` |
//!
//! `stdout`/`stderr` are UTF-8 text (the service performs lossy conversion);
//! file contents travel base64-encoded.
//!
//! Profile: isolation_strength **90** (microVM), `supports_fork = true`
//! (snapshot + clone), replay class `ProcessAndFilesystem` (snapshots capture
//! the process tree and filesystem).
//!
//! ## State sync (real state transitions, not audit-only excursions)
//!
//! With a [`StateProvider`] attached ([`CubeBackend::with_state_provider`]),
//! every step becomes a **real kernel state transition**:
//!
//! 1. **Push** — before executing, the adapter diffs what the sandbox's
//!    workspace currently holds against the step's base-state manifest and
//!    transfers only the difference (content-addressed: re-running on the
//!    same branch pushes nothing).
//! 2. **Pull** — after executing, it lists the remote tree
//!    (`files/list`), downloads only files whose hash changed, and returns
//!    them as a [`WorkspaceDelta`] for the kernel to validate against the
//!    step's confinement, apply to the branch workspace mirror, and
//!    snapshot into the state DAG.
//!
//! The cache/scratch tier ([`ak_core::state::DEFAULT_SNAPSHOT_IGNORES`])
//! never travels in either direction. Any push/pull failure **poisons** the
//! branch's sandbox: the adapter forgets it and deletes it best-effort, so
//! the next step re-materializes from the branch head instead of trusting a
//! half-synced tree. A service that misreports listing hashes can only
//! corrupt its own branch's delta — paths are still validated and confined
//! by the kernel before anything touches the workspace mirror.
//!
//! Without a provider the profile stays `syncs_state = false` and shell
//! steps are recorded as audit-only excursions, exactly as before.

use ak_core::action::ActionKind;
use ak_core::budget::ResourceBudget;
use ak_core::error::{KernelError, KernelResult};
use ak_core::hash::{hash_bytes, ContentHash};
use ak_core::ids::{BranchId, StateId};
use ak_core::replay::ReplayClass;
use ak_core::sync::{push_plan, syncable_path, SyncEntry, SyncManifest};
use ak_core::traits::{
    Backend, BackendProfile, ExecutionOutcome, ExecutionRequest, StateProvider, SyncedFile,
    WorkspaceDelta,
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

const BACKEND_NAME: &str = "cube";

/// Maximum bytes accepted in any control-plane response body.
const MAX_RESPONSE_BYTES: usize = 64 * 1024 * 1024;

fn config_error(reason: impl std::fmt::Display) -> KernelError {
    KernelError::Other(format!("{BACKEND_NAME} config error: {reason}"))
}

/// Enforce HTTPS for non-loopback control planes. Plain `http://` is allowed
/// only for loopback (localhost / 127.0.0.0/8 / ::1) dev endpoints.
fn validate_endpoint(endpoint: &str) -> KernelResult<()> {
    let url = reqwest::Url::parse(endpoint)
        .map_err(|e| config_error(format!("invalid endpoint `{endpoint}`: {e}")))?;
    match url.scheme() {
        "https" => Ok(()),
        "http" => {
            let host = url.host_str().unwrap_or_default();
            let bare = host.trim_start_matches('[').trim_end_matches(']');
            let loopback = bare.eq_ignore_ascii_case("localhost")
                || bare
                    .parse::<std::net::IpAddr>()
                    .map(|ip| ip.is_loopback())
                    .unwrap_or(false);
            if loopback {
                Ok(())
            } else {
                Err(config_error(format!(
                    "plain http endpoint `{endpoint}` is only allowed for loopback; use https"
                )))
            }
        }
        other => Err(config_error(format!(
            "unsupported endpoint scheme `{other}`; use https"
        ))),
    }
}

/// Validate a remote-supplied identifier before it is spliced into a URL
/// path. Only `[A-Za-z0-9._-]` is accepted, so no percent-encoding is needed.
fn validate_remote_id(id: &str) -> KernelResult<()> {
    let ok = !id.is_empty()
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    if ok {
        Ok(())
    } else {
        Err(unavailable(format!(
            "service returned invalid id `{id}` (allowed characters: [A-Za-z0-9._-])"
        )))
    }
}

/// Read a response body, rejecting bodies larger than [`MAX_RESPONSE_BYTES`].
async fn read_body_limited(mut resp: reqwest::Response) -> KernelResult<Vec<u8>> {
    if let Some(len) = resp.content_length() {
        if len > MAX_RESPONSE_BYTES as u64 {
            return Err(unavailable(format!(
                "response body of {len} bytes exceeds the {MAX_RESPONSE_BYTES}-byte limit"
            )));
        }
    }
    let mut buf = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(unavailable)? {
        if buf.len() + chunk.len() > MAX_RESPONSE_BYTES {
            return Err(unavailable(format!(
                "response body exceeds the {MAX_RESPONSE_BYTES}-byte limit"
            )));
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

/// Configuration for [`CubeBackend`].
#[derive(Debug, Clone)]
pub struct CubeConfig {
    /// Base URL of the Cube control plane, e.g. `https://api.cube.example`.
    pub endpoint: String,
    /// Bearer token. Prefer injecting via [`CubeConfig::from_env`].
    pub auth_token: Option<String>,
    /// Per-request HTTP timeout.
    pub request_timeout: Duration,
}

impl CubeConfig {
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            auth_token: None,
            request_timeout: Duration::from_secs(30),
        }
    }

    /// Read the auth token from `CUBE_API_TOKEN` in the environment.
    pub fn from_env(endpoint: impl Into<String>) -> Self {
        let mut c = Self::new(endpoint);
        c.auth_token = std::env::var("CUBE_API_TOKEN").ok();
        c
    }
}

// ---- Wire DTOs -------------------------------------------------------------

#[derive(Debug, Serialize)]
struct CreateSandboxRequest<'a> {
    metadata: BTreeMap<&'a str, &'a str>,
}

#[derive(Debug, Deserialize)]
struct CreateSandboxResponse {
    sandbox_id: String,
}

#[derive(Debug, Serialize)]
struct ExecRequest<'a> {
    command: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    cwd: Option<&'a str>,
    env: &'a BTreeMap<String, String>,
    timeout_ms: u64,
    /// Full step budget, forwarded so the service can enforce it.
    budget: &'a ResourceBudget,
    /// Compiled confinement, forwarded so the service can enforce it.
    writable_prefixes: &'a [String],
    readable_prefixes: &'a [String],
    egress_domains: &'a [String],
}

/// Parameters for a remote exec, including the confinement and budget that
/// the remote side must enforce.
#[derive(Debug, Clone, Copy)]
pub struct ExecParams<'a> {
    pub command: &'a str,
    pub cwd: Option<&'a str>,
    pub env: &'a BTreeMap<String, String>,
    pub timeout_ms: u64,
    pub budget: &'a ResourceBudget,
    pub writable_prefixes: &'a [String],
    pub readable_prefixes: &'a [String],
    pub egress_domains: &'a [String],
}

#[derive(Debug, Deserialize)]
struct ExecResponse {
    exit_code: i32,
    #[serde(default)]
    stdout: String,
    #[serde(default)]
    stderr: String,
    #[serde(default)]
    duration_ms: u64,
    /// Network egress bytes as measured by the service, when it reports them.
    #[serde(default)]
    network_bytes: Option<u64>,
}

#[derive(Debug, Serialize)]
struct FileWriteRequest<'a> {
    path: &'a str,
    contents_b64: &'a str,
    /// Unix permission bits; services without mode support may ignore it.
    #[serde(skip_serializing_if = "Option::is_none")]
    mode: Option<u32>,
}

#[derive(Debug, Serialize)]
struct FilePathRequest<'a> {
    path: &'a str,
}

#[derive(Debug, Deserialize)]
struct FileReadResponse {
    contents_b64: String,
}

#[derive(Debug, Deserialize)]
struct SnapshotResponse {
    snapshot_id: String,
}

/// One entry of `files/list`: the remote workspace manifest.
#[derive(Debug, Clone, Deserialize)]
pub struct RemoteFile {
    pub path: String,
    /// Lowercase hex SHA-256 of the file's bytes.
    pub sha256: String,
    #[serde(default = "default_remote_mode")]
    pub mode: u32,
}

fn default_remote_mode() -> u32 {
    0o644
}

#[derive(Debug, Deserialize)]
struct FileListResponse {
    files: Vec<RemoteFile>,
}

// ---- Client ----------------------------------------------------------------

fn unavailable(reason: impl std::fmt::Display) -> KernelError {
    KernelError::BackendUnavailable {
        backend: BACKEND_NAME.into(),
        reason: reason.to_string(),
    }
}

/// Typed HTTP client for the Cube control API.
pub struct CubeClient {
    config: CubeConfig,
    http: reqwest::Client,
}

impl CubeClient {
    pub fn new(config: CubeConfig) -> KernelResult<Self> {
        validate_endpoint(&config.endpoint)?;
        let http = reqwest::Client::builder()
            .timeout(config.request_timeout)
            .build()
            .map_err(unavailable)?;
        Ok(Self { config, http })
    }

    async fn post<B: Serialize, R: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        body: &B,
    ) -> KernelResult<R> {
        let url = format!("{}{path}", self.config.endpoint.trim_end_matches('/'));
        let mut req = self.http.post(&url).json(body);
        if let Some(token) = &self.config.auth_token {
            req = req.bearer_auth(token);
        }
        let resp = req.send().await.map_err(unavailable)?;
        let status = resp.status();
        let bytes = read_body_limited(resp).await?;
        if !status.is_success() {
            let text = String::from_utf8_lossy(&bytes);
            return Err(unavailable(format!("{url} returned {status}: {text}")));
        }
        serde_json::from_slice(&bytes).map_err(unavailable)
    }

    pub async fn create_sandbox(&self, branch: &BranchId) -> KernelResult<String> {
        let mut metadata = BTreeMap::new();
        metadata.insert("branch", branch.as_str());
        let resp: CreateSandboxResponse = self
            .post("/v1/sandboxes", &CreateSandboxRequest { metadata })
            .await?;
        validate_remote_id(&resp.sandbox_id)?;
        Ok(resp.sandbox_id)
    }

    pub async fn exec(
        &self,
        sandbox: &str,
        params: ExecParams<'_>,
    ) -> KernelResult<(i32, String, String, u64, Option<u64>)> {
        validate_remote_id(sandbox)?;
        let resp: ExecResponse = self
            .post(
                &format!("/v1/sandboxes/{sandbox}/exec"),
                &ExecRequest {
                    command: params.command,
                    cwd: params.cwd,
                    env: params.env,
                    timeout_ms: params.timeout_ms,
                    budget: params.budget,
                    writable_prefixes: params.writable_prefixes,
                    readable_prefixes: params.readable_prefixes,
                    egress_domains: params.egress_domains,
                },
            )
            .await?;
        Ok((
            resp.exit_code,
            resp.stdout,
            resp.stderr,
            resp.duration_ms,
            resp.network_bytes,
        ))
    }

    pub async fn write_file(
        &self,
        sandbox: &str,
        path: &str,
        contents_b64: &str,
        mode: Option<u32>,
    ) -> KernelResult<()> {
        validate_remote_id(sandbox)?;
        let _: serde_json::Value = self
            .post(
                &format!("/v1/sandboxes/{sandbox}/files/write"),
                &FileWriteRequest {
                    path,
                    contents_b64,
                    mode,
                },
            )
            .await?;
        Ok(())
    }

    /// List the sandbox's workspace tree: path, content hash, mode.
    pub async fn list_files(&self, sandbox: &str) -> KernelResult<Vec<RemoteFile>> {
        validate_remote_id(sandbox)?;
        let resp: FileListResponse = self
            .post(
                &format!("/v1/sandboxes/{sandbox}/files/list"),
                &serde_json::json!({}),
            )
            .await?;
        Ok(resp.files)
    }

    pub async fn read_file(&self, sandbox: &str, path: &str) -> KernelResult<Vec<u8>> {
        validate_remote_id(sandbox)?;
        let resp: FileReadResponse = self
            .post(
                &format!("/v1/sandboxes/{sandbox}/files/read"),
                &FilePathRequest { path },
            )
            .await?;
        ak_core::b64::decode(&resp.contents_b64)
            .map_err(|e| unavailable(format!("service returned invalid base64: {e}")))
    }

    pub async fn delete_path(&self, sandbox: &str, path: &str) -> KernelResult<()> {
        validate_remote_id(sandbox)?;
        let _: serde_json::Value = self
            .post(
                &format!("/v1/sandboxes/{sandbox}/files/delete"),
                &FilePathRequest { path },
            )
            .await?;
        Ok(())
    }

    pub async fn snapshot(&self, sandbox: &str) -> KernelResult<String> {
        validate_remote_id(sandbox)?;
        let resp: SnapshotResponse = self
            .post(
                &format!("/v1/sandboxes/{sandbox}/snapshot"),
                &serde_json::json!({}),
            )
            .await?;
        validate_remote_id(&resp.snapshot_id)?;
        Ok(resp.snapshot_id)
    }

    pub async fn clone_snapshot(&self, snapshot: &str, branch: &BranchId) -> KernelResult<String> {
        validate_remote_id(snapshot)?;
        let mut metadata = BTreeMap::new();
        metadata.insert("branch", branch.as_str());
        let resp: CreateSandboxResponse = self
            .post(
                &format!("/v1/snapshots/{snapshot}/clone"),
                &CreateSandboxRequest { metadata },
            )
            .await?;
        validate_remote_id(&resp.sandbox_id)?;
        Ok(resp.sandbox_id)
    }

    pub async fn delete_sandbox(&self, sandbox: &str) -> KernelResult<()> {
        validate_remote_id(sandbox)?;
        let url = format!(
            "{}/v1/sandboxes/{sandbox}",
            self.config.endpoint.trim_end_matches('/')
        );
        let mut req = self.http.delete(&url);
        if let Some(token) = &self.config.auth_token {
            req = req.bearer_auth(token);
        }
        let resp = req.send().await.map_err(unavailable)?;
        if !resp.status().is_success() {
            return Err(unavailable(format!("{url} returned {}", resp.status())));
        }
        Ok(())
    }
}

// ---- Backend ---------------------------------------------------------------

/// Cube backend: routes actions to per-branch remote sandboxes and supports
/// CoW fork via snapshot + clone. With a [`StateProvider`] attached it
/// performs full state sync (see the module docs).
pub struct CubeBackend {
    client: CubeClient,
    /// Live sandbox per branch.
    sandboxes: Mutex<HashMap<BranchId, String>>,
    /// Sandbox that materialized each base state (for `fork`).
    state_sandboxes: Mutex<HashMap<StateId, String>>,
    /// Resolves kernel states to manifests/blobs for state sync.
    state_provider: Option<Arc<dyn StateProvider>>,
    /// What each sandbox's workspace currently holds (path → blob, mode),
    /// maintained across pushes and pulls. Content-addressed: sync-in
    /// diffs are computed against this, so a sandbox already at the base
    /// state transfers nothing.
    synced: Mutex<HashMap<String, SyncManifest>>,
}

impl CubeBackend {
    pub fn new(config: CubeConfig) -> KernelResult<Self> {
        Ok(Self {
            client: CubeClient::new(config)?,
            sandboxes: Mutex::new(HashMap::new()),
            state_sandboxes: Mutex::new(HashMap::new()),
            state_provider: None,
            synced: Mutex::new(HashMap::new()),
        })
    }

    /// Attach a state provider, turning excursions into real state
    /// transitions (the profile then advertises `syncs_state`).
    pub fn with_state_provider(mut self, provider: Arc<dyn StateProvider>) -> Self {
        self.state_provider = Some(provider);
        self
    }

    /// Get-or-create is atomic: the map lock is held across the remote create
    /// so concurrent first uses of a branch cannot race two sandboxes.
    async fn sandbox_for(&self, branch: &BranchId) -> KernelResult<String> {
        let mut sandboxes = self.sandboxes.lock().await;
        if let Some(id) = sandboxes.get(branch) {
            return Ok(id.clone());
        }
        let id = self.client.create_sandbox(branch).await?;
        sandboxes.insert(branch.clone(), id.clone());
        Ok(id)
    }

    /// Forget a branch's sandbox after a failed sync and delete it
    /// best-effort: a half-synced tree must never serve another step, so
    /// the next use re-creates and re-materializes from the branch head.
    async fn poison(&self, branch: &BranchId, sandbox: &str) {
        self.sandboxes.lock().await.remove(branch);
        self.synced.lock().await.remove(sandbox);
        if let Err(e) = self.client.delete_sandbox(sandbox).await {
            tracing::warn!(sandbox, error = %e, "failed to delete poisoned sandbox");
        }
    }

    /// Bring `sandbox`'s workspace to `base_state` by pushing the diff
    /// between what it holds and the base-state manifest.
    async fn sync_in(
        &self,
        provider: &Arc<dyn StateProvider>,
        sandbox: &str,
        base_state: &StateId,
    ) -> KernelResult<()> {
        let target = provider.manifest(base_state)?;
        let current = self
            .synced
            .lock()
            .await
            .get(sandbox)
            .cloned()
            .unwrap_or_default();
        let plan = push_plan(&current, &target);
        for (path, entry) in &plan.upserts {
            let bytes = provider.blob(&entry.blob)?;
            self.client
                .write_file(
                    sandbox,
                    path,
                    &ak_core::b64::encode(&bytes),
                    Some(entry.mode & 0o777),
                )
                .await?;
        }
        for path in &plan.deletes {
            self.client.delete_path(sandbox, path).await?;
        }
        self.synced.lock().await.insert(sandbox.to_string(), target);
        Ok(())
    }

    /// List the remote tree after execution and pull only changed files,
    /// returning the delta against what was pushed. Updates the sync cache
    /// to the observed tree (hashes recomputed from the pulled bytes — the
    /// listing hash only decides what to download).
    async fn sync_out(&self, sandbox: &str) -> KernelResult<WorkspaceDelta> {
        let listing = self.client.list_files(sandbox).await?;
        let known = self
            .synced
            .lock()
            .await
            .get(sandbox)
            .cloned()
            .unwrap_or_default();
        let mut delta = WorkspaceDelta::default();
        let mut next = SyncManifest::new();
        for file in &listing {
            let path = match syncable_path(&file.path) {
                Ok(p) => p,
                // The cache/scratch tier stays remote; hostile paths are a
                // protocol violation.
                Err(reason) if reason.contains("cache/scratch") => continue,
                Err(reason) => {
                    return Err(unavailable(format!(
                        "service listed an unsyncable path: {reason}"
                    )))
                }
            };
            let mode = file.mode & 0o777;
            let listed = SyncEntry {
                blob: ContentHash(format!("sha256:{}", file.sha256)),
                mode,
            };
            match known.get(&path) {
                Some(entry) if *entry == listed => {
                    next.insert(path, listed);
                }
                _ => {
                    let bytes = self.client.read_file(sandbox, &path).await?;
                    let blob = hash_bytes(&bytes);
                    next.insert(path.clone(), SyncEntry { blob, mode });
                    delta.upserts.push(SyncedFile {
                        path,
                        contents: bytes,
                        mode,
                    });
                }
            }
        }
        for path in known.keys() {
            if !next.contains_key(path) {
                delta.deletes.push(path.clone());
            }
        }
        self.synced.lock().await.insert(sandbox.to_string(), next);
        Ok(delta)
    }
}

#[async_trait]
impl Backend for CubeBackend {
    fn profile(&self) -> BackendProfile {
        BackendProfile {
            name: BACKEND_NAME.into(),
            isolation_strength: 90,
            cold_start_ms: 250,
            replay_class: ReplayClass::ProcessAndFilesystem,
            supports_fork: true,
            supports_gui: false,
            full_linux: true,
            // Remote workspace: never the kernel's own tree.
            shares_workspace: false,
            // Honest capability: real state sync only with a provider.
            syncs_state: self.state_provider.is_some(),
        }
    }

    async fn execute(&self, req: ExecutionRequest) -> KernelResult<ExecutionOutcome> {
        let sandbox = self.sandbox_for(&req.branch).await?;
        // State sync in: materialize the base state before acting. Failure
        // poisons the sandbox — a half-pushed tree must not execute.
        if let Some(provider) = &self.state_provider {
            if let Err(e) = self.sync_in(provider, &sandbox, &req.base_state).await {
                self.poison(&req.branch, &sandbox).await;
                return Err(e);
            }
        }
        let (exit_code, stdout, stderr, duration_ms, network_bytes) = match &req.action {
            ActionKind::Shell { command, cwd, env } => {
                self.client
                    .exec(
                        &sandbox,
                        ExecParams {
                            command,
                            cwd: cwd.as_deref(),
                            env,
                            timeout_ms: req.budget.cpu_ms.max(1),
                            budget: &req.budget,
                            writable_prefixes: &req.writable_prefixes,
                            readable_prefixes: &req.readable_prefixes,
                            egress_domains: &req.egress_domains,
                        },
                    )
                    .await?
            }
            ActionKind::ReadFile { path } => {
                let bytes = self.client.read_file(&sandbox, path).await?;
                let text = String::from_utf8_lossy(&bytes).into_owned();
                (0, text, String::new(), 0, None)
            }
            ActionKind::WriteFile { path, contents_b64 } => {
                self.client
                    .write_file(&sandbox, path, contents_b64, None)
                    .await?;
                (0, String::new(), String::new(), 0, None)
            }
            ActionKind::DeletePath { path } => {
                self.client.delete_path(&sandbox, path).await?;
                (0, String::new(), String::new(), 0, None)
            }
            other => {
                return Err(unavailable(format!(
                    "cube backend does not execute `{}` actions",
                    other.required_operation().0
                )))
            }
        };
        // State sync out: pull the post-execution delta regardless of exit
        // code (failed commands write files too). Failure poisons the
        // sandbox and fails the step — the kernel never sees a half-pulled
        // delta, and the branch head stays at the base state.
        let workspace_delta = match &self.state_provider {
            Some(_) => match self.sync_out(&sandbox).await {
                Ok(delta) => Some(delta),
                Err(e) => {
                    self.poison(&req.branch, &sandbox).await;
                    return Err(e);
                }
            },
            None => None,
        };
        self.state_sandboxes
            .lock()
            .await
            .insert(req.base_state.clone(), sandbox.clone());
        let paths_written = match &workspace_delta {
            Some(delta) => delta
                .upserts
                .iter()
                .map(|f| f.path.clone())
                .chain(delta.deletes.iter().cloned())
                .collect(),
            None => match &req.action {
                ActionKind::WriteFile { path, .. } => vec![path.clone()],
                _ => Vec::new(),
            },
        };
        let bytes = network_bytes.unwrap_or(0);
        Ok(ExecutionOutcome {
            exit_code,
            stdout: stdout.into_bytes(),
            stderr: stderr.into_bytes(),
            usage: ResourceBudget {
                cpu_ms: duration_ms,
                // Real value when the service reports one; otherwise 0 —
                // network accounting is not available and is never fabricated.
                network_bytes: bytes,
                ..ResourceBudget::zero()
            },
            paths_written,
            replay_class: ReplayClass::ProcessAndFilesystem,
            workspace_delta,
        })
    }

    /// Fork via snapshot + clone. Returns `Ok(false)` when the source state
    /// is unknown to this backend (kernel then re-materializes from the CAS).
    /// The clone inherits the source sandbox's sync view: its tree is a
    /// byte-identical copy, so the next push diffs from the same manifest.
    async fn fork(&self, from: &StateId, to_branch: &BranchId) -> KernelResult<bool> {
        let source = { self.state_sandboxes.lock().await.get(from).cloned() };
        let Some(source) = source else {
            return Ok(false);
        };
        let snapshot = self.client.snapshot(&source).await?;
        let clone = self.client.clone_snapshot(&snapshot, to_branch).await?;
        let inherited = { self.synced.lock().await.get(&source).cloned() };
        if let Some(manifest) = inherited {
            self.synced.lock().await.insert(clone.clone(), manifest);
        }
        self.sandboxes.lock().await.insert(to_branch.clone(), clone);
        Ok(true)
    }

    async fn discard(&self, branch: &BranchId) -> KernelResult<()> {
        let sandbox = { self.sandboxes.lock().await.remove(branch) };
        if let Some(sandbox) = sandbox {
            self.synced.lock().await.remove(&sandbox);
            self.client.delete_sandbox(&sandbox).await?;
        }
        Ok(())
    }
}

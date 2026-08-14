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
//! half-synced tree. The adapter re-lists before every sync-in and CoW clone,
//! then verifies the clone itself before reporting native CoW success,
//! and rejects malformed manifests, a file whose bytes no longer match its
//! listing hash, or a complete tree that drifts while its delta is pulled;
//! paths are then independently validated and confined by the kernel before
//! anything touches the workspace mirror.
//!
//! Without a provider the profile stays `syncs_state = false` and shell
//! steps are recorded as audit-only excursions, exactly as before.

use ak_core::action::ActionKind;
use ak_core::budget::ResourceBudget;
use ak_core::error::{KernelError, KernelResult};
use ak_core::hash::{hash_bytes, ContentHash};
use ak_core::ids::{BranchId, StateId};
use ak_core::replay::ReplayClass;
use ak_core::sync::{push_plan, syncable_path, validate_manifest_shape, SyncEntry, SyncManifest};
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
    /// Resolves kernel states to manifests/blobs for state sync.
    state_provider: Option<Arc<dyn StateProvider>>,
    /// Last verified manifest per sandbox (path → blob, mode). This is a
    /// transfer/CoW candidate cache only; live state is re-listed before
    /// sync-in and before cloning.
    synced: Mutex<HashMap<String, SyncManifest>>,
    /// Serializes mutation of each remote sandbox and lets CoW clone reserve
    /// only a quiescent exact-manifest source.
    sandbox_gates: Mutex<HashMap<String, Arc<Mutex<()>>>>,
}

impl CubeBackend {
    pub fn new(config: CubeConfig) -> KernelResult<Self> {
        Ok(Self {
            client: CubeClient::new(config)?,
            sandboxes: Mutex::new(HashMap::new()),
            state_provider: None,
            synced: Mutex::new(HashMap::new()),
            sandbox_gates: Mutex::new(HashMap::new()),
        })
    }

    /// Attach a state provider, turning excursions into real state
    /// transitions (the profile then advertises `syncs_state`).
    pub fn with_state_provider(mut self, provider: Arc<dyn StateProvider>) -> Self {
        self.state_provider = Some(provider);
        self
    }

    async fn sandbox_gate(&self, sandbox: &str) -> Arc<Mutex<()>> {
        Arc::clone(
            self.sandbox_gates
                .lock()
                .await
                .entry(sandbox.to_string())
                .or_insert_with(|| Arc::new(Mutex::new(()))),
        )
    }

    /// Find and reserve a quiescent sandbox at exactly `target`. A matching
    /// cache entry is insufficient while that sandbox is executing: its
    /// mutable tree may already have moved ahead of the cached manifest.
    async fn quiescent_source(
        &self,
        target: &SyncManifest,
    ) -> KernelResult<Option<(String, tokio::sync::OwnedMutexGuard<()>)>> {
        let candidates: Vec<String> = self
            .synced
            .lock()
            .await
            .iter()
            .filter(|(_, current)| *current == target)
            .map(|(sandbox, _)| sandbox.clone())
            .collect();
        for sandbox in candidates {
            let gate = self.sandbox_gate(&sandbox).await;
            if let Ok(guard) = gate.try_lock_owned() {
                // The cache is only a candidate index. A process retained by
                // the remote sandbox may have changed files between steps;
                // re-list under the mutation gate before cloning it.
                let current = self.remote_manifest(&sandbox).await?;
                self.synced
                    .lock()
                    .await
                    .insert(sandbox.clone(), current.clone());
                if &current == target {
                    return Ok(Some((sandbox, guard)));
                }
            }
        }
        Ok(None)
    }

    /// Get-or-create is atomic: the map lock is held across the remote create
    /// so concurrent first uses of a branch cannot race two sandboxes.
    async fn sandbox_for(
        &self,
        branch: &BranchId,
        target: Option<&SyncManifest>,
    ) -> KernelResult<(String, tokio::sync::OwnedMutexGuard<()>)> {
        let mut sandboxes = self.sandboxes.lock().await;
        if let Some(id) = sandboxes.get(branch) {
            let id = id.clone();
            drop(sandboxes);
            let guard = self.sandbox_gate(&id).await.lock_owned().await;
            return Ok((id, guard));
        }
        // Lazy CoW: a just-forked kernel branch first arrives with exactly
        // its fork-point manifest. If a live sandbox still has that exact
        // tree, clone it instead of creating an empty sandbox and re-pushing
        // every blob. Equality is against the full manifest, never a stale
        // state-id -> mutable-sandbox association.
        if let Some(target) = target {
            if let Some((source, _source_guard)) = self.quiescent_source(target).await? {
                let snapshot = self.client.snapshot(&source).await?;
                let clone = self.client.clone_snapshot(&snapshot, branch).await?;
                self.synced
                    .lock()
                    .await
                    .insert(clone.clone(), target.clone());
                sandboxes.insert(branch.clone(), clone.clone());
                let guard = self.sandbox_gate(&clone).await.lock_owned().await;
                return Ok((clone, guard));
            }
        }
        let id = self.client.create_sandbox(branch).await?;
        sandboxes.insert(branch.clone(), id.clone());
        let guard = self.sandbox_gate(&id).await.lock_owned().await;
        Ok((id, guard))
    }

    /// Forget a branch's sandbox after a failed sync and delete it
    /// best-effort: a half-synced tree must never serve another step, so
    /// the next use re-creates and re-materializes from the branch head.
    async fn poison(&self, branch: &BranchId, sandbox: &str) {
        self.sandboxes.lock().await.remove(branch);
        self.synced.lock().await.remove(sandbox);
        self.sandbox_gates.lock().await.remove(sandbox);
        if let Err(e) = self.client.delete_sandbox(sandbox).await {
            tracing::warn!(sandbox, error = %e, "failed to delete poisoned sandbox");
        }
    }

    /// Read and validate the service's current workspace manifest. This is
    /// the data-plane source of truth; `synced` is only a transfer cache.
    async fn remote_manifest(&self, sandbox: &str) -> KernelResult<SyncManifest> {
        let listing = self.client.list_files(sandbox).await?;
        let mut manifest = SyncManifest::new();
        for file in listing {
            let path = match syncable_path(&file.path) {
                Ok(path) => path,
                // The cache/scratch tier stays remote; every other invalid
                // path is a protocol violation.
                Err(reason) if reason.contains("cache/scratch") => continue,
                Err(reason) => {
                    return Err(unavailable(format!(
                        "service listed an unsyncable path: {reason}"
                    )))
                }
            };
            if file.sha256.len() != 64 || !file.sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(unavailable(format!(
                    "service listed an invalid SHA-256 for `{path}`"
                )));
            }
            let entry = SyncEntry {
                blob: ContentHash(format!("sha256:{}", file.sha256.to_ascii_lowercase())),
                mode: file.mode & 0o777,
            };
            if manifest.insert(path.clone(), entry).is_some() {
                return Err(unavailable(format!(
                    "service listed duplicate canonical path `{path}`"
                )));
            }
        }
        validate_manifest_shape(&manifest).map_err(unavailable)?;
        Ok(manifest)
    }

    /// Bring `sandbox`'s workspace to `base_state` by pushing the diff
    /// between a fresh remote listing and the base-state manifest.
    async fn sync_in(
        &self,
        provider: &Arc<dyn StateProvider>,
        sandbox: &str,
        target: &SyncManifest,
    ) -> KernelResult<()> {
        let current = self.remote_manifest(sandbox).await?;
        let plan = push_plan(&current, target);
        // Delete first, then write. This is required for file/directory
        // transitions (`a` -> `a/b`, or the reverse). Deleting an upsert's
        // destination as well clears an empty/old directory at that path;
        // the files API's delete operation is idempotent.
        for path in &plan.deletes {
            self.client.delete_path(sandbox, path).await?;
        }
        for (path, entry) in &plan.upserts {
            self.client.delete_path(sandbox, path).await?;
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
        if !plan.is_empty() {
            let verified = self.remote_manifest(sandbox).await?;
            if &verified != target {
                return Err(unavailable(
                    "service did not materialize the requested base manifest exactly",
                ));
            }
        }
        self.synced
            .lock()
            .await
            .insert(sandbox.to_string(), target.clone());
        Ok(())
    }

    /// List the remote tree after execution and pull only changed files,
    /// returning the delta against what was pushed. Every downloaded file
    /// must hash to the listing entry, rejecting a concurrent mutation
    /// instead of committing a mixed-time tree.
    async fn sync_out(&self, sandbox: &str) -> KernelResult<WorkspaceDelta> {
        let remote = self.remote_manifest(sandbox).await?;
        let known = self
            .synced
            .lock()
            .await
            .get(sandbox)
            .cloned()
            .unwrap_or_default();
        let mut delta = WorkspaceDelta::default();
        for (path, listed) in &remote {
            if known.get(path) != Some(listed) {
                let bytes = self.client.read_file(sandbox, path).await?;
                let actual = hash_bytes(&bytes);
                if actual != listed.blob {
                    return Err(unavailable(format!(
                        "service file `{path}` changed between list and read"
                    )));
                }
                delta.upserts.push(SyncedFile {
                    path: path.clone(),
                    contents: bytes,
                    mode: listed.mode,
                });
            }
        }
        for path in known.keys() {
            if !remote.contains_key(path) {
                delta.deletes.push(path.clone());
            }
        }
        // Per-file hashes reject a mutation between that file's list/read,
        // but a retained background process could still change an already
        // downloaded file (or add/delete another one) while the rest of the
        // tree is being pulled. Re-list the complete tree before vouching for
        // the delta; a mismatch poisons this sandbox at the caller.
        if !delta.upserts.is_empty() {
            let verified = self.remote_manifest(sandbox).await?;
            if verified != remote {
                return Err(unavailable(
                    "service workspace changed while its state delta was being pulled",
                ));
            }
        }
        self.synced.lock().await.insert(sandbox.to_string(), remote);
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
            // A state provider is required to prove which mutable remote
            // tree exactly represents the requested source state.
            supports_fork: self.state_provider.is_some(),
            supports_gui: false,
            full_linux: true,
            // Remote workspace: never the kernel's own tree.
            shares_workspace: false,
            // Honest capability: real state sync only with a provider.
            syncs_state: self.state_provider.is_some(),
        }
    }

    async fn execute(&self, req: ExecutionRequest) -> KernelResult<ExecutionOutcome> {
        let target = match &self.state_provider {
            Some(provider) => Some(provider.manifest(&req.base_state)?),
            None => None,
        };
        let (sandbox, _sandbox_guard) = self.sandbox_for(&req.branch, target.as_ref()).await?;
        // State sync in: materialize the base state before acting. Failure
        // poisons the sandbox — a half-pushed tree must not execute.
        if let Some(provider) = &self.state_provider {
            if let Err(e) = self
                .sync_in(
                    provider,
                    &sandbox,
                    target.as_ref().expect("provider produced a target"),
                )
                .await
            {
                self.poison(&req.branch, &sandbox).await;
                return Err(e);
            }
        }
        let executed = match &req.action {
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
                    .await
            }
            ActionKind::ReadFile { path } => {
                self.client.read_file(&sandbox, path).await.map(|bytes| {
                    let text = String::from_utf8_lossy(&bytes).into_owned();
                    (0, text, String::new(), 0, None)
                })
            }
            ActionKind::WriteFile { path, contents_b64 } => self
                .client
                .write_file(&sandbox, path, contents_b64, None)
                .await
                .map(|()| (0, String::new(), String::new(), 0, None)),
            ActionKind::DeletePath { path } => self
                .client
                .delete_path(&sandbox, path)
                .await
                .map(|()| (0, String::new(), String::new(), 0, None)),
            other => Err(unavailable(format!(
                "cube backend does not execute `{}` actions",
                other.required_operation().0
            ))),
        };
        // A transport/status failure is ambiguous: the remote action may
        // have changed the tree before its response was lost. Never reuse
        // that sandbox under the old sync cache.
        let (exit_code, stdout, stderr, duration_ms, network_bytes) = match executed {
            Ok(out) => out,
            Err(e) => {
                self.poison(&req.branch, &sandbox).await;
                return Err(e);
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

    /// Fork via snapshot + clone. The source is selected only when a live
    /// sandbox's complete sync manifest exactly equals `from`; mutable
    /// sandboxes are never remembered under stale state IDs.
    async fn fork(&self, from: &StateId, to_branch: &BranchId) -> KernelResult<bool> {
        let Some(provider) = &self.state_provider else {
            return Ok(false);
        };
        let target = provider.manifest(from)?;
        let Some((source, _source_guard)) = self.quiescent_source(&target).await? else {
            return Ok(false);
        };
        let snapshot = self.client.snapshot(&source).await?;
        let clone = self.client.clone_snapshot(&snapshot, to_branch).await?;
        // The source was exact before snapshotting, but a retained process
        // can race that control-plane boundary. Verify the clone itself
        // before reporting native CoW success. A non-exact clone remains a
        // safe warm materialization candidate: sync-in repairs it from CAS
        // before the first command, so return false honestly.
        let current = match self.remote_manifest(&clone).await {
            Ok(current) => current,
            Err(error) => {
                self.sandboxes
                    .lock()
                    .await
                    .insert(to_branch.clone(), clone.clone());
                self.poison(to_branch, &clone).await;
                return Err(error);
            }
        };
        let exact = current == target;
        self.synced.lock().await.insert(clone.clone(), current);
        self.sandboxes.lock().await.insert(to_branch.clone(), clone);
        Ok(exact)
    }

    async fn discard(&self, branch: &BranchId) -> KernelResult<()> {
        let sandbox = { self.sandboxes.lock().await.get(branch).cloned() };
        if let Some(sandbox) = sandbox {
            let _guard = self.sandbox_gate(&sandbox).await.lock_owned().await;
            self.client.delete_sandbox(&sandbox).await?;
            self.sandboxes.lock().await.remove(branch);
            self.synced.lock().await.remove(&sandbox);
            self.sandbox_gates.lock().await.remove(&sandbox);
        }
        Ok(())
    }
}

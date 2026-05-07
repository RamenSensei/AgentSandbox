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
//! | `POST /v1/sandboxes/{id}/files/write` | `{"path","contents_b64"}` | `{}` |
//! | `POST /v1/sandboxes/{id}/files/read` | `{"path"}` | `{"contents_b64"}` |
//! | `POST /v1/sandboxes/{id}/files/delete` | `{"path"}` | `{}` |
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

use ak_core::action::ActionKind;
use ak_core::budget::ResourceBudget;
use ak_core::error::{KernelError, KernelResult};
use ak_core::ids::{BranchId, StateId};
use ak_core::replay::ReplayClass;
use ak_core::traits::{Backend, BackendProfile, ExecutionOutcome, ExecutionRequest};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::time::Duration;
use tokio::sync::Mutex;

const BACKEND_NAME: &str = "cube";

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
        Self { endpoint: endpoint.into(), auth_token: None, request_timeout: Duration::from_secs(30) }
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
}

#[derive(Debug, Serialize)]
struct FileWriteRequest<'a> {
    path: &'a str,
    contents_b64: &'a str,
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

// ---- Client ----------------------------------------------------------------

fn unavailable(reason: impl std::fmt::Display) -> KernelError {
    KernelError::BackendUnavailable { backend: BACKEND_NAME.into(), reason: reason.to_string() }
}

/// Typed HTTP client for the Cube control API.
pub struct CubeClient {
    config: CubeConfig,
    http: reqwest::Client,
}

impl CubeClient {
    pub fn new(config: CubeConfig) -> KernelResult<Self> {
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
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(unavailable(format!("{url} returned {status}: {text}")));
        }
        resp.json().await.map_err(unavailable)
    }

    pub async fn create_sandbox(&self, branch: &BranchId) -> KernelResult<String> {
        let mut metadata = BTreeMap::new();
        metadata.insert("branch", branch.as_str());
        let resp: CreateSandboxResponse =
            self.post("/v1/sandboxes", &CreateSandboxRequest { metadata }).await?;
        Ok(resp.sandbox_id)
    }

    pub async fn exec(
        &self,
        sandbox: &str,
        command: &str,
        cwd: Option<&str>,
        env: &BTreeMap<String, String>,
        timeout_ms: u64,
    ) -> KernelResult<(i32, String, String, u64)> {
        let resp: ExecResponse = self
            .post(
                &format!("/v1/sandboxes/{sandbox}/exec"),
                &ExecRequest { command, cwd, env, timeout_ms },
            )
            .await?;
        Ok((resp.exit_code, resp.stdout, resp.stderr, resp.duration_ms))
    }

    pub async fn write_file(&self, sandbox: &str, path: &str, contents_b64: &str) -> KernelResult<()> {
        let _: serde_json::Value = self
            .post(
                &format!("/v1/sandboxes/{sandbox}/files/write"),
                &FileWriteRequest { path, contents_b64 },
            )
            .await?;
        Ok(())
    }

    pub async fn read_file(&self, sandbox: &str, path: &str) -> KernelResult<Vec<u8>> {
        let resp: FileReadResponse = self
            .post(&format!("/v1/sandboxes/{sandbox}/files/read"), &FilePathRequest { path })
            .await?;
        b64_decode(&resp.contents_b64)
            .map_err(|e| unavailable(format!("service returned invalid base64: {e}")))
    }

    pub async fn delete_path(&self, sandbox: &str, path: &str) -> KernelResult<()> {
        let _: serde_json::Value = self
            .post(&format!("/v1/sandboxes/{sandbox}/files/delete"), &FilePathRequest { path })
            .await?;
        Ok(())
    }

    pub async fn snapshot(&self, sandbox: &str) -> KernelResult<String> {
        let resp: SnapshotResponse = self
            .post(&format!("/v1/sandboxes/{sandbox}/snapshot"), &serde_json::json!({}))
            .await?;
        Ok(resp.snapshot_id)
    }

    pub async fn clone_snapshot(&self, snapshot: &str, branch: &BranchId) -> KernelResult<String> {
        let mut metadata = BTreeMap::new();
        metadata.insert("branch", branch.as_str());
        let resp: CreateSandboxResponse = self
            .post(&format!("/v1/snapshots/{snapshot}/clone"), &CreateSandboxRequest { metadata })
            .await?;
        Ok(resp.sandbox_id)
    }

    pub async fn delete_sandbox(&self, sandbox: &str) -> KernelResult<()> {
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
/// CoW fork via snapshot + clone.
pub struct CubeBackend {
    client: CubeClient,
    /// Live sandbox per branch.
    sandboxes: Mutex<HashMap<BranchId, String>>,
    /// Sandbox that materialized each base state (for `fork`).
    state_sandboxes: Mutex<HashMap<StateId, String>>,
}

impl CubeBackend {
    pub fn new(config: CubeConfig) -> KernelResult<Self> {
        Ok(Self {
            client: CubeClient::new(config)?,
            sandboxes: Mutex::new(HashMap::new()),
            state_sandboxes: Mutex::new(HashMap::new()),
        })
    }

    async fn sandbox_for(&self, branch: &BranchId) -> KernelResult<String> {
        if let Some(id) = self.sandboxes.lock().await.get(branch) {
            return Ok(id.clone());
        }
        let id = self.client.create_sandbox(branch).await?;
        self.sandboxes.lock().await.insert(branch.clone(), id.clone());
        Ok(id)
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
        }
    }

    async fn execute(&self, req: ExecutionRequest) -> KernelResult<ExecutionOutcome> {
        let sandbox = self.sandbox_for(&req.branch).await?;
        let (exit_code, stdout, stderr, duration_ms) = match &req.action {
            ActionKind::Shell { command, cwd, env } => {
                self.client
                    .exec(&sandbox, command, cwd.as_deref(), env, req.budget.cpu_ms.max(1))
                    .await?
            }
            ActionKind::ReadFile { path } => {
                let bytes = self.client.read_file(&sandbox, path).await?;
                let text = String::from_utf8_lossy(&bytes).into_owned();
                (0, text, String::new(), 0)
            }
            ActionKind::WriteFile { path, contents_b64 } => {
                self.client.write_file(&sandbox, path, contents_b64).await?;
                (0, String::new(), String::new(), 0)
            }
            ActionKind::DeletePath { path } => {
                self.client.delete_path(&sandbox, path).await?;
                (0, String::new(), String::new(), 0)
            }
            other => {
                return Err(unavailable(format!(
                    "cube backend does not execute `{}` actions",
                    other.required_operation().0
                )))
            }
        };
        self.state_sandboxes
            .lock()
            .await
            .insert(req.base_state.clone(), sandbox.clone());
        let paths_written = match &req.action {
            ActionKind::WriteFile { path, .. } => vec![path.clone()],
            _ => Vec::new(),
        };
        let bytes = (stdout.len() + stderr.len()) as u64;
        Ok(ExecutionOutcome {
            exit_code,
            stdout: stdout.into_bytes(),
            stderr: stderr.into_bytes(),
            usage: ResourceBudget {
                cpu_ms: duration_ms,
                network_bytes: bytes,
                ..ResourceBudget::zero()
            },
            paths_written,
            replay_class: ReplayClass::ProcessAndFilesystem,
        })
    }

    /// Fork via snapshot + clone. Returns `Ok(false)` when the source state
    /// is unknown to this backend (kernel then re-materializes from the CAS).
    async fn fork(&self, from: &StateId, to_branch: &BranchId) -> KernelResult<bool> {
        let source = { self.state_sandboxes.lock().await.get(from).cloned() };
        let Some(source) = source else { return Ok(false) };
        let snapshot = self.client.snapshot(&source).await?;
        let clone = self.client.clone_snapshot(&snapshot, to_branch).await?;
        self.sandboxes.lock().await.insert(to_branch.clone(), clone);
        Ok(true)
    }

    async fn discard(&self, branch: &BranchId) -> KernelResult<()> {
        let sandbox = { self.sandboxes.lock().await.remove(branch) };
        if let Some(sandbox) = sandbox {
            self.client.delete_sandbox(&sandbox).await?;
        }
        Ok(())
    }
}

/// Minimal standard base64 decode (padding optional) for file reads.
fn b64_decode(input: &str) -> Result<Vec<u8>, String> {
    fn val(c: u8) -> Result<u32, String> {
        match c {
            b'A'..=b'Z' => Ok(u32::from(c - b'A')),
            b'a'..=b'z' => Ok(u32::from(c - b'a') + 26),
            b'0'..=b'9' => Ok(u32::from(c - b'0') + 52),
            b'+' => Ok(62),
            b'/' => Ok(63),
            _ => Err(format!("invalid base64 byte 0x{c:02x}")),
        }
    }
    let cleaned: Vec<u8> =
        input.bytes().filter(|b| !b.is_ascii_whitespace() && *b != b'=').collect();
    let mut out = Vec::with_capacity(cleaned.len() * 3 / 4);
    for chunk in cleaned.chunks(4) {
        if chunk.len() == 1 {
            return Err("truncated base64 input".into());
        }
        let mut n: u32 = 0;
        for &c in chunk {
            n = (n << 6) | val(c)?;
        }
        n <<= 6 * (4 - chunk.len()) as u32;
        out.push((n >> 16) as u8);
        if chunk.len() > 2 {
            out.push((n >> 8) as u8);
        }
        if chunk.len() > 3 {
            out.push(n as u8);
        }
    }
    Ok(out)
}

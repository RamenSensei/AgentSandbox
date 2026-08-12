//! # ak-backend-forkd
//!
//! Remote adapter [`Backend`] for a **forkd** service: a warm-parent process
//! that fans out sandboxed children by `fork(2)`-style copy-on-write cloning.
//! This is an *honest adapter*: real HTTP via `reqwest`, and any unreachable
//! or erroring endpoint maps to [`KernelError::BackendUnavailable`].
//!
//! ## Assumed control API (documented here because these APIs evolve)
//!
//! All requests carry `Authorization: Bearer <token>` when a token is set.
//!
//! | Method & path | Body | Response |
//! |---|---|---|
//! | `POST /v1/parents` | `{}` | `{"parent_id": "p-..."}` — ensure a warm parent |
//! | `POST /v1/parents/{id}/fork` | `{"branch": "..."}` | `{"child_id": "c-..."}` |
//! | `POST /v1/children/{id}/fork` | `{"branch": "..."}` | `{"child_id": "c-..."}` — CoW fan-out of a live child |
//! | `POST /v1/children/{id}/exec` | `{"command","cwd?","env","timeout_ms"}` | `{"exit_code","stdout","stderr","duration_ms"}` |
//! | `DELETE /v1/children/{id}` | — | `{}` |
//!
//! File actions (`ReadFile`/`WriteFile`/`DeletePath`) are translated into
//! shell execs inside the child (`cat`, `base64 -d > path`, `rm -rf`), since
//! forkd exposes only process-level control.
//!
//! Profile: isolation_strength **90**, `supports_fork = true`, replay class
//! [`ReplayClass::ProcessAndFilesystem`] (the forked child carries both the
//! process image and its filesystem view).

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

const BACKEND_NAME: &str = "forkd";

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

/// Configuration for [`ForkdBackend`].
#[derive(Debug, Clone)]
pub struct ForkdConfig {
    /// Base URL of the forkd control plane.
    pub endpoint: String,
    /// Bearer token. Prefer injecting via [`ForkdConfig::from_env`].
    pub auth_token: Option<String>,
    /// Per-request HTTP timeout.
    pub request_timeout: Duration,
}

impl ForkdConfig {
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            auth_token: None,
            request_timeout: Duration::from_secs(30),
        }
    }

    /// Read the auth token from `FORKD_API_TOKEN` in the environment.
    pub fn from_env(endpoint: impl Into<String>) -> Self {
        let mut c = Self::new(endpoint);
        c.auth_token = std::env::var("FORKD_API_TOKEN").ok();
        c
    }
}

// ---- Wire DTOs -------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct ParentResponse {
    parent_id: String,
}

#[derive(Debug, Serialize)]
struct ForkRequest<'a> {
    branch: &'a str,
}

#[derive(Debug, Deserialize)]
struct ForkResponse {
    child_id: String,
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

fn unavailable(reason: impl std::fmt::Display) -> KernelError {
    KernelError::BackendUnavailable {
        backend: BACKEND_NAME.into(),
        reason: reason.to_string(),
    }
}

/// POSIX single-quote a string for safe embedding in `sh -c`.
fn shq(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

// ---- Client ----------------------------------------------------------------

/// Typed HTTP client for the forkd control API.
pub struct ForkdClient {
    config: ForkdConfig,
    http: reqwest::Client,
}

impl ForkdClient {
    pub fn new(config: ForkdConfig) -> KernelResult<Self> {
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

    /// Ensure a warm parent exists; idempotent on the service side.
    pub async fn ensure_parent(&self) -> KernelResult<String> {
        let resp: ParentResponse = self.post("/v1/parents", &serde_json::json!({})).await?;
        validate_remote_id(&resp.parent_id)?;
        Ok(resp.parent_id)
    }

    pub async fn fork_parent(&self, parent: &str, branch: &BranchId) -> KernelResult<String> {
        validate_remote_id(parent)?;
        let resp: ForkResponse = self
            .post(
                &format!("/v1/parents/{parent}/fork"),
                &ForkRequest {
                    branch: branch.as_str(),
                },
            )
            .await?;
        validate_remote_id(&resp.child_id)?;
        Ok(resp.child_id)
    }

    pub async fn fork_child(&self, child: &str, branch: &BranchId) -> KernelResult<String> {
        validate_remote_id(child)?;
        let resp: ForkResponse = self
            .post(
                &format!("/v1/children/{child}/fork"),
                &ForkRequest {
                    branch: branch.as_str(),
                },
            )
            .await?;
        validate_remote_id(&resp.child_id)?;
        Ok(resp.child_id)
    }

    pub async fn exec(&self, child: &str, params: ExecParams<'_>) -> KernelResult<ExecOutcome> {
        validate_remote_id(child)?;
        let resp: ExecResponse = self
            .post(
                &format!("/v1/children/{child}/exec"),
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
        Ok(ExecOutcome {
            exit_code: resp.exit_code,
            stdout: resp.stdout,
            stderr: resp.stderr,
            duration_ms: resp.duration_ms,
            network_bytes: resp.network_bytes,
        })
    }

    pub async fn delete_child(&self, child: &str) -> KernelResult<()> {
        validate_remote_id(child)?;
        let url = format!(
            "{}/v1/children/{child}",
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

/// Result of a remote exec.
#[derive(Debug, Clone)]
pub struct ExecOutcome {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub duration_ms: u64,
    /// Network egress bytes if the service reports them; `None` otherwise.
    pub network_bytes: Option<u64>,
}

// ---- Backend ---------------------------------------------------------------

/// forkd backend: one CoW child per branch, forked from a warm parent.
pub struct ForkdBackend {
    client: ForkdClient,
    parent: Mutex<Option<String>>,
    children: Mutex<HashMap<BranchId, String>>,
    state_children: Mutex<HashMap<StateId, String>>,
}

impl ForkdBackend {
    pub fn new(config: ForkdConfig) -> KernelResult<Self> {
        Ok(Self {
            client: ForkdClient::new(config)?,
            parent: Mutex::new(None),
            children: Mutex::new(HashMap::new()),
            state_children: Mutex::new(HashMap::new()),
        })
    }

    /// Get-or-create is atomic: the children map lock is held across the
    /// remote fork so concurrent first uses of a branch cannot race two
    /// children (and the parent lock is held across parent creation).
    async fn child_for(&self, branch: &BranchId) -> KernelResult<String> {
        let mut children = self.children.lock().await;
        if let Some(id) = children.get(branch) {
            return Ok(id.clone());
        }
        let parent = {
            let mut guard = self.parent.lock().await;
            match guard.as_ref() {
                Some(p) => p.clone(),
                None => {
                    let p = self.client.ensure_parent().await?;
                    *guard = Some(p.clone());
                    p
                }
            }
        };
        let child = self.client.fork_parent(&parent, branch).await?;
        children.insert(branch.clone(), child.clone());
        Ok(child)
    }
}

#[async_trait]
impl Backend for ForkdBackend {
    fn profile(&self) -> BackendProfile {
        BackendProfile {
            name: BACKEND_NAME.into(),
            isolation_strength: 90,
            cold_start_ms: 15,
            replay_class: ReplayClass::ProcessAndFilesystem,
            supports_fork: true,
            supports_gui: false,
            full_linux: true,
        }
    }

    async fn execute(&self, req: ExecutionRequest) -> KernelResult<ExecutionOutcome> {
        let child = self.child_for(&req.branch).await?;
        let timeout_ms = req.budget.cpu_ms.max(1);
        let empty = BTreeMap::new();
        // Forward budget + confinement on every exec so the remote enforces them.
        macro_rules! params {
            ($command:expr, $cwd:expr, $env:expr) => {
                ExecParams {
                    command: $command,
                    cwd: $cwd,
                    env: $env,
                    timeout_ms,
                    budget: &req.budget,
                    writable_prefixes: &req.writable_prefixes,
                    readable_prefixes: &req.readable_prefixes,
                    egress_domains: &req.egress_domains,
                }
            };
        }
        let out = match &req.action {
            ActionKind::Shell { command, cwd, env } => {
                self.client
                    .exec(&child, params!(command, cwd.as_deref(), env))
                    .await?
            }
            ActionKind::ReadFile { path } => {
                let cmd = format!("cat {}", shq(path));
                self.client
                    .exec(&child, params!(&cmd, None, &empty))
                    .await?
            }
            ActionKind::WriteFile { path, contents_b64 } => {
                let cmd = format!(
                    "mkdir -p \"$(dirname {p})\" && printf %s {b} | base64 -d > {p}",
                    p = shq(path),
                    b = shq(contents_b64)
                );
                self.client
                    .exec(&child, params!(&cmd, None, &empty))
                    .await?
            }
            ActionKind::DeletePath { path } => {
                let cmd = format!("rm -rf -- {}", shq(path));
                self.client
                    .exec(&child, params!(&cmd, None, &empty))
                    .await?
            }
            other => {
                return Err(unavailable(format!(
                    "forkd backend does not execute `{}` actions",
                    other.required_operation().0
                )))
            }
        };
        self.state_children
            .lock()
            .await
            .insert(req.base_state.clone(), child);
        let paths_written = match &req.action {
            ActionKind::WriteFile { path, .. } => vec![path.clone()],
            _ => Vec::new(),
        };
        // Real value when the service reports one; otherwise 0 — network
        // accounting is not available and is never fabricated.
        let bytes = out.network_bytes.unwrap_or(0);
        Ok(ExecutionOutcome {
            exit_code: out.exit_code,
            stdout: out.stdout.into_bytes(),
            stderr: out.stderr.into_bytes(),
            usage: ResourceBudget {
                cpu_ms: out.duration_ms,
                network_bytes: bytes,
                ..ResourceBudget::zero()
            },
            paths_written,
            replay_class: ReplayClass::ProcessAndFilesystem,
        })
    }

    /// CoW fan-out: fork the live child that produced `from`. Returns
    /// `Ok(false)` when that state is unknown to this backend.
    async fn fork(&self, from: &StateId, to_branch: &BranchId) -> KernelResult<bool> {
        let source = { self.state_children.lock().await.get(from).cloned() };
        let Some(source) = source else {
            return Ok(false);
        };
        let child = self.client.fork_child(&source, to_branch).await?;
        self.children.lock().await.insert(to_branch.clone(), child);
        Ok(true)
    }

    async fn discard(&self, branch: &BranchId) -> KernelResult<()> {
        let child = { self.children.lock().await.remove(branch) };
        if let Some(child) = child {
            self.client.delete_child(&child).await?;
        }
        Ok(())
    }
}

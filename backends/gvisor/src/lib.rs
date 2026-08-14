//! # ak-backend-gvisor
//!
//! Remote adapter [`Backend`] for a **gVisor** (`runsc`) container host that
//! exposes an HTTP control API in front of its runsc-managed containers.
//! Honest adapter: real HTTP via `reqwest`; unreachable/erroring endpoints map
//! to [`KernelError::BackendUnavailable`]. No pretend-success paths.
//!
//! ## Assumed control API (documented here because these APIs evolve)
//!
//! All requests carry `Authorization: Bearer <token>` when a token is set.
//!
//! | Method & path | Body | Response |
//! |---|---|---|
//! | `POST /v1/containers` | `{"branch": "...", "image?": "..."}` | `{"container_id": "ct-..."}` |
//! | `POST /v1/containers/{id}/exec` | `{"command","cwd?","env","timeout_ms"}` | `{"exit_code","stdout","stderr","duration_ms"}` |
//! | `DELETE /v1/containers/{id}` | — | `{}` |
//!
//! File actions are translated into shell execs (`cat`, `base64 -d`, `rm`)
//! inside the container, since runsc exposes only exec-level control here.
//!
//! Profile: isolation_strength **70** (user-space kernel, syscall
//! interception), `supports_fork = false` (runsc has no CoW container fork),
//! replay class [`ReplayClass::FilesystemOnly`].

use ak_core::action::ActionKind;
use ak_core::budget::ResourceBudget;
use ak_core::error::{KernelError, KernelResult};
use ak_core::ids::BranchId;
use ak_core::replay::ReplayClass;
use ak_core::traits::{Backend, BackendProfile, ExecutionOutcome, ExecutionRequest};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::time::Duration;
use tokio::sync::Mutex;

const BACKEND_NAME: &str = "gvisor";

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

/// Configuration for [`GvisorBackend`].
#[derive(Debug, Clone)]
pub struct GvisorConfig {
    /// Base URL of the runsc host's control API.
    pub endpoint: String,
    /// Bearer token. Prefer injecting via [`GvisorConfig::from_env`].
    pub auth_token: Option<String>,
    /// Container image to launch for new branches, if the host requires one.
    pub image: Option<String>,
    /// Per-request HTTP timeout.
    pub request_timeout: Duration,
}

impl GvisorConfig {
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            auth_token: None,
            image: None,
            request_timeout: Duration::from_secs(30),
        }
    }

    /// Read the auth token from `GVISOR_API_TOKEN` in the environment.
    pub fn from_env(endpoint: impl Into<String>) -> Self {
        let mut c = Self::new(endpoint);
        c.auth_token = std::env::var("GVISOR_API_TOKEN").ok();
        c
    }
}

#[derive(Debug, Serialize)]
struct CreateContainerRequest<'a> {
    branch: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    image: Option<&'a str>,
}

#[derive(Debug, Deserialize)]
struct CreateContainerResponse {
    container_id: String,
}

#[derive(Debug, Serialize)]
struct ExecRequest<'a> {
    command: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    cwd: Option<&'a str>,
    env: &'a BTreeMap<String, String>,
    timeout_ms: u64,
    /// Full step budget, forwarded so the host can enforce it.
    budget: &'a ResourceBudget,
    /// Compiled confinement, forwarded so the host can enforce it.
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
    /// Network egress bytes as measured by the host, when it reports them.
    #[serde(default)]
    network_bytes: Option<u64>,
}

fn unavailable(reason: impl std::fmt::Display) -> KernelError {
    KernelError::BackendUnavailable {
        backend: BACKEND_NAME.into(),
        reason: reason.to_string(),
    }
}

fn shq(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// Typed HTTP client for the runsc host control API.
pub struct GvisorClient {
    config: GvisorConfig,
    http: reqwest::Client,
}

impl GvisorClient {
    pub fn new(config: GvisorConfig) -> KernelResult<Self> {
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

    pub async fn create_container(&self, branch: &BranchId) -> KernelResult<String> {
        let resp: CreateContainerResponse = self
            .post(
                "/v1/containers",
                &CreateContainerRequest {
                    branch: branch.as_str(),
                    image: self.config.image.as_deref(),
                },
            )
            .await?;
        validate_remote_id(&resp.container_id)?;
        Ok(resp.container_id)
    }

    pub async fn exec(
        &self,
        container: &str,
        params: ExecParams<'_>,
    ) -> KernelResult<(i32, String, String, u64, Option<u64>)> {
        validate_remote_id(container)?;
        let resp: ExecResponse = self
            .post(
                &format!("/v1/containers/{container}/exec"),
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

    pub async fn delete_container(&self, container: &str) -> KernelResult<()> {
        validate_remote_id(container)?;
        let url = format!(
            "{}/v1/containers/{container}",
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

/// gVisor backend: one runsc container per branch.
pub struct GvisorBackend {
    client: GvisorClient,
    containers: Mutex<HashMap<BranchId, String>>,
}

impl GvisorBackend {
    pub fn new(config: GvisorConfig) -> KernelResult<Self> {
        Ok(Self {
            client: GvisorClient::new(config)?,
            containers: Mutex::new(HashMap::new()),
        })
    }

    /// Get-or-create is atomic: the map lock is held across the remote create
    /// so concurrent first uses of a branch cannot race two containers.
    async fn container_for(&self, branch: &BranchId) -> KernelResult<String> {
        let mut containers = self.containers.lock().await;
        if let Some(id) = containers.get(branch) {
            return Ok(id.clone());
        }
        let id = self.client.create_container(branch).await?;
        containers.insert(branch.clone(), id.clone());
        Ok(id)
    }
}

#[async_trait]
impl Backend for GvisorBackend {
    fn profile(&self) -> BackendProfile {
        BackendProfile {
            name: BACKEND_NAME.into(),
            isolation_strength: 70,
            cold_start_ms: 120,
            replay_class: ReplayClass::FilesystemOnly,
            supports_fork: false,
            supports_gui: false,
            full_linux: true,
            // Remote workspace, no state sync into the kernel's CAS yet:
            // steps are recorded as audit-only excursions.
            shares_workspace: false,
            syncs_state: false,
        }
    }

    async fn execute(&self, req: ExecutionRequest) -> KernelResult<ExecutionOutcome> {
        let container = self.container_for(&req.branch).await?;
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
        let (exit_code, stdout, stderr, duration_ms, network_bytes) = match &req.action {
            ActionKind::Shell { command, cwd, env } => {
                self.client
                    .exec(&container, params!(command, cwd.as_deref(), env))
                    .await?
            }
            ActionKind::ReadFile { path } => {
                let cmd = format!("cat {}", shq(path));
                self.client
                    .exec(&container, params!(&cmd, None, &empty))
                    .await?
            }
            ActionKind::WriteFile { path, contents_b64 } => {
                let cmd = format!(
                    "mkdir -p \"$(dirname {p})\" && printf %s {b} | base64 -d > {p}",
                    p = shq(path),
                    b = shq(contents_b64)
                );
                self.client
                    .exec(&container, params!(&cmd, None, &empty))
                    .await?
            }
            ActionKind::DeletePath { path } => {
                let cmd = format!("rm -rf -- {}", shq(path));
                self.client
                    .exec(&container, params!(&cmd, None, &empty))
                    .await?
            }
            other => {
                return Err(unavailable(format!(
                    "gvisor backend does not execute `{}` actions",
                    other.required_operation().0
                )))
            }
        };
        let paths_written = match &req.action {
            ActionKind::WriteFile { path, .. } => vec![path.clone()],
            _ => Vec::new(),
        };
        // Real value when the host reports one; otherwise 0 — network
        // accounting is not available and is never fabricated.
        let bytes = network_bytes.unwrap_or(0);
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
            replay_class: ReplayClass::FilesystemOnly,
            workspace_delta: None,
        })
    }

    async fn discard(&self, branch: &BranchId) -> KernelResult<()> {
        let container = { self.containers.lock().await.remove(branch) };
        if let Some(container) = container {
            self.client.delete_container(&container).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn unreachable_endpoint_maps_to_backend_unavailable() {
        let b = GvisorBackend::new(GvisorConfig::new("http://127.0.0.1:1")).unwrap();
        let err = b
            .execute(ExecutionRequest {
                branch: BranchId("br-1".into()),
                base_state: ak_core::ids::StateId("st-1".into()),
                actor: ak_core::ids::PrincipalId("pr-1".into()),
                action: ActionKind::Shell {
                    command: "true".into(),
                    cwd: None,
                    env: BTreeMap::new(),
                },
                budget: ResourceBudget::step_default(),
                writable_prefixes: vec![],
                readable_prefixes: vec![],
                egress_domains: vec![],
            })
            .await
            .unwrap_err();
        assert!(matches!(err, KernelError::BackendUnavailable { .. }));
    }

    #[test]
    fn profile_is_honest() {
        let b = GvisorBackend::new(GvisorConfig::new("http://localhost:9999")).unwrap();
        let p = b.profile();
        assert_eq!(p.isolation_strength, 70);
        assert!(!p.supports_fork);
        assert_eq!(p.replay_class, ReplayClass::FilesystemOnly);
    }

    #[test]
    fn exec_wire_request_serializes_confinement_and_budget() {
        let env = BTreeMap::new();
        let budget = ResourceBudget::step_default();
        let writable = vec!["src/".to_string()];
        let readable = vec!["docs/".to_string()];
        let egress = vec!["example.com".to_string()];
        let wire = serde_json::to_value(ExecRequest {
            command: "true",
            cwd: None,
            env: &env,
            timeout_ms: 5,
            budget: &budget,
            writable_prefixes: &writable,
            readable_prefixes: &readable,
            egress_domains: &egress,
        })
        .unwrap();
        assert_eq!(wire["writable_prefixes"], serde_json::json!(["src/"]));
        assert_eq!(wire["readable_prefixes"], serde_json::json!(["docs/"]));
        assert_eq!(wire["egress_domains"], serde_json::json!(["example.com"]));
        assert_eq!(wire["budget"]["cpu_ms"], budget.cpu_ms);
    }

    #[test]
    fn invalid_remote_ids_are_rejected() {
        for bad in ["", "../evil", "a b", "x/y", "id?x=1", "sb%2e%2e"] {
            assert!(validate_remote_id(bad).is_err(), "{bad}");
        }
        for good in ["ct-1", "A.b_c-9"] {
            assert!(validate_remote_id(good).is_ok(), "{good}");
        }
    }

    #[test]
    fn non_loopback_http_endpoint_is_rejected() {
        let err = GvisorBackend::new(GvisorConfig::new("http://gvisor.example.com"))
            .err()
            .expect("expected config error");
        assert!(err.to_string().contains("https"), "{err}");
        GvisorBackend::new(GvisorConfig::new("http://127.0.0.1:9")).unwrap();
        GvisorBackend::new(GvisorConfig::new("http://[::1]:9")).unwrap();
        GvisorBackend::new(GvisorConfig::new("https://gvisor.example.com")).unwrap();
    }
}

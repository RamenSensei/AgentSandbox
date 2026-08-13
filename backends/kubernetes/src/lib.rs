//! # ak-backend-kubernetes
//!
//! Remote adapter [`Backend`] for the Kubernetes **agent Sandbox CRD**
//! (`agents.x-k8s.io/v1alpha1`, kind `Sandbox`), driving the API server over
//! HTTP. Honest adapter: real HTTP via `reqwest`; unreachable/erroring
//! endpoints map to [`KernelError::BackendUnavailable`].
//!
//! ## Assumed API surface (documented here because the CRD is alpha and evolves)
//!
//! All requests carry `Authorization: Bearer <token>` when a token is set.
//!
//! | Method & path | Body | Response |
//! |---|---|---|
//! | `POST /apis/agents.x-k8s.io/v1alpha1/namespaces/{ns}/sandboxes` | Sandbox manifest | Sandbox object (`metadata.name`) |
//! | `POST /apis/agents.x-k8s.io/v1alpha1/namespaces/{ns}/sandboxes/{name}/exec` | `{"command","cwd?","env","timeoutMs"}` | `{"exitCode","stdout","stderr","durationMs"}` |
//! | `DELETE /apis/agents.x-k8s.io/v1alpha1/namespaces/{ns}/sandboxes/{name}` | — | Status |
//!
//! The `exec` subresource is assumed to be provided by the sandbox controller
//! (analogous to `pods/exec` but request/response JSON instead of SPDY).
//!
//! ## Isolation is parameterized by RuntimeClass
//!
//! The effective isolation depends on the `runtimeClassName` in the sandbox
//! spec: `runc` ~40, `gvisor` ~70, `kata`/microVM ~90. Because the kernel's
//! router must never guess, [`KubernetesConfig::isolation_strength`] is an
//! explicit configuration input supplied alongside the runtime class.
//! `supports_fork = false` (no CoW sandbox cloning in the CRD).

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

const BACKEND_NAME: &str = "kubernetes";
const API_BASE: &str = "/apis/agents.x-k8s.io/v1alpha1";

/// Default sandbox image. Pinned to a specific release tag (never `:latest`)
/// so sandbox behavior is reproducible and upgrades are explicit; override
/// via [`KubernetesConfig::image`] to change it.
pub const DEFAULT_SANDBOX_IMAGE: &str = "ghcr.io/agent-kernel/sandbox:v0.8.0";

/// Maximum bytes accepted in any API-server response body.
const MAX_RESPONSE_BYTES: usize = 64 * 1024 * 1024;

fn config_error(reason: impl std::fmt::Display) -> KernelError {
    KernelError::Other(format!("{BACKEND_NAME} config error: {reason}"))
}

/// Enforce HTTPS for non-loopback API servers. Plain `http://` is allowed
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

/// Validate an identifier (sandbox name, namespace) before it is spliced into
/// a URL path. Only `[A-Za-z0-9._-]` is accepted, so no percent-encoding is
/// needed.
fn validate_remote_id(id: &str) -> KernelResult<()> {
    let ok = !id.is_empty()
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    if ok {
        Ok(())
    } else {
        Err(unavailable(format!(
            "invalid id `{id}` (allowed characters: [A-Za-z0-9._-])"
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

/// Configuration for [`KubernetesBackend`].
#[derive(Debug, Clone)]
pub struct KubernetesConfig {
    /// API server base URL, e.g. `https://kube-apiserver:6443`.
    pub endpoint: String,
    /// Bearer token (service account). Prefer [`KubernetesConfig::from_env`].
    pub auth_token: Option<String>,
    /// Namespace in which sandboxes are created.
    pub namespace: String,
    /// `runtimeClassName` for sandbox pods (e.g. `gvisor`, `kata`).
    pub runtime_class: Option<String>,
    /// Pod image for the sandbox. Defaults to [`DEFAULT_SANDBOX_IMAGE`],
    /// which is pinned to a release tag (never `:latest`).
    pub image: String,
    /// Isolation strength advertised to the router. MUST match the configured
    /// runtime class; there is no safe default guess, so callers set it
    /// explicitly (see crate docs for suggested values).
    pub isolation_strength: u8,
    /// Per-request HTTP timeout.
    pub request_timeout: Duration,
}

impl KubernetesConfig {
    pub fn new(endpoint: impl Into<String>, isolation_strength: u8) -> Self {
        Self {
            endpoint: endpoint.into(),
            auth_token: None,
            namespace: "default".into(),
            runtime_class: None,
            image: DEFAULT_SANDBOX_IMAGE.into(),
            isolation_strength,
            request_timeout: Duration::from_secs(60),
        }
    }

    /// Read the auth token from `KUBERNETES_API_TOKEN` in the environment.
    pub fn from_env(endpoint: impl Into<String>, isolation_strength: u8) -> Self {
        let mut c = Self::new(endpoint, isolation_strength);
        c.auth_token = std::env::var("KUBERNETES_API_TOKEN").ok();
        c
    }
}

// ---- Wire DTOs -------------------------------------------------------------

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SandboxManifest<'a> {
    api_version: &'static str,
    kind: &'static str,
    metadata: SandboxMetadata<'a>,
    spec: SandboxSpec<'a>,
}

#[derive(Debug, Serialize, Deserialize)]
struct SandboxMetadata<'a> {
    #[serde(rename = "generateName", skip_serializing_if = "Option::is_none")]
    generate_name: Option<&'a str>,
    #[serde(default)]
    labels: BTreeMap<String, String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SandboxSpec<'a> {
    image: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    runtime_class_name: Option<&'a str>,
}

#[derive(Debug, Deserialize)]
struct SandboxObject {
    metadata: SandboxObjectMetadata,
}

#[derive(Debug, Deserialize)]
struct SandboxObjectMetadata {
    name: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ExecRequest<'a> {
    command: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    cwd: Option<&'a str>,
    env: &'a BTreeMap<String, String>,
    timeout_ms: u64,
    /// Full step budget, forwarded so the sandbox controller can enforce it.
    budget: &'a ResourceBudget,
    /// Compiled confinement, forwarded so the controller can enforce it.
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
#[serde(rename_all = "camelCase")]
struct ExecResponse {
    exit_code: i32,
    #[serde(default)]
    stdout: String,
    #[serde(default)]
    stderr: String,
    #[serde(default)]
    duration_ms: u64,
    /// Network egress bytes as measured by the controller, when reported.
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

// ---- Client ----------------------------------------------------------------

/// Typed client for the Sandbox CRD via the API server.
pub struct KubernetesClient {
    config: KubernetesConfig,
    http: reqwest::Client,
}

impl KubernetesClient {
    pub fn new(config: KubernetesConfig) -> KernelResult<Self> {
        validate_endpoint(&config.endpoint)?;
        validate_remote_id(&config.namespace)
            .map_err(|_| config_error(format!("invalid namespace `{}`", config.namespace)))?;
        let http = reqwest::Client::builder()
            .timeout(config.request_timeout)
            .build()
            .map_err(unavailable)?;
        Ok(Self { config, http })
    }

    fn sandboxes_url(&self) -> String {
        format!(
            "{}{API_BASE}/namespaces/{}/sandboxes",
            self.config.endpoint.trim_end_matches('/'),
            self.config.namespace
        )
    }

    async fn post_json<B: Serialize, R: for<'de> Deserialize<'de>>(
        &self,
        url: &str,
        body: &B,
    ) -> KernelResult<R> {
        let mut req = self.http.post(url).json(body);
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

    /// Create a Sandbox object for a branch; returns its generated name.
    pub async fn create_sandbox(&self, branch: &BranchId) -> KernelResult<String> {
        let mut labels = BTreeMap::new();
        labels.insert(
            "agent-kernel/branch".to_string(),
            branch.as_str().to_string(),
        );
        let manifest = SandboxManifest {
            api_version: "agents.x-k8s.io/v1alpha1",
            kind: "Sandbox",
            metadata: SandboxMetadata {
                generate_name: Some("ak-sandbox-"),
                labels,
            },
            spec: SandboxSpec {
                image: &self.config.image,
                runtime_class_name: self.config.runtime_class.as_deref(),
            },
        };
        let obj: SandboxObject = self.post_json(&self.sandboxes_url(), &manifest).await?;
        validate_remote_id(&obj.metadata.name)?;
        Ok(obj.metadata.name)
    }

    pub async fn exec(
        &self,
        sandbox: &str,
        params: ExecParams<'_>,
    ) -> KernelResult<(i32, String, String, u64, Option<u64>)> {
        validate_remote_id(sandbox)?;
        let url = format!("{}/{sandbox}/exec", self.sandboxes_url());
        let resp: ExecResponse = self
            .post_json(
                &url,
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

    pub async fn delete_sandbox(&self, sandbox: &str) -> KernelResult<()> {
        validate_remote_id(sandbox)?;
        let url = format!("{}/{sandbox}", self.sandboxes_url());
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

/// Kubernetes Sandbox-CRD backend: one Sandbox object per branch.
pub struct KubernetesBackend {
    client: KubernetesClient,
    isolation_strength: u8,
    sandboxes: Mutex<HashMap<BranchId, String>>,
}

impl KubernetesBackend {
    pub fn new(config: KubernetesConfig) -> KernelResult<Self> {
        let isolation_strength = config.isolation_strength;
        Ok(Self {
            client: KubernetesClient::new(config)?,
            isolation_strength,
            sandboxes: Mutex::new(HashMap::new()),
        })
    }

    /// Get-or-create is atomic: the map lock is held across the remote create
    /// so concurrent first uses of a branch cannot race two sandboxes.
    async fn sandbox_for(&self, branch: &BranchId) -> KernelResult<String> {
        let mut sandboxes = self.sandboxes.lock().await;
        if let Some(name) = sandboxes.get(branch) {
            return Ok(name.clone());
        }
        let name = self.client.create_sandbox(branch).await?;
        sandboxes.insert(branch.clone(), name.clone());
        Ok(name)
    }
}

#[async_trait]
impl Backend for KubernetesBackend {
    fn profile(&self) -> BackendProfile {
        BackendProfile {
            name: BACKEND_NAME.into(),
            // Parameterized: depends on the configured RuntimeClass.
            isolation_strength: self.isolation_strength,
            cold_start_ms: 2_000,
            replay_class: ReplayClass::FilesystemOnly,
            supports_fork: false,
            supports_gui: false,
            full_linux: true,
            // Remote workspace, no state sync into the kernel's CAS yet:
            // steps are recorded as audit-only excursions.
            shares_workspace: false,
        }
    }

    async fn execute(&self, req: ExecutionRequest) -> KernelResult<ExecutionOutcome> {
        let sandbox = self.sandbox_for(&req.branch).await?;
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
                    .exec(&sandbox, params!(command, cwd.as_deref(), env))
                    .await?
            }
            ActionKind::ReadFile { path } => {
                let cmd = format!("cat {}", shq(path));
                self.client
                    .exec(&sandbox, params!(&cmd, None, &empty))
                    .await?
            }
            ActionKind::WriteFile { path, contents_b64 } => {
                let cmd = format!(
                    "mkdir -p \"$(dirname {p})\" && printf %s {b} | base64 -d > {p}",
                    p = shq(path),
                    b = shq(contents_b64)
                );
                self.client
                    .exec(&sandbox, params!(&cmd, None, &empty))
                    .await?
            }
            ActionKind::DeletePath { path } => {
                let cmd = format!("rm -rf -- {}", shq(path));
                self.client
                    .exec(&sandbox, params!(&cmd, None, &empty))
                    .await?
            }
            other => {
                return Err(unavailable(format!(
                    "kubernetes backend does not execute `{}` actions",
                    other.required_operation().0
                )))
            }
        };
        let paths_written = match &req.action {
            ActionKind::WriteFile { path, .. } => vec![path.clone()],
            _ => Vec::new(),
        };
        // Real value when the controller reports one; otherwise 0 — network
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
        })
    }

    async fn discard(&self, branch: &BranchId) -> KernelResult<()> {
        let sandbox = { self.sandboxes.lock().await.remove(branch) };
        if let Some(sandbox) = sandbox {
            self.client.delete_sandbox(&sandbox).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn isolation_is_parameterized_by_config() {
        for strength in [40u8, 70, 90] {
            let b =
                KubernetesBackend::new(KubernetesConfig::new("http://localhost:6443", strength))
                    .unwrap();
            assert_eq!(b.profile().isolation_strength, strength);
        }
    }

    #[tokio::test]
    async fn unreachable_api_server_maps_to_backend_unavailable() {
        let b = KubernetesBackend::new(KubernetesConfig::new("http://127.0.0.1:1", 70)).unwrap();
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
        match err {
            KernelError::BackendUnavailable { backend, .. } => assert_eq!(backend, "kubernetes"),
            other => panic!("expected BackendUnavailable, got {other:?}"),
        }
    }

    #[test]
    fn default_image_is_pinned_not_latest() {
        let c = KubernetesConfig::new("https://kube.example:6443", 70);
        assert_eq!(c.image, DEFAULT_SANDBOX_IMAGE);
        assert!(!c.image.ends_with(":latest"), "{}", c.image);
        assert!(c.image.contains(':'), "image must carry an explicit tag");
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
        assert_eq!(wire["writablePrefixes"], serde_json::json!(["src/"]));
        assert_eq!(wire["readablePrefixes"], serde_json::json!(["docs/"]));
        assert_eq!(wire["egressDomains"], serde_json::json!(["example.com"]));
        assert_eq!(wire["budget"]["cpu_ms"], budget.cpu_ms);
    }

    #[test]
    fn invalid_remote_ids_are_rejected() {
        for bad in ["", "../evil", "a b", "x/y", "name?x=1"] {
            assert!(validate_remote_id(bad).is_err(), "{bad}");
        }
        assert!(validate_remote_id("ak-sandbox-x7f2").is_ok());
    }

    #[test]
    fn non_loopback_http_endpoint_is_rejected() {
        let err = KubernetesBackend::new(KubernetesConfig::new("http://kube.example:6443", 70))
            .err()
            .expect("expected config error");
        assert!(err.to_string().contains("https"), "{err}");
        KubernetesBackend::new(KubernetesConfig::new("http://127.0.0.1:6443", 70)).unwrap();
        KubernetesBackend::new(KubernetesConfig::new("https://kube.example:6443", 70)).unwrap();
    }
}

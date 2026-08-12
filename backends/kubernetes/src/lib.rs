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
    /// Pod image for the sandbox.
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
            image: "ghcr.io/agent-kernel/sandbox:latest".into(),
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
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(unavailable(format!("{url} returned {status}: {text}")));
        }
        resp.json().await.map_err(unavailable)
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
        Ok(obj.metadata.name)
    }

    pub async fn exec(
        &self,
        sandbox: &str,
        command: &str,
        cwd: Option<&str>,
        env: &BTreeMap<String, String>,
        timeout_ms: u64,
    ) -> KernelResult<(i32, String, String, u64)> {
        let url = format!("{}/{sandbox}/exec", self.sandboxes_url());
        let resp: ExecResponse = self
            .post_json(
                &url,
                &ExecRequest {
                    command,
                    cwd,
                    env,
                    timeout_ms,
                },
            )
            .await?;
        Ok((resp.exit_code, resp.stdout, resp.stderr, resp.duration_ms))
    }

    pub async fn delete_sandbox(&self, sandbox: &str) -> KernelResult<()> {
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

    async fn sandbox_for(&self, branch: &BranchId) -> KernelResult<String> {
        if let Some(name) = self.sandboxes.lock().await.get(branch) {
            return Ok(name.clone());
        }
        let name = self.client.create_sandbox(branch).await?;
        self.sandboxes
            .lock()
            .await
            .insert(branch.clone(), name.clone());
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
        }
    }

    async fn execute(&self, req: ExecutionRequest) -> KernelResult<ExecutionOutcome> {
        let sandbox = self.sandbox_for(&req.branch).await?;
        let timeout_ms = req.budget.cpu_ms.max(1);
        let empty = BTreeMap::new();
        let (exit_code, stdout, stderr, duration_ms) = match &req.action {
            ActionKind::Shell { command, cwd, env } => {
                self.client
                    .exec(&sandbox, command, cwd.as_deref(), env, timeout_ms)
                    .await?
            }
            ActionKind::ReadFile { path } => {
                self.client
                    .exec(
                        &sandbox,
                        &format!("cat {}", shq(path)),
                        None,
                        &empty,
                        timeout_ms,
                    )
                    .await?
            }
            ActionKind::WriteFile { path, contents_b64 } => {
                let cmd = format!(
                    "mkdir -p \"$(dirname {p})\" && printf %s {b} | base64 -d > {p}",
                    p = shq(path),
                    b = shq(contents_b64)
                );
                self.client
                    .exec(&sandbox, &cmd, None, &empty, timeout_ms)
                    .await?
            }
            ActionKind::DeletePath { path } => {
                self.client
                    .exec(
                        &sandbox,
                        &format!("rm -rf -- {}", shq(path)),
                        None,
                        &empty,
                        timeout_ms,
                    )
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
}

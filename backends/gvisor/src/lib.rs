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
        Ok(resp.container_id)
    }

    pub async fn exec(
        &self,
        container: &str,
        command: &str,
        cwd: Option<&str>,
        env: &BTreeMap<String, String>,
        timeout_ms: u64,
    ) -> KernelResult<(i32, String, String, u64)> {
        let resp: ExecResponse = self
            .post(
                &format!("/v1/containers/{container}/exec"),
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

    pub async fn delete_container(&self, container: &str) -> KernelResult<()> {
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

    async fn container_for(&self, branch: &BranchId) -> KernelResult<String> {
        if let Some(id) = self.containers.lock().await.get(branch) {
            return Ok(id.clone());
        }
        let id = self.client.create_container(branch).await?;
        self.containers
            .lock()
            .await
            .insert(branch.clone(), id.clone());
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
        }
    }

    async fn execute(&self, req: ExecutionRequest) -> KernelResult<ExecutionOutcome> {
        let container = self.container_for(&req.branch).await?;
        let timeout_ms = req.budget.cpu_ms.max(1);
        let empty = BTreeMap::new();
        let (exit_code, stdout, stderr, duration_ms) = match &req.action {
            ActionKind::Shell { command, cwd, env } => {
                self.client
                    .exec(&container, command, cwd.as_deref(), env, timeout_ms)
                    .await?
            }
            ActionKind::ReadFile { path } => {
                self.client
                    .exec(
                        &container,
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
                    .exec(&container, &cmd, None, &empty, timeout_ms)
                    .await?
            }
            ActionKind::DeletePath { path } => {
                self.client
                    .exec(
                        &container,
                        &format!("rm -rf -- {}", shq(path)),
                        None,
                        &empty,
                        timeout_ms,
                    )
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
}

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
        Self { endpoint: endpoint.into(), auth_token: None, request_timeout: Duration::from_secs(30) }
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
    KernelError::BackendUnavailable { backend: BACKEND_NAME.into(), reason: reason.to_string() }
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

    /// Ensure a warm parent exists; idempotent on the service side.
    pub async fn ensure_parent(&self) -> KernelResult<String> {
        let resp: ParentResponse = self.post("/v1/parents", &serde_json::json!({})).await?;
        Ok(resp.parent_id)
    }

    pub async fn fork_parent(&self, parent: &str, branch: &BranchId) -> KernelResult<String> {
        let resp: ForkResponse = self
            .post(&format!("/v1/parents/{parent}/fork"), &ForkRequest { branch: branch.as_str() })
            .await?;
        Ok(resp.child_id)
    }

    pub async fn fork_child(&self, child: &str, branch: &BranchId) -> KernelResult<String> {
        let resp: ForkResponse = self
            .post(&format!("/v1/children/{child}/fork"), &ForkRequest { branch: branch.as_str() })
            .await?;
        Ok(resp.child_id)
    }

    pub async fn exec(
        &self,
        child: &str,
        command: &str,
        cwd: Option<&str>,
        env: &BTreeMap<String, String>,
        timeout_ms: u64,
    ) -> KernelResult<ExecOutcome> {
        let resp: ExecResponse = self
            .post(
                &format!("/v1/children/{child}/exec"),
                &ExecRequest { command, cwd, env, timeout_ms },
            )
            .await?;
        Ok(ExecOutcome {
            exit_code: resp.exit_code,
            stdout: resp.stdout,
            stderr: resp.stderr,
            duration_ms: resp.duration_ms,
        })
    }

    pub async fn delete_child(&self, child: &str) -> KernelResult<()> {
        let url =
            format!("{}/v1/children/{child}", self.config.endpoint.trim_end_matches('/'));
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

    async fn child_for(&self, branch: &BranchId) -> KernelResult<String> {
        if let Some(id) = self.children.lock().await.get(branch) {
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
        self.children.lock().await.insert(branch.clone(), child.clone());
        Ok(child)
    }
}

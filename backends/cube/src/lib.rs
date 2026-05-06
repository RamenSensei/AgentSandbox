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

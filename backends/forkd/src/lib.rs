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

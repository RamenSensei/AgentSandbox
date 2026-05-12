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

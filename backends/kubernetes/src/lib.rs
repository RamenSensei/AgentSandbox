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

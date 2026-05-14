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

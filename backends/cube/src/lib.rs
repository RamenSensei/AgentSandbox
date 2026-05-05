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

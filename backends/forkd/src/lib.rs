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

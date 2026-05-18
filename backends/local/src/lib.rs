//! # ak-backend-local
//!
//! A real, working local OS-sandbox [`Backend`] for macOS and Linux, used by
//! tests and examples. It executes [`ActionKind::Shell`], [`ActionKind::ReadFile`],
//! [`ActionKind::WriteFile`] and [`ActionKind::DeletePath`] inside a
//! **per-branch workspace directory** with:
//!
//! - a **scrubbed environment**: the child process environment is cleared and
//!   only `PATH` (host value), `HOME` (set to the workspace) and `LANG` are
//!   provided, plus any explicitly pre-authorized variables carried on the
//!   action itself;
//! - a **wall-clock timeout** derived from `budget.cpu_ms`, with
//!   kill-on-timeout via the child's process group where available;
//! - **output capture with byte caps** (see [`LocalBackendConfig::max_capture_bytes`]);
//! - **in-process path confinement**: every path is verified to be inside the
//!   workspace (no absolute paths, no `..`, symlink escapes rejected by
//!   canonicalizing the deepest existing ancestor) and to match the request's
//!   readable/writable prefixes;
//! - **`paths_written` detection** via an mtime/size scan diff of the
//!   workspace before and after execution.
//!
//! On Linux, if a `bwrap` (bubblewrap) binary is found at runtime, shell
//! commands are additionally wrapped in a bubblewrap sandbox with network and
//! PID namespaces unshared. This is feature-detected at *runtime*, not compile
//! time; without it the backend performs a plain confined exec.
//!
//! Replay class: [`ReplayClass::FilesystemOnly`] — the workspace tree is the
//! only state this backend can faithfully restore.

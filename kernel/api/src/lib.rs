//! # ak-api
//!
//! The integration layer of AgentKernel: the [`Kernel`] façade that composes
//! every component crate (state DAG, causal ledger, identity, policy, effect
//! broker, scheduler, local backend) behind one transactional API, plus the
//! [`http`] module exposing the JSON/HTTP binding of the Agent Execution
//! Protocol and the `agent-kernel-server` binary.
//!
//! ## Replay guarantees (documented honestly)
//!
//! - **Audit replay** ([`Kernel::replay_audit`]) streams recorded ledger
//!   events for a sequence range. It never re-executes anything and is
//!   available for every step.
//! - **Sandbox replay** ([`Kernel::replay_sandbox`]) materializes the
//!   parent state of a recorded step from the CAS into a scratch workspace
//!   and re-runs the recorded local action there. It guarantees the same
//!   *inputs* (workspace bytes, action); the outcome may differ when the
//!   action itself is nondeterministic — the report says whether the
//!   resulting workspace tree matched the recorded one.
//! - **Live replay** ([`Kernel::replay_live`]) re-proposes and re-commits an
//!   effect *contract* against the live external world under a fresh
//!   idempotency key, running the full commit-time revalidation again. It
//!   guarantees the **contract**, never the outcome: the external system may
//!   have drifted, in which case revalidation aborts with
//!   `StaleAuthorization` instead of committing something unapproved.

pub mod auth;
pub mod http;
pub mod kernel;

pub use ak_core as core;
pub use kernel::{
    AutoStepResult, BackendSetup, EnvelopeItemReport, EnvelopeReport, EnvelopeRequest,
    EpisodeDescription, ExploreCandidate, ExploreCandidateReport, ExploreOptions, ExploreReport,
    HttpEgressSetup, Kernel, KernelConfig, McpServerSetup, ReplaySandboxReport, StepExplanation,
    StepResult,
};

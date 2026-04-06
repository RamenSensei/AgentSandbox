//! # ak-policy
//!
//! The deterministic policy engine and capability compiler of AgentKernel.
//!
//! - [`PolicyDocument`] — a typed, declarative policy loadable from YAML:
//!   rules (principal selectors, operation globs, allow/deny/require-approval,
//!   parameter [`ak_core::Constraint`]s, use counts, TTLs, budget caps, risk
//!   weights), path policies, an egress domain allowlist, a tool policy, and
//!   an escalation policy. Every mutation bumps `policy_epoch`.
//! - [`PolicyEngine`] — `evaluate(principal, operation, params, branch, now)`
//!   returning a fully machine-readable [`Decision`].
//! - [`compiler`] — turns an approved semantic grant into a
//!   [`ak_core::CapabilityLease`] plus a [`CompiledConfinement`] that the
//!   scheduler hands to isolation backends.
//! - [`envelope`] — parses a human-approved *autonomy envelope* ("approve a
//!   space, not each command") into a set of leases.
//!
//! ## Determinism invariant
//!
//! **LLM intent hints are never an input to policy evaluation.** The engine's
//! signature deliberately accepts only the principal, the canonical operation,
//! the canonical parameters, the branch, and the clock. Free-text like
//! [`ak_core::action::Action::intent_hint`] is used elsewhere for scheduling
//! and audit narration, but it cannot change an authorization outcome: the
//! same five inputs always produce the same [`Decision`].

pub mod compiler;
pub mod document;
pub mod engine;
pub mod envelope;
pub mod error;

pub use compiler::{compile_grant, CompiledConfinement, CompiledGrant, SyscallProfile};
pub use document::{
    EscalationPolicy, PathPolicy, PolicyDocument, PolicyRule, PrincipalSelector,
    RequestableScopeSpec, RuleEffect, ToolPolicy,
};
pub use engine::{Decision, PolicyEngine};
pub use envelope::{AutonomyEnvelope, EnvelopeGrant};
pub use error::{PolicyError, PolicyResult};

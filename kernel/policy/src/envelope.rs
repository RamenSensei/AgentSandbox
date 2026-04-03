//! Autonomy envelopes: "approve a space, not each command".
//!
//! A human approves one YAML document describing everything an agent may do
//! for the duration of a task — an allow list of scoped operations, a forbid
//! list that overrides it, and an overall budget. The envelope compiles into
//! a set of [`CapabilityLease`]s issued to a single principal, so every later
//! action is authorized mechanically without further interruptions.

use crate::error::{PolicyError, PolicyResult};
use ak_core::budget::ResourceBudget;
use ak_core::capability::{glob_match, CapabilityLease, Constraint, Operation};
use ak_core::ids::{LeaseId, PrincipalId};
use chrono::{DateTime, Duration, Utc};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

/// One allowed operation inside an envelope.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvelopeGrant {
    /// Concrete operation (no globs — every lease names one operation).
    pub operation: String,
    /// Parameter constraints for this operation.
    #[serde(default, skip_serializing_if = "IndexMap::is_empty")]
    pub constraints: IndexMap<String, Constraint>,
    /// Invocation budget (default 1).
    #[serde(default = "default_uses")]
    pub max_uses: u32,
    /// Per-grant TTL override in seconds; defaults to the envelope TTL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<u64>,
    /// Per-grant resource cap; defaults to the envelope budget.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget: Option<ResourceBudget>,
}

fn default_uses() -> u32 {
    1
}
fn default_envelope_ttl() -> u64 {
    3600
}

/// A human-approved autonomy envelope.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutonomyEnvelope {
    /// Human-facing name of the approved task, audit only.
    #[serde(default)]
    pub name: String,
    /// Operations the principal may perform.
    pub allow: Vec<EnvelopeGrant>,
    /// Operation globs that must never be granted, even if listed in `allow`.
    /// Forbid wins over allow.
    #[serde(default)]
    pub forbid: Vec<String>,
    /// Default lease TTL in seconds (default 3600).
    #[serde(default = "default_envelope_ttl")]
    pub ttl_seconds: u64,
    /// Default per-lease resource budget; defaults to
    /// [`ResourceBudget::step_default`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget: Option<ResourceBudget>,
}

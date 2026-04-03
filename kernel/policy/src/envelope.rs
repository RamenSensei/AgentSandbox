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

impl AutonomyEnvelope {
    /// Parse an envelope from YAML text.
    pub fn from_yaml_str(yaml: &str) -> PolicyResult<Self> {
        let env: AutonomyEnvelope = serde_yaml::from_str(yaml)?;
        env.validate()?;
        Ok(env)
    }

    /// Load an envelope from a YAML file.
    pub fn from_yaml_file(path: impl AsRef<std::path::Path>) -> PolicyResult<Self> {
        Self::from_yaml_str(&std::fs::read_to_string(path)?)
    }

    /// Reject envelopes whose allow list collides with the forbid list.
    /// Colliding entries are an authoring error, not something to silently
    /// drop: the human should see exactly what they are approving.
    pub fn validate(&self) -> PolicyResult<()> {
        if self.allow.is_empty() {
            return Err(PolicyError::EnvelopeRejected("envelope allows nothing".into()));
        }
        for grant in &self.allow {
            if grant.operation.contains('*') {
                return Err(PolicyError::EnvelopeRejected(format!(
                    "allow entry `{}` uses a glob; envelopes grant concrete operations",
                    grant.operation
                )));
            }
            if let Some(forbidden) = self.forbid.iter().find(|f| glob_match(f, &grant.operation)) {
                return Err(PolicyError::EnvelopeRejected(format!(
                    "allow entry `{}` collides with forbid pattern `{forbidden}`",
                    grant.operation
                )));
            }
        }
        Ok(())
    }

    /// Compile this envelope into a set of leases for `principal`, issued at
    /// `now`. Each allow entry becomes one lease.
    pub fn into_leases(
        &self,
        principal: &PrincipalId,
        now: DateTime<Utc>,
    ) -> PolicyResult<Vec<CapabilityLease>> {
        self.validate()?;
        let default_budget = self.budget.unwrap_or_else(ResourceBudget::step_default);
        let mut leases = Vec::with_capacity(self.allow.len());
        for grant in &self.allow {
            let ttl_secs = grant.ttl_seconds.unwrap_or(self.ttl_seconds);
            let ttl = Duration::seconds(i64::try_from(ttl_secs).unwrap_or(i64::MAX));
            leases.push(CapabilityLease {
                id: LeaseId::generate(),
                principal: principal.clone(),
                operation: Operation::new(grant.operation.clone()),
                constraints: grant.constraints.clone(),
                remaining_uses: grant.max_uses,
                issued_at: now,
                expires_at: now + ttl,
                bound_branch: None,
                budget: grant.budget.unwrap_or(default_budget),
                parent_lease: None,
                preconditions: IndexMap::new(),
                revoked: false,
            });
        }
        Ok(leases)
    }
}

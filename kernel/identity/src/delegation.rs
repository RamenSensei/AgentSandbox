//! Audited delegation: registry-checked attenuation of capability leases.

use crate::db::IdentityDb;
use crate::error::{IdentityError, IdentityResult};
use crate::lease_store::LeaseStore;
use crate::registry::PrincipalRegistry;
use ak_core::budget::ResourceBudget;
use ak_core::capability::{CapabilityLease, Constraint};
use ak_core::ids::{LeaseId, PrincipalId};
use chrono::{DateTime, Utc};
use indexmap::IndexMap;
use rusqlite::params;
use serde::{Deserialize, Serialize};

/// One recorded delegation event, kept for audit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegationRecord {
    /// The lease that was attenuated.
    pub parent_lease: LeaseId,
    /// The newly issued child lease.
    pub child_lease: LeaseId,
    /// The principal that performed the delegation.
    pub delegator: PrincipalId,
    /// The principal that received the attenuated lease.
    pub delegatee: PrincipalId,
    pub delegated_at: DateTime<Utc>,
}

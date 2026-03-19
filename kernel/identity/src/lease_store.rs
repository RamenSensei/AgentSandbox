//! The [`LeaseStore`]: durable capability leases with cascading revocation.

use crate::db::IdentityDb;
use crate::error::{IdentityError, IdentityResult};
use ak_core::capability::CapabilityLease;
use ak_core::ids::{LeaseId, PrincipalId};
use chrono::{DateTime, Utc};
use rusqlite::{params, OptionalExtension};

/// Durable storage for [`CapabilityLease`] rows.
///
/// The store enforces two lifecycle rules the in-memory lease type cannot:
///
/// 1. **Cascading revocation** — because attenuated leases record their
///    `parent_lease`, revoking a lease transitively revokes everything derived
///    from it. Authority handed to a sub-agent dies with the grant it came
///    from.
/// 2. **Consume-a-use** — [`LeaseStore::consume_use`] atomically decrements
///    `remaining_uses` and refuses revoked, expired or exhausted leases.
#[derive(Clone)]
pub struct LeaseStore {
    db: IdentityDb,
}

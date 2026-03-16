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

/// Wraps [`CapabilityLease::attenuate`] with registry-level checks and an
/// audit trail.
///
/// The core lease algebra guarantees the *authority* can only shrink; this
/// service additionally guarantees the *topology* is sane:
///
/// - the delegatee must be a registered principal;
/// - the delegatee must be the delegator itself (rebinding one's own
///   authority) or one of the delegator's spawned descendants — authority
///   never flows sideways or upwards in the spawn tree;
/// - the parent lease must actually be held by the delegator;
/// - every successful delegation is recorded in the `delegations` table.
#[derive(Clone)]
pub struct DelegationService {
    db: IdentityDb,
    registry: PrincipalRegistry,
    leases: LeaseStore,
}

impl DelegationService {
    /// Build a delegation service over the shared identity database.
    pub fn new(db: IdentityDb) -> Self {
        Self {
            registry: PrincipalRegistry::new(db.clone()),
            leases: LeaseStore::new(db.clone()),
            db,
        }
    }

    /// Attenuate `parent_lease` (held by `delegator`) into a new lease for
    /// `delegatee`, persist it, and record the delegation for audit.
    #[allow(clippy::too_many_arguments)]
    pub fn delegate(
        &self,
        delegator: &PrincipalId,
        parent_lease: &LeaseId,
        delegatee: &PrincipalId,
        constraints: IndexMap<String, Constraint>,
        uses: u32,
        expires_at: DateTime<Utc>,
        budget: ResourceBudget,
        now: DateTime<Utc>,
    ) -> IdentityResult<CapabilityLease> {
        if !self.registry.exists(delegator)? {
            return Err(IdentityError::UnknownPrincipal(delegator.to_string()));
        }
        if !self.registry.exists(delegatee)? {
            return Err(IdentityError::DelegationRejected(format!(
                "delegatee `{delegatee}` is not a registered principal"
            )));
        }
        if !self.registry.is_self_or_descendant(delegatee, delegator)? {
            return Err(IdentityError::DelegationRejected(format!(
                "delegatee `{delegatee}` is not the delegator or one of its descendants"
            )));
        }
        let parent = self.leases.get(parent_lease)?;
        if &parent.principal != delegator {
            return Err(IdentityError::DelegationRejected(
                "parent lease is not held by the delegator".into(),
            ));
        }
        let child = parent.attenuate(delegatee.clone(), constraints, uses, expires_at, budget, now)?;
        self.leases.issue(&child)?;
        self.db.lock().execute(
            "INSERT INTO delegations (parent_lease, child_lease, delegator, delegatee, delegated_at)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                parent_lease.as_str(),
                child.id.as_str(),
                delegator.as_str(),
                delegatee.as_str(),
                now.to_rfc3339()
            ],
        )?;
        tracing::info!(from = %delegator, to = %delegatee, lease = %child.id, "delegated");
        Ok(child)
    }

    /// The full delegation audit log, oldest first.
    pub fn audit_log(&self) -> IdentityResult<Vec<DelegationRecord>> {
        let conn = self.db.lock();
        let mut stmt = conn.prepare(
            "SELECT parent_lease, child_lease, delegator, delegatee, delegated_at
             FROM delegations ORDER BY id",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (p, c, dr, de, at) = row?;
            let delegated_at = DateTime::parse_from_rfc3339(&at)
                .map_err(|e| IdentityError::Key(format!("bad timestamp in audit row: {e}")))?
                .with_timezone(&Utc);
            out.push(DelegationRecord {
                parent_lease: LeaseId(p),
                child_lease: LeaseId(c),
                delegator: PrincipalId(dr),
                delegatee: PrincipalId(de),
                delegated_at,
            });
        }
        Ok(out)
    }

    /// The registry this service consults.
    pub fn registry(&self) -> &PrincipalRegistry {
        &self.registry
    }

    /// The lease store this service issues into.
    pub fn leases(&self) -> &LeaseStore {
        &self.leases
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use ak_core::capability::Operation;
    use ak_core::principal::{Principal, PrincipalKind};
    use chrono::Duration;
    use serde_json::json;

    fn setup() -> (DelegationService, Principal, Principal, CapabilityLease, DateTime<Utc>) {
        let db = IdentityDb::open_in_memory().expect("db");
        let svc = DelegationService::new(db);
        let now = Utc::now();
        let root = Principal::new_agent("root");
        let child = root.spawn_child(PrincipalKind::SubAgent, "worker");
        svc.registry().register(&root).unwrap();
        svc.registry().register(&child).unwrap();
        let mut constraints = IndexMap::new();
        constraints.insert("path".into(), Constraint::Prefix { prefix: "src/".into() });
        let lease = CapabilityLease {
            id: LeaseId::generate(),
            principal: root.id.clone(),
            operation: Operation::new("fs.write"),
            constraints,
            remaining_uses: 5,
            issued_at: now,
            expires_at: now + Duration::hours(1),
            bound_branch: None,
            budget: ResourceBudget::step_default(),
            parent_lease: None,
            preconditions: IndexMap::new(),
            revoked: false,
        };
        svc.leases().issue(&lease).unwrap();
        (svc, root, child, lease, now)
    }
    #[test]
    fn delegation_to_descendant_succeeds_and_is_audited() {
        let (svc, root, child, lease, now) = setup();
        let mut narrowed = lease.constraints.clone();
        narrowed.insert("path".into(), Constraint::Prefix { prefix: "src/gen/".into() });
        let child_lease = svc
            .delegate(
                &root.id,
                &lease.id,
                &child.id,
                narrowed,
                2,
                now + Duration::minutes(5),
                ResourceBudget::zero(),
                now,
            )
            .unwrap();
        assert_eq!(child_lease.principal, child.id);
        assert_eq!(child_lease.parent_lease.as_ref(), Some(&lease.id));
        // Persisted and auditable.
        assert_eq!(svc.leases().get(&child_lease.id).unwrap(), child_lease);
        let log = svc.audit_log().unwrap();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].delegatee, child.id);
        // Revoking the parent kills the delegated lease too.
        let revoked = svc.leases().revoke_cascading(&lease.id).unwrap();
        assert_eq!(revoked.len(), 2);
    }
}

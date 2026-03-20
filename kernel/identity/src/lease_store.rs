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

impl LeaseStore {
    /// Create a lease store over a shared identity database.
    pub fn new(db: IdentityDb) -> Self {
        Self { db }
    }

    /// Persist a newly issued (or attenuated) lease.
    pub fn issue(&self, lease: &CapabilityLease) -> IdentityResult<()> {
        let json = serde_json::to_string(lease)?;
        self.db.lock().execute(
            "INSERT OR REPLACE INTO leases (id, principal, operation, parent_lease, revoked, expires_at, json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                lease.id.as_str(),
                lease.principal.as_str(),
                lease.operation.0,
                lease.parent_lease.as_ref().map(|p| p.as_str()),
                lease.revoked as i64,
                lease.expires_at.to_rfc3339(),
                json
            ],
        )?;
        Ok(())
    }

    /// Fetch a lease by id.
    pub fn get(&self, id: &LeaseId) -> IdentityResult<CapabilityLease> {
        let conn = self.db.lock();
        let json: Option<String> = conn
            .query_row(
                "SELECT json FROM leases WHERE id = ?1",
                params![id.as_str()],
                |r| r.get(0),
            )
            .optional()?;
        match json {
            Some(j) => Ok(serde_json::from_str(&j)?),
            None => Err(IdentityError::UnknownLease(id.to_string())),
        }
    }

    /// All leases (including revoked/expired ones) held by a principal.
    pub fn list_for_principal(&self, id: &PrincipalId) -> IdentityResult<Vec<CapabilityLease>> {
        let conn = self.db.lock();
        let mut stmt = conn.prepare("SELECT json FROM leases WHERE principal = ?1 ORDER BY id")?;
        let rows = stmt.query_map(params![id.as_str()], |r| r.get::<_, String>(0))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(serde_json::from_str(&row?)?);
        }
        Ok(out)
    }

    /// Leases a principal can still present at time `now`: not revoked, not
    /// expired, with at least one use remaining.
    pub fn active_for_principal(
        &self,
        id: &PrincipalId,
        now: DateTime<Utc>,
    ) -> IdentityResult<Vec<CapabilityLease>> {
        Ok(self
            .list_for_principal(id)?
            .into_iter()
            .filter(|l| !l.revoked && l.expires_at > now && l.remaining_uses > 0)
            .collect())
    }

    /// Revoke a lease **and every lease transitively attenuated from it**.
    /// Returns the ids of all leases that were newly revoked, root first.
    pub fn revoke_cascading(&self, id: &LeaseId) -> IdentityResult<Vec<LeaseId>> {
        // Ensure the root exists before mutating anything.
        let _ = self.get(id)?;
        let mut revoked = Vec::new();
        let mut frontier = vec![id.clone()];
        while let Some(current) = frontier.pop() {
            let mut lease = self.get(&current)?;
            if !lease.revoked {
                lease.revoked = true;
                self.issue(&lease)?;
                revoked.push(current.clone());
            }
            let children: Vec<LeaseId> = {
                let conn = self.db.lock();
                let mut stmt = conn.prepare("SELECT id FROM leases WHERE parent_lease = ?1")?;
                let rows = stmt.query_map(params![current.as_str()], |r| r.get::<_, String>(0))?;
                let mut ids = Vec::new();
                for row in rows {
                    ids.push(LeaseId(row?));
                }
                ids
            };
            frontier.extend(children);
        }
        tracing::info!(root = %id, count = revoked.len(), "cascading revocation");
        Ok(revoked)
    }

    /// Atomically consume one use of a lease. Fails if the lease is revoked,
    /// expired at `now`, or exhausted. Returns the updated lease.
    pub fn consume_use(&self, id: &LeaseId, now: DateTime<Utc>) -> IdentityResult<CapabilityLease> {
        let mut lease = self.get(id)?;
        let unusable = |reason: &str| IdentityError::LeaseUnusable {
            lease: id.to_string(),
            reason: reason.to_string(),
        };
        if lease.revoked {
            return Err(unusable("revoked"));
        }
        if now >= lease.expires_at {
            return Err(unusable("expired"));
        }
        if lease.remaining_uses == 0 {
            return Err(unusable("exhausted"));
        }
        lease.remaining_uses -= 1;
        self.issue(&lease)?;
        Ok(lease)
    }

    /// Mark every lease whose expiry is at or before `now` as revoked
    /// ("sweeping"). Returns the ids swept. Sweeping is not cascading — child
    /// leases can never outlive their parents by construction of
    /// [`CapabilityLease::attenuate`], so they expire on their own.
    pub fn sweep_expired(&self, now: DateTime<Utc>) -> IdentityResult<Vec<LeaseId>> {
        let candidates: Vec<LeaseId> = {
            let conn = self.db.lock();
            let mut stmt =
                conn.prepare("SELECT id, json FROM leases WHERE revoked = 0")?;
            let rows = stmt.query_map([], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
            })?;
            let mut ids = Vec::new();
            for row in rows {
                let (id, json) = row?;
                let lease: CapabilityLease = serde_json::from_str(&json)?;
                if lease.expires_at <= now {
                    ids.push(LeaseId(id));
                }
            }
            ids
        };
        for id in &candidates {
            let mut lease = self.get(id)?;
            lease.revoked = true;
            self.issue(&lease)?;
        }
        Ok(candidates)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use ak_core::budget::ResourceBudget;
    use ak_core::capability::Operation;
    use chrono::Duration;
    use indexmap::IndexMap;

    fn lease(principal: &str, parent: Option<&LeaseId>, now: DateTime<Utc>) -> CapabilityLease {
        CapabilityLease {
            id: LeaseId::generate(),
            principal: PrincipalId(format!("pr-{principal}")),
            operation: Operation::new("fs.read"),
            constraints: IndexMap::new(),
            remaining_uses: 3,
            issued_at: now,
            expires_at: now + Duration::minutes(10),
            bound_branch: None,
            budget: ResourceBudget::step_default(),
            parent_lease: parent.cloned(),
            preconditions: IndexMap::new(),
            revoked: false,
        }
    }

    fn store() -> LeaseStore {
        LeaseStore::new(IdentityDb::open_in_memory().expect("db"))
    }
    #[test]
    fn issue_get_and_list() {
        let s = store();
        let now = Utc::now();
        let l = lease("a", None, now);
        s.issue(&l).unwrap();
        assert_eq!(s.get(&l.id).unwrap(), l);
        assert_eq!(s.list_for_principal(&l.principal).unwrap(), vec![l.clone()]);
        assert_eq!(s.active_for_principal(&l.principal, now).unwrap().len(), 1);
        assert!(matches!(
            s.get(&LeaseId("lease-missing".into())),
            Err(IdentityError::UnknownLease(_))
        ));
    }
}

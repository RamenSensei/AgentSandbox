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
            "INSERT OR REPLACE INTO leases
             (id, principal, operation, parent_lease, revoked, remaining_uses, expires_at, json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                lease.id.as_str(),
                lease.principal.as_str(),
                lease.operation.0,
                lease.parent_lease.as_ref().map(|p| p.as_str()),
                lease.revoked as i64,
                lease.remaining_uses as i64,
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
    ///
    /// The whole cascade runs in one SQLite transaction while holding the
    /// connection lock, so a concurrent [`LeaseStore::consume_use`] either
    /// happens entirely before the revocation or observes it entirely.
    pub fn revoke_cascading(&self, id: &LeaseId) -> IdentityResult<Vec<LeaseId>> {
        let mut conn = self.db.lock();
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let exists =
            tx.prepare("SELECT 1 FROM leases WHERE id = ?1")?.exists(params![id.as_str()])?;
        if !exists {
            return Err(IdentityError::UnknownLease(id.to_string()));
        }
        let mut revoked = Vec::new();
        let mut frontier = vec![id.clone()];
        while let Some(current) = frontier.pop() {
            // Both the authoritative column and the JSON mirror flip in the
            // same statement; `changes() > 0` means we newly revoked it.
            let newly = tx.execute(
                "UPDATE leases
                 SET revoked = 1, json = json_set(json, '$.revoked', json('true'))
                 WHERE id = ?1 AND revoked = 0",
                params![current.as_str()],
            )?;
            if newly > 0 {
                revoked.push(current.clone());
            }
            let mut stmt = tx.prepare("SELECT id FROM leases WHERE parent_lease = ?1")?;
            let rows = stmt.query_map(params![current.as_str()], |r| r.get::<_, String>(0))?;
            for row in rows {
                frontier.push(LeaseId(row?));
            }
        }
        tx.commit()?;
        tracing::info!(root = %id, count = revoked.len(), "cascading revocation");
        Ok(revoked)
    }

    /// Atomically consume one use of a lease. Fails if the lease is revoked,
    /// expired at `now`, or exhausted. Returns the updated lease.
    ///
    /// Consumption is a **single conditional UPDATE**: only as many callers
    /// can succeed as there are uses remaining, no matter how many race.
    /// The JSON mirror is decremented in the same statement, so readers can
    /// never observe a decrement the authoritative column did not make.
    pub fn consume_use(&self, id: &LeaseId, now: DateTime<Utc>) -> IdentityResult<CapabilityLease> {
        let updated: Option<String> = {
            let conn = self.db.lock();
            conn.query_row(
                "UPDATE leases
                 SET remaining_uses = remaining_uses - 1,
                     json = json_set(json, '$.remaining_uses', remaining_uses - 1)
                 WHERE id = ?1
                   AND revoked = 0
                   AND remaining_uses > 0
                   AND expires_at > ?2
                 RETURNING json",
                params![id.as_str(), now.to_rfc3339()],
                |r| r.get(0),
            )
            .optional()?
        };
        match updated {
            Some(json) => Ok(serde_json::from_str(&json)?),
            None => {
                // Zero rows updated: classify the refusal for the caller.
                let lease = self.get(id)?;
                let reason = if lease.revoked {
                    "revoked"
                } else if now >= lease.expires_at {
                    "expired"
                } else {
                    "exhausted"
                };
                Err(IdentityError::LeaseUnusable {
                    lease: id.to_string(),
                    reason: reason.to_string(),
                })
            }
        }
    }

    /// Mark every lease whose expiry is at or before `now` as revoked
    /// ("sweeping"). Returns the ids swept. Sweeping is not cascading — child
    /// leases can never outlive their parents by construction of
    /// [`CapabilityLease::attenuate`], so they expire on their own.
    pub fn sweep_expired(&self, now: DateTime<Utc>) -> IdentityResult<Vec<LeaseId>> {
        let conn = self.db.lock();
        let mut stmt = conn.prepare(
            "UPDATE leases
             SET revoked = 1, json = json_set(json, '$.revoked', json('true'))
             WHERE revoked = 0 AND expires_at <= ?1
             RETURNING id",
        )?;
        let rows = stmt.query_map(params![now.to_rfc3339()], |r| r.get::<_, String>(0))?;
        let mut swept = Vec::new();
        for row in rows {
            swept.push(LeaseId(row?));
        }
        Ok(swept)
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

    #[test]
    fn cascading_revocation_is_transitive() {
        let s = store();
        let now = Utc::now();
        let root = lease("a", None, now);
        let child = lease("b", Some(&root.id), now);
        let grandchild = lease("c", Some(&child.id), now);
        let unrelated = lease("d", None, now);
        for l in [&root, &child, &grandchild, &unrelated] {
            s.issue(l).unwrap();
        }
        let revoked = s.revoke_cascading(&root.id).unwrap();
        assert_eq!(revoked.len(), 3);
        assert!(s.get(&root.id).unwrap().revoked);
        assert!(s.get(&child.id).unwrap().revoked);
        assert!(s.get(&grandchild.id).unwrap().revoked);
        assert!(!s.get(&unrelated.id).unwrap().revoked);
        // Idempotent: revoking again revokes nothing new below the root.
        assert_eq!(s.revoke_cascading(&child.id).unwrap().len(), 0);
    }

    #[test]
    fn consume_use_counts_down_and_refuses_dead_leases() {
        let s = store();
        let now = Utc::now();
        let mut l = lease("a", None, now);
        l.remaining_uses = 2;
        s.issue(&l).unwrap();
        assert_eq!(s.consume_use(&l.id, now).unwrap().remaining_uses, 1);
        assert_eq!(s.consume_use(&l.id, now).unwrap().remaining_uses, 0);
        assert!(matches!(
            s.consume_use(&l.id, now),
            Err(IdentityError::LeaseUnusable { .. })
        ));
        // Expired lease also refuses.
        let l2 = lease("a", None, now);
        s.issue(&l2).unwrap();
        assert!(matches!(
            s.consume_use(&l2.id, now + Duration::hours(1)),
            Err(IdentityError::LeaseUnusable { .. })
        ));
    }

    #[test]
    fn sweep_marks_only_expired() {
        let s = store();
        let now = Utc::now();
        let fresh = lease("a", None, now);
        let mut stale = lease("a", None, now - Duration::hours(1));
        stale.expires_at = now - Duration::minutes(30);
        s.issue(&fresh).unwrap();
        s.issue(&stale).unwrap();
        let swept = s.sweep_expired(now).unwrap();
        assert_eq!(swept, vec![stale.id.clone()]);
        assert!(s.get(&stale.id).unwrap().revoked);
        assert!(!s.get(&fresh.id).unwrap().revoked);
    }

    /// AK-004 regression: a single-use lease must never be consumable twice,
    /// no matter how many callers race. This reproduces the review's exploit
    /// (64 concurrent consumers, `remaining_uses = 1`) and requires exactly
    /// one winner.
    #[test]
    fn concurrent_consumption_never_exceeds_remaining_uses() {
        for round in 0..8 {
            let s = store();
            let now = Utc::now();
            let mut l = lease(&format!("race-{round}"), None, now);
            l.remaining_uses = 1;
            s.issue(&l).unwrap();

            let barrier = std::sync::Arc::new(std::sync::Barrier::new(64));
            let successes = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let handles: Vec<_> = (0..64)
                .map(|_| {
                    let s = s.clone();
                    let id = l.id.clone();
                    let barrier = barrier.clone();
                    let successes = successes.clone();
                    std::thread::spawn(move || {
                        barrier.wait();
                        if s.consume_use(&id, Utc::now()).is_ok() {
                            successes.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        }
                    })
                })
                .collect();
            for h in handles {
                h.join().unwrap();
            }
            let winners = successes.load(std::sync::atomic::Ordering::SeqCst);
            assert_eq!(winners, 1, "round {round}: {winners} consumers won a single-use lease");
            assert_eq!(s.get(&l.id).unwrap().remaining_uses, 0);
        }
    }

    /// A multi-use lease admits exactly `remaining_uses` winners under
    /// contention, and the persisted counter lands at zero (never negative).
    #[test]
    fn concurrent_consumption_of_multi_use_lease_is_exact() {
        let s = store();
        let now = Utc::now();
        let mut l = lease("multi", None, now);
        l.remaining_uses = 5;
        s.issue(&l).unwrap();

        let successes = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let handles: Vec<_> = (0..32)
            .map(|_| {
                let s = s.clone();
                let id = l.id.clone();
                let successes = successes.clone();
                std::thread::spawn(move || {
                    if s.consume_use(&id, Utc::now()).is_ok() {
                        successes.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(successes.load(std::sync::atomic::Ordering::SeqCst), 5);
        assert_eq!(s.get(&l.id).unwrap().remaining_uses, 0);
    }

    /// Revocation racing consumption: a consumer either wins before the
    /// cascade or is refused — the revoked lease can never be spent after.
    #[test]
    fn revocation_wins_over_later_consumption() {
        let s = store();
        let now = Utc::now();
        let mut l = lease("rv", None, now);
        l.remaining_uses = 100;
        s.issue(&l).unwrap();
        s.revoke_cascading(&l.id).unwrap();
        let err = s.consume_use(&l.id, now).unwrap_err();
        assert!(matches!(err, IdentityError::LeaseUnusable { ref reason, .. } if reason == "revoked"));
        // The JSON mirror agrees with the authoritative column.
        assert!(s.get(&l.id).unwrap().revoked);
    }
}

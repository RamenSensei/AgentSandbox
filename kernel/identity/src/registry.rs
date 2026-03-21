//! The [`PrincipalRegistry`]: durable identities and lineage.

use crate::db::IdentityDb;
use crate::error::{IdentityError, IdentityResult};
use ak_core::ids::PrincipalId;
use ak_core::principal::{Principal, TrustLevel};
use rusqlite::{params, OptionalExtension};

/// A rusqlite-backed registry of every principal known to the kernel.
///
/// The registry is the authority on:
/// - which principals exist,
/// - their [`TrustLevel`] (used to redact denials, never to skip enforcement),
/// - the parent/child spawn lineage (used by [`crate::DelegationService`] to
///   decide whether a delegation is structurally legal).
#[derive(Clone)]
pub struct PrincipalRegistry {
    db: IdentityDb,
}

impl PrincipalRegistry {
    /// Create a registry over a shared identity database.
    pub fn new(db: IdentityDb) -> Self {
        Self { db }
    }

    /// Register a principal. The parent (if any) must already be registered;
    /// re-registering an existing id is an error.
    pub fn register(&self, principal: &Principal) -> IdentityResult<()> {
        let conn = self.db.lock();
        if let Some(parent) = &principal.parent {
            let exists: Option<String> = conn
                .query_row(
                    "SELECT id FROM principals WHERE id = ?1",
                    params![parent.as_str()],
                    |r| r.get(0),
                )
                .optional()?;
            if exists.is_none() {
                return Err(IdentityError::UnknownParent(parent.to_string()));
            }
        }
        let json = serde_json::to_string(principal)?;
        let trust = serde_json::to_string(&principal.trust)?;
        let inserted = conn.execute(
            "INSERT OR IGNORE INTO principals (id, parent, trust, json) VALUES (?1, ?2, ?3, ?4)",
            params![
                principal.id.as_str(),
                principal.parent.as_ref().map(|p| p.as_str()),
                trust,
                json
            ],
        )?;
        if inserted == 0 {
            return Err(IdentityError::DuplicatePrincipal(principal.id.to_string()));
        }
        tracing::debug!(principal = %principal.id, "registered principal");
        Ok(())
    }

    /// Look up a principal by id.
    pub fn get(&self, id: &PrincipalId) -> IdentityResult<Principal> {
        let conn = self.db.lock();
        let json: Option<String> = conn
            .query_row(
                "SELECT json FROM principals WHERE id = ?1",
                params![id.as_str()],
                |r| r.get(0),
            )
            .optional()?;
        match json {
            Some(j) => Ok(serde_json::from_str(&j)?),
            None => Err(IdentityError::UnknownPrincipal(id.to_string())),
        }
    }

    /// Whether a principal id is registered.
    pub fn exists(&self, id: &PrincipalId) -> IdentityResult<bool> {
        match self.get(id) {
            Ok(_) => Ok(true),
            Err(IdentityError::UnknownPrincipal(_)) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// Update a principal's trust level (e.g. quarantining a misbehaving
    /// skill). Trust changes never grant authority — they only change how much
    /// policy detail the principal is shown.
    pub fn set_trust(&self, id: &PrincipalId, trust: TrustLevel) -> IdentityResult<()> {
        let mut p = self.get(id)?;
        p.trust = trust;
        let json = serde_json::to_string(&p)?;
        let trust_s = serde_json::to_string(&trust)?;
        self.db.lock().execute(
            "UPDATE principals SET trust = ?1, json = ?2 WHERE id = ?3",
            params![trust_s, json, id.as_str()],
        )?;
        Ok(())
    }

    /// Direct children of a principal.
    pub fn children(&self, id: &PrincipalId) -> IdentityResult<Vec<Principal>> {
        let conn = self.db.lock();
        let mut stmt =
            conn.prepare("SELECT json FROM principals WHERE parent = ?1 ORDER BY id")?;
        let rows = stmt.query_map(params![id.as_str()], |r| r.get::<_, String>(0))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(serde_json::from_str(&row?)?);
        }
        Ok(out)
    }

    /// The chain of ancestors of `id`, nearest parent first.
    pub fn lineage(&self, id: &PrincipalId) -> IdentityResult<Vec<Principal>> {
        let mut out = Vec::new();
        let mut current = self.get(id)?;
        while let Some(parent_id) = current.parent.clone() {
            let parent = self.get(&parent_id)?;
            out.push(parent.clone());
            current = parent;
            // Defensive: lineage longer than the table size means a cycle.
            if out.len() > 4096 {
                return Err(IdentityError::DelegationRejected(
                    "principal lineage contains a cycle".into(),
                ));
            }
        }
        Ok(out)
    }

    /// Whether `descendant` is `ancestor` itself or transitively spawned
    /// from it.
    pub fn is_self_or_descendant(
        &self,
        descendant: &PrincipalId,
        ancestor: &PrincipalId,
    ) -> IdentityResult<bool> {
        if descendant == ancestor {
            return Ok(true);
        }
        Ok(self.lineage(descendant)?.iter().any(|p| &p.id == ancestor))
    }

    /// All registered principals.
    pub fn list(&self) -> IdentityResult<Vec<Principal>> {
        let conn = self.db.lock();
        let mut stmt = conn.prepare("SELECT json FROM principals ORDER BY id")?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        let mut out = Vec::new();
        for row in rows {
            out.push(serde_json::from_str(&row?)?);
        }
        Ok(out)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use ak_core::principal::PrincipalKind;

    fn registry() -> PrincipalRegistry {
        PrincipalRegistry::new(IdentityDb::open_in_memory().expect("db"))
    }
    #[test]
    fn register_lookup_and_lineage() {
        let reg = registry();
        let root = Principal::new_agent("root");
        let child = root.spawn_child(PrincipalKind::SubAgent, "worker");
        let grandchild = child.spawn_child(PrincipalKind::Tool, "grep-tool");
        reg.register(&root).unwrap();
        reg.register(&child).unwrap();
        reg.register(&grandchild).unwrap();

        assert_eq!(reg.get(&root.id).unwrap(), root);
        assert_eq!(reg.children(&root.id).unwrap(), vec![child.clone()]);
        let lineage = reg.lineage(&grandchild.id).unwrap();
        assert_eq!(lineage.len(), 2);
        assert_eq!(lineage[0].id, child.id);
        assert_eq!(lineage[1].id, root.id);
        assert!(reg.is_self_or_descendant(&grandchild.id, &root.id).unwrap());
        assert!(reg.is_self_or_descendant(&root.id, &root.id).unwrap());
        assert!(!reg.is_self_or_descendant(&root.id, &child.id).unwrap());
        assert_eq!(reg.list().unwrap().len(), 3);
    }

    #[test]
    fn duplicate_and_orphan_registration_fail() {
        let reg = registry();
        let root = Principal::new_agent("root");
        reg.register(&root).unwrap();
        assert!(matches!(
            reg.register(&root),
            Err(IdentityError::DuplicatePrincipal(_))
        ));
        let orphan = root.spawn_child(PrincipalKind::SubAgent, "orphan");
        let unregistered = Principal::new_agent("ghost");
        let mut bad = orphan;
        bad.parent = Some(unregistered.id);
        assert!(matches!(reg.register(&bad), Err(IdentityError::UnknownParent(_))));
    }

    #[test]
    fn trust_updates_persist() {
        let reg = registry();
        let root = Principal::new_agent("root");
        reg.register(&root).unwrap();
        reg.set_trust(&root.id, TrustLevel::Quarantined).unwrap();
        assert_eq!(reg.get(&root.id).unwrap().trust, TrustLevel::Quarantined);
    }
}

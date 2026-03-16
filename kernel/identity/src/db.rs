//! Shared SQLite handle for the identity stores.

use crate::error::IdentityResult;
use rusqlite::Connection;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};

/// A shared, mutex-guarded SQLite database used by [`crate::PrincipalRegistry`],
/// [`crate::LeaseStore`] and [`crate::DelegationService`].
///
/// Cloning an `IdentityDb` clones the handle, not the database: all clones see
/// the same rows. The schema is created idempotently on open.
#[derive(Clone)]
pub struct IdentityDb {
    conn: Arc<Mutex<Connection>>,
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS principals (
    id           TEXT PRIMARY KEY,
    parent       TEXT REFERENCES principals(id),
    trust        TEXT NOT NULL,
    json         TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS leases (
    id           TEXT PRIMARY KEY,
    principal    TEXT NOT NULL,
    operation    TEXT NOT NULL,
    parent_lease TEXT,
    revoked      INTEGER NOT NULL DEFAULT 0,
    expires_at   TEXT NOT NULL,
    json         TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS leases_by_principal ON leases(principal);
CREATE INDEX IF NOT EXISTS leases_by_parent ON leases(parent_lease);
CREATE TABLE IF NOT EXISTS delegations (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    parent_lease  TEXT NOT NULL,
    child_lease   TEXT NOT NULL,
    delegator     TEXT NOT NULL,
    delegatee     TEXT NOT NULL,
    delegated_at  TEXT NOT NULL
);
"#;

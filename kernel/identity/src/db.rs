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
    id             TEXT PRIMARY KEY,
    principal      TEXT NOT NULL,
    operation      TEXT NOT NULL,
    parent_lease   TEXT,
    revoked        INTEGER NOT NULL DEFAULT 0,
    remaining_uses INTEGER NOT NULL DEFAULT 0,
    expires_at     TEXT NOT NULL,
    json           TEXT NOT NULL
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

impl IdentityDb {
    /// Open (or create) an on-disk identity database at `path`.
    pub fn open(path: impl AsRef<Path>) -> IdentityResult<Self> {
        Self::from_connection(Connection::open(path)?)
    }

    /// Open a fresh in-memory database (used for tests and ephemeral kernels).
    pub fn open_in_memory() -> IdentityResult<Self> {
        Self::from_connection(Connection::open_in_memory()?)
    }

    fn from_connection(conn: Connection) -> IdentityResult<Self> {
        conn.execute_batch(SCHEMA)?;
        migrate(&conn)?;
        Ok(Self { conn: Arc::new(Mutex::new(conn)) })
    }

    /// Lock the underlying connection. Poisoned locks are recovered: the
    /// database itself is the source of truth, not in-process state.
    pub(crate) fn lock(&self) -> MutexGuard<'_, Connection> {
        match self.conn.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

/// Bring databases created by earlier schema versions up to date. Each step
/// is idempotent; the whole migration runs on every open.
fn migrate(conn: &Connection) -> IdentityResult<()> {
    // v0.7: `remaining_uses` became an authoritative column so consumption
    // can be a single conditional UPDATE instead of read-modify-write.
    let has_remaining_uses = conn
        .prepare("SELECT 1 FROM pragma_table_info('leases') WHERE name = 'remaining_uses'")?
        .exists([])?;
    if !has_remaining_uses {
        conn.execute_batch(
            "ALTER TABLE leases ADD COLUMN remaining_uses INTEGER NOT NULL DEFAULT 0;
             UPDATE leases SET remaining_uses = COALESCE(json_extract(json, '$.remaining_uses'), 0);",
        )?;
    }
    Ok(())
}

//! The SQLite-backed append-only ledger: storage, hash chain, queries,
//! raw-output blobs, and receipt persistence.

use crate::event::{EventBody, EventKind, LedgerEvent, NewEvent};
use ak_core::effect::Receipt;
use ak_core::hash::{hash_bytes, ContentHash};
use ak_core::ids::{BranchId, EpisodeId, PrincipalId, ReceiptId, StateId, StepId};
use ak_core::state::StateDelta;
use ak_core::{KernelError, KernelResult};
use chrono::{DateTime, Utc};
use rusqlite::types::Value as SqlValue;
use rusqlite::{params, Connection, OptionalExtension, Row};
use std::collections::BTreeSet;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};

const MIGRATIONS: &[(&str, &str)] = &[(
    "0001_initial",
    "CREATE TABLE events (
         seq INTEGER PRIMARY KEY AUTOINCREMENT,
         kind TEXT NOT NULL,
         episode TEXT NOT NULL,
         branch TEXT,
         step TEXT,
         principal TEXT NOT NULL,
         timestamp TEXT NOT NULL,
         payload TEXT NOT NULL,
         caused_by TEXT NOT NULL,
         prev_event_hash TEXT,
         event_hash TEXT NOT NULL
     );
     CREATE INDEX idx_events_episode ON events(episode);
     CREATE INDEX idx_events_kind ON events(kind);
     CREATE TABLE raw_outputs (
         hash TEXT PRIMARY KEY,
         bytes BLOB NOT NULL,
         stored_at TEXT NOT NULL
     );
     CREATE TABLE receipts (
         id TEXT PRIMARY KEY,
         idempotency_key TEXT NOT NULL UNIQUE,
         receipt_json TEXT NOT NULL,
         stored_at TEXT NOT NULL
     );",
)];

/// Filters for [`Ledger::query`] (`trace.query`). All fields are optional
/// and AND-combined.
#[derive(Debug, Clone, Default)]
pub struct TraceQuery {
    pub episode: Option<EpisodeId>,
    pub branch: Option<BranchId>,
    /// Restrict to events produced by a specific step.
    pub step: Option<StepId>,
    /// Inclusive ledger-sequence range — the total order over steps.
    pub seq_range: Option<(i64, i64)>,
    pub principal: Option<PrincipalId>,
    /// Empty = all kinds.
    pub kinds: Vec<EventKind>,
    /// Inclusive UTC time range.
    pub time_range: Option<(DateTime<Utc>, DateTime<Utc>)>,
    /// Maximum number of events returned (default: unlimited).
    pub limit: Option<usize>,
}

/// The append-only, tamper-evident causal ledger.
///
/// Every appended event embeds the previous event's content hash, so any
/// mutation of a persisted row is detected by [`Ledger::verify_chain`].
/// Thread-safe; share via [`Arc`] and hand [`EventWriter`]s to per-step code.
pub struct Ledger {
    conn: Mutex<Connection>,
}

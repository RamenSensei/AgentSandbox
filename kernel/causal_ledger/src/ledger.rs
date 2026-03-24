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

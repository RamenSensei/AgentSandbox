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

impl Ledger {
    /// Open (creating if necessary) the ledger database at `path`.
    /// Enables WAL mode and runs schema migrations.
    #[tracing::instrument(level = "info", skip_all)]
    pub fn open(path: &Path) -> KernelResult<Self> {
        Self::init(Connection::open(path).map_err(sql_err)?)
    }

    /// In-memory ledger (tests / ephemeral kernels).
    pub fn open_in_memory() -> KernelResult<Self> {
        Self::init(Connection::open_in_memory().map_err(sql_err)?)
    }

    fn init(conn: Connection) -> KernelResult<Self> {
        conn.pragma_update(None, "journal_mode", "WAL").map_err(sql_err)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS migrations (
                 name TEXT PRIMARY KEY, applied_at TEXT NOT NULL
             );",
        )
        .map_err(sql_err)?;
        for (name, sql) in MIGRATIONS {
            let applied: Option<String> = conn
                .query_row("SELECT name FROM migrations WHERE name = ?1", [name], |r| r.get(0))
                .optional()
                .map_err(sql_err)?;
            if applied.is_none() {
                conn.execute_batch(sql).map_err(sql_err)?;
                conn.execute(
                    "INSERT INTO migrations (name, applied_at) VALUES (?1, ?2)",
                    params![name, Utc::now().to_rfc3339()],
                )
                .map_err(sql_err)?;
            }
        }
        Ok(Self { conn: Mutex::new(conn) })
    }

    fn conn(&self) -> KernelResult<MutexGuard<'_, Connection>> {
        self.conn
            .lock()
            .map_err(|_| KernelError::Storage("ledger mutex poisoned".into()))
    }

    // ---------------------------------------------------------------- append

    /// Append an event to the chain, assigning its sequence number,
    /// timestamp, previous-hash link and content hash.
    #[tracing::instrument(level = "debug", skip(self, event), fields(kind = event.kind.as_str(), episode = %event.episode))]
    pub fn append(&self, event: NewEvent) -> KernelResult<LedgerEvent> {
        let conn = self.conn()?;
        let last: Option<(i64, String)> = conn
            .query_row(
                "SELECT seq, event_hash FROM events ORDER BY seq DESC LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(sql_err)?;
        let (seq, prev_event_hash) = match last {
            Some((s, h)) => (s + 1, Some(ContentHash(h))),
            None => (1, None),
        };
        let body = EventBody {
            seq,
            kind: event.kind,
            episode: event.episode,
            branch: event.branch,
            step: event.step,
            principal: event.principal,
            timestamp: Utc::now(),
            payload: event.payload,
            caused_by: event.caused_by,
            prev_event_hash,
        };
        let event_hash = body.compute_hash();
        conn.execute(
            "INSERT INTO events (seq, kind, episode, branch, step, principal, timestamp,
                                 payload, caused_by, prev_event_hash, event_hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                body.seq,
                body.kind.as_str(),
                body.episode.as_str(),
                body.branch.as_ref().map(|b| b.as_str()),
                body.step.as_ref().map(|s| s.as_str()),
                body.principal.as_str(),
                serde_json::to_string(&body.timestamp)?,
                serde_json::to_string(&body.payload)?,
                serde_json::to_string(&body.caused_by)?,
                body.prev_event_hash.as_ref().map(|h| h.as_str()),
                event_hash.as_str(),
            ],
        )
        .map_err(sql_err)?;
        Ok(LedgerEvent { body, event_hash })
    }

    /// Create an [`EventWriter`] bound to one step's attribution context.
    pub fn writer(
        self: &Arc<Self>,
        episode: EpisodeId,
        branch: Option<BranchId>,
        step: Option<StepId>,
        principal: PrincipalId,
    ) -> EventWriter {
        EventWriter { ledger: Arc::clone(self), episode, branch, step, principal }
    }

    // ---------------------------------------------------------------- verify

    /// Verify the entire hash chain: every event's stored hash must equal the
    /// recomputed hash of its body, and every `prev_event_hash` must equal
    /// the previous event's hash. Returns the number of verified events;
    /// fails with [`KernelError::Storage`] naming the first bad sequence.
    #[tracing::instrument(level = "info", skip(self))]
    pub fn verify_chain(&self) -> KernelResult<u64> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare("SELECT * FROM events ORDER BY seq ASC").map_err(sql_err)?;
        let events = stmt
            .query_map([], row_to_event)
            .map_err(sql_err)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(sql_err)?;
        let mut prev: Option<ContentHash> = None;
        let mut count = 0u64;
        for ev in events {
            let ev = ev?;
            if ev.body.prev_event_hash != prev {
                return Err(KernelError::Storage(format!(
                    "ledger chain broken at seq {}: prev_event_hash mismatch",
                    ev.body.seq
                )));
            }
            let recomputed = ev.body.compute_hash();
            if recomputed != ev.event_hash {
                return Err(KernelError::Storage(format!(
                    "ledger tampering detected at seq {}: content hash mismatch",
                    ev.body.seq
                )));
            }
            prev = Some(ev.event_hash);
            count += 1;
        }
        Ok(count)
    }

    // ------------------------------------------------------------- raw blobs

    /// Store a large raw output (stdout, model response bytes, …) by content
    /// hash. Idempotent. Reference the returned hash from event payloads.
    #[tracing::instrument(level = "debug", skip_all, fields(len = bytes.len()))]
    pub fn store_raw(&self, bytes: &[u8]) -> KernelResult<ContentHash> {
        let hash = hash_bytes(bytes);
        self.conn()?
            .execute(
                "INSERT OR IGNORE INTO raw_outputs (hash, bytes, stored_at) VALUES (?1, ?2, ?3)",
                params![hash.as_str(), bytes, Utc::now().to_rfc3339()],
            )
            .map_err(sql_err)?;
        Ok(hash)
    }

    /// Retrieve a raw output by hash (`trace.fetch`).
    pub fn fetch_raw(&self, hash: &ContentHash) -> KernelResult<Vec<u8>> {
        self.conn()?
            .query_row("SELECT bytes FROM raw_outputs WHERE hash = ?1", [hash.as_str()], |r| {
                r.get(0)
            })
            .optional()
            .map_err(sql_err)?
            .ok_or_else(|| KernelError::NotFound { kind: "raw_output", id: hash.to_string() })
    }

    // --------------------------------------------------------------- queries

    /// Filtered event query (`trace.query`), returned in sequence order.
    #[tracing::instrument(level = "debug", skip_all)]
    pub fn query(&self, q: &TraceQuery) -> KernelResult<Vec<LedgerEvent>> {
        let mut sql = String::from("SELECT * FROM events WHERE 1=1");
        let mut binds: Vec<SqlValue> = Vec::new();
        let push = |sql: &mut String, clause: &str, v: SqlValue, binds: &mut Vec<SqlValue>| {
            binds.push(v);
            sql.push_str(&clause.replace('?', &format!("?{}", binds.len())));
        };
        if let Some(ep) = &q.episode {
            push(&mut sql, " AND episode = ?", SqlValue::Text(ep.to_string()), &mut binds);
        }
        if let Some(b) = &q.branch {
            push(&mut sql, " AND branch = ?", SqlValue::Text(b.to_string()), &mut binds);
        }
        if let Some(s) = &q.step {
            push(&mut sql, " AND step = ?", SqlValue::Text(s.to_string()), &mut binds);
        }
        if let Some(p) = &q.principal {
            push(&mut sql, " AND principal = ?", SqlValue::Text(p.to_string()), &mut binds);
        }
        if let Some((lo, hi)) = q.seq_range {
            push(&mut sql, " AND seq >= ?", SqlValue::Integer(lo), &mut binds);
            push(&mut sql, " AND seq <= ?", SqlValue::Integer(hi), &mut binds);
        }
        if !q.kinds.is_empty() {
            sql.push_str(" AND kind IN (");
            for (i, k) in q.kinds.iter().enumerate() {
                if i > 0 {
                    sql.push(',');
                }
                binds.push(SqlValue::Text(k.as_str().to_string()));
                sql.push_str(&format!("?{}", binds.len()));
            }
            sql.push(')');
        }
        sql.push_str(" ORDER BY seq ASC");
        if let Some(limit) = q.limit {
            sql.push_str(&format!(" LIMIT {limit}"));
        }
        let conn = self.conn()?;
        let mut stmt = conn.prepare(&sql).map_err(sql_err)?;
        let events = stmt
            .query_map(rusqlite::params_from_iter(binds), row_to_event)
            .map_err(sql_err)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(sql_err)?
            .into_iter()
            .collect::<KernelResult<Vec<_>>>()?;
        // Time range is filtered in Rust: timestamps are stored as JSON strings.
        Ok(events
            .into_iter()
            .filter(|e| match q.time_range {
                Some((lo, hi)) => e.body.timestamp >= lo && e.body.timestamp <= hi,
                None => true,
            })
            .collect())
    }

    /// Fetch a single event by sequence number.
    pub fn get(&self, seq: i64) -> KernelResult<LedgerEvent> {
        let conn = self.conn()?;
        conn.query_row("SELECT * FROM events WHERE seq = ?1", [seq], row_to_event)
            .optional()
            .map_err(sql_err)?
            .ok_or_else(|| KernelError::NotFound { kind: "ledger_event", id: seq.to_string() })?
    }

    /// Causal query: every event that recorded a state delta touching `path`.
    ///
    /// Looks at [`EventKind::StateDeltaRecorded`] events whose payload is a
    /// [`StateDelta`] (or `{"delta": <StateDelta>, ...}`) containing `path`.
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn events_modifying_path(&self, path: &str) -> KernelResult<Vec<LedgerEvent>> {
        let events = self.query(&TraceQuery {
            kinds: vec![EventKind::StateDeltaRecorded],
            ..TraceQuery::default()
        })?;
        Ok(events
            .into_iter()
            .filter(|e| {
                let delta_value = e.body.payload.get("delta").unwrap_or(&e.body.payload);
                serde_json::from_value::<StateDelta>(delta_value.clone())
                    .map(|d| d.files.iter().any(|f| f.path() == path))
                    .unwrap_or(false)
            })
            .collect())
    }

    /// Causal query: the events that led to effect `effect_id`.
    ///
    /// Seeds from every event whose payload carries `"effect_id" == effect_id`,
    /// then walks `caused_by` attribution links transitively. Returned in
    /// sequence order (the effect events themselves included).
    #[tracing::instrument(level = "debug", skip(self))]
    pub fn events_leading_to_effect(&self, effect_id: &str) -> KernelResult<Vec<LedgerEvent>> {
        let all = self.query(&TraceQuery::default())?;
        let mut wanted: BTreeSet<i64> = all
            .iter()
            .filter(|e| {
                e.body.payload.get("effect_id").and_then(|v| v.as_str()) == Some(effect_id)
            })
            .map(|e| e.body.seq)
            .collect();
        // Transitive closure over caused_by links.
        loop {
            let before = wanted.len();
            for e in &all {
                if wanted.contains(&e.body.seq) {
                    wanted.extend(e.body.caused_by.iter().copied());
                }
            }
            if wanted.len() == before {
                break;
            }
        }
        Ok(all.into_iter().filter(|e| wanted.contains(&e.body.seq)).collect())
    }

    /// Causal query: irreversible effects committed since state `state`.
    ///
    /// Finds the [`EventKind::StateDeltaRecorded`] event whose payload names
    /// `state` via `"state_id"`, then returns every later
    /// [`EventKind::EffectCommitted`] event whose payload `"class"` is
    /// `"irreversible"` or `"opaque_external"`.
    #[tracing::instrument(level = "debug", skip(self), fields(state = %state))]
    pub fn irreversible_effects_since(&self, state: &StateId) -> KernelResult<Vec<LedgerEvent>> {
        let anchor = self
            .query(&TraceQuery {
                kinds: vec![EventKind::StateDeltaRecorded],
                ..TraceQuery::default()
            })?
            .into_iter()
            .find(|e| {
                e.body.payload.get("state_id").and_then(|v| v.as_str()) == Some(state.as_str())
            })
            .ok_or_else(|| KernelError::NotFound {
                kind: "state_delta_event",
                id: state.to_string(),
            })?;
        let committed = self.query(&TraceQuery {
            kinds: vec![EventKind::EffectCommitted],
            seq_range: Some((anchor.body.seq + 1, i64::MAX)),
            ..TraceQuery::default()
        })?;
        Ok(committed
            .into_iter()
            .filter(|e| {
                matches!(
                    e.body.payload.get("class").and_then(|v| v.as_str()),
                    Some("irreversible") | Some("opaque_external")
                )
            })
            .collect())
    }

    // -------------------------------------------------------------- receipts

    /// Persist a signed [`Receipt`] under its effect's idempotency key.
    /// Storing a *different* receipt under an existing key fails with
    /// [`KernelError::DuplicateCommit`]; re-storing the same receipt is a
    /// no-op.
    #[tracing::instrument(level = "info", skip(self, receipt), fields(receipt = %receipt.id, key = idempotency_key))]
    pub fn store_receipt(&self, receipt: &Receipt, idempotency_key: &str) -> KernelResult<()> {
        let conn = self.conn()?;
        if let Some(existing) = receipt_by_key(&conn, idempotency_key)? {
            if existing.id == receipt.id {
                return Ok(());
            }
            return Err(KernelError::DuplicateCommit {
                key: idempotency_key.to_string(),
                receipt: existing.id.to_string(),
            });
        }
        conn.execute(
            "INSERT INTO receipts (id, idempotency_key, receipt_json, stored_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                receipt.id.as_str(),
                idempotency_key,
                serde_json::to_string(receipt)?,
                Utc::now().to_rfc3339()
            ],
        )
        .map_err(sql_err)?;
        Ok(())
    }

    /// Look up a receipt by idempotency key (`None` if never committed).
    pub fn receipt_by_idempotency_key(&self, key: &str) -> KernelResult<Option<Receipt>> {
        let conn = self.conn()?;
        receipt_by_key(&conn, key)
    }

    /// Look up a receipt by id.
    pub fn get_receipt(&self, id: &ReceiptId) -> KernelResult<Receipt> {
        self.conn()?
            .query_row(
                "SELECT receipt_json FROM receipts WHERE id = ?1",
                [id.as_str()],
                |r| r.get::<_, String>(0),
            )
            .optional()
            .map_err(sql_err)?
            .map(|json| serde_json::from_str(&json).map_err(KernelError::Serde))
            .transpose()?
            .ok_or_else(|| KernelError::NotFound { kind: "receipt", id: id.to_string() })
    }
}

/// A per-step handle the kernel uses to record events with fixed
/// episode/branch/step/principal attribution.
#[derive(Clone)]
pub struct EventWriter {
    ledger: Arc<Ledger>,
    episode: EpisodeId,
    branch: Option<BranchId>,
    step: Option<StepId>,
    principal: PrincipalId,
}

impl EventWriter {
    /// Record an event with this writer's attribution and no causal parents.
    pub fn record(&self, kind: EventKind, payload: serde_json::Value) -> KernelResult<LedgerEvent> {
        self.record_caused_by(kind, payload, Vec::new())
    }

    /// Record an event citing the sequence numbers of its causal parents.
    pub fn record_caused_by(
        &self,
        kind: EventKind,
        payload: serde_json::Value,
        caused_by: Vec<i64>,
    ) -> KernelResult<LedgerEvent> {
        self.ledger.append(NewEvent {
            kind,
            episode: self.episode.clone(),
            branch: self.branch.clone(),
            step: self.step.clone(),
            principal: self.principal.clone(),
            payload,
            caused_by,
        })
    }

    /// The underlying ledger (for `trace.fetch` / queries).
    pub fn ledger(&self) -> &Arc<Ledger> {
        &self.ledger
    }
}

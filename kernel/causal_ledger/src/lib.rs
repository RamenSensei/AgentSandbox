//! # ak-causal-ledger
//!
//! The append-only causal ledger of AgentKernel: a tamper-evident,
//! hash-chained record of everything from objective to committed effect.
//!
//! - [`LedgerEvent`] / [`EventKind`]: the causal-chain vocabulary, each event
//!   carrying episode/branch/step/principal attribution, a timestamp, a JSON
//!   payload, `caused_by` attribution links, and a hash chain
//!   (`prev_event_hash` + `event_hash`).
//! - [`Ledger`]: SQLite (WAL) storage with [`Ledger::append`],
//!   [`Ledger::verify_chain`], raw-output blobs
//!   ([`Ledger::store_raw`] / [`Ledger::fetch_raw`], i.e. `trace.fetch`),
//!   the [`Ledger::query`] API (`trace.query`) with [`TraceQuery`] filters,
//!   causal queries ([`Ledger::events_modifying_path`],
//!   [`Ledger::events_leading_to_effect`],
//!   [`Ledger::irreversible_effects_since`]), and receipt persistence keyed
//!   by idempotency key.
//! - [`EventWriter`]: the per-step handle the kernel records through.

pub mod event;
pub mod ledger;

pub use event::{EventBody, EventKind, LedgerEvent, NewEvent};
pub use ledger::{EventWriter, Ledger, TraceQuery};

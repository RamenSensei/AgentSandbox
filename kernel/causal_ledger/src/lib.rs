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
#[cfg(test)]
mod tests {
    use super::*;
    use ak_core::effect::{Receipt, ReceiptBody};
    use ak_core::hash::hash_bytes;
    use ak_core::ids::{BranchId, EffectId, EpisodeId, PrincipalId, ReceiptId, StateId, StepId};
    use ak_core::KernelError;
    use serde_json::json;
    use std::sync::Arc;

    fn ev(kind: EventKind, ep: &EpisodeId, payload: serde_json::Value) -> NewEvent {
        NewEvent {
            kind,
            episode: ep.clone(),
            branch: None,
            step: None,
            principal: PrincipalId::generate(),
            payload,
            caused_by: vec![],
        }
    }








    fn receipt(key_hint: &str) -> Receipt {
        Receipt {
            id: ReceiptId::generate(),
            body: ReceiptBody {
                effect: EffectId::generate(),
                who: PrincipalId::generate(),
                operation: "github.create_pull_request".into(),
                resource: "org/repo".into(),
                contract_hash: hash_bytes(key_hint.as_bytes()),
                branch: BranchId::generate(),
                step: StepId::generate(),
                policy_epoch: 1,
                authorization_witness: hash_bytes(b"witness"),
                external_response_digest: hash_bytes(b"resp"),
                committed_at: chrono::Utc::now(),
            },
            signature: "00".into(),
            key_id: "kernel-key-1".into(),
        }
    }
    #[test]
    fn append_chains_hashes_and_verifies() {
        let ledger = Ledger::open_in_memory().unwrap();
        let ep = EpisodeId::generate();
        let e1 = ledger.append(ev(EventKind::Objective, &ep, json!({"goal": "fix bug"}))).unwrap();
        let e2 = ledger
            .append(ev(EventKind::DeclaredIntent, &ep, json!({"intent": "edit files"})))
            .unwrap();
        assert_eq!(e1.seq, 1);
        assert!(e1.prev_event_hash.is_none());
        assert_eq!(e2.prev_event_hash.as_ref(), Some(&e1.event_hash));
        assert_eq!(ledger.verify_chain().unwrap(), 2);
        assert_eq!(ledger.get(2).unwrap(), e2);
    }
}

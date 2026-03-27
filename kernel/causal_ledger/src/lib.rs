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

    #[test]
    fn tampering_with_a_row_is_detected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger.db");
        let ledger = Ledger::open(&path).unwrap();
        let ep = EpisodeId::generate();
        ledger.append(ev(EventKind::Objective, &ep, json!({"goal": "honest"}))).unwrap();
        ledger.append(ev(EventKind::ToolInvocation, &ep, json!({"tool": "bash"}))).unwrap();
        assert_eq!(ledger.verify_chain().unwrap(), 2);
        drop(ledger);

        // Attacker edits the payload of event 1 directly in SQLite.
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute(
            "UPDATE events SET payload = ? WHERE seq = 1",
            [serde_json::to_string(&json!({"goal": "evil"})).unwrap()],
        )
        .unwrap();
        drop(conn);

        let ledger = Ledger::open(&path).unwrap();
        let err = ledger.verify_chain().unwrap_err();
        assert!(err.to_string().contains("seq 1"), "got: {err}");

        // Deleting an interior event also breaks the prev-hash chain.
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute("UPDATE events SET payload = ? WHERE seq = 1", [
            serde_json::to_string(&json!({"goal": "honest"})).unwrap(),
        ])
        .unwrap();
        conn.execute("DELETE FROM events WHERE seq = 1", []).unwrap();
        drop(conn);
        let ledger = Ledger::open(&path).unwrap();
        assert!(ledger.verify_chain().is_err());
    }

    #[test]
    fn raw_blob_store_and_fetch() {
        let ledger = Ledger::open_in_memory().unwrap();
        let h = ledger.store_raw(b"very long stdout ...").unwrap();
        assert_eq!(h, hash_bytes(b"very long stdout ..."));
        // idempotent
        assert_eq!(ledger.store_raw(b"very long stdout ...").unwrap(), h);
        assert_eq!(ledger.fetch_raw(&h).unwrap(), b"very long stdout ...");
        assert!(matches!(
            ledger.fetch_raw(&hash_bytes(b"missing")),
            Err(KernelError::NotFound { .. })
        ));
    }

    #[test]
    fn query_filters_by_episode_kind_principal_seq_and_limit() {
        let ledger = Arc::new(Ledger::open_in_memory().unwrap());
        let ep1 = EpisodeId::generate();
        let ep2 = EpisodeId::generate();
        let alice = PrincipalId::generate();
        let branch = BranchId::generate();
        let step = StepId::generate();

        let w = ledger.writer(ep1.clone(), Some(branch.clone()), Some(step.clone()), alice.clone());
        w.record(EventKind::Objective, json!({"n": 1})).unwrap();
        w.record(EventKind::ToolInvocation, json!({"n": 2})).unwrap();
        w.record(EventKind::ToolInvocation, json!({"n": 3})).unwrap();
        ledger.append(ev(EventKind::ToolInvocation, &ep2, json!({"n": 4}))).unwrap();

        let by_ep = ledger
            .query(&TraceQuery { episode: Some(ep1.clone()), ..Default::default() })
            .unwrap();
        assert_eq!(by_ep.len(), 3);
        assert!(by_ep.iter().all(|e| e.branch.as_ref() == Some(&branch)));
        assert!(by_ep.iter().all(|e| e.step.as_ref() == Some(&step)));

        let tools_for_alice = ledger
            .query(&TraceQuery {
                kinds: vec![EventKind::ToolInvocation],
                principal: Some(alice.clone()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(tools_for_alice.len(), 2);

        let ranged = ledger
            .query(&TraceQuery { seq_range: Some((2, 4)), limit: Some(2), ..Default::default() })
            .unwrap();
        assert_eq!(ranged.iter().map(|e| e.seq).collect::<Vec<_>>(), vec![2, 3]);

        // Time range: everything happened "now"; a past-only window is empty.
        let past = chrono::Utc::now() - chrono::Duration::hours(2);
        let empty = ledger
            .query(&TraceQuery {
                time_range: Some((past - chrono::Duration::hours(1), past)),
                ..Default::default()
            })
            .unwrap();
        assert!(empty.is_empty());
    }

    #[test]
    fn causal_query_path_modifications() {
        let ledger = Ledger::open_in_memory().unwrap();
        let ep = EpisodeId::generate();
        let delta = ak_core::StateDelta {
            files: vec![ak_core::state::FileChange::Added {
                path: "src/main.rs".into(),
                blob: hash_bytes(b"fn main() {}"),
                mode: 0o644,
            }],
            ..Default::default()
        };
        ledger
            .append(ev(
                EventKind::StateDeltaRecorded,
                &ep,
                json!({"state_id": "st-1", "delta": delta}),
            ))
            .unwrap();
        ledger
            .append(ev(EventKind::StateDeltaRecorded, &ep, json!({"state_id": "st-2", "delta": ak_core::StateDelta::default()})))
            .unwrap();

        let hits = ledger.events_modifying_path("src/main.rs").unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].seq, 1);
        assert!(ledger.events_modifying_path("nope.rs").unwrap().is_empty());
    }

    #[test]
    fn causal_query_events_leading_to_effect() {
        let ledger = Ledger::open_in_memory().unwrap();
        let ep = EpisodeId::generate();
        let fx = EffectId::generate();
        let e1 = ledger.append(ev(EventKind::Objective, &ep, json!({}))).unwrap(); // seq 1
        let e2 = ledger.append(ev(EventKind::DeclaredIntent, &ep, json!({}))).unwrap(); // seq 2
        ledger.append(ev(EventKind::OsEvent, &ep, json!({"noise": true}))).unwrap(); // seq 3, unrelated
        let mut proposed = ev(EventKind::EffectProposed, &ep, json!({"effect_id": fx.as_str()}));
        proposed.caused_by = vec![e2.seq];
        let e4 = ledger.append(proposed).unwrap();
        // Link committed -> proposed and objective.
        let mut committed = ev(
            EventKind::EffectCommitted,
            &ep,
            json!({"effect_id": fx.as_str(), "class": "irreversible"}),
        );
        committed.caused_by = vec![e4.seq, e1.seq];
        ledger.append(committed).unwrap(); // seq 5

        let chain = ledger.events_leading_to_effect(fx.as_str()).unwrap();
        let seqs: Vec<i64> = chain.iter().map(|e| e.seq).collect();
        assert_eq!(seqs, vec![1, 2, 4, 5]); // noise (3) excluded
    }
}

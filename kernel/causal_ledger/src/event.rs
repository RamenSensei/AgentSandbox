//! Ledger event types and the tamper-evident hash chain.

use ak_core::hash::{hash_canonical, ContentHash};
use ak_core::ids::{BranchId, EpisodeId, PrincipalId, StepId};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// The kind of a causal-chain event. Ordered roughly along the causal path
/// from intent to effect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    /// The user/system objective that started the episode.
    Objective,
    /// A raw model response (payload typically references a raw blob).
    ModelResponse,
    /// The intent the agent declared before acting.
    DeclaredIntent,
    /// A request for capability (lease) grant or attenuation.
    CapabilityRequest,
    /// A policy engine allow/deny/escalate decision.
    PolicyDecision,
    /// A tool or MCP invocation.
    ToolInvocation,
    /// A raw OS-level observation (exec, open, connect, …).
    OsEvent,
    /// A [`ak_core::StateDelta`] was recorded for a step. By convention the
    /// payload is `{"state_id": …, "delta": <StateDelta>}`.
    StateDeltaRecorded,
    /// A structured observation was emitted to the agent.
    ObservationEmitted,
    /// An external effect was proposed. Payload includes `"effect_id"`.
    EffectProposed,
    /// An external effect was prepared (previewed).
    EffectPrepared,
    /// An external effect was approved.
    EffectApproved,
    /// An external effect was committed. By convention the payload carries
    /// `"effect_id"`, `"receipt_id"` and `"class"` (the [`ak_core::EffectClass`]).
    EffectCommitted,
    /// An external effect was aborted.
    EffectAborted,
    /// A machine-readable denial was issued.
    DenialIssued,
}

impl EventKind {
    /// Stable wire string (snake_case, matching serde).
    pub fn as_str(self) -> &'static str {
        match self {
            EventKind::Objective => "objective",
            EventKind::ModelResponse => "model_response",
            EventKind::DeclaredIntent => "declared_intent",
            EventKind::CapabilityRequest => "capability_request",
            EventKind::PolicyDecision => "policy_decision",
            EventKind::ToolInvocation => "tool_invocation",
            EventKind::OsEvent => "os_event",
            EventKind::StateDeltaRecorded => "state_delta_recorded",
            EventKind::ObservationEmitted => "observation_emitted",
            EventKind::EffectProposed => "effect_proposed",
            EventKind::EffectPrepared => "effect_prepared",
            EventKind::EffectApproved => "effect_approved",
            EventKind::EffectCommitted => "effect_committed",
            EventKind::EffectAborted => "effect_aborted",
            EventKind::DenialIssued => "denial_issued",
        }
    }

    /// All kinds, in causal order.
    pub const ALL: [EventKind; 15] = [
        EventKind::Objective,
        EventKind::ModelResponse,
        EventKind::DeclaredIntent,
        EventKind::CapabilityRequest,
        EventKind::PolicyDecision,
        EventKind::ToolInvocation,
        EventKind::OsEvent,
        EventKind::StateDeltaRecorded,
        EventKind::ObservationEmitted,
        EventKind::EffectProposed,
        EventKind::EffectPrepared,
        EventKind::EffectApproved,
        EventKind::EffectCommitted,
        EventKind::EffectAborted,
        EventKind::DenialIssued,
    ];

    /// Parse the wire string.
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.as_str() == s)
    }
}

/// The hash-covered body of a ledger event. [`LedgerEvent::event_hash`] is
/// `hash_canonical` of this structure, and each body embeds the previous
/// event's hash — mutating any persisted row breaks the chain.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EventBody {
    /// Monotonic sequence number assigned by the ledger (1-based).
    pub seq: i64,
    pub kind: EventKind,
    pub episode: EpisodeId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub branch: Option<BranchId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub step: Option<StepId>,
    pub principal: PrincipalId,
    pub timestamp: DateTime<Utc>,
    /// Arbitrary structured payload (see [`EventKind`] conventions).
    pub payload: serde_json::Value,
    /// Attribution links: `seq`s of the events that caused this one.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub caused_by: Vec<i64>,
    /// Hash of the previous event in the ledger; `None` for the first event.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_event_hash: Option<ContentHash>,
}

impl EventBody {
    /// Canonical content hash of this body.
    pub fn compute_hash(&self) -> ContentHash {
        hash_canonical(self)
    }
}

/// A fully persisted, hash-chained ledger event.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LedgerEvent {
    #[serde(flatten)]
    pub body: EventBody,
    /// `hash_canonical(body)`.
    pub event_hash: ContentHash,
}

impl std::ops::Deref for LedgerEvent {
    type Target = EventBody;
    fn deref(&self) -> &EventBody {
        &self.body
    }
}

/// Input to [`crate::Ledger::append`]: everything the caller provides;
/// `seq`, `timestamp`, chain hashes are assigned by the ledger.
#[derive(Debug, Clone)]
pub struct NewEvent {
    pub kind: EventKind,
    pub episode: EpisodeId,
    pub branch: Option<BranchId>,
    pub step: Option<StepId>,
    pub principal: PrincipalId,
    pub payload: serde_json::Value,
    /// Sequence numbers of causally prior events.
    pub caused_by: Vec<i64>,
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn kind_wire_strings_round_trip() {
        for k in EventKind::ALL {
            assert_eq!(EventKind::parse(k.as_str()), Some(k));
            // serde and as_str agree
            let json = serde_json::to_string(&k).unwrap();
            assert_eq!(json, format!("\"{}\"", k.as_str()));
        }
        assert_eq!(EventKind::parse("nope"), None);
    }
}

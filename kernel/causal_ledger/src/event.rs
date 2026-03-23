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

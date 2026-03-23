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

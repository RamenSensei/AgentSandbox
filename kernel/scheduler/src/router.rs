//! Backend routing: pick the cheapest backend that satisfies the risk floor
//! and compatibility needs.
//!
//! ## Routing rule (deterministic, documented)
//!
//! 1. A [`RiskTier`] maps to a **minimum isolation strength** (the "floor"):
//!    `Low >= 20`, `Medium >= 60`, `High >= 85`. The floor is a hard
//!    requirement — nothing (in particular no intent hint) can lower it.
//! 2. A candidate backend must additionally satisfy every set flag in
//!    [`Needs`] (`full_linux`, `gui`, `fork`) and, when `replay_at_least` is
//!    set, advertise a replay class at least that strong (using the total
//!    order on [`ReplayClass`]).
//! 3. Among the satisfying candidates, the **cheapest** wins, by the cost
//!    model `cost = cold_start_ms + 10 * isolation_strength` (stronger
//!    isolation carries per-step overhead: syscall interception, guest
//!    kernels, network hops). Ties break lexicographically on the backend
//!    name, so routing is fully deterministic.
//! 4. If no backend satisfies the requirements the router returns
//!    [`KernelError::BackendUnavailable`].

use ak_core::error::{KernelError, KernelResult};
use ak_core::replay::ReplayClass;
use ak_core::traits::{Backend, BackendProfile};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Risk tier of a step, decided by policy — never by the agent's own hints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskTier {
    Low,
    Medium,
    High,
}

impl RiskTier {
    /// Minimum `isolation_strength` a backend must advertise for this tier.
    pub fn isolation_floor(self) -> u8 {
        match self {
            RiskTier::Low => 20,
            RiskTier::Medium => 60,
            RiskTier::High => 85,
        }
    }
}

/// Compatibility requirements of a request. All default to "don't care".
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Needs {
    /// Requires arbitrary Linux binaries to run.
    pub full_linux: bool,
    /// Requires a GUI/browser surface.
    pub gui: bool,
    /// Requires native CoW fork for branch fan-out.
    pub fork: bool,
    /// Requires at least this replay guarantee.
    pub replay_at_least: Option<ReplayClass>,
}

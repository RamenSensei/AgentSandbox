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

/// Registry of isolation backends plus the deterministic routing rule.
#[derive(Default)]
pub struct BackendRouter {
    backends: Vec<Arc<dyn Backend>>,
}

impl BackendRouter {
    pub fn new() -> Self {
        Self { backends: Vec::new() }
    }

    /// Register a backend. Registration order does not affect routing.
    pub fn register(&mut self, backend: Arc<dyn Backend>) {
        self.backends.push(backend);
    }

    /// Profiles of all registered backends.
    pub fn profiles(&self) -> Vec<BackendProfile> {
        self.backends.iter().map(|b| b.profile()).collect()
    }

    /// Look up a registered backend by profile name.
    pub fn get(&self, name: &str) -> Option<Arc<dyn Backend>> {
        self.backends.iter().find(|b| b.profile().name == name).cloned()
    }

    /// Cost model: cold start plus a per-strength overhead term.
    pub fn cost(profile: &BackendProfile) -> u64 {
        profile.cold_start_ms + 10 * u64::from(profile.isolation_strength)
    }

    fn satisfies(profile: &BackendProfile, risk: RiskTier, needs: &Needs) -> bool {
        profile.isolation_strength >= risk.isolation_floor()
            && (!needs.full_linux || profile.full_linux)
            && (!needs.gui || profile.supports_gui)
            && (!needs.fork || profile.supports_fork)
            && needs
                .replay_at_least
                .map(|floor| profile.replay_class >= floor)
                .unwrap_or(true)
    }

    /// Choose the cheapest backend satisfying the floor and needs.
    /// See the module docs for the exact rule.
    pub fn route(&self, risk: RiskTier, needs: &Needs) -> KernelResult<Arc<dyn Backend>> {
        self.backends
            .iter()
            .map(|b| (b.profile(), b))
            .filter(|(p, _)| Self::satisfies(p, risk, needs))
            .min_by(|(a, _), (b, _)| {
                Self::cost(a).cmp(&Self::cost(b)).then_with(|| a.name.cmp(&b.name))
            })
            .map(|(_, b)| Arc::clone(b))
            .ok_or_else(|| KernelError::BackendUnavailable {
                backend: "router".into(),
                reason: format!(
                    "no registered backend satisfies isolation >= {} with needs {:?} \
                     (registered: {:?})",
                    risk.isolation_floor(),
                    needs,
                    self.backends.iter().map(|b| b.profile().name).collect::<Vec<_>>()
                ),
            })
    }
}

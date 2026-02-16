//! The two extension traits of the kernel: isolation [`Backend`]s and typed
//! world [`Connector`]s. Everything pluggable implements one of these.

use crate::action::ActionKind;
use crate::budget::ResourceBudget;
use crate::effect::{EffectClass, EffectContract};
use crate::error::KernelResult;
use crate::ids::{BranchId, PrincipalId, StateId};
use crate::replay::ReplayClass;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// A request handed to a backend after policy has already been enforced.
/// Backends never see leases or secrets — only the concrete, pre-authorized
/// work and the compiled confinement to apply.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionRequest {
    pub branch: BranchId,
    pub base_state: StateId,
    pub actor: PrincipalId,
    pub action: ActionKind,
    pub budget: ResourceBudget,
    /// Compiled confinement: allowed path prefixes (workspace-relative).
    pub writable_prefixes: Vec<String>,
    pub readable_prefixes: Vec<String>,
    /// Allowed egress domains for `HttpRead` (empty = no network).
    pub egress_domains: Vec<String>,
}

/// What a backend reports back after executing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionOutcome {
    pub exit_code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub usage: ResourceBudget,
    /// Workspace-relative paths the backend observed being written.
    pub paths_written: Vec<String>,
    pub replay_class: ReplayClass,
}

/// Capabilities a backend advertises so the router can pick the cheapest one
/// that satisfies the request's risk and compatibility requirements.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendProfile {
    pub name: String,
    /// 0 = weakest (in-process), 100 = hardware-virtualized.
    pub isolation_strength: u8,
    /// Typical cold-start latency in milliseconds, self-reported.
    pub cold_start_ms: u64,
    pub replay_class: ReplayClass,
    pub supports_fork: bool,
    pub supports_gui: bool,
    /// Whether arbitrary Linux binaries run (vs. e.g. WASI-only).
    pub full_linux: bool,
}

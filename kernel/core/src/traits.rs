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

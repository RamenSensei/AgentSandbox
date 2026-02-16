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

/// An isolation backend: local OS sandbox, gVisor, microVM, cluster, …
#[async_trait]
pub trait Backend: Send + Sync {
    fn profile(&self) -> BackendProfile;

    /// Materialize `base_state`'s workspace and execute the action.
    async fn execute(&self, req: ExecutionRequest) -> KernelResult<ExecutionOutcome>;

    /// Fork the backend-side state of a branch (CoW where supported).
    /// Backends without native fork return `Ok(false)`; the kernel then
    /// falls back to workspace re-materialization from the CAS.
    async fn fork(&self, _from: &StateId, _to_branch: &BranchId) -> KernelResult<bool> {
        Ok(false)
    }

    /// Drop any backend-side resources for a discarded branch.
    async fn discard(&self, _branch: &BranchId) -> KernelResult<()> {
        Ok(())
    }
}

/// Result of preparing an effect against the live external system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreparedEffect {
    /// Human/agent-reviewable preview of exactly what will happen.
    pub preview: serde_json::Value,
    /// Current values of the contract's preconditions, observed now.
    pub observed_preconditions: serde_json::Value,
}

/// Result of committing an effect.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitResult {
    /// External system response (canonicalized subset).
    pub response: serde_json::Value,
}

/// A typed connector to an external system. Connectors are the ONLY code that
/// touches real credentials; guests never see them. A connector declares the
/// semantic contract of each operation — the kernel does not trust HTTP verbs.
#[async_trait]
pub trait Connector: Send + Sync {
    fn name(&self) -> &str;

    /// Operations this connector supports, with their effect class.
    fn operations(&self) -> Vec<(String, EffectClass)>;

    /// Validate + canonicalize arguments for an operation.
    fn canonicalize(&self, operation: &str, args: &serde_json::Value)
        -> KernelResult<serde_json::Value>;

    /// Observe the live world and produce a preview (dry-run). Must not
    /// cause any external side effect.
    async fn prepare(&self, contract: &EffectContract) -> KernelResult<PreparedEffect>;

    /// Perform the effect. Called only after commit-time revalidation.
    async fn commit(&self, contract: &EffectContract) -> KernelResult<CommitResult>;

    /// Best-effort compensation for a committed effect (e.g. close the PR).
    async fn compensate(&self, contract: &EffectContract) -> KernelResult<CommitResult> {
        let _ = contract;
        Err(crate::error::KernelError::Connector(
            "operation is not compensatable".into(),
        ))
    }
}

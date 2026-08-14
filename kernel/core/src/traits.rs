//! The two extension traits of the kernel: isolation [`Backend`]s and typed
//! world [`Connector`]s. Everything pluggable implements one of these.

use crate::action::ActionKind;
use crate::budget::ResourceBudget;
use crate::effect::{EffectClass, EffectContract};
use crate::error::KernelResult;
use crate::hash::ContentHash;
use crate::ids::{BranchId, PrincipalId, StateId};
use crate::replay::ReplayClass;
use crate::sync::SyncManifest;
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
    /// Filesystem changes a state-syncing remote backend pulled back after
    /// executing, relative to the base state it materialized beforehand.
    /// `Some` (even when empty) means the remote tree was honestly synced
    /// and the kernel may record a real state transition; `None` means the
    /// backend has no state sync — a non-workspace-sharing backend's step
    /// is then recorded as an audit-only excursion.
    #[serde(default)]
    pub workspace_delta: Option<WorkspaceDelta>,
}

/// One file pushed to or pulled from a remote synced workspace.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncedFile {
    /// Workspace-relative path (`/`-separated, no `..`, not absolute).
    pub path: String,
    pub contents: Vec<u8>,
    /// Unix permission bits. The kernel masks these to `0o777` on apply —
    /// setuid/setgid/sticky bits never survive a remote round trip.
    pub mode: u32,
}

/// Filesystem changes observed in a remote synced workspace, expressed
/// against the base state the backend materialized before executing.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WorkspaceDelta {
    /// Files created or modified.
    pub upserts: Vec<SyncedFile>,
    /// Paths removed.
    pub deletes: Vec<String>,
}

impl WorkspaceDelta {
    pub fn is_empty(&self) -> bool {
        self.upserts.is_empty() && self.deletes.is_empty()
    }
}

/// Read-only access to committed workspace state, injected into remote
/// backends that materialize kernel state in their own sandboxes (state
/// sync). Implementations resolve a state to its file manifest and blobs
/// from the kernel's CAS. Calls are synchronous local reads.
pub trait StateProvider: Send + Sync {
    /// The workspace tree of `state`: path → (blob hash, mode).
    fn manifest(&self, state: &StateId) -> KernelResult<SyncManifest>;
    /// The raw bytes of one blob.
    fn blob(&self, hash: &ContentHash) -> KernelResult<Vec<u8>>;
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
    /// Whether the backend executes against the kernel's own workspace
    /// tree, so the state DAG can snapshot its filesystem effects. Remote
    /// backends must report `false`.
    #[serde(default)]
    pub shares_workspace: bool,
    /// Whether the backend materializes kernel state in its own sandbox
    /// and returns a [`WorkspaceDelta`] after each step (state sync). Steps
    /// on such a backend are real state transitions; a remote backend with
    /// neither `shares_workspace` nor `syncs_state` runs steps as
    /// audit-only excursions.
    #[serde(default)]
    pub syncs_state: bool,
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

/// A connector's answer to "did a commit for this contract's idempotency key
/// already happen externally?" — the recovery half of exactly-once.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CommitProbe {
    /// The external system confirms the operation executed; here is its
    /// (re-fetched) response.
    Committed(CommitResult),
    /// The external system confirms the operation never executed.
    NotCommitted,
    /// The connector cannot tell. The effect stays in doubt.
    Unknown,
}

/// A typed connector to an external system. Connectors are the ONLY code that
/// touches real credentials; guests never see them. A connector declares the
/// semantic contract of each operation — the kernel does not trust HTTP verbs.
#[async_trait]
pub trait Connector: Send + Sync {
    fn name(&self) -> &str;

    /// Operations this connector supports, with their effect class.
    fn operations(&self) -> Vec<(String, EffectClass)>;

    /// Classify a **specific invocation** of `operation` with (already
    /// canonicalized) arguments. Defaults to the statically declared class
    /// from [`Connector::operations`], or [`EffectClass::OpaqueExternal`]
    /// for undeclared operations.
    ///
    /// Connectors whose operations have argument-dependent semantics (e.g.
    /// an HTTP GET that is `Pure` only for allowlisted read-safe hosts)
    /// override this. The kernel calls it **before** creating an effect
    /// contract, so the contract carries the real per-invocation class —
    /// a read of an allowlisted docs site must never be gated behind the
    /// human-approval path reserved for opaque external writes.
    fn classify_operation(&self, operation: &str, arguments: &serde_json::Value) -> EffectClass {
        let _ = arguments;
        self.operations()
            .iter()
            .find(|(op, _)| op == operation)
            .map(|(_, class)| *class)
            .unwrap_or(EffectClass::OpaqueExternal)
    }

    /// Validate + canonicalize arguments for an operation.
    fn canonicalize(
        &self,
        operation: &str,
        args: &serde_json::Value,
    ) -> KernelResult<serde_json::Value>;

    /// Observe the live world and produce a preview (dry-run). Must not
    /// cause any external side effect.
    async fn prepare(&self, contract: &EffectContract) -> KernelResult<PreparedEffect>;

    /// Perform the effect. Called only after commit-time revalidation, and
    /// only by the single claim-holder for the contract's idempotency key.
    /// Implementations SHOULD forward the idempotency key to the external
    /// system where it supports one.
    async fn commit(&self, contract: &EffectContract) -> KernelResult<CommitResult>;

    /// Report whether a commit for this contract's idempotency key already
    /// executed externally. Used when a commit attempt failed indeterminately
    /// (crash, timeout) to resolve the in-doubt effect. Connectors that keep
    /// no queryable execution record return [`CommitProbe::Unknown`].
    async fn probe_commit(&self, contract: &EffectContract) -> KernelResult<CommitProbe> {
        let _ = contract;
        Ok(CommitProbe::Unknown)
    }

    /// Best-effort compensation for a committed effect (e.g. close the PR).
    async fn compensate(&self, contract: &EffectContract) -> KernelResult<CommitResult> {
        let _ = contract;
        Err(crate::error::KernelError::Connector(
            "operation is not compensatable".into(),
        ))
    }
}

//! The [`Kernel`] façade: one composed, transactional execution kernel.

use ak_backend_local::{LocalBackend, LocalBackendConfig};
use ak_causal_ledger::{EventKind, Ledger, LedgerEvent, TraceQuery};
use ak_connector_http::{HttpConnector, HttpConnectorConfig};
use ak_connector_mcp::{McpGateway, SignedManifest, SpawnOptions};
use ak_core::action::{Action, ActionKind};
use ak_core::budget::ResourceBudget;
use ak_core::capability::{glob_match, CapabilityLease, Constraint, LeaseCheckFailure, Operation};
use ak_core::denial::{Denial, DenialCode, RequestableScope};
use ak_core::effect::{EffectClass, EffectContract, PendingEffect, Receipt};
use ak_core::hash::ContentHash;
use ak_core::ids::{
    BranchId, EffectId, EpisodeId, LeaseId, PrincipalId, ReceiptId, StateId, StepId,
};
use ak_core::observation::{distill_output, extract_causal_failure, Observation};
use ak_core::replay::ReplayClass;
use ak_core::state::{FileChange, StateDelta, StateNode};
use ak_core::traits::{
    Backend, Connector, ExecutionRequest, PreparedEffect, StateProvider, WorkspaceDelta,
};
use ak_core::{KernelError, KernelResult, Principal};
use ak_effect_broker::{EffectBroker, SecretVault};
use ak_identity::{
    DelegationService, IdentityDb, KernelKeypair, LeaseStore, PrincipalRegistry, SealKey,
};
use ak_policy::{CompiledConfinement, Decision, PolicyDocument, PolicyEngine};
use ak_scheduler::{BackendRouter, Needs, RiskTier, SchedulerConfig, StepScheduler};
use ak_state_dag::{Branch, BranchComparison, BranchStatus, EpisodeHandle, StateDag};
use chrono::Utc;
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use tracing::{info, instrument, warn};

/// Configuration for [`Kernel::open`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelConfig {
    /// Directory holding every durable store (DAG db, CAS, ledger, identity
    /// db, effect store, signing key, secret vault, workspaces).
    pub data_dir: PathBuf,
    /// Optional YAML policy document; when absent an empty (default-deny)
    /// document is used.
    #[serde(default)]
    pub policy_file: Option<PathBuf>,
    /// Optional initial workspace snapshotted as episode roots when an
    /// episode is created without an explicit workspace.
    #[serde(default)]
    pub workspace_root: Option<PathBuf>,
    /// Episode budget enforced by the scheduler at step boundaries.
    #[serde(default = "default_episode_budget")]
    pub episode_budget: ResourceBudget,
    /// Maximum concurrently executing steps across branches.
    #[serde(default = "default_fanout")]
    pub max_concurrent_branches: usize,
    /// Path of the file holding the 32-byte key that seals secret files
    /// (vault, receipt-signing seed) at rest. Kept **outside** `data_dir` so
    /// copying the data dir does not copy the key. Overridden entirely by the
    /// `AK_VAULT_KEY` env var; defaults to `~/.agent-kernel/vault.key`.
    #[serde(default)]
    pub vault_key_file: Option<PathBuf>,
    /// When set, [`Kernel::open`] registers the built-in HTTP read connector
    /// so `HttpRead` steps and `http.get` effects work out of the box — the
    /// observation plane is not an optional accessory for an agent runtime.
    #[serde(default)]
    pub http: Option<HttpEgressSetup>,
    /// Out-of-the-box MCP servers: each is spawned at [`Kernel::open`] as a
    /// **confined, low-trust tool process** (verified OS sandbox, scrubbed
    /// environment, private scratch cell, no network) and registered as a
    /// connector. Hosts without a verified sandbox refuse to spawn a server
    /// unless it opts out explicitly. When non-empty, `open` must be called
    /// inside a tokio runtime (the servers are tokio child processes).
    #[serde(default)]
    pub mcp: Vec<McpServerSetup>,
    /// Additional isolation backends registered at [`Kernel::open`] — the
    /// public configuration for multi-backend routing. Each entry becomes a
    /// router candidate next to the built-in local sandbox: the policy
    /// rule's `risk_weight` sets a step's isolation floor and the router
    /// picks the cheapest satisfying backend. Auth tokens come from each
    /// adapter's environment variable (`GVISOR_API_TOKEN`,
    /// `FORKD_API_TOKEN`, `CUBE_API_TOKEN`, `KUBERNETES_API_TOKEN`), never
    /// from this file.
    #[serde(default)]
    pub backends: Vec<BackendSetup>,
}

/// One configured remote isolation backend (see [`KernelConfig::backends`]).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BackendSetup {
    /// gVisor (runsc) control host.
    Gvisor {
        endpoint: String,
        #[serde(default)]
        image: Option<String>,
    },
    /// forkd CoW-fork host.
    Forkd { endpoint: String },
    /// Cube microVM host.
    Cube { endpoint: String },
    /// Kubernetes exec service. `isolation_strength` MUST match the
    /// configured runtime class — there is no safe guess, so the operator
    /// declares it.
    Kubernetes {
        endpoint: String,
        isolation_strength: u8,
        #[serde(default)]
        namespace: Option<String>,
        #[serde(default)]
        runtime_class: Option<String>,
        #[serde(default)]
        image: Option<String>,
    },
}

/// One out-of-the-box MCP server (see [`KernelConfig::mcp`]).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpServerSetup {
    /// Server/connector name: `McpInvoke { server, .. }` refers to it and
    /// its tools become `"<name>.<tool>"` operations. Must match
    /// `[a-z0-9_-]+` — it also names the server's on-disk scratch cell.
    pub name: String,
    /// Command launching the stdio (newline-delimited JSON-RPC) server.
    pub command: String,
    /// Arguments for `command`.
    #[serde(default)]
    pub args: Vec<String>,
    /// YAML file holding the signed tool manifest (`manifest_yaml`,
    /// `signature`, `key_id`); requires `manifest_public_key_hex`. Without
    /// a manifest every tool classifies `OpaqueExternal`: still callable,
    /// but only through the effect-approval path — never inline.
    #[serde(default)]
    pub manifest_file: Option<PathBuf>,
    /// Hex Ed25519 public key the manifest must verify against.
    #[serde(default)]
    pub manifest_public_key_hex: Option<String>,
    /// Environment granted to the server on top of `PATH` (plus `HOME` and
    /// `TMPDIR`, which default to the server's scratch cell).
    #[serde(default)]
    pub env: std::collections::BTreeMap<String, String>,
    /// **Development only.** Spawn as a plain host process (still with a
    /// scrubbed environment) when no verified OS sandbox is available.
    /// Default: such hosts refuse the server entirely (fail closed).
    #[serde(default)]
    pub dangerously_allow_unsandboxed: bool,
}

/// Out-of-the-box HTTP observation-plane configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpEgressSetup {
    /// `*`-glob patterns of read-safe domains (e.g. `docs.rs`,
    /// `*.wikipedia.org`). GETs to these classify `Pure` and execute inline
    /// on the observation plane; every other target becomes a proposed
    /// `OpaqueExternal` effect requiring approval.
    #[serde(default)]
    pub read_safe_domains: Vec<String>,
    /// Response body cap in bytes.
    #[serde(default = "default_http_response_cap")]
    pub max_response_bytes: usize,
}

impl Default for HttpEgressSetup {
    fn default() -> Self {
        Self {
            read_safe_domains: Vec::new(),
            max_response_bytes: default_http_response_cap(),
        }
    }
}

fn default_http_response_cap() -> usize {
    4 << 20
}

fn default_episode_budget() -> ResourceBudget {
    ResourceBudget {
        cpu_ms: 10 * 60 * 1000,
        memory_bytes: 8 << 30,
        network_bytes: 1 << 30,
        tokens: 1_000_000,
        cost_micro_usd: 10_000_000,
        risk_units: 1000,
    }
}
fn default_fanout() -> usize {
    8
}

impl KernelConfig {
    /// A config rooted at `data_dir` with defaults everywhere else.
    pub fn new(data_dir: impl Into<PathBuf>) -> Self {
        Self {
            data_dir: data_dir.into(),
            policy_file: None,
            workspace_root: None,
            episode_budget: default_episode_budget(),
            max_concurrent_branches: default_fanout(),
            vault_key_file: None,
            http: None,
            mcp: Vec::new(),
            backends: Vec::new(),
        }
    }

    /// Effective sealing-key file: the configured path, or
    /// `$HOME/.agent-kernel/vault.key` when unset.
    pub fn effective_vault_key_file(&self) -> PathBuf {
        match &self.vault_key_file {
            Some(p) => p.clone(),
            None => std::env::var_os("HOME")
                .map(PathBuf::from)
                .unwrap_or_default()
                .join(".agent-kernel")
                .join("vault.key"),
        }
    }
}

/// Construct a remote backend adapter from its setup. Auth tokens are read
/// from each adapter's environment variable, never from configuration.
/// [`StateProvider`] over the kernel's state DAG and CAS: resolves a state
/// to its manifest (path → blob hash, mode) and blobs to bytes. Handed to
/// remote backends that sync state.
struct DagStateProvider(Arc<StateDag>);

impl StateProvider for DagStateProvider {
    fn manifest(&self, state: &StateId) -> KernelResult<ak_core::sync::SyncManifest> {
        let node = self.0.get_state(state)?;
        let manifest = ak_state_dag::Manifest::load(self.0.cas(), &node.workspace_root)?;
        Ok(manifest
            .files
            .into_iter()
            .map(|(path, e)| {
                (
                    path,
                    ak_core::sync::SyncEntry {
                        blob: e.blob,
                        mode: e.mode,
                    },
                )
            })
            .collect())
    }

    fn blob(&self, hash: &ak_core::hash::ContentHash) -> KernelResult<Vec<u8>> {
        self.0.cas().get(hash)
    }
}

fn build_backend(
    setup: &BackendSetup,
    state_provider: Arc<dyn StateProvider>,
) -> KernelResult<Arc<dyn Backend>> {
    Ok(match setup {
        BackendSetup::Gvisor { endpoint, image } => {
            let mut config = ak_backend_gvisor::GvisorConfig::from_env(endpoint.clone());
            config.image = image.clone();
            Arc::new(ak_backend_gvisor::GvisorBackend::new(config)?)
        }
        // forkd and Cube get the kernel's state provider: their steps are
        // real state transitions (push base state, pull the delta), not
        // audit-only excursions.
        BackendSetup::Forkd { endpoint } => Arc::new(
            ak_backend_forkd::ForkdBackend::new(ak_backend_forkd::ForkdConfig::from_env(
                endpoint.clone(),
            ))?
            .with_state_provider(state_provider),
        ),
        BackendSetup::Cube { endpoint } => Arc::new(
            ak_backend_cube::CubeBackend::new(ak_backend_cube::CubeConfig::from_env(
                endpoint.clone(),
            ))?
            .with_state_provider(state_provider),
        ),
        BackendSetup::Kubernetes {
            endpoint,
            isolation_strength,
            namespace,
            runtime_class,
            image,
        } => {
            let mut config = ak_backend_kubernetes::KubernetesConfig::from_env(
                endpoint.clone(),
                *isolation_strength,
            );
            if let Some(ns) = namespace {
                config.namespace = ns.clone();
            }
            config.runtime_class = runtime_class.clone();
            if let Some(image) = image {
                config.image = image.clone();
            }
            Arc::new(ak_backend_kubernetes::KubernetesBackend::new(config)?)
        }
    })
}

/// Validate a state-synced excursion's returned delta before it may touch
/// the branch workspace mirror. The remote sandbox is *outside* the
/// kernel's trust boundary: every path must be a clean workspace-relative
/// path outside the cache/scratch tier (`..`, absolute paths and ignored
/// components are refused — the latter closes symlink ambush via preserved
/// cache directories) **and** inside this step's writable prefixes. A
/// violation means the remote failed to enforce the confinement it was
/// handed; the delta is rejected wholesale.
fn validate_workspace_delta(
    delta: &WorkspaceDelta,
    writable_prefixes: &[String],
    backend: &str,
) -> Result<(), Denial> {
    let refuse = |verb: &str, raw: &str, why: String| Denial {
        code: DenialCode::ConstraintViolated,
        attempted_operation: Operation::new("backend.state_sync"),
        reason: format!(
            "backend `{backend}` returned a workspace delta that {verb} `{raw}`, \
             which {why}; the delta was rejected and the remote sandbox discarded \
             — the branch head is unchanged"
        ),
        safe_alternatives: Vec::new(),
        requestable_scopes: Vec::new(),
        escalation_allowed: false,
    };
    let check = |raw: &str, verb: &str| -> Result<String, Denial> {
        let path = ak_core::sync::syncable_path(raw).map_err(|why| refuse(verb, raw, why))?;
        if path != raw {
            return Err(refuse(
                verb,
                raw,
                format!("is not canonical (the canonical path is `{path}`)"),
            ));
        }
        if !ak_core::path::matches_prefixes(std::path::Path::new(&path), writable_prefixes) {
            return Err(refuse(
                verb,
                raw,
                format!("is outside the step's writable prefixes {writable_prefixes:?}"),
            ));
        }
        Ok(path)
    };

    // A delta is a canonical set, not an instruction stream. Duplicate or
    // conflicting entries would otherwise make application order matter.
    let mut touched = std::collections::BTreeSet::new();
    let mut upserts = std::collections::BTreeSet::new();
    for f in &delta.upserts {
        let path = check(&f.path, "writes")?;
        if !touched.insert(path.clone()) {
            return Err(refuse(
                "mentions more than once",
                &f.path,
                "makes the delta order-dependent".into(),
            ));
        }
        upserts.insert(path);
    }
    for p in &delta.deletes {
        let path = check(p, "deletes")?;
        if !touched.insert(path) {
            return Err(refuse(
                "both writes and/or deletes",
                p,
                "makes the delta order-dependent".into(),
            ));
        }
    }
    // A real tree cannot contain both a regular file and a child below it.
    for path in &upserts {
        let mut parent = std::path::Path::new(path).parent();
        while let Some(p) = parent {
            if p.as_os_str().is_empty() {
                break;
            }
            let parent_path = p.to_string_lossy();
            if upserts.contains(parent_path.as_ref()) {
                return Err(refuse(
                    "writes",
                    path,
                    format!("also writes its file ancestor `{parent_path}`"),
                ));
            }
            parent = p.parent();
        }
    }
    Ok(())
}

/// Remove empty directories above `path`, stopping at the workspace root or
/// the first non-empty directory.
fn prune_empty_parents(path: &std::path::Path, root: &std::path::Path) -> KernelResult<()> {
    let mut parent = path.parent();
    while let Some(dir) = parent {
        if dir == root || !dir.starts_with(root) {
            break;
        }
        match std::fs::remove_dir(dir) {
            Ok(()) => parent = dir.parent(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => parent = dir.parent(),
            Err(e) if e.kind() == std::io::ErrorKind::DirectoryNotEmpty => break,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

/// Apply a **validated** delta to the branch workspace mirror. Deletes run
/// before writes so file↔directory transitions work. Modes are masked to
/// `0o777`; setuid/setgid/sticky bits never survive a remote round trip.
fn apply_workspace_delta(dir: &std::path::Path, delta: &WorkspaceDelta) -> KernelResult<()> {
    let mut deletes: Vec<&str> = delta.deletes.iter().map(String::as_str).collect();
    deletes.sort_by_key(|p| std::cmp::Reverse(std::path::Path::new(p).components().count()));
    for p in deletes {
        let dest = dir.join(p);
        // Deltas describe persistent files. A directory here is either an
        // already-absent file or a parent whose listed children are removed
        // separately; never recursively delete unreported content.
        if std::fs::symlink_metadata(&dest)
            .map(|m| m.file_type().is_dir())
            .unwrap_or(false)
        {
            continue;
        }
        match std::fs::remove_file(&dest) {
            Ok(()) => prune_empty_parents(&dest, dir)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
    }
    for f in &delta.upserts {
        let dest = dir.join(&f.path);
        // A complete delta removed all former children first. Remove only an
        // empty directory here; a non-empty one signals an incomplete delta.
        if std::fs::symlink_metadata(&dest)
            .map(|m| m.file_type().is_dir())
            .unwrap_or(false)
        {
            std::fs::remove_dir(&dest)?;
        }
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&dest, &f.contents)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(f.mode & 0o777))?;
        }
    }
    Ok(())
}

/// Map a policy rule's risk weight to the scheduler's risk tier (and so an
/// isolation floor): `0..=2` low, `3..=6` medium, `>=7` high. The tier is
/// decided by policy — never by the agent's own hints.
fn risk_tier_of(weight: u32) -> RiskTier {
    match weight {
        0..=2 => RiskTier::Low,
        3..=6 => RiskTier::Medium,
        _ => RiskTier::High,
    }
}

/// Compatibility needs implied by the action itself. Anything whose effects
/// the state DAG must snapshot — file actions, process sessions — requires
/// a backend that either shares the kernel workspace or syncs state back.
/// A plain shell command may route to any backend satisfying the risk
/// floor; when a backend with neither capability runs it, the step is
/// recorded as an audit-only excursion.
fn needs_of(kind: &ActionKind) -> Needs {
    Needs {
        workspace: !matches!(kind, ActionKind::Shell { .. }),
        ..Needs::default()
    }
}

/// Per-episode bookkeeping the façade keeps in memory.
#[derive(Debug, Clone)]
struct EpisodeInfo {
    root_branch: BranchId,
    root_state: StateId,
    branches: Vec<BranchId>,
    created_by: PrincipalId,
}

/// Wire-friendly description of an episode.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpisodeDescription {
    pub episode: EpisodeId,
    pub root_branch: BranchId,
    pub root_state: StateId,
    pub branches: Vec<Branch>,
    pub created_by: PrincipalId,
    pub remaining_budget: ResourceBudget,
}

/// Result of one [`Kernel::execute_step`] call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepResult {
    pub step: StepId,
    /// Branch head after the step (unchanged when the step was denied).
    pub state: StateId,
    pub observation: Observation,
}

/// Result of one [`Kernel::execute_step_auto`] call: the step result plus
/// which lease authorized it (and whether it was freshly minted).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoStepResult {
    #[serde(flatten)]
    pub result: StepResult,
    /// The lease the kernel selected or minted for this step.
    pub lease: LeaseId,
    /// Whether the lease was minted by this call (vs. reusing an active one).
    pub lease_minted: bool,
}

/// Hard cap on candidates per [`Kernel::explore`] call.
pub const MAX_EXPLORE_CANDIDATES: usize = 16;

/// Hard cap on requests per [`Kernel::compile_envelope`] call.
pub const MAX_ENVELOPE_ITEMS: usize = 64;

/// One requested capability inside an autonomy envelope
/// (see [`Kernel::compile_envelope`]).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvelopeRequest {
    /// Operation the task needs (e.g. `proc.shell`, `net.http_read`,
    /// `github.create_pr`).
    pub operation: String,
    /// Constraint parameters, the same shape as a single capability
    /// request (`domain`, `path_prefix`, …).
    #[serde(default)]
    pub params: serde_json::Value,
}

/// Per-request outcome of [`Kernel::compile_envelope`]: exactly one of
/// `lease` / `denial` is set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvelopeItemReport {
    pub operation: String,
    /// Minted lease when policy allowed the request outright.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease: Option<CapabilityLease>,
    /// Structured denial (with requestable scopes) otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub denial: Option<Denial>,
}

/// The compiled envelope: explicit partial autonomy, one call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvelopeReport {
    /// Per-request outcomes, in request order.
    pub items: Vec<EnvelopeItemReport>,
    /// Items that minted a lease.
    pub granted: usize,
    /// Denied items whose requestable scopes name a human escalation.
    pub needs_human: usize,
    /// Denied items with no human escalation on offer.
    pub refused: usize,
}

/// One candidate in a server-side exploration: a named sequence of actions
/// applied to a fresh fork of the source branch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExploreCandidate {
    #[serde(default)]
    pub name: Option<String>,
    pub actions: Vec<ActionKind>,
}

/// Options for [`Kernel::explore`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExploreOptions {
    pub candidates: Vec<ExploreCandidate>,
    /// Success criterion, run after a candidate's actions: the candidate
    /// passes iff the evaluator observation is `Success` with exit code 0.
    /// Without an evaluator, a candidate passes when all its actions succeed.
    #[serde(default)]
    pub evaluator: Option<ActionKind>,
    /// Concurrent candidate cap (default 4, clamped to the kernel fanout).
    #[serde(default)]
    pub max_parallel: Option<usize>,
    /// Skip remaining candidates once one has passed (default true).
    #[serde(default = "default_true")]
    pub early_stop: bool,
    /// Merge the winning branch back into the source branch.
    #[serde(default)]
    pub merge_winner: bool,
    /// Discard non-winning branches (default true).
    #[serde(default = "default_true")]
    pub discard_losers: bool,
    /// Per-step budget for candidate/evaluator steps (clamped into each
    /// auto-resolved lease's envelope).
    #[serde(default)]
    pub step_budget: Option<ResourceBudget>,
}

fn default_true() -> bool {
    true
}

/// Per-candidate outcome of an exploration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExploreCandidateReport {
    pub index: usize,
    #[serde(default)]
    pub name: Option<String>,
    /// The fork this candidate ran on (`None` when skipped before forking).
    pub branch: Option<BranchId>,
    pub steps: Vec<StepResult>,
    pub evaluation: Option<StepResult>,
    pub passed: bool,
    /// Skipped because early-stop already had a winner.
    pub skipped: bool,
    /// Infrastructure error (fork/step/evaluator), when one occurred.
    #[serde(default)]
    pub error: Option<String>,
}

/// Result of [`Kernel::explore`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExploreReport {
    pub source: BranchId,
    /// Index of the winning candidate (lowest passing index).
    pub winner: Option<usize>,
    /// Head state of the source branch after merging the winner (when
    /// `merge_winner` was set and the merge succeeded).
    pub merged_state: Option<StateId>,
    /// Why the merge failed, when it did (e.g. a conflict).
    #[serde(default)]
    pub merge_error: Option<String>,
    pub candidates: Vec<ExploreCandidateReport>,
    pub discarded: Vec<BranchId>,
}

/// Structured answer to "why did this step do what it did" — the causal
/// chain the ledger recorded for one step, decoded into protocol shapes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepExplanation {
    pub step: StepId,
    pub episode: EpisodeId,
    pub branch: Option<BranchId>,
    pub principal: PrincipalId,
    /// The invoked action as recorded (kind, lease, budget, intent hint).
    pub action: Option<serde_json::Value>,
    /// Policy decisions and capability requests that led to the action.
    pub policy_decisions: Vec<serde_json::Value>,
    /// The machine-readable denial, when the step was denied.
    pub denial: Option<Denial>,
    /// State the step produced (absent for denied steps).
    pub state: Option<StateId>,
    pub state_delta: Option<serde_json::Value>,
    /// The distilled observation the agent saw.
    pub observation: Option<serde_json::Value>,
    /// Effects proposed by this step.
    pub effects_proposed: Vec<serde_json::Value>,
    /// Every raw ledger event for the step, in causal order.
    pub events: Vec<LedgerEvent>,
}

/// Report produced by [`Kernel::replay_sandbox`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplaySandboxReport {
    pub step: StepId,
    /// Exit code recorded in the original observation.
    pub original_exit_code: Option<i32>,
    /// Exit code of the re-execution.
    pub rerun_exit_code: i32,
    /// Whether the re-executed workspace tree hashed identically to the
    /// recorded post-step state.
    pub workspace_match: bool,
    /// Replay class of the recorded state (sandbox replay requires at least
    /// `filesystem_only`).
    pub replay_class: ReplayClass,
}

/// The composed AgentKernel. See the crate docs for the replay guarantees
/// and the module docs of every component crate for their invariants.
pub struct Kernel {
    config: KernelConfig,
    dag: Arc<StateDag>,
    ledger: Arc<Ledger>,
    delegation: DelegationService,
    keypair: Arc<KernelKeypair>,
    policy: RwLock<PolicyEngine>,
    broker: Arc<EffectBroker>,
    vault: Arc<SecretVault>,
    scheduler: StepScheduler,
    backend: Arc<LocalBackend>,
    episodes: Mutex<HashMap<EpisodeId, EpisodeInfo>>,
    /// One transition at a time per branch. Different branches still run in
    /// parallel; serializing a single branch prevents two remote excursions
    /// from materializing the same stale base and racing the movable head.
    branch_gates: Mutex<HashMap<BranchId, Arc<tokio::sync::Mutex<()>>>>,
    /// Effect classes of registered connector operations, for contracts.
    op_classes: Mutex<HashMap<String, EffectClass>>,
    /// Registered connector names (routing prefixes).
    connector_names: Mutex<Vec<String>>,
    /// Registered connector objects, for canonicalization, per-invocation
    /// classification and inline observation-plane reads.
    connectors: Mutex<HashMap<String, Arc<dyn Connector>>>,
}

impl std::fmt::Debug for Kernel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Kernel")
            .field("data_dir", &self.config.data_dir)
            .finish_non_exhaustive()
    }
}

struct KeySigner(Arc<KernelKeypair>);

impl ak_effect_broker::ReceiptSigner for KeySigner {
    fn sign(&self, message: &[u8]) -> (String, String) {
        (self.0.sign_bytes(message), self.0.key_id())
    }
}

/// Extension: raw-byte signing over the identity keypair. The broker hands us
/// canonical JSON bytes already, so we sign them as-is.
trait SignBytes {
    fn sign_bytes(&self, message: &[u8]) -> String;
}

impl SignBytes for KernelKeypair {
    fn sign_bytes(&self, message: &[u8]) -> String {
        // `sign_canonical` canonicalizes a serde value; the broker gives us
        // the canonical bytes of a ReceiptBody. Signing the raw string value
        // would double-encode, so we parse and re-sign the value: canonical
        // JSON is a fixed point of canonicalization, so this signs exactly
        // the bytes the broker hashed.
        match serde_json::from_slice::<serde_json::Value>(message) {
            Ok(v) => self.sign_canonical(&v),
            Err(_) => self.sign_canonical(&String::from_utf8_lossy(message).into_owned()),
        }
    }
}

impl Kernel {
    /// Open (creating on first use) a kernel rooted at `config.data_dir`.
    #[instrument(skip(config), fields(data_dir = %config.data_dir.display()))]
    pub fn open(config: KernelConfig) -> KernelResult<Self> {
        std::fs::create_dir_all(&config.data_dir)?;
        let dag = Arc::new(StateDag::open(
            &config.data_dir.join("dag.db"),
            &config.data_dir.join("cas"),
        )?);
        let ledger = Arc::new(Ledger::open(&config.data_dir.join("ledger.db"))?);
        let identity_db =
            IdentityDb::open(config.data_dir.join("identity.db")).map_err(KernelError::from)?;
        let delegation = DelegationService::new(identity_db);
        let key_file = config.effective_vault_key_file();
        let seal_key = SealKey::resolve(&key_file).map_err(KernelError::from)?;
        let keypair = Arc::new(
            KernelKeypair::load_or_generate(config.data_dir.join("receipt.key"), &seal_key)
                .map_err(KernelError::from)?,
        );
        let policy_doc = match &config.policy_file {
            Some(path) => PolicyDocument::from_yaml_file(path)
                .map_err(|e| KernelError::Other(format!("policy load failed: {e}")))?,
            None => PolicyDocument::default(),
        };
        let broker = Arc::new(EffectBroker::open(
            &config.data_dir.join("effects.db"),
            Box::new(KeySigner(Arc::clone(&keypair))),
        )?);
        let vault = Arc::new(SecretVault::open(
            config.data_dir.join("vault.json"),
            seal_key,
        )?);
        let backend = Arc::new(LocalBackend::new(LocalBackendConfig::new(
            config.data_dir.join("workspaces"),
        ))?);
        let mut router = BackendRouter::new();
        router.register(Arc::clone(&backend) as Arc<dyn Backend>);
        let scheduler = StepScheduler::new(
            router,
            SchedulerConfig {
                max_concurrent_branches: config.max_concurrent_branches,
                episode_budget: config.episode_budget,
            },
        );
        // Restore persisted episodes so the control plane survives restarts:
        // rebuild the in-memory index and reopen each episode's budget
        // account (AK-006).
        let mut episodes = HashMap::new();
        for rec in dag.list_episodes()? {
            // Rows written before the 0002 migration lack metadata; they
            // cannot be authorized correctly, so they stay unlisted.
            if rec.root_branch.as_str().is_empty() || rec.created_by.as_str().is_empty() {
                warn!(episode = %rec.id, "skipping pre-migration episode without metadata");
                continue;
            }
            let branches: Vec<BranchId> = dag
                .branches_of(&rec.id)?
                .into_iter()
                .map(|b| b.id)
                .collect();
            scheduler.register_episode_default(&rec.id);
            episodes.insert(
                rec.id.clone(),
                EpisodeInfo {
                    root_branch: rec.root_branch,
                    root_state: rec.root_state,
                    branches,
                    created_by: rec.created_by,
                },
            );
        }
        info!(restored = episodes.len(), "kernel opened");
        let http_setup = config.http.clone();
        let kernel = Self {
            config,
            dag,
            ledger,
            delegation,
            keypair,
            policy: RwLock::new(PolicyEngine::new(policy_doc)),
            broker,
            vault,
            scheduler,
            backend,
            episodes: Mutex::new(episodes),
            branch_gates: Mutex::new(HashMap::new()),
            op_classes: Mutex::new(HashMap::new()),
            connector_names: Mutex::new(Vec::new()),
            connectors: Mutex::new(HashMap::new()),
        };
        // Out-of-the-box observation plane: a configured HTTP connector makes
        // `HttpRead` a first-class action instead of a declared-but-dead one.
        if let Some(http) = http_setup {
            let connector = HttpConnector::new(HttpConnectorConfig {
                allowlist: http.read_safe_domains,
                max_response_bytes: http.max_response_bytes,
                ..HttpConnectorConfig::default()
            })?;
            kernel.register_connector(Arc::new(connector))?;
        }
        // Out-of-the-box MCP: every configured server spawns as a confined,
        // low-trust tool process and registers as a connector.
        let mcp_setups = kernel.config.mcp.clone();
        for setup in &mcp_setups {
            kernel.spawn_mcp_server(setup)?;
        }
        // Public multi-backend routing: configured remote backends become
        // router candidates next to the built-in local sandbox. Sync-capable
        // adapters receive the kernel's state provider so their steps are
        // real state transitions.
        let backend_setups = kernel.config.backends.clone();
        for setup in &backend_setups {
            let provider = kernel.state_provider();
            kernel.register_backend(build_backend(setup, provider)?);
        }
        Ok(kernel)
    }

    // ------------------------------------------------------------ accessors

    pub fn config(&self) -> &KernelConfig {
        &self.config
    }
    pub fn dag(&self) -> &StateDag {
        self.dag.as_ref()
    }

    /// A read-only [`StateProvider`] over this kernel's DAG + CAS, for
    /// state-syncing backends (see [`Kernel::register_backend`]).
    pub fn state_provider(&self) -> Arc<dyn StateProvider> {
        Arc::new(DagStateProvider(Arc::clone(&self.dag)))
    }
    pub fn ledger(&self) -> &Arc<Ledger> {
        &self.ledger
    }
    pub fn broker(&self) -> &Arc<EffectBroker> {
        &self.broker
    }
    pub fn vault(&self) -> &Arc<SecretVault> {
        &self.vault
    }
    pub fn registry(&self) -> &PrincipalRegistry {
        self.delegation.registry()
    }
    pub fn leases(&self) -> &LeaseStore {
        self.delegation.leases()
    }
    pub fn delegation(&self) -> &DelegationService {
        &self.delegation
    }
    pub fn keypair(&self) -> &Arc<KernelKeypair> {
        &self.keypair
    }
    pub fn scheduler(&self) -> &StepScheduler {
        &self.scheduler
    }

    fn branch_gate(&self, branch: &BranchId) -> KernelResult<Arc<tokio::sync::Mutex<()>>> {
        Ok(Arc::clone(
            lock(&self.branch_gates)?
                .entry(branch.clone())
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(()))),
        ))
    }

    async fn lock_branch(
        &self,
        branch: &BranchId,
    ) -> KernelResult<tokio::sync::OwnedMutexGuard<()>> {
        Ok(self.branch_gate(branch)?.lock_owned().await)
    }

    /// Terminal branches no longer need an entry in the in-memory gate map.
    /// Any waiter already holding the old Arc wakes and observes the durable
    /// Merged/Discarded status before it can mutate state.
    fn forget_branch_gate(&self, branch: &BranchId) {
        match self.branch_gates.lock() {
            Ok(mut gates) => {
                gates.remove(branch);
            }
            Err(poisoned) => {
                poisoned.into_inner().remove(branch);
            }
        }
    }

    /// The local backend (workspace materialization + discard).
    pub fn local_backend(&self) -> &Arc<LocalBackend> {
        &self.backend
    }

    fn policy_read(&self) -> KernelResult<std::sync::RwLockReadGuard<'_, PolicyEngine>> {
        self.policy
            .read()
            .map_err(|_| KernelError::Storage("policy lock poisoned".into()))
    }

    /// The current policy epoch.
    pub fn policy_epoch(&self) -> KernelResult<u64> {
        Ok(self.policy_read()?.document().policy_epoch)
    }

    /// Run `f` with mutable access to the policy engine (epoch bumps are the
    /// document's responsibility).
    pub fn with_policy_mut<R>(&self, f: impl FnOnce(&mut PolicyEngine) -> R) -> KernelResult<R> {
        let mut guard = self
            .policy
            .write()
            .map_err(|_| KernelError::Storage("policy lock poisoned".into()))?;
        Ok(f(&mut guard))
    }

    /// Register a principal in the identity registry.
    pub fn register_principal(&self, principal: &Principal) -> KernelResult<()> {
        self.registry()
            .register(principal)
            .map_err(KernelError::from)
    }

    /// Register a connector with the effect broker, recording its declared
    /// operation classes so proposals can be classified.
    pub fn register_connector(&self, connector: Arc<dyn Connector>) -> KernelResult<()> {
        {
            let mut classes = lock(&self.op_classes)?;
            for (op, class) in connector.operations() {
                classes.insert(op, class);
            }
            lock(&self.connector_names)?.push(connector.name().to_string());
            lock(&self.connectors)?.insert(connector.name().to_string(), Arc::clone(&connector));
        }
        self.broker.register_connector(connector);
        Ok(())
    }

    /// The registered connector named `name`, if any.
    pub fn connector(&self, name: &str) -> KernelResult<Option<Arc<dyn Connector>>> {
        Ok(lock(&self.connectors)?.get(name).cloned())
    }

    /// Register an additional isolation backend with the router. Steps whose
    /// policy risk tier demands more isolation than the built-in local
    /// sandbox provides route to the cheapest satisfying backend.
    ///
    /// A backend that advertises `syncs_state` (build the adapter with a
    /// [`StateProvider`] from [`Kernel::state_provider`]) runs steps as
    /// **real state transitions**: it materializes the base state remotely
    /// and returns the observed delta, which the kernel validates against
    /// the step's confinement, applies to the branch mirror and snapshots.
    /// A backend with neither `shares_workspace` nor `syncs_state` has its
    /// steps recorded as **audit-only excursions**: full observations in
    /// the ledger, no local state transition claimed.
    pub fn register_backend(&self, backend: Arc<dyn Backend>) {
        self.scheduler.register_backend(backend);
    }

    /// Profiles of every registered isolation backend.
    pub fn backend_profiles(&self) -> Vec<ak_core::traits::BackendProfile> {
        self.scheduler.backend_profiles()
    }

    /// Spawn one configured MCP server as a confined, low-trust tool process
    /// and register it as a connector.
    ///
    /// The server gets a scrubbed environment, a private scratch cell at
    /// `data_dir/mcp/<name>` as cwd/`HOME`/`TMPDIR`, and — when a verified
    /// OS sandbox is available — a Seatbelt/bwrap wrapper confining reads
    /// and writes to that cell with no network. The Seatbelt profile lives
    /// *outside* the cell, so the server can never rewrite its own rules.
    /// Hosts without a verified sandbox fail closed unless the setup sets
    /// `dangerously_allow_unsandboxed`.
    fn spawn_mcp_server(&self, setup: &McpServerSetup) -> KernelResult<()> {
        if setup.name.is_empty()
            || !setup
                .name
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
        {
            return Err(KernelError::Other(format!(
                "mcp server name `{}` must match [a-z0-9_-]+ — it names an on-disk scratch \
                 cell and an operation prefix",
                setup.name
            )));
        }
        let mcp_root = self.config.data_dir.join("mcp");
        let cell = mcp_root.join(&setup.name);
        std::fs::create_dir_all(&cell)?;
        let cell = cell.canonicalize()?;
        let profile_out = mcp_root.join(format!("{}.sb", setup.name));
        let wrapper = ak_backend_local::sandbox::tool_wrapper(
            self.backend.sandbox_tech(),
            &cell,
            &profile_out,
        )?;
        let wrapper = match wrapper {
            Some(w) => w,
            None if setup.dangerously_allow_unsandboxed => {
                warn!(
                    server = %setup.name,
                    "spawning MCP server WITHOUT OS confinement (explicit dev opt-out)"
                );
                Vec::new()
            }
            None => {
                return Err(KernelError::BackendUnavailable {
                    backend: "local".into(),
                    reason: format!(
                        "no verified OS sandbox on this host: MCP server `{}` is a low-trust \
                         tool process and fails closed. Install bubblewrap (Linux) or ensure \
                         /usr/bin/sandbox-exec works (macOS), or opt in for trusted \
                         development servers only via `dangerously_allow_unsandboxed`.",
                        setup.name
                    ),
                });
            }
        };
        let manifest = match (&setup.manifest_file, &setup.manifest_public_key_hex) {
            (Some(path), Some(key)) => {
                let text = std::fs::read_to_string(path)?;
                let signed: SignedManifest = serde_yaml::from_str(&text).map_err(|e| {
                    KernelError::Other(format!(
                        "mcp manifest `{}` is not a SignedManifest document: {e}",
                        path.display()
                    ))
                })?;
                Some((signed, key.clone()))
            }
            (None, None) => None,
            _ => {
                return Err(KernelError::Other(format!(
                    "mcp server `{}`: `manifest_file` and `manifest_public_key_hex` must be \
                     set together",
                    setup.name
                )));
            }
        };
        let mut env = setup.env.clone();
        env.entry("HOME".into())
            .or_insert_with(|| cell.display().to_string());
        env.entry("TMPDIR".into())
            .or_insert_with(|| cell.display().to_string());
        let args: Vec<&str> = setup.args.iter().map(String::as_str).collect();
        let gateway = McpGateway::spawn_with(
            &setup.name,
            &setup.command,
            &args,
            manifest.as_ref().map(|(m, k)| (m, k.as_str())),
            SpawnOptions {
                env,
                cwd: Some(cell),
                wrapper,
            },
        )?;
        self.register_connector(Arc::new(gateway))
    }

    /// Names of every registered connector.
    pub fn connector_names(&self) -> KernelResult<Vec<String>> {
        Ok(lock(&self.connector_names)?.clone())
    }

    /// The declared effect class for a connector operation; undeclared
    /// operations classify as [`EffectClass::OpaqueExternal`].
    pub fn effect_class_of(&self, operation: &str) -> KernelResult<EffectClass> {
        Ok(lock(&self.op_classes)?
            .get(operation)
            .copied()
            .unwrap_or(EffectClass::OpaqueExternal))
    }

    // ------------------------------------------------------------- episodes

    /// Create an episode: root state (optionally snapshotting `workspace`,
    /// else the configured `workspace_root`, else empty), initial branch,
    /// materialized backend workspace, and an `Objective` ledger event.
    #[instrument(skip(self, workspace))]
    pub fn create_episode(
        &self,
        actor: &PrincipalId,
        workspace: Option<&Path>,
        objective: &str,
    ) -> KernelResult<EpisodeHandle> {
        let ws = workspace.or(self.config.workspace_root.as_deref());
        let handle = self
            .dag
            .create_episode(actor, ws, ReplayClass::FilesystemOnly, objective)?;
        // Materialize the root workspace for the initial branch.
        let dir = self.backend.workspace_for(&handle.branch)?;
        self.dag.materialize(&handle.root.id, &dir)?;
        // Open the episode's own budget account (budgets are per-episode,
        // not scheduler-global).
        self.scheduler.register_episode_default(&handle.episode);
        lock(&self.episodes)?.insert(
            handle.episode.clone(),
            EpisodeInfo {
                root_branch: handle.branch.clone(),
                root_state: handle.root.id.clone(),
                branches: vec![handle.branch.clone()],
                created_by: actor.clone(),
            },
        );
        self.ledger
            .writer(
                handle.episode.clone(),
                Some(handle.branch.clone()),
                None,
                actor.clone(),
            )
            .record(
                EventKind::Objective,
                serde_json::json!({ "objective": objective }),
            )?;
        Ok(handle)
    }

    /// Describe an episode: branches and remaining budget.
    pub async fn describe_episode(&self, episode: &EpisodeId) -> KernelResult<EpisodeDescription> {
        let info =
            lock(&self.episodes)?
                .get(episode)
                .cloned()
                .ok_or_else(|| KernelError::NotFound {
                    kind: "episode",
                    id: episode.to_string(),
                })?;
        let branches = info
            .branches
            .iter()
            .map(|b| self.dag.get_branch(b))
            .collect::<KernelResult<Vec<_>>>()?;
        Ok(EpisodeDescription {
            episode: episode.clone(),
            root_branch: info.root_branch,
            root_state: info.root_state,
            branches,
            created_by: info.created_by,
            remaining_budget: self
                .scheduler
                .remaining_budget(episode)
                .unwrap_or_else(ResourceBudget::zero),
        })
    }

    // ------------------------------------------------------------- branches

    /// Load a branch only if it can still accept transitions. This check is
    /// deliberately performed while the caller holds the branch gate, before
    /// any backend work: discovering a terminal branch after execution would
    /// turn a rejected step into an unrecorded side effect.
    fn active_branch(&self, branch: &BranchId) -> KernelResult<Branch> {
        let value = self.dag.get_branch(branch)?;
        match value.status {
            BranchStatus::Active => Ok(value),
            BranchStatus::Discarded | BranchStatus::Merged => Err(KernelError::BranchDiscarded {
                branch: branch.to_string(),
            }),
        }
    }

    /// The principal that created `episode` (the resource owner for
    /// authorization purposes).
    pub fn episode_owner(&self, episode: &EpisodeId) -> KernelResult<PrincipalId> {
        lock(&self.episodes)?
            .get(episode)
            .map(|i| i.created_by.clone())
            .ok_or_else(|| KernelError::NotFound {
                kind: "episode",
                id: episode.to_string(),
            })
    }

    /// The owner of the episode a branch belongs to.
    pub fn branch_owner(&self, branch: &BranchId) -> KernelResult<PrincipalId> {
        let episode = self.dag.get_branch(branch)?.episode;
        self.episode_owner(&episode)
    }

    /// Fork a new branch from the head of `branch` and materialize its
    /// backend workspace.
    #[instrument(skip(self))]
    pub async fn fork_branch(&self, branch: &BranchId) -> KernelResult<Branch> {
        let _branch_guard = self.lock_branch(branch).await?;
        let source = self.active_branch(branch)?;
        let head = self.dag.get_state(&source.head)?;
        let new = self.dag.fork(&head.id)?;
        let setup = self
            .backend
            .workspace_for(&new.id)
            .and_then(|dir| self.dag.materialize(&new.head, &dir));
        if let Err(error) = setup {
            if let Err(e) = self.backend.discard(&new.id).await {
                warn!(branch = %new.id, error = %e,
                      "failed to clean local workspace after fork setup failure");
            }
            if let Err(e) = self.dag.discard_branch(&new.id) {
                warn!(branch = %new.id, error = %e,
                      "failed to mark partially-created fork discarded");
            }
            return Err(error);
        }
        // Register the durable branch before optional remote optimization;
        // after this point native fork failures merely fall back to CAS.
        let registration_error = {
            match lock(&self.episodes) {
                Ok(mut episodes) => {
                    if let Some(info) = episodes.get_mut(&new.episode) {
                        info.branches.push(new.id.clone());
                    }
                    None
                }
                Err(error) => Some(error),
            }
        };
        if let Some(error) = registration_error {
            if let Err(e) = self.backend.discard(&new.id).await {
                warn!(branch = %new.id, error = %e,
                      "failed to clean local workspace after fork registration failure");
            }
            if let Err(e) = self.dag.discard_branch(&new.id) {
                warn!(branch = %new.id, error = %e,
                      "failed to mark unregistered fork discarded");
            }
            return Err(error);
        }
        // Native remote CoW is an optimization, never a correctness
        // dependency: adapters return false when they do not currently own
        // this exact state, and the first step then materializes from CAS.
        for backend in self.scheduler.backends() {
            if !backend.profile().supports_fork {
                continue;
            }
            match backend.fork(&head.id, &new.id).await {
                Ok(true) => info!(backend = %backend.profile().name, branch = %new.id,
                                  "forked backend state natively"),
                Ok(false) => {}
                Err(e) => warn!(backend = %backend.profile().name, error = %e,
                                "native backend fork failed; branch will materialize from CAS"),
            }
        }
        Ok(new)
    }

    /// File-level diff of a branch head since `since` (defaults to the
    /// branch base state).
    pub fn branch_diff(
        &self,
        branch: &BranchId,
        since: Option<&StateId>,
    ) -> KernelResult<Vec<FileChange>> {
        let b = self.dag.get_branch(branch)?;
        let since = since.cloned().unwrap_or(b.base_state);
        self.dag.diff(&since, &b.head)
    }

    /// Compare two branches since their lowest common ancestor.
    pub fn branch_compare(&self, a: &BranchId, b: &BranchId) -> KernelResult<BranchComparison> {
        self.dag.branch_compare(a, b)
    }

    /// Merge `source` into `target` (artifact-only three-way merge), then
    /// re-materialize the target backend workspace.
    #[instrument(skip(self))]
    pub async fn merge_branch(
        &self,
        target: &BranchId,
        source: &BranchId,
        actor: &PrincipalId,
    ) -> KernelResult<StateNode> {
        if target == source {
            return Err(KernelError::Storage(format!(
                "cannot merge branch `{target}` into itself"
            )));
        }
        // Deterministic acquisition order lets cross-merges wait safely while
        // preventing either branch from changing under the three-way merge.
        let (first, second) = if target.as_str() <= source.as_str() {
            (target, source)
        } else {
            (source, target)
        };
        let _first_guard = self.lock_branch(first).await?;
        let _second_guard = self.lock_branch(second).await?;
        let node = self.dag.merge(target, source, actor)?;
        let materialized = self
            .backend
            .workspace_for(target)
            .and_then(|dir| self.dag.materialize(&node.id, &dir));
        // The source is now immutable/merged. Release all of its local and
        // remote runtime resources; cleanup failure does not un-merge the
        // already committed DAG transition, so report it loudly and retain
        // the adapter handle for an explicit discard retry.
        for backend in self.scheduler.backends() {
            if let Err(e) = backend.discard(source).await {
                warn!(backend = %backend.profile().name, error = %e,
                      "failed to release merged source branch resources");
            }
        }
        self.forget_branch_gate(source);
        if let Err(error) = materialized {
            return Err(KernelError::Storage(format!(
                "merge committed as {} but rebuilding target workspace `{target}` failed: \
                 {error}; retrying any target step will materialize its durable head",
                node.id
            )));
        }
        Ok(node)
    }

    /// Discard an active branch in the DAG and tear down its backend
    /// workspace. Calling this for a merged source retries runtime cleanup
    /// only and preserves its durable `Merged` status.
    #[instrument(skip(self))]
    pub async fn discard_branch(&self, branch: &BranchId) -> KernelResult<()> {
        let _branch_guard = self.lock_branch(branch).await?;
        let status = self.dag.get_branch(branch)?.status;
        if status == BranchStatus::Discarded {
            return Err(KernelError::BranchDiscarded {
                branch: branch.to_string(),
            });
        }
        if status == BranchStatus::Merged {
            // Merge is already durable, but a transport failure may have
            // left a remote adapter handle for this source. Retrying discard
            // is the narrow cleanup operation: do not rewrite Merged to
            // Discarded and do not resurrect the branch.
            let mut first_error = None;
            for backend in self.scheduler.backends() {
                if let Err(error) = backend.discard(branch).await {
                    warn!(backend = %backend.profile().name, error = %error,
                          "merged branch cleanup retry failed");
                    if first_error.is_none() {
                        first_error = Some(error);
                    }
                }
            }
            if let Some(error) = first_error {
                return Err(error);
            }
            self.forget_branch_gate(branch);
            return Ok(());
        }
        // Remote adapters may own a sandbox even when the most recent step
        // ran locally. Tear every one down before making the DAG transition
        // irreversible. Adapter discard is idempotent, so a failed deletion
        // retains its handle and a retry can finish cleanly.
        let local: Arc<dyn Backend> = Arc::clone(&self.backend) as Arc<dyn Backend>;
        let mut first_error = None;
        for backend in self.scheduler.backends() {
            if Arc::ptr_eq(&backend, &local) {
                continue;
            }
            if let Err(e) = backend.discard(branch).await {
                warn!(backend = %backend.profile().name, error = %e,
                      "backend branch cleanup failed");
                if first_error.is_none() {
                    first_error = Some(e);
                }
            }
        }
        if let Some(error) = first_error {
            return Err(error);
        }
        local.discard(branch).await?;
        self.dag.discard_branch(branch)?;
        self.forget_branch_gate(branch);
        Ok(())
    }

    // ---------------------------------------------------------- capabilities

    /// Request a capability: deterministic policy evaluation; on `Allow` the
    /// compiled lease is issued and returned; `RequireApproval` and `Deny`
    /// surface as [`KernelError::Denied`] (approval-required denials carry
    /// [`DenialCode::EffectRequiresApproval`]).
    #[instrument(skip(self, params))]
    pub fn request_capability(
        &self,
        principal: &PrincipalId,
        operation: &Operation,
        params: &serde_json::Value,
        branch: Option<&BranchId>,
    ) -> KernelResult<CapabilityLease> {
        let who = self.registry().get(principal).map_err(KernelError::from)?;
        let decision = self
            .policy_read()?
            .evaluate(&who, operation, params, branch, Utc::now());
        match decision {
            Decision::Allow { rule_id, grant } => {
                self.leases().issue(&grant.lease).map_err(KernelError::from)?;
                if let Some(br) = branch {
                    let episode = self.dag.get_branch(br)?.episode;
                    let w = self.ledger.writer(episode, Some(br.clone()), None, principal.clone());
                    let req = w.record(
                        EventKind::CapabilityRequest,
                        serde_json::json!({ "operation": operation, "params": params }),
                    )?;
                    w.record_caused_by(
                        EventKind::PolicyDecision,
                        serde_json::json!({
                            "decision": "allow", "rule_id": rule_id, "lease": grant.lease.id
                        }),
                        vec![req.seq],
                    )?;
                }
                Ok(grant.lease)
            }
            Decision::RequireApproval { rule_id, operation, constraints, policy_epoch } => {
                Err(KernelError::Denied(Box::new(Denial {
                    code: DenialCode::EffectRequiresApproval,
                    attempted_operation: operation.clone(),
                    reason: format!(
                        "rule `{rule_id}` requires out-of-band approval (policy epoch {policy_epoch}); \
                         approved constraint sketch: {constraints}"
                    ),
                    safe_alternatives: Vec::new(),
                    requestable_scopes: vec![RequestableScope {
                        operation: operation.clone(),
                        constraints: constraints.clone(),
                        requires_human: true,
                    }],
                    escalation_allowed: true,
                })))
            }
            Decision::Deny { denial } => Err(KernelError::Denied(Box::new(denial))),
        }
    }

    /// Compile an **autonomy envelope**: request every capability a task
    /// needs in one call, before the first step.
    ///
    /// Items are evaluated independently. Policy-allowed items mint leases
    /// immediately — the same leases [`Kernel::execute_step_auto`] resolves,
    /// so the task then runs with zero per-step authorization ceremony.
    /// Items requiring out-of-band approval or refused outright come back
    /// as structured denials with their requestable scopes. The result is
    /// explicit *partial* autonomy: the agent knows exactly which subset of
    /// its plan it holds, instead of discovering scope gaps one denial at a
    /// time, mid-task.
    ///
    /// Infrastructure failures (unknown principal, storage errors) fail the
    /// whole call; policy outcomes never do.
    pub fn compile_envelope(
        &self,
        principal: &PrincipalId,
        branch: Option<&BranchId>,
        requests: &[EnvelopeRequest],
    ) -> KernelResult<EnvelopeReport> {
        if requests.is_empty() {
            return Err(KernelError::Other(
                "an autonomy envelope needs at least one capability request".into(),
            ));
        }
        if requests.len() > MAX_ENVELOPE_ITEMS {
            return Err(KernelError::Other(format!(
                "envelope has {} requests; the maximum is {MAX_ENVELOPE_ITEMS}",
                requests.len()
            )));
        }
        let mut items = Vec::with_capacity(requests.len());
        let (mut granted, mut needs_human, mut refused) = (0usize, 0usize, 0usize);
        for req in requests {
            let operation = Operation::new(&req.operation);
            let params = if req.params.is_null() {
                serde_json::json!({})
            } else {
                req.params.clone()
            };
            match self.request_capability(principal, &operation, &params, branch) {
                Ok(lease) => {
                    granted += 1;
                    items.push(EnvelopeItemReport {
                        operation: req.operation.clone(),
                        lease: Some(lease),
                        denial: None,
                    });
                }
                Err(KernelError::Denied(denial)) => {
                    if denial.requestable_scopes.iter().any(|s| s.requires_human) {
                        needs_human += 1;
                    } else {
                        refused += 1;
                    }
                    items.push(EnvelopeItemReport {
                        operation: req.operation.clone(),
                        lease: None,
                        denial: Some(*denial),
                    });
                }
                Err(other) => return Err(other),
            }
        }
        Ok(EnvelopeReport {
            items,
            granted,
            needs_human,
            refused,
        })
    }

    /// Delegate (attenuate) a lease from `delegator` to `delegatee`.
    #[allow(clippy::too_many_arguments)]
    pub fn delegate(
        &self,
        delegator: &PrincipalId,
        parent_lease: &LeaseId,
        delegatee: &PrincipalId,
        constraints: IndexMap<String, Constraint>,
        uses: u32,
        expires_at: chrono::DateTime<Utc>,
        budget: ResourceBudget,
    ) -> KernelResult<CapabilityLease> {
        self.delegation
            .delegate(
                delegator,
                parent_lease,
                delegatee,
                constraints,
                uses,
                expires_at,
                budget,
                Utc::now(),
            )
            .map_err(KernelError::from)
    }

    /// Revoke a lease and everything transitively attenuated from it.
    pub fn revoke(&self, lease: &LeaseId) -> KernelResult<Vec<LeaseId>> {
        self.leases()
            .revoke_cascading(lease)
            .map_err(KernelError::from)
    }

    // ------------------------------------------------------------ execution

    /// Execute one step on `branch` as `principal`.
    ///
    /// Pipeline: lease check (fail → machine-readable denial + `DenialIssued`
    /// ledger event) → deterministic policy evaluation (compiled confinement)
    /// → lease use consumed → route to a backend via the scheduler →
    /// workspace snapshot appended to the state DAG → full causal chain in
    /// the ledger (`ToolInvocation` → `StateDeltaRecorded` →
    /// `ObservationEmitted`) with the raw output blob in the ledger raw
    /// store. `ConnectorOp` actions never execute inline: they become
    /// broker proposals and return [`Observation::EffectPending`].
    #[instrument(skip(self, action), fields(principal = %principal, branch = %branch))]
    pub async fn execute_step(
        &self,
        principal: &PrincipalId,
        branch: &BranchId,
        action: Action,
    ) -> KernelResult<StepResult> {
        let _branch_guard = self.lock_branch(branch).await?;
        let step = StepId::generate();
        let b = self.active_branch(branch)?;
        let who = self.registry().get(principal).map_err(KernelError::from)?;
        let writer = self.ledger.writer(
            b.episode.clone(),
            Some(branch.clone()),
            Some(step.clone()),
            principal.clone(),
        );
        let now = Utc::now();
        let operation = action.kind.required_operation();
        let params = action.kind.params();

        // ---- lease check ----------------------------------------------
        let lease = match self.leases().get(&action.lease) {
            Ok(l) => l,
            Err(e) => {
                let denial = Denial {
                    code: DenialCode::CapabilityDenied,
                    attempted_operation: operation.clone(),
                    reason: format!(
                        "lease `{}` is unknown: {e}. Recover by requesting a fresh lease for \
                         this operation via capability.request (POST /v1/capabilities/request), \
                         or use steps/execute_auto to have the kernel resolve leases for you",
                        action.lease
                    ),
                    safe_alternatives: Vec::new(),
                    requestable_scopes: vec![scope_sketch(&operation, &params, false)],
                    escalation_allowed: true,
                };
                return self.deny_step(&writer, &b, step, &who, denial);
            }
        };
        if let Err(failure) = lease.check(principal, &operation, &params, Some(branch), now) {
            let denial = denial_from_lease_failure(&operation, &params, &failure);
            return self.deny_step(&writer, &b, step, &who, denial);
        }

        // ---- the action budget must fit inside the lease's envelope -------
        // (AK-005: a client must not out-spend the budget its lease grants.)
        if !action.budget.fits_within(&lease.budget) {
            let over = action.budget.exceeding_dimensions(&lease.budget);
            let denial = Denial {
                code: DenialCode::BudgetExhausted,
                attempted_operation: operation.clone(),
                reason: format!(
                    "the action budget exceeds the lease budget envelope in: {}. Recover by \
                     lowering the action budget to fit the lease, or request a lease with a \
                     larger envelope",
                    over.join(", ")
                ),
                safe_alternatives: Vec::new(),
                requestable_scopes: vec![RequestableScope {
                    operation: operation.clone(),
                    constraints: serde_json::json!({
                        "params": params,
                        "budget": action.budget,
                    }),
                    requires_human: false,
                }],
                escalation_allowed: true,
            };
            return self.deny_step(&writer, &b, step, &who, denial);
        }

        // ---- deterministic policy evaluation ---------------------------
        let confinement = {
            let decision =
                self.policy_read()?
                    .evaluate(&who, &operation, &params, Some(branch), now);
            match decision {
                Decision::Allow { grant, .. } => grant.confinement,
                Decision::RequireApproval { rule_id, .. } => {
                    let denial = Denial {
                        code: DenialCode::EffectRequiresApproval,
                        attempted_operation: operation.clone(),
                        reason: format!(
                            "rule `{rule_id}` requires out-of-band approval; a human (or an \
                             approver-role principal) must grant this scope before it can run"
                        ),
                        safe_alternatives: Vec::new(),
                        requestable_scopes: vec![scope_sketch(&operation, &params, true)],
                        escalation_allowed: true,
                    };
                    return self.deny_step(&writer, &b, step, &who, denial);
                }
                Decision::Deny { denial } => {
                    return self.deny_step(&writer, &b, step, &who, denial)
                }
            }
        };

        // ---- consume the lease use --------------------------------------
        // Atomic conditional decrement: when steps race for the last use,
        // exactly one wins and the rest get a machine-readable denial here
        // (AK-004).
        if let Err(e) = self.leases().consume_use(&action.lease, now) {
            let denial = denial_from_consume_failure(&operation, &params, &e);
            return self.deny_step(&writer, &b, step, &who, denial);
        }

        match &action.kind {
            ActionKind::ConnectorOp {
                connector,
                operation: op,
                params: op_params,
            } => {
                self.propose_connector_op(
                    &writer, &b, branch, step, principal, &action, connector, op, op_params,
                )
                .await
            }
            ActionKind::HttpRead { url } => {
                self.execute_http_read(
                    &writer,
                    &b,
                    branch,
                    step,
                    principal,
                    &action,
                    url,
                    &confinement.egress_domains,
                )
                .await
            }
            ActionKind::McpInvoke {
                server,
                tool,
                arguments,
            } => {
                self.execute_mcp_invoke(
                    &writer, &b, branch, step, principal, &action, server, tool, arguments,
                )
                .await
            }
            ActionKind::TraceQuery { query } => {
                let q = parse_trace_query(b.episode.clone(), query);
                let events = self.trace_query(&q)?;
                let raw = serde_json::to_vec(&events)?;
                let full = self.ledger.store_raw(&raw)?;
                let obs = Observation::Success {
                    summary: format!("trace query `{query}` returned {} events", events.len()),
                    data: Some(serde_json::json!({
                        "count": events.len(),
                        "applied": {
                            "kinds": q.kinds,
                            "branch": q.branch,
                            "step": q.step,
                            "principal": q.principal,
                            "limit": q.limit,
                        },
                    })),
                    stdout_head: None,
                    stdout_tail: None,
                    exit_code: 0,
                    full_output: full,
                    truncated: false,
                };
                self.finish_metadata_step(&writer, &b, branch, step, principal, &action, obs)
            }
            ActionKind::BranchDiff { since } => {
                let changes = self.branch_diff(branch, Some(since))?;
                let raw = serde_json::to_vec(&changes)?;
                let full = self.ledger.store_raw(&raw)?;
                let obs = Observation::Success {
                    summary: format!("{} file(s) changed since {since}", changes.len()),
                    data: Some(serde_json::to_value(&changes)?),
                    stdout_head: None,
                    stdout_tail: None,
                    exit_code: 0,
                    full_output: full,
                    truncated: false,
                };
                self.finish_metadata_step(&writer, &b, branch, step, principal, &action, obs)
            }
            _ => {
                self.execute_local(&writer, &b, branch, step, principal, action, confinement)
                    .await
            }
        }
    }

    /// Execute a step with **automatic lease resolution** (`steps/execute_auto`
    /// in the protocol): the kernel finds the narrowest active lease that
    /// authorizes the action on this branch, or mints one through the policy
    /// engine, and picks a step budget clamped inside the lease envelope.
    ///
    /// Lease bookkeeping is deterministic control-plane work; making the
    /// model do it wastes reasoning tokens and invites avoidable denials.
    pub async fn execute_step_auto(
        &self,
        principal: &PrincipalId,
        branch: &BranchId,
        kind: ActionKind,
        intent_hint: Option<String>,
        budget: Option<ResourceBudget>,
    ) -> KernelResult<AutoStepResult> {
        let operation = kind.required_operation();
        let params = kind.params();
        let now = Utc::now();
        // Prefer branch-bound leases over unbound ones, then the one
        // expiring soonest (spend narrow authority before broad authority).
        let mut chosen: Option<CapabilityLease> = None;
        for lease in self
            .leases()
            .active_for_principal(principal, now)
            .map_err(KernelError::from)?
        {
            if lease
                .check(principal, &operation, &params, Some(branch), now)
                .is_err()
            {
                continue;
            }
            let better = match &chosen {
                None => true,
                Some(current) => {
                    let bound = |l: &CapabilityLease| l.bound_branch.is_some();
                    (bound(&lease), std::cmp::Reverse(lease.expires_at))
                        > (bound(current), std::cmp::Reverse(current.expires_at))
                }
            };
            if better {
                chosen = Some(lease);
            }
        }
        let (lease, lease_minted) = match chosen {
            Some(l) => (l, false),
            // No usable lease: ask the policy engine. A policy denial (or
            // approval requirement) propagates as the structured denial —
            // which now carries the requestable scope.
            None => (
                self.request_capability(principal, &operation, &params, Some(branch))?,
                true,
            ),
        };
        let budget = budget
            .unwrap_or_else(ResourceBudget::step_default)
            .clamped_to(&lease.budget);
        let result = self
            .execute_step(
                principal,
                branch,
                Action {
                    kind,
                    lease: lease.id.clone(),
                    intent_hint,
                    budget,
                },
            )
            .await?;
        Ok(AutoStepResult {
            result,
            lease: lease.id,
            lease_minted,
        })
    }

    /// Server-side parallel branch exploration (`branches/{id}/explore`).
    ///
    /// Forks one branch per candidate, executes each candidate's actions
    /// (with automatic lease resolution) under a parallelism cap, runs the
    /// optional evaluator, and reports which candidates passed. With
    /// `early_stop`, later candidates are skipped once a winner passed; with
    /// `merge_winner`, the first passing candidate is merged back into the
    /// source branch; with `discard_losers`, non-winning branches are torn
    /// down. The agent supplies candidates and the success criterion; the
    /// kernel does the fork/lease/collect/merge bookkeeping.
    pub async fn explore(
        self: &Arc<Self>,
        principal: &PrincipalId,
        source: &BranchId,
        options: ExploreOptions,
    ) -> KernelResult<ExploreReport> {
        if options.candidates.is_empty() {
            return Err(KernelError::Other(
                "explore requires at least one candidate".into(),
            ));
        }
        if options.candidates.len() > MAX_EXPLORE_CANDIDATES {
            return Err(KernelError::Other(format!(
                "explore accepts at most {MAX_EXPLORE_CANDIDATES} candidates per call"
            )));
        }
        let max_parallel = options
            .max_parallel
            .unwrap_or(4)
            .clamp(1, self.config.max_concurrent_branches.max(1));
        let semaphore = Arc::new(tokio::sync::Semaphore::new(max_parallel));
        let won = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut handles = Vec::new();
        for (index, candidate) in options.candidates.iter().cloned().enumerate() {
            let kernel = Arc::clone(self);
            let principal = principal.clone();
            let source = source.clone();
            let evaluator = options.evaluator.clone();
            let step_budget = options.step_budget;
            let early_stop = options.early_stop;
            let semaphore = Arc::clone(&semaphore);
            let won = Arc::clone(&won);
            handles.push(tokio::spawn(async move {
                use std::sync::atomic::Ordering;
                let _permit = semaphore.acquire_owned().await;
                let mut report = ExploreCandidateReport {
                    index,
                    name: candidate.name.clone(),
                    branch: None,
                    steps: Vec::new(),
                    evaluation: None,
                    passed: false,
                    skipped: false,
                    error: None,
                };
                if early_stop && won.load(Ordering::SeqCst) {
                    report.skipped = true;
                    return report;
                }
                let branch = match kernel.fork_branch(&source).await {
                    Ok(b) => b,
                    Err(e) => {
                        report.error = Some(format!("fork failed: {e}"));
                        return report;
                    }
                };
                report.branch = Some(branch.id.clone());
                let mut all_ok = true;
                for kind in candidate.actions {
                    if early_stop && won.load(Ordering::SeqCst) {
                        report.skipped = true;
                        all_ok = false;
                        break;
                    }
                    match kernel
                        .execute_step_auto(
                            &principal,
                            &branch.id,
                            kind,
                            Some(format!("explore candidate {index}")),
                            step_budget,
                        )
                        .await
                    {
                        Ok(auto) => {
                            let ok = matches!(
                                auto.result.observation,
                                Observation::Success { .. } | Observation::EffectPending { .. }
                            );
                            report.steps.push(auto.result);
                            if !ok {
                                all_ok = false;
                                break;
                            }
                        }
                        Err(e) => {
                            report.error = Some(format!("step failed: {e}"));
                            all_ok = false;
                            break;
                        }
                    }
                }
                if all_ok {
                    match evaluator {
                        Some(eval_kind) => {
                            match kernel
                                .execute_step_auto(
                                    &principal,
                                    &branch.id,
                                    eval_kind,
                                    Some(format!("explore evaluator {index}")),
                                    step_budget,
                                )
                                .await
                            {
                                Ok(auto) => {
                                    report.passed = matches!(
                                        auto.result.observation,
                                        Observation::Success { exit_code: 0, .. }
                                    );
                                    report.evaluation = Some(auto.result);
                                }
                                Err(e) => {
                                    report.error = Some(format!("evaluator failed: {e}"));
                                }
                            }
                        }
                        None => report.passed = true,
                    }
                }
                if report.passed {
                    won.store(true, Ordering::SeqCst);
                }
                report
            }));
        }
        let mut candidates = Vec::with_capacity(handles.len());
        for handle in handles {
            match handle.await {
                Ok(report) => candidates.push(report),
                Err(e) => {
                    return Err(KernelError::Other(format!(
                        "explore candidate task panicked: {e}"
                    )))
                }
            }
        }
        candidates.sort_by_key(|c| c.index);
        // Winner: the passing candidate with the lowest index (deterministic
        // regardless of completion order).
        let winner = candidates.iter().find(|c| c.passed).map(|c| c.index);
        let mut merged_state = None;
        let mut merge_error = None;
        if let (true, Some(w)) = (options.merge_winner, winner) {
            if let Some(branch) = candidates[w].branch.clone() {
                match self.merge_branch(source, &branch, principal).await {
                    Ok(node) => merged_state = Some(node.id),
                    Err(e) => merge_error = Some(e.to_string()),
                }
            }
        }
        let mut discarded = Vec::new();
        if options.discard_losers {
            for c in &candidates {
                if Some(c.index) == winner {
                    continue;
                }
                if let Some(branch) = &c.branch {
                    if self.discard_branch(branch).await.is_ok() {
                        discarded.push(branch.clone());
                    }
                }
            }
        }
        Ok(ExploreReport {
            source: source.clone(),
            winner,
            merged_state,
            merge_error,
            candidates,
            discarded,
        })
    }

    /// Record a denial as a full step: `DenialIssued` + `ObservationEmitted`.
    fn deny_step(
        &self,
        writer: &ak_causal_ledger::EventWriter,
        branch: &Branch,
        step: StepId,
        who: &Principal,
        denial: Denial,
    ) -> KernelResult<StepResult> {
        let denial = denial.redact_for(who.trust);
        warn!(code = ?denial.code, "step denied");
        let ev = writer.record(EventKind::DenialIssued, serde_json::to_value(&denial)?)?;
        writer.record_caused_by(
            EventKind::ObservationEmitted,
            serde_json::json!({ "kind": "denied", "code": denial.code }),
            vec![ev.seq],
        )?;
        Ok(StepResult {
            step,
            state: branch.head.clone(),
            observation: Observation::Denied { denial },
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn propose_connector_op(
        &self,
        writer: &ak_causal_ledger::EventWriter,
        b: &Branch,
        branch: &BranchId,
        step: StepId,
        principal: &PrincipalId,
        action: &Action,
        connector: &str,
        op: &str,
        op_params: &serde_json::Value,
    ) -> KernelResult<StepResult> {
        let full_op = format!("{connector}.{op}");
        let resource = op_params
            .get("resource")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .unwrap_or_else(|| {
                match (
                    op_params.get("owner").and_then(|v| v.as_str()),
                    op_params.get("repo").and_then(|v| v.as_str()),
                ) {
                    (Some(o), Some(r)) => format!("{o}/{r}"),
                    _ => connector.to_string(),
                }
            });
        let mut arguments = op_params.clone();
        if let Some(obj) = arguments.as_object_mut() {
            obj.remove("resource");
            obj.remove("preconditions");
        }
        // Per-invocation classification happens BEFORE the contract is
        // created: an allowlisted read must carry `Pure` in its contract, not
        // the operation's worst-case class (which would force human approval
        // onto plain observation).
        let class = match self.connector(connector)? {
            Some(c) => c.classify_operation(&full_op, &arguments),
            None => self.effect_class_of(&full_op)?,
        };
        let contract = EffectContract {
            operation: full_op,
            resource,
            arguments,
            preconditions: op_params
                .get("preconditions")
                .cloned()
                .unwrap_or(serde_json::json!({})),
            idempotency_key: format!("{}-{}", b.episode, step),
            class,
        };
        let effect = self.broker.propose(
            contract,
            principal.clone(),
            branch.clone(),
            step.clone(),
            action.lease.clone(),
        )?;
        let tool = writer.record(
            EventKind::ToolInvocation,
            serde_json::json!({
                "action": action.kind, "intent_hint": action.intent_hint,
                "lease": action.lease, "budget": action.budget,
            }),
        )?;
        let proposed = writer.record_caused_by(
            EventKind::EffectProposed,
            serde_json::json!({
                "effect_id": effect.id, "contract_hash": effect.contract_hash,
                "class": effect.contract.class,
            }),
            vec![tool.seq],
        )?;
        // Record the proposal in the state DAG (no workspace change).
        let head = self.dag.head(branch)?;
        let delta = StateDelta {
            effects_proposed: vec![effect.id.clone()],
            policy_epoch: head.delta.policy_epoch,
            ..StateDelta::default()
        };
        let node = self.dag.append_step(
            branch,
            &step,
            principal,
            delta,
            head.workspace_root.clone(),
            head.replay_class,
        )?;
        let delta_ev = writer.record_caused_by(
            EventKind::StateDeltaRecorded,
            serde_json::json!({ "state_id": node.id, "delta": node.delta }),
            vec![proposed.seq],
        )?;
        let observation = Observation::EffectPending {
            effect: effect.id.clone(),
            contract_hash: effect.contract_hash.clone(),
            class: effect.contract.class,
        };
        writer.record_caused_by(
            EventKind::ObservationEmitted,
            serde_json::to_value(&observation)?,
            vec![delta_ev.seq],
        )?;
        Ok(StepResult {
            step,
            state: node.id,
            observation,
        })
    }

    /// Deny helper for connector-plane paths (already past lease
    /// consumption): records the denial as a step.
    fn deny_connector_step(
        &self,
        writer: &ak_causal_ledger::EventWriter,
        b: &Branch,
        step: StepId,
        principal: &PrincipalId,
        denial: Denial,
    ) -> KernelResult<StepResult> {
        let who = self.registry().get(principal).map_err(KernelError::from)?;
        self.deny_step(writer, b, step, &who, denial)
    }

    /// `HttpRead` on the main execution path.
    ///
    /// Observation/effect plane split: a guard-passing, allowlisted GET is
    /// `Pure` and executes **inline** (low-latency observation, full body in
    /// the raw store); anything else becomes a proposed `http.get` effect
    /// and returns [`Observation::EffectPending`] for the transactional
    /// path. Requires a registered `http` connector.
    #[allow(clippy::too_many_arguments)]
    async fn execute_http_read(
        &self,
        writer: &ak_causal_ledger::EventWriter,
        b: &Branch,
        branch: &BranchId,
        step: StepId,
        principal: &PrincipalId,
        action: &Action,
        url: &str,
        egress_domains: &[String],
    ) -> KernelResult<StepResult> {
        let operation = Operation::new("net.http_read");
        let Some(connector) = self.connector("http")? else {
            let denial = Denial {
                code: DenialCode::BackendUnavailable,
                attempted_operation: operation,
                reason: "no `http` connector is registered with this kernel; configure \
                         `http` in KernelConfig (or register an HttpConnector) to enable \
                         the observation plane"
                    .into(),
                safe_alternatives: Vec::new(),
                requestable_scopes: Vec::new(),
                escalation_allowed: false,
            };
            return self.deny_connector_step(writer, b, step, principal, denial);
        };
        // Canonicalize runs the full SSRF guard set.
        let canon = match connector.canonicalize("http.get", &serde_json::json!({ "url": url })) {
            Ok(c) => c,
            Err(e) => {
                let denial = Denial {
                    code: DenialCode::ConstraintViolated,
                    attempted_operation: operation,
                    reason: format!("url refused: {e}"),
                    safe_alternatives: Vec::new(),
                    requestable_scopes: Vec::new(),
                    escalation_allowed: false,
                };
                return self.deny_connector_step(writer, b, step, principal, denial);
            }
        };
        let canon_url = canon
            .get("url")
            .and_then(|v| v.as_str())
            .unwrap_or(url)
            .to_string();
        let host = host_of(&canon_url).unwrap_or_default();
        // Compiled egress confinement is enforced at the kernel boundary:
        // empty means no network for this grant.
        if !egress_domains.iter().any(|g| glob_match(g, &host)) {
            let denial = Denial {
                code: DenialCode::PolicyForbidden,
                attempted_operation: operation,
                reason: format!(
                    "host `{host}` is not covered by this grant's egress domains; request \
                     net.http_read scoped to the domain, or ask an operator to extend the \
                     policy egress allowlist"
                ),
                safe_alternatives: Vec::new(),
                requestable_scopes: vec![RequestableScope {
                    operation: Operation::new("net.http_read"),
                    constraints: serde_json::json!({ "domain": host }),
                    requires_human: false,
                }],
                escalation_allowed: true,
            };
            return self.deny_connector_step(writer, b, step, principal, denial);
        }
        let class = connector.classify_operation("http.get", &canon);
        if class == EffectClass::Pure {
            self.execute_read_via_connector(
                writer, b, branch, step, principal, action, connector, "http.get", host, canon,
            )
            .await
        } else {
            // Not read-safe: route through the transactional effect plane.
            let mut params = canon;
            if let Some(obj) = params.as_object_mut() {
                obj.insert("resource".into(), serde_json::json!(host));
            }
            self.propose_connector_op(
                writer, b, branch, step, principal, action, "http", "get", &params,
            )
            .await
        }
    }

    /// `McpInvoke` on the main execution path: manifest-vouched `Pure` tools
    /// execute inline on the observation plane; everything else becomes a
    /// proposed effect requiring the transactional path.
    #[allow(clippy::too_many_arguments)]
    async fn execute_mcp_invoke(
        &self,
        writer: &ak_causal_ledger::EventWriter,
        b: &Branch,
        branch: &BranchId,
        step: StepId,
        principal: &PrincipalId,
        action: &Action,
        server: &str,
        tool: &str,
        arguments: &serde_json::Value,
    ) -> KernelResult<StepResult> {
        let operation = Operation::new("mcp.invoke");
        let Some(connector) = self.connector(server)? else {
            let known = self.connector_names()?.join(", ");
            let denial = Denial {
                code: DenialCode::BackendUnavailable,
                attempted_operation: operation,
                reason: format!(
                    "no MCP server `{server}` is registered with this kernel (registered \
                     connectors: [{known}])"
                ),
                safe_alternatives: Vec::new(),
                requestable_scopes: Vec::new(),
                escalation_allowed: false,
            };
            return self.deny_connector_step(writer, b, step, principal, denial);
        };
        let full_op = format!("{server}.{tool}");
        let canon = match connector.canonicalize(&full_op, arguments) {
            Ok(c) => c,
            Err(e) => {
                let denial = Denial {
                    code: DenialCode::ConstraintViolated,
                    attempted_operation: operation,
                    reason: format!("arguments refused by the `{server}` manifest: {e}"),
                    safe_alternatives: Vec::new(),
                    requestable_scopes: Vec::new(),
                    escalation_allowed: false,
                };
                return self.deny_connector_step(writer, b, step, principal, denial);
            }
        };
        let class = connector.classify_operation(&full_op, &canon);
        if class == EffectClass::Pure {
            self.execute_read_via_connector(
                writer,
                b,
                branch,
                step,
                principal,
                action,
                connector,
                &full_op,
                server.to_string(),
                canon,
            )
            .await
        } else {
            self.propose_connector_op(
                writer, b, branch, step, principal, action, server, tool, &canon,
            )
            .await
        }
    }

    /// Inline observation-plane read through a connector: the operation was
    /// classified `Pure` for these exact arguments, so it commits directly —
    /// no proposal, no approval, no receipt. The full response body goes to
    /// the raw store; the observation carries head+tail and metadata.
    #[allow(clippy::too_many_arguments)]
    async fn execute_read_via_connector(
        &self,
        writer: &ak_causal_ledger::EventWriter,
        b: &Branch,
        branch: &BranchId,
        step: StepId,
        principal: &PrincipalId,
        action: &Action,
        connector: Arc<dyn Connector>,
        full_op: &str,
        resource: String,
        arguments: serde_json::Value,
    ) -> KernelResult<StepResult> {
        let contract = EffectContract {
            operation: full_op.to_string(),
            resource,
            arguments,
            preconditions: serde_json::json!({}),
            idempotency_key: format!("{}-{}-read", b.episode, step),
            class: EffectClass::Pure,
        };
        let tool = writer.record(
            EventKind::ToolInvocation,
            serde_json::json!({
                "action": action.kind, "intent_hint": action.intent_hint,
                "lease": action.lease, "budget": action.budget,
                "plane": "observation",
            }),
        )?;
        let started = std::time::Instant::now();
        let outcome = connector.commit(&contract).await;
        let elapsed_ms = started.elapsed().as_millis() as u64;
        let observation = match outcome {
            Ok(result) => {
                let (raw, data) = shape_read_response(&result.response);
                let full_output = self.ledger.store_raw(&raw)?;
                let d = distill_output(&raw, 2048, 1024);
                Observation::Success {
                    summary: format!("{full_op} returned {} bytes in {elapsed_ms} ms", raw.len()),
                    data,
                    stdout_head: d.head,
                    stdout_tail: d.tail,
                    exit_code: 0,
                    full_output,
                    truncated: d.truncated,
                }
            }
            Err(e) => {
                // Network/tool failures are normal agent-visible outcomes,
                // not kernel errors: return a Failure observation the agent
                // can react to (retry, different URL, …).
                let msg = e.to_string();
                let full_output = self.ledger.store_raw(msg.as_bytes())?;
                Observation::Failure {
                    summary: format!("{full_op} failed"),
                    exit_code: 1,
                    first_causal_failure: Some(msg.chars().take(400).collect()),
                    output_tail: None,
                    full_output,
                }
            }
        };
        let head = self.dag.head(branch)?;
        let node = self.dag.append_step(
            branch,
            &step,
            principal,
            StateDelta {
                tool_sessions: vec![full_op.to_string()],
                policy_epoch: head.delta.policy_epoch,
                ..StateDelta::default()
            },
            head.workspace_root.clone(),
            head.replay_class,
        )?;
        let delta_ev = writer.record_caused_by(
            EventKind::StateDeltaRecorded,
            serde_json::json!({ "state_id": node.id, "delta": node.delta }),
            vec![tool.seq],
        )?;
        writer.record_caused_by(
            EventKind::ObservationEmitted,
            serde_json::to_value(&observation)?,
            vec![delta_ev.seq],
        )?;
        Ok(StepResult {
            step,
            state: node.id,
            observation,
        })
    }

    /// Finish a metadata-only step (trace query / branch diff): appends a
    /// no-change state node and the causal chain.
    #[allow(clippy::too_many_arguments)]
    fn finish_metadata_step(
        &self,
        writer: &ak_causal_ledger::EventWriter,
        _b: &Branch,
        branch: &BranchId,
        step: StepId,
        principal: &PrincipalId,
        action: &Action,
        observation: Observation,
    ) -> KernelResult<StepResult> {
        let head = self.dag.head(branch)?;
        let tool = writer.record(
            EventKind::ToolInvocation,
            serde_json::json!({
                "action": action.kind, "lease": action.lease, "budget": action.budget,
            }),
        )?;
        let node = self.dag.append_step(
            branch,
            &step,
            principal,
            StateDelta {
                policy_epoch: head.delta.policy_epoch,
                ..StateDelta::default()
            },
            head.workspace_root.clone(),
            head.replay_class,
        )?;
        let delta_ev = writer.record_caused_by(
            EventKind::StateDeltaRecorded,
            serde_json::json!({ "state_id": node.id, "delta": node.delta }),
            vec![tool.seq],
        )?;
        writer.record_caused_by(
            EventKind::ObservationEmitted,
            serde_json::to_value(&observation)?,
            vec![delta_ev.seq],
        )?;
        Ok(StepResult {
            step,
            state: node.id,
            observation,
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn execute_local(
        &self,
        writer: &ak_causal_ledger::EventWriter,
        b: &Branch,
        branch: &BranchId,
        step: StepId,
        principal: &PrincipalId,
        action: Action,
        confinement: CompiledConfinement,
    ) -> KernelResult<StepResult> {
        // Ensure the branch workspace reflects the branch head.
        let base_state = b.head.clone();
        // Policy decides the isolation floor; the action decides the
        // compatibility needs. Neither is influenced by agent hints.
        let risk = risk_tier_of(confinement.risk_weight);
        let needs = needs_of(&action.kind);
        // Kept for validating a state-synced excursion's returned delta
        // against exactly what this step was allowed to write.
        let writable_prefixes = confinement.writable_prefixes.clone();
        let req = ExecutionRequest {
            branch: branch.clone(),
            base_state: base_state.clone(),
            actor: principal.clone(),
            action: action.kind.clone(),
            budget: action.budget,
            writable_prefixes: confinement.writable_prefixes,
            readable_prefixes: confinement.readable_prefixes,
            egress_domains: confinement.egress_domains,
        };
        let tool = writer.record(
            EventKind::ToolInvocation,
            serde_json::json!({
                "action": action.kind, "intent_hint": action.intent_hint,
                "lease": action.lease, "budget": action.budget,
            }),
        )?;
        let routed = match self
            .scheduler
            .execute_step(&b.episode, step.clone(), req, risk, &needs)
            .await
        {
            Ok(o) => o,
            Err(KernelError::Denied(denial)) => {
                let who = self.registry().get(principal).map_err(KernelError::from)?;
                return self.deny_step(writer, b, step, &who, *denial);
            }
            // A routing failure is a *recorded* denial with a recovery path,
            // not a bare 500: the agent (or operator) can see exactly which
            // floor was unsatisfiable.
            Err(KernelError::BackendUnavailable { backend, reason }) if backend == "router" => {
                let who = self.registry().get(principal).map_err(KernelError::from)?;
                let denial = Denial {
                    code: DenialCode::BackendUnavailable,
                    attempted_operation: action.kind.required_operation(),
                    reason: format!(
                        "{reason}. The policy rule's risk_weight demands this isolation \
                         floor; register a stronger backend (KernelConfig.backends) or \
                         lower the rule's risk_weight"
                    ),
                    safe_alternatives: Vec::new(),
                    requestable_scopes: Vec::new(),
                    escalation_allowed: false,
                };
                return self.deny_step(writer, b, step, &who, denial);
            }
            Err(e) => return Err(e),
        };
        let outcome = routed.outcome;

        // The profile and outcome form a strict state-plane contract. A
        // backend may share the local tree, sync a remote tree, or do
        // neither (audit-only) — never more than one, and a syncing backend
        // must return `Some(delta)` even when the delta is empty.
        let contract_ok = matches!(
            (
                routed.backend.shares_workspace,
                routed.backend.syncs_state,
                outcome.workspace_delta.is_some(),
            ),
            (true, false, false) | (false, true, true) | (false, false, false)
        );
        if !contract_ok {
            if let Err(e) = routed.executor.discard(branch).await {
                warn!(backend = %routed.backend.name, error = %e,
                      "failed to discard branch after state-plane contract violation");
            }
            let who = self.registry().get(principal).map_err(KernelError::from)?;
            let denial = Denial {
                code: DenialCode::BackendUnavailable,
                attempted_operation: action.kind.required_operation(),
                reason: format!(
                    "backend `{}` violated its state-plane contract \
                     (shares_workspace={}, syncs_state={}, returned_delta={}); its branch \
                     resources were discarded and the branch head is unchanged",
                    routed.backend.name,
                    routed.backend.shares_workspace,
                    routed.backend.syncs_state,
                    outcome.workspace_delta.is_some(),
                ),
                safe_alternatives: Vec::new(),
                requestable_scopes: Vec::new(),
                escalation_allowed: false,
            };
            return self.deny_step(writer, b, step, &who, denial);
        }

        // Record the state transition honestly, in one of three ways:
        //
        // 1. a **workspace-sharing** backend's effects are snapshotted
        //    directly from the kernel tree;
        // 2. a **state-syncing** backend returns the delta it observed
        //    remotely; the kernel validates every path against this step's
        //    writable prefixes, applies it to the branch's local mirror
        //    (materialized at the base state first) and snapshots — a real
        //    state transition;
        // 3. any other backend leaves the local tree untouched and is
        //    recorded as exactly that: an audit-only node with an empty
        //    file delta.
        let node = if routed.backend.shares_workspace {
            let dir = self.backend.workspace_for(branch)?;
            self.dag
                .snapshot_and_append(branch, &step, principal, &dir, outcome.replay_class)?
        } else if routed.backend.syncs_state {
            let delta = outcome
                .workspace_delta
                .as_ref()
                .expect("state-plane contract checked above");
            if let Err(denial) =
                validate_workspace_delta(delta, &writable_prefixes, &routed.backend.name)
            {
                // The remote tree no longer matches any state the kernel
                // would vouch for: scrap the backend's branch resources so
                // the next step re-materializes from the (unchanged) head.
                if let Err(e) = routed.executor.discard(branch).await {
                    warn!(backend = %routed.backend.name, error = %e,
                          "failed to discard branch after rejected sync delta");
                }
                let who = self.registry().get(principal).map_err(KernelError::from)?;
                return self.deny_step(writer, b, step, &who, denial);
            }
            let dir = self.backend.workspace_for(branch)?;
            let transition = (|| {
                self.dag.materialize(&base_state, &dir)?;
                apply_workspace_delta(&dir, delta)?;
                self.dag
                    .snapshot_and_append(branch, &step, principal, &dir, outcome.replay_class)
            })();
            match transition {
                Ok(node) => node,
                Err(error) => {
                    // Applying a remote delta is transactional with respect
                    // to the local mirror: on any I/O/snapshot failure put
                    // the mirror back at the unchanged base and poison the
                    // remote tree whose post-state was not committed.
                    let rollback = self.dag.materialize(&base_state, &dir);
                    if let Err(e) = routed.executor.discard(branch).await {
                        warn!(backend = %routed.backend.name, error = %e,
                              "failed to discard branch after state-sync apply failure");
                    }
                    if let Err(rollback_error) = rollback {
                        return Err(KernelError::Storage(format!(
                            "state-sync apply failed ({error}); restoring the branch mirror to \
                             {base_state} also failed ({rollback_error})"
                        )));
                    }
                    return Err(error);
                }
            }
        } else {
            let head = self.dag.head(branch)?;
            self.dag.append_step(
                branch,
                &step,
                principal,
                StateDelta {
                    policy_epoch: head.delta.policy_epoch,
                    ..StateDelta::default()
                },
                head.workspace_root.clone(),
                ReplayClass::AuditOnly,
            )?
        };
        let delta_ev = writer.record_caused_by(
            EventKind::StateDeltaRecorded,
            serde_json::json!({ "state_id": node.id, "delta": node.delta }),
            vec![tool.seq],
        )?;

        // Distill the output; the full blob lives in the ledger raw store.
        let mut raw = outcome.stdout.clone();
        if !outcome.stderr.is_empty() {
            raw.extend_from_slice(b"\n--- stderr ---\n");
            raw.extend_from_slice(&outcome.stderr);
        }
        let full_output = self.ledger.store_raw(&raw)?;
        let d = distill_output(&raw, 2048, 1024);
        debug_assert_eq!(d.hash, ak_core::hash::hash_bytes(&raw));
        let observation = if outcome.exit_code == 0 {
            let via = if routed.backend.shares_workspace {
                String::new()
            } else if routed.backend.syncs_state {
                format!(" via `{}` (state-synced)", routed.backend.name)
            } else {
                format!(" via `{}` (audit-only excursion)", routed.backend.name)
            };
            Observation::Success {
                summary: format!(
                    "{} exited 0 ({} file(s) changed){via}",
                    action.kind.required_operation().0,
                    node.delta.files.len()
                ),
                data: None,
                stdout_head: d.head,
                stdout_tail: d.tail,
                exit_code: 0,
                full_output,
                truncated: d.truncated,
            }
        } else {
            // Root-cause scan prefers stderr; falls back to stdout (build
            // tools that print errors to stdout exist). The tail carries the
            // end of the combined stream — where summaries live.
            let causal = extract_causal_failure(&outcome.stderr)
                .or_else(|| extract_causal_failure(&outcome.stdout));
            let tail_start = raw.len().saturating_sub(1024);
            let output_tail =
                (!raw.is_empty()).then(|| String::from_utf8_lossy(&raw[tail_start..]).into_owned());
            Observation::Failure {
                summary: format!(
                    "{} exited {}",
                    action.kind.required_operation().0,
                    outcome.exit_code
                ),
                exit_code: outcome.exit_code,
                first_causal_failure: causal,
                output_tail,
                full_output,
            }
        };
        writer.record_caused_by(
            EventKind::ObservationEmitted,
            serde_json::to_value(&observation)?,
            vec![delta_ev.seq],
        )?;
        Ok(StepResult {
            step,
            state: node.id,
            observation,
        })
    }

    // -------------------------------------------------------------- effects

    fn effect_writer(&self, effect: &PendingEffect) -> KernelResult<ak_causal_ledger::EventWriter> {
        let episode = self.dag.get_branch(&effect.branch)?.episode;
        Ok(self.ledger.writer(
            episode,
            Some(effect.branch.clone()),
            Some(effect.step.clone()),
            effect.proposer.clone(),
        ))
    }

    /// Prepare (dry-run preview) a proposed effect.
    pub async fn prepare_effect(&self, effect: &EffectId) -> KernelResult<PreparedEffect> {
        let prepared = self.broker.prepare(effect).await?;
        let e = self.broker.effect(effect)?;
        self.effect_writer(&e)?.record(
            EventKind::EffectPrepared,
            serde_json::json!({ "effect_id": effect, "preview": prepared.preview }),
        )?;
        Ok(prepared)
    }

    /// Approve a prepared effect, pinning the current policy epoch.
    pub fn approve_effect(&self, effect: &EffectId, approver: &PrincipalId) -> KernelResult<()> {
        let epoch = self.policy_epoch()?;
        self.broker.approve(effect, approver.clone(), epoch)?;
        let e = self.broker.effect(effect)?;
        self.effect_writer(&e)?.record(
            EventKind::EffectApproved,
            serde_json::json!({ "effect_id": effect, "approver": approver, "policy_epoch": epoch }),
        )?;
        Ok(())
    }

    /// Commit an effect after full revalidation (contract hash, policy
    /// epoch, live lease, re-observed preconditions, exactly-once key claim).
    /// Receipts are Ed25519-signed with the kernel keypair.
    ///
    /// The receipt in the broker store is the durable record of the external
    /// effect. Ledger and DAG bookkeeping happen after it and are repairable:
    /// their failure is logged loudly but never invents a second commit.
    pub async fn commit_effect(&self, effect: &EffectId) -> KernelResult<Receipt> {
        let epoch = self.policy_epoch()?;
        let leases = self.leases();
        let now = Utc::now();
        let result = self
            .broker
            .commit(effect, epoch, |lease_id: &LeaseId| {
                leases
                    .get(lease_id)
                    .map(|l| !l.revoked && now < l.expires_at)
                    .unwrap_or(false)
            })
            .await;
        let e = self.broker.effect(effect)?;
        let writer = self.effect_writer(&e)?;
        match result {
            Ok(receipt) => {
                if let Err(err) = self
                    .ledger
                    .store_receipt(&receipt, &e.contract.idempotency_key)
                {
                    tracing::error!(
                        effect = %effect, receipt = %receipt.id, error = %err,
                        "receipt committed but ledger receipt store failed; \
                         the broker store remains authoritative"
                    );
                }
                writer.record(
                    EventKind::EffectCommitted,
                    serde_json::json!({
                        "effect_id": effect, "receipt_id": receipt.id,
                        "class": e.contract.class,
                    }),
                )?;
                // Record the committed effect in the state DAG.
                let head = self.dag.head(&e.branch)?;
                let commit_step = StepId::generate();
                if let Err(err) = self.dag.append_step(
                    &e.branch,
                    &commit_step,
                    &e.proposer,
                    StateDelta {
                        effects_committed: vec![receipt.id.clone()],
                        policy_epoch: head.delta.policy_epoch,
                        ..StateDelta::default()
                    },
                    head.workspace_root.clone(),
                    head.replay_class,
                ) {
                    tracing::error!(
                        effect = %effect, receipt = %receipt.id, error = %err,
                        "receipt committed but DAG bookkeeping failed; \
                         the ledger and broker store remain authoritative"
                    );
                }
                Ok(receipt)
            }
            Err(err @ KernelError::CommitInDoubt { .. }) => {
                // Not aborted: the external outcome is unknown. Record the
                // in-doubt marker so the trace shows why nothing may retry.
                writer.record(
                    EventKind::EffectAborted,
                    serde_json::json!({
                        "effect_id": effect, "in_doubt": true, "reason": err.to_string(),
                    }),
                )?;
                Err(err)
            }
            Err(err) => {
                writer.record(
                    EventKind::EffectAborted,
                    serde_json::json!({ "effect_id": effect, "reason": err.to_string() }),
                )?;
                Err(err)
            }
        }
    }

    /// Resolve effects left in doubt by a crash or indeterminate connector
    /// failure. Run at server startup and available on demand.
    pub async fn recover_in_doubt_effects(
        &self,
    ) -> KernelResult<Vec<(EffectId, ak_effect_broker::InDoubtResolution)>> {
        let resolutions = self.broker.recover_in_doubt().await?;
        for (effect, resolution) in &resolutions {
            if let Ok(e) = self.broker.effect(effect) {
                if let Ok(writer) = self.effect_writer(&e) {
                    let _ = writer.record(
                        EventKind::EffectCommitted,
                        serde_json::json!({
                            "effect_id": effect,
                            "recovery": true,
                            "resolution": resolution,
                        }),
                    );
                }
            }
            tracing::info!(effect = %effect, resolution = ?resolution, "in-doubt effect recovery");
        }
        Ok(resolutions)
    }

    /// Operator override for an in-doubt effect (out-of-band verified).
    pub fn resolve_in_doubt_effect(
        &self,
        effect: &EffectId,
        outcome: ak_effect_broker::OperatorResolution,
    ) -> KernelResult<Option<Receipt>> {
        let receipt = self.broker.resolve_in_doubt(effect, outcome)?;
        if let Some(r) = &receipt {
            if let Err(err) = self.ledger.store_receipt(r, &r.body.operation) {
                tracing::error!(receipt = %r.id, error = %err, "ledger receipt store failed");
            }
        }
        Ok(receipt)
    }

    /// Run the compensating action for a committed effect.
    pub async fn compensate_effect(&self, effect: &EffectId) -> KernelResult<Receipt> {
        let receipt = self.broker.compensate(effect).await?;
        let e = self.broker.effect(effect)?;
        self.effect_writer(&e)?.record(
            EventKind::EffectAborted,
            serde_json::json!({
                "effect_id": effect, "compensating_receipt": receipt.id, "compensated": true
            }),
        )?;
        Ok(receipt)
    }

    /// Fetch a pending effect.
    pub fn effect(&self, id: &EffectId) -> KernelResult<PendingEffect> {
        self.broker.effect(id)
    }

    /// List effects, newest first, optionally filtered by phase name.
    pub fn list_effects(&self, phase: Option<&str>) -> KernelResult<Vec<PendingEffect>> {
        self.broker.list_effects(phase)
    }

    /// Fetch a signed receipt.
    pub fn receipt(&self, id: &ReceiptId) -> KernelResult<Receipt> {
        self.broker.receipt(id)
    }

    /// Verify a receipt signature against the kernel public key.
    pub fn verify_receipt(&self, receipt: &Receipt) -> KernelResult<bool> {
        KernelKeypair::verify_canonical(
            &self.keypair.public_key(),
            &receipt.body,
            &receipt.signature,
        )
        .map_err(KernelError::from)
    }

    // ---------------------------------------------------------------- trace

    /// Query the causal ledger.
    pub fn trace_query(&self, q: &TraceQuery) -> KernelResult<Vec<LedgerEvent>> {
        self.ledger.query(q)
    }

    /// Explain a recorded step: decode its ledger events into the action,
    /// policy decisions, denial, state delta, observation and proposed
    /// effects (`step.explain` in the protocol).
    pub fn step_explain(&self, step: &StepId) -> KernelResult<StepExplanation> {
        let events = self.ledger.query(&TraceQuery {
            step: Some(step.clone()),
            ..TraceQuery::default()
        })?;
        let first = events.first().ok_or_else(|| KernelError::NotFound {
            kind: "step",
            id: step.to_string(),
        })?;
        let mut explanation = StepExplanation {
            step: step.clone(),
            episode: first.episode.clone(),
            branch: first.branch.clone(),
            principal: first.principal.clone(),
            action: None,
            policy_decisions: Vec::new(),
            denial: None,
            state: None,
            state_delta: None,
            observation: None,
            effects_proposed: Vec::new(),
            events: events.clone(),
        };
        for ev in &events {
            match ev.kind {
                EventKind::ToolInvocation => explanation.action = Some(ev.payload.clone()),
                EventKind::PolicyDecision | EventKind::CapabilityRequest => {
                    explanation.policy_decisions.push(ev.payload.clone())
                }
                EventKind::DenialIssued => {
                    explanation.denial = serde_json::from_value(ev.payload.clone()).ok()
                }
                EventKind::StateDeltaRecorded => {
                    explanation.state = ev
                        .payload
                        .get("state_id")
                        .cloned()
                        .and_then(|v| serde_json::from_value(v).ok());
                    explanation.state_delta = ev.payload.get("delta").cloned();
                }
                EventKind::ObservationEmitted => explanation.observation = Some(ev.payload.clone()),
                EventKind::EffectProposed => explanation.effects_proposed.push(ev.payload.clone()),
                _ => {}
            }
        }
        Ok(explanation)
    }

    /// Retry a recorded step: re-present the *same* recorded action (kind,
    /// lease, budget) as a fresh step on the same branch. Retrying never
    /// mints authority — if the recorded lease has since expired or been
    /// revoked, the retry is denied like any other step.
    pub async fn step_retry(&self, step: &StepId) -> KernelResult<StepResult> {
        let explanation = self.step_explain(step)?;
        let branch = explanation
            .branch
            .clone()
            .ok_or_else(|| KernelError::NotFound {
                kind: "step_branch",
                id: step.to_string(),
            })?;
        let payload = explanation.action.ok_or_else(|| KernelError::NotFound {
            kind: "tool_invocation",
            id: step.to_string(),
        })?;
        let kind: ActionKind =
            serde_json::from_value(payload.get("action").cloned().ok_or_else(|| {
                KernelError::NotFound {
                    kind: "recorded_action",
                    id: step.to_string(),
                }
            })?)?;
        let lease: LeaseId =
            serde_json::from_value(payload.get("lease").cloned().ok_or_else(|| {
                KernelError::NotFound {
                    kind: "recorded_lease",
                    id: step.to_string(),
                }
            })?)?;
        let budget: ResourceBudget = payload
            .get("budget")
            .cloned()
            .and_then(|v| serde_json::from_value(v).ok())
            .unwrap_or_else(ResourceBudget::step_default);
        let intent_hint = payload
            .get("intent_hint")
            .and_then(|v| v.as_str())
            .map(|s| format!("retry of {step}: {s}"))
            .or_else(|| Some(format!("retry of {step}")));
        let action = Action {
            kind,
            lease,
            intent_hint,
            budget,
        };
        self.execute_step(&explanation.principal, &branch, action)
            .await
    }

    // --------------------------------------------------------------- replay

    /// Audit replay: stream recorded ledger events for an inclusive sequence
    /// range. Never re-executes anything; available for every step.
    pub fn replay_audit(&self, seq_from: i64, seq_to: i64) -> KernelResult<Vec<LedgerEvent>> {
        self.ledger.query(&TraceQuery {
            seq_range: Some((seq_from, seq_to)),
            ..TraceQuery::default()
        })
    }

    /// Sandbox replay: materialize the recorded parent state into a scratch
    /// workspace and re-run the recorded local action. See the crate docs
    /// for the exact guarantee.
    pub async fn replay_sandbox(&self, step: &StepId) -> KernelResult<ReplaySandboxReport> {
        // Find the recorded action and the state the step produced.
        let events = self.ledger.query(&TraceQuery {
            step: Some(step.clone()),
            ..TraceQuery::default()
        })?;
        let action_kind: ActionKind = events
            .iter()
            .find(|e| e.kind == EventKind::ToolInvocation)
            .and_then(|e| e.payload.get("action").cloned())
            .map(serde_json::from_value)
            .transpose()?
            .ok_or_else(|| KernelError::NotFound {
                kind: "tool_invocation",
                id: step.to_string(),
            })?;
        let state_id: StateId = events
            .iter()
            .find(|e| e.kind == EventKind::StateDeltaRecorded)
            .and_then(|e| e.payload.get("state_id").cloned())
            .map(serde_json::from_value)
            .transpose()?
            .ok_or_else(|| KernelError::NotFound {
                kind: "state_delta",
                id: step.to_string(),
            })?;
        let original_exit_code = events
            .iter()
            .find(|e| e.kind == EventKind::ObservationEmitted)
            .and_then(|e| e.payload.get("exit_code"))
            .and_then(|v| v.as_i64())
            .map(|v| v as i32);

        let recorded = self.dag.get_state(&state_id)?;
        if !recorded
            .replay_class
            .supports(ak_core::replay::ReplayMode::Sandbox)
        {
            return Err(KernelError::Other(format!(
                "step {step} was recorded at replay class {:?}, which does not support sandbox replay",
                recorded.replay_class
            )));
        }
        let parent = recorded
            .parent
            .clone()
            .ok_or_else(|| KernelError::NotFound {
                kind: "parent_state",
                id: state_id.to_string(),
            })?;

        // Re-authorize before re-executing (AK-011): the recorded actor must
        // still pass the *current* policy for this action, and the replay
        // runs under the compiled confinement, not an empty one.
        let who = self
            .registry()
            .get(&recorded.actor)
            .map_err(KernelError::from)?;
        let operation = action_kind.required_operation();
        let params = action_kind.params();
        let confinement = match self.policy_read()?.evaluate(
            &who,
            &operation,
            &params,
            Some(&recorded.branch),
            Utc::now(),
        ) {
            Decision::Allow { grant, .. } => grant.confinement,
            Decision::RequireApproval { rule_id, .. } => {
                return Err(KernelError::Other(format!(
                    "sandbox replay refused: rule `{rule_id}` now requires approval"
                )))
            }
            Decision::Deny { denial } => return Err(KernelError::Denied(Box::new(denial))),
        };

        // Scratch backend rooted in a temp dir; the replay branch id is
        // fresh. The backend enforces the same verified OS sandbox as live
        // execution and fails closed without one.
        let tmp = tempfile::tempdir()?;
        let scratch = LocalBackend::new(LocalBackendConfig::new(tmp.path().join("replay")))?;
        let replay_branch = BranchId::generate();
        let dir = scratch.workspace_for(&replay_branch)?;
        self.dag.materialize(&parent, &dir)?;
        let outcome = scratch
            .execute(ExecutionRequest {
                branch: replay_branch,
                base_state: parent,
                actor: recorded.actor.clone(),
                action: action_kind,
                budget: ResourceBudget::step_default(),
                writable_prefixes: confinement.writable_prefixes,
                readable_prefixes: confinement.readable_prefixes,
                egress_domains: confinement.egress_domains,
            })
            .await?;
        let (root, _) = ak_state_dag::snapshot_dir(self.dag.cas(), &dir)?;
        Ok(ReplaySandboxReport {
            step: step.clone(),
            original_exit_code,
            rerun_exit_code: outcome.exit_code,
            workspace_match: root == recorded.workspace_root,
            replay_class: recorded.replay_class,
        })
    }

    /// Live replay: re-propose the recorded effect *contract* under a fresh
    /// idempotency key and drive it through prepare → approve → commit with
    /// full revalidation. Guarantees the contract, never the outcome; drift
    /// aborts with `StaleAuthorization`.
    pub async fn replay_live(
        &self,
        effect: &EffectId,
        approver: &PrincipalId,
    ) -> KernelResult<Receipt> {
        let original = self.broker.effect(effect)?;
        let mut contract = original.contract.clone();
        contract.idempotency_key = format!(
            "{}-replay-{}",
            contract.idempotency_key,
            Utc::now().timestamp_millis()
        );
        let replayed = self.broker.propose(
            contract,
            original.proposer.clone(),
            original.branch.clone(),
            original.step.clone(),
            original.lease.clone(),
        )?;
        self.prepare_effect(&replayed.id).await?;
        self.approve_effect(&replayed.id, approver)?;
        self.commit_effect(&replayed.id).await
    }

    /// Content of a raw ledger blob (full step output).
    pub fn fetch_raw(&self, hash: &ContentHash) -> KernelResult<Vec<u8>> {
        self.ledger.fetch_raw(hash)
    }
}

fn lock<'a, T>(m: &'a Mutex<T>) -> KernelResult<std::sync::MutexGuard<'a, T>> {
    m.lock()
        .map_err(|_| KernelError::Storage("kernel mutex poisoned".into()))
}

/// A requestable-scope sketch for `operation` with these exact parameters:
/// the concrete recovery action an agent can take after a denial.
fn scope_sketch(
    operation: &Operation,
    params: &serde_json::Value,
    requires_human: bool,
) -> RequestableScope {
    RequestableScope {
        operation: operation.clone(),
        constraints: serde_json::json!({ "params": params }),
        requires_human,
    }
}

/// Extract the host from an http(s) URL without pulling a URL crate into the
/// façade. Ports and userinfo are stripped; bracketed IPv6 hosts keep their
/// brackets (they never match domain globs, which is correct — literal IPs
/// are refused by the connector guards anyway).
fn host_of(url: &str) -> Option<String> {
    let rest = url.split("://").nth(1)?;
    let authority = rest.split(['/', '?', '#']).next()?;
    let host = authority.rsplit('@').next()?;
    let host = if let Some(stripped) = host.strip_prefix('[') {
        // Bracketed IPv6: keep up to the closing bracket.
        format!("[{}", stripped.split(']').next().unwrap_or(""))
    } else {
        host.split(':').next().unwrap_or("").to_string()
    };
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

/// Split a connector read response into raw bytes for the raw store and a
/// small structured `data` payload. HTTP-shaped responses (`{body, ...}`)
/// keep their metadata in `data` and their body in the raw stream; anything
/// else is stored as pretty JSON with no separate metadata.
fn shape_read_response(response: &serde_json::Value) -> (Vec<u8>, Option<serde_json::Value>) {
    if let Some(obj) = response.as_object() {
        if let Some(body) = obj.get("body").and_then(|v| v.as_str()) {
            let mut meta = obj.clone();
            meta.remove("body");
            return (
                body.as_bytes().to_vec(),
                Some(serde_json::Value::Object(meta)),
            );
        }
    }
    (
        serde_json::to_vec_pretty(response).unwrap_or_default(),
        None,
    )
}

/// Parse a `TraceQuery` action's query string: whitespace-separated
/// `key=value` tokens (`kind=`, `limit=`, `step=`, `branch=`, `principal=`).
/// Unknown keys and malformed values are ignored; the query always stays
/// scoped to the step's episode and capped at 1000 events (200 by default).
fn parse_trace_query(episode: EpisodeId, query: &str) -> TraceQuery {
    let mut q = TraceQuery {
        episode: Some(episode),
        limit: Some(200),
        ..TraceQuery::default()
    };
    for token in query.split_whitespace() {
        let Some((key, value)) = token.split_once('=') else {
            continue;
        };
        match key {
            "kind" => {
                if let Some(kind) = EventKind::parse(value) {
                    q.kinds.push(kind);
                }
            }
            "limit" => {
                if let Ok(n) = value.parse::<usize>() {
                    q.limit = Some(n.clamp(1, 1000));
                }
            }
            "step" => q.step = StepId::parse(value).ok(),
            "branch" => q.branch = BranchId::parse(value).ok(),
            "principal" => q.principal = PrincipalId::parse(value).ok(),
            _ => {}
        }
    }
    q
}

/// Map an atomic consume-use refusal (lost race, revoked, expired,
/// exhausted) to a machine-readable denial with a concrete recovery scope.
fn denial_from_consume_failure(
    operation: &Operation,
    params: &serde_json::Value,
    err: &ak_identity::IdentityError,
) -> Denial {
    let (code, reason) = match err {
        ak_identity::IdentityError::LeaseUnusable { reason, .. } => match reason.as_str() {
            "expired" => (
                DenialCode::CapabilityExpired,
                "the presented lease expired before the use could be consumed".to_string(),
            ),
            "revoked" => (
                DenialCode::CapabilityDenied,
                "the presented lease was revoked before the use could be consumed".to_string(),
            ),
            _ => (
                DenialCode::CapabilityExhausted,
                "the presented lease has no remaining uses (a concurrent step may have consumed the last one)"
                    .to_string(),
            ),
        },
        other => (DenialCode::CapabilityDenied, format!("lease could not be consumed: {other}")),
    };
    Denial {
        code,
        attempted_operation: operation.clone(),
        reason: format!("{reason}. Recover by requesting a fresh lease for this operation"),
        safe_alternatives: Vec::new(),
        requestable_scopes: vec![scope_sketch(operation, params, false)],
        escalation_allowed: true,
    }
}

/// Map a deterministic lease-check failure to a machine-readable denial
/// carrying the concrete scope to re-request.
fn denial_from_lease_failure(
    operation: &Operation,
    params: &serde_json::Value,
    failure: &LeaseCheckFailure,
) -> Denial {
    let (code, reason) = match failure {
        LeaseCheckFailure::Revoked => {
            (DenialCode::CapabilityDenied, "the presented lease has been revoked".to_string())
        }
        LeaseCheckFailure::Expired { expired_at } => (
            DenialCode::CapabilityExpired,
            format!("the presented lease expired at {expired_at}"),
        ),
        LeaseCheckFailure::Exhausted => (
            DenialCode::CapabilityExhausted,
            "the presented lease has no remaining uses".to_string(),
        ),
        LeaseCheckFailure::WrongPrincipal => (
            DenialCode::CapabilityDenied,
            "the presented lease belongs to a different principal".to_string(),
        ),
        LeaseCheckFailure::WrongOperation { granted } => (
            DenialCode::CapabilityDenied,
            format!("the presented lease grants `{}`, not this operation", granted.0),
        ),
        LeaseCheckFailure::WrongBranch { bound } => (
            DenialCode::BranchMismatch,
            format!("the presented lease is bound to branch `{bound}`; authority does not follow the agent across branches — request a lease bound to the current branch"),
        ),
        LeaseCheckFailure::ConstraintViolated { parameter } => (
            DenialCode::ConstraintViolated,
            format!("parameter `{parameter}` violates the lease constraints"),
        ),
    };
    Denial {
        code,
        attempted_operation: operation.clone(),
        reason: format!(
            "{reason}. Recover by requesting the scope below (capability.request), or use \
             steps/execute_auto to have the kernel resolve leases automatically"
        ),
        safe_alternatives: Vec::new(),
        requestable_scopes: vec![scope_sketch(operation, params, false)],
        escalation_allowed: true,
    }
}

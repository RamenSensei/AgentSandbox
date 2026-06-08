//! The [`Kernel`] façade: one composed, transactional execution kernel.

use ak_backend_local::{LocalBackend, LocalBackendConfig};
use ak_causal_ledger::{EventKind, Ledger, LedgerEvent, TraceQuery};
use ak_core::action::{Action, ActionKind};
use ak_core::budget::ResourceBudget;
use ak_core::capability::{CapabilityLease, Constraint, LeaseCheckFailure, Operation};
use ak_core::denial::{Denial, DenialCode};
use ak_core::effect::{EffectClass, EffectContract, PendingEffect, Receipt};
use ak_core::hash::ContentHash;
use ak_core::ids::{BranchId, EffectId, EpisodeId, LeaseId, PrincipalId, ReceiptId, StateId, StepId};
use ak_core::observation::{distill_output, Observation};
use ak_core::replay::ReplayClass;
use ak_core::state::{FileChange, StateDelta, StateNode};
use ak_core::traits::{Backend, Connector, ExecutionRequest, PreparedEffect};
use ak_core::{KernelError, KernelResult, Principal};
use ak_effect_broker::{EffectBroker, SecretVault};
use ak_identity::{DelegationService, IdentityDb, KernelKeypair, LeaseStore, PrincipalRegistry};
use ak_policy::{CompiledConfinement, Decision, PolicyDocument, PolicyEngine};
use ak_scheduler::{BackendRouter, Needs, RiskTier, SchedulerConfig, StepScheduler};
use ak_state_dag::{Branch, BranchComparison, EpisodeHandle, StateDag};
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
        }
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
    dag: StateDag,
    ledger: Arc<Ledger>,
    delegation: DelegationService,
    keypair: Arc<KernelKeypair>,
    policy: RwLock<PolicyEngine>,
    broker: Arc<EffectBroker>,
    vault: Arc<SecretVault>,
    scheduler: StepScheduler,
    backend: Arc<LocalBackend>,
    episodes: Mutex<HashMap<EpisodeId, EpisodeInfo>>,
    /// Effect classes of registered connector operations, for contracts.
    op_classes: Mutex<HashMap<String, EffectClass>>,
    /// Registered connector names (routing prefixes).
    connector_names: Mutex<Vec<String>>,
}

impl std::fmt::Debug for Kernel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Kernel").field("data_dir", &self.config.data_dir).finish_non_exhaustive()
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
        let dag = StateDag::open(&config.data_dir.join("dag.db"), &config.data_dir.join("cas"))?;
        let ledger = Arc::new(Ledger::open(&config.data_dir.join("ledger.db"))?);
        let identity_db = IdentityDb::open(config.data_dir.join("identity.db"))
            .map_err(KernelError::from)?;
        let delegation = DelegationService::new(identity_db);
        let keypair = Arc::new(
            KernelKeypair::load_or_generate(config.data_dir.join("receipt.key"))
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
        let vault = Arc::new(SecretVault::open(config.data_dir.join("vault.json"))?);
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
        info!("kernel opened");
        Ok(Self {
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
            episodes: Mutex::new(HashMap::new()),
            op_classes: Mutex::new(HashMap::new()),
            connector_names: Mutex::new(Vec::new()),
        })
    }

    // ------------------------------------------------------------ accessors

    pub fn config(&self) -> &KernelConfig {
        &self.config
    }
    pub fn dag(&self) -> &StateDag {
        &self.dag
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
    /// The local backend (workspace materialization + discard).
    pub fn local_backend(&self) -> &Arc<LocalBackend> {
        &self.backend
    }

    fn policy_read(&self) -> KernelResult<std::sync::RwLockReadGuard<'_, PolicyEngine>> {
        self.policy.read().map_err(|_| KernelError::Storage("policy lock poisoned".into()))
    }

    /// The current policy epoch.
    pub fn policy_epoch(&self) -> KernelResult<u64> {
        Ok(self.policy_read()?.document().policy_epoch)
    }

    /// Run `f` with mutable access to the policy engine (epoch bumps are the
    /// document's responsibility).
    pub fn with_policy_mut<R>(&self, f: impl FnOnce(&mut PolicyEngine) -> R) -> KernelResult<R> {
        let mut guard =
            self.policy.write().map_err(|_| KernelError::Storage("policy lock poisoned".into()))?;
        Ok(f(&mut guard))
    }

    /// Register a principal in the identity registry.
    pub fn register_principal(&self, principal: &Principal) -> KernelResult<()> {
        self.registry().register(principal).map_err(KernelError::from)
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
        }
        self.broker.register_connector(connector);
        Ok(())
    }

    /// The declared effect class for a connector operation; undeclared
    /// operations classify as [`EffectClass::OpaqueExternal`].
    pub fn effect_class_of(&self, operation: &str) -> KernelResult<EffectClass> {
        Ok(lock(&self.op_classes)?.get(operation).copied().unwrap_or(EffectClass::OpaqueExternal))
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
        let handle = self.dag.create_episode(actor, ws, ReplayClass::FilesystemOnly)?;
        // Materialize the root workspace for the initial branch.
        let dir = self.backend.workspace_for(&handle.branch)?;
        self.dag.materialize(&handle.root.id, &dir)?;
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
            .writer(handle.episode.clone(), Some(handle.branch.clone()), None, actor.clone())
            .record(EventKind::Objective, serde_json::json!({ "objective": objective }))?;
        Ok(handle)
    }

    /// Describe an episode: branches and remaining budget.
    pub async fn describe_episode(&self, episode: &EpisodeId) -> KernelResult<EpisodeDescription> {
        let info = lock(&self.episodes)?
            .get(episode)
            .cloned()
            .ok_or_else(|| KernelError::NotFound { kind: "episode", id: episode.to_string() })?;
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
            remaining_budget: self.scheduler.remaining_budget().await,
        })
    }

    // ------------------------------------------------------------- branches

    /// Fork a new branch from the head of `branch` and materialize its
    /// backend workspace.
    #[instrument(skip(self))]
    pub fn fork_branch(&self, branch: &BranchId) -> KernelResult<Branch> {
        let head = self.dag.head(branch)?;
        let new = self.dag.fork(&head.id)?;
        let dir = self.backend.workspace_for(&new.id)?;
        self.dag.materialize(&new.head, &dir)?;
        if let Some(info) = lock(&self.episodes)?.get_mut(&new.episode) {
            info.branches.push(new.id.clone());
        }
        Ok(new)
    }

    /// File-level diff of a branch head since `since` (defaults to the
    /// branch base state).
    pub fn branch_diff(&self, branch: &BranchId, since: Option<&StateId>) -> KernelResult<Vec<FileChange>> {
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
    pub fn merge_branch(
        &self,
        target: &BranchId,
        source: &BranchId,
        actor: &PrincipalId,
    ) -> KernelResult<StateNode> {
        let node = self.dag.merge(target, source, actor)?;
        let dir = self.backend.workspace_for(target)?;
        self.dag.materialize(&node.id, &dir)?;
        Ok(node)
    }

    /// Discard a branch in the DAG and tear down its backend workspace.
    #[instrument(skip(self))]
    pub async fn discard_branch(&self, branch: &BranchId) -> KernelResult<()> {
        self.dag.discard_branch(branch)?;
        self.backend.discard(branch).await
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
        let decision = self.policy_read()?.evaluate(&who, operation, params, branch, Utc::now());
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
                    requestable_scopes: Vec::new(),
                    escalation_allowed: true,
                })))
            }
            Decision::Deny { denial } => Err(KernelError::Denied(Box::new(denial))),
        }
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
            .delegate(delegator, parent_lease, delegatee, constraints, uses, expires_at, budget, Utc::now())
            .map_err(KernelError::from)
    }

    /// Revoke a lease and everything transitively attenuated from it.
    pub fn revoke(&self, lease: &LeaseId) -> KernelResult<Vec<LeaseId>> {
        self.leases().revoke_cascading(lease).map_err(KernelError::from)
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
        let step = StepId::generate();
        let b = self.dag.get_branch(branch)?;
        let who = self.registry().get(principal).map_err(KernelError::from)?;
        let writer =
            self.ledger.writer(b.episode.clone(), Some(branch.clone()), Some(step.clone()), principal.clone());
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
                    reason: format!("lease `{}` is unknown: {e}", action.lease),
                    safe_alternatives: Vec::new(),
                    requestable_scopes: Vec::new(),
                    escalation_allowed: true,
                };
                return self.deny_step(&writer, &b, step, &who, denial);
            }
        };
        if let Err(failure) = lease.check(principal, &operation, &params, Some(branch), now) {
            let denial = denial_from_lease_failure(&operation, &failure);
            return self.deny_step(&writer, &b, step, &who, denial);
        }

        // ---- deterministic policy evaluation ---------------------------
        let confinement = {
            let decision =
                self.policy_read()?.evaluate(&who, &operation, &params, Some(branch), now);
            match decision {
                Decision::Allow { grant, .. } => grant.confinement,
                Decision::RequireApproval { rule_id, .. } => {
                    let denial = Denial {
                        code: DenialCode::EffectRequiresApproval,
                        attempted_operation: operation.clone(),
                        reason: format!("rule `{rule_id}` requires out-of-band approval"),
                        safe_alternatives: Vec::new(),
                        requestable_scopes: Vec::new(),
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
        self.leases().consume_use(&action.lease, now).map_err(KernelError::from)?;

        match &action.kind {
            ActionKind::ConnectorOp { connector, operation: op, params: op_params } => {
                self.propose_connector_op(
                    &writer, &b, branch, step, principal, &action, connector, op, op_params,
                )
                .await
            }
            ActionKind::TraceQuery { query } => {
                let events = self.trace_query(&TraceQuery {
                    episode: Some(b.episode.clone()),
                    limit: Some(200),
                    ..TraceQuery::default()
                })?;
                let raw = serde_json::to_vec(&events)?;
                let full = self.ledger.store_raw(&raw)?;
                let obs = Observation::Success {
                    summary: format!("trace query `{query}` returned {} events", events.len()),
                    data: Some(serde_json::json!({ "count": events.len() })),
                    stdout_head: None,
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
        Ok(StepResult { step, state: branch.head.clone(), observation: Observation::Denied { denial } })
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
        let class = self.effect_class_of(&full_op)?;
        let resource = op_params
            .get("resource")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .unwrap_or_else(|| {
                match (op_params.get("owner").and_then(|v| v.as_str()), op_params.get("repo").and_then(|v| v.as_str())) {
                    (Some(o), Some(r)) => format!("{o}/{r}"),
                    _ => connector.to_string(),
                }
            });
        let mut arguments = op_params.clone();
        if let Some(obj) = arguments.as_object_mut() {
            obj.remove("resource");
            obj.remove("preconditions");
        }
        let contract = EffectContract {
            operation: full_op,
            resource,
            arguments,
            preconditions: op_params.get("preconditions").cloned().unwrap_or(serde_json::json!({})),
            idempotency_key: format!("{}-{}", b.episode, step),
            class,
        };
        let effect =
            self.broker.propose(contract, principal.clone(), branch.clone(), step.clone(), action.lease.clone())?;
        let tool = writer.record(
            EventKind::ToolInvocation,
            serde_json::json!({ "action": action.kind, "intent_hint": action.intent_hint }),
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
            branch, &step, principal, delta, head.workspace_root.clone(), head.replay_class,
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
        Ok(StepResult { step, state: node.id, observation })
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
            serde_json::json!({ "action": action.kind }),
        )?;
        let node = self.dag.append_step(
            branch,
            &step,
            principal,
            StateDelta { policy_epoch: head.delta.policy_epoch, ..StateDelta::default() },
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
        Ok(StepResult { step, state: node.id, observation })
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
            serde_json::json!({ "action": action.kind, "intent_hint": action.intent_hint }),
        )?;
        let outcome = match self
            .scheduler
            .execute_step(step.clone(), req, RiskTier::Low, &Needs::default())
            .await
        {
            Ok(o) => o,
            Err(KernelError::Denied(denial)) => {
                let who = self.registry().get(principal).map_err(KernelError::from)?;
                return self.deny_step(writer, b, step, &who, *denial);
            }
            Err(e) => return Err(e),
        };

        // Snapshot the workspace and append to the DAG.
        let dir = self.backend.workspace_for(branch)?;
        let node =
            self.dag.snapshot_and_append(branch, &step, principal, &dir, outcome.replay_class)?;
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
        let (head, hashed, truncated) = distill_output(&raw, 2048);
        debug_assert_eq!(hashed, ak_core::hash::hash_bytes(&raw));
        let observation = if outcome.exit_code == 0 {
            Observation::Success {
                summary: format!(
                    "{} exited 0 ({} file(s) changed)",
                    action.kind.required_operation().0,
                    node.delta.files.len()
                ),
                data: None,
                stdout_head: head,
                exit_code: 0,
                full_output,
                truncated,
            }
        } else {
            Observation::Failure {
                summary: format!(
                    "{} exited {}",
                    action.kind.required_operation().0,
                    outcome.exit_code
                ),
                exit_code: outcome.exit_code,
                first_causal_failure: String::from_utf8_lossy(&outcome.stderr)
                    .lines()
                    .next()
                    .map(str::to_string),
                full_output,
            }
        };
        writer.record_caused_by(
            EventKind::ObservationEmitted,
            serde_json::to_value(&observation)?,
            vec![delta_ev.seq],
        )?;
        Ok(StepResult { step, state: node.id, observation })
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
    /// epoch, live lease, re-observed preconditions, exactly-once key).
    /// Receipts are Ed25519-signed with the kernel keypair.
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
                self.ledger.store_receipt(&receipt, &e.contract.idempotency_key)?;
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
                let _ = self.dag.append_step(
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
                );
                Ok(receipt)
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

    /// Fetch a signed receipt.
    pub fn receipt(&self, id: &ReceiptId) -> KernelResult<Receipt> {
        self.broker.receipt(id)
    }

    /// Verify a receipt signature against the kernel public key.
    pub fn verify_receipt(&self, receipt: &Receipt) -> KernelResult<bool> {
        KernelKeypair::verify_canonical(&self.keypair.public_key(), &receipt.body, &receipt.signature)
            .map_err(KernelError::from)
    }

    // ---------------------------------------------------------------- trace

    /// Query the causal ledger.
    pub fn trace_query(&self, q: &TraceQuery) -> KernelResult<Vec<LedgerEvent>> {
        self.ledger.query(q)
    }

    // --------------------------------------------------------------- replay

    /// Audit replay: stream recorded ledger events for an inclusive sequence
    /// range. Never re-executes anything; available for every step.
    pub fn replay_audit(&self, seq_from: i64, seq_to: i64) -> KernelResult<Vec<LedgerEvent>> {
        self.ledger.query(&TraceQuery { seq_range: Some((seq_from, seq_to)), ..TraceQuery::default() })
    }

    /// Sandbox replay: materialize the recorded parent state into a scratch
    /// workspace and re-run the recorded local action. See the crate docs
    /// for the exact guarantee.
    pub async fn replay_sandbox(&self, step: &StepId) -> KernelResult<ReplaySandboxReport> {
        // Find the recorded action and the state the step produced.
        let events = self
            .ledger
            .query(&TraceQuery { step: Some(step.clone()), ..TraceQuery::default() })?;
        let action_kind: ActionKind = events
            .iter()
            .find(|e| e.kind == EventKind::ToolInvocation)
            .and_then(|e| e.payload.get("action").cloned())
            .map(serde_json::from_value)
            .transpose()?
            .ok_or_else(|| KernelError::NotFound { kind: "tool_invocation", id: step.to_string() })?;
        let state_id: StateId = events
            .iter()
            .find(|e| e.kind == EventKind::StateDeltaRecorded)
            .and_then(|e| e.payload.get("state_id").cloned())
            .map(serde_json::from_value)
            .transpose()?
            .ok_or_else(|| KernelError::NotFound { kind: "state_delta", id: step.to_string() })?;
        let original_exit_code = events
            .iter()
            .find(|e| e.kind == EventKind::ObservationEmitted)
            .and_then(|e| e.payload.get("exit_code"))
            .and_then(|v| v.as_i64())
            .map(|v| v as i32);

        let recorded = self.dag.get_state(&state_id)?;
        if !recorded.replay_class.supports(ak_core::replay::ReplayMode::Sandbox) {
            return Err(KernelError::Other(format!(
                "step {step} was recorded at replay class {:?}, which does not support sandbox replay",
                recorded.replay_class
            )));
        }
        let parent = recorded
            .parent
            .clone()
            .ok_or_else(|| KernelError::NotFound { kind: "parent_state", id: state_id.to_string() })?;

        // Scratch backend rooted in a temp dir; the replay branch id is fresh.
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
                writable_prefixes: Vec::new(),
                readable_prefixes: Vec::new(),
                egress_domains: Vec::new(),
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
        contract.idempotency_key =
            format!("{}-replay-{}", contract.idempotency_key, Utc::now().timestamp_millis());
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
    m.lock().map_err(|_| KernelError::Storage("kernel mutex poisoned".into()))
}

/// Map a deterministic lease-check failure to a machine-readable denial.
fn denial_from_lease_failure(operation: &Operation, failure: &LeaseCheckFailure) -> Denial {
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
            format!("the presented lease is bound to branch `{bound}`; authority does not follow the agent across branches"),
        ),
        LeaseCheckFailure::ConstraintViolated { parameter } => (
            DenialCode::ConstraintViolated,
            format!("parameter `{parameter}` violates the lease constraints"),
        ),
    };
    Denial {
        code,
        attempted_operation: operation.clone(),
        reason,
        safe_alternatives: Vec::new(),
        requestable_scopes: Vec::new(),
        escalation_allowed: true,
    }
}

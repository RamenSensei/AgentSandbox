//! # ak-conformance
//!
//! The protocol conformance suite: table-driven scenarios loaded from
//! `conformance/cases/*.yaml`, each driven against the [`ak_api::Kernel`]
//! façade by a scenario driver keyed on the case's `kind`.
//!
//! Run with `cargo test -p ak-conformance`.

use ak_api::{Kernel, KernelConfig};
use ak_core::action::{Action, ActionKind};
use ak_core::budget::ResourceBudget;
use ak_core::capability::{Constraint, Operation};
use ak_core::denial::DenialCode;
use ak_core::effect::{EffectClass, EffectContract, EffectPhase};
use ak_core::ids::{BranchId, LeaseId, StepId};
use ak_core::observation::Observation;
use ak_core::replay::{ReplayClass, ReplayMode};
use ak_core::traits::{CommitResult, Connector, PreparedEffect};
use ak_core::{KernelError, KernelResult, Principal};
use ak_policy::{PolicyDocument, PolicyRule, PrincipalSelector, RuleEffect};
use async_trait::async_trait;
use chrono::{Duration, Utc};
use indexmap::IndexMap;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

/// One conformance case loaded from YAML.
#[derive(Debug, Clone, Deserialize)]
pub struct Case {
    /// Human-readable case name.
    pub name: String,
    /// What protocol requirement this case checks.
    pub description: String,
    /// Driver key; see [`run_case`] for the supported kinds.
    pub kind: String,
    /// Driver-specific parameters.
    #[serde(default)]
    pub params: Value,
}

/// Load every `*.yaml` case in `dir`, sorted by file name.
pub fn load_cases(dir: &Path) -> Result<Vec<Case>, String> {
    let mut paths: Vec<_> = std::fs::read_dir(dir)
        .map_err(|e| format!("read {}: {e}", dir.display()))?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().map(|x| x == "yaml" || x == "yml").unwrap_or(false))
        .collect();
    paths.sort();
    paths
        .into_iter()
        .map(|p| {
            let raw = std::fs::read_to_string(&p).map_err(|e| format!("{}: {e}", p.display()))?;
            serde_yaml::from_str(&raw).map_err(|e| format!("{}: {e}", p.display()))
        })
        .collect()
}

// ---------------------------------------------------------------- fixture

/// A mock connector whose observed precondition value is externally mutable
/// (to simulate external-world drift) and whose single operation's effect
/// class is configurable.
pub struct DriftableConnector {
    class: EffectClass,
    /// The externally observable state (compared against contract
    /// preconditions at prepare/commit time by the broker).
    pub world: Arc<Mutex<String>>,
}

impl DriftableConnector {
    pub fn new(class: EffectClass) -> Self {
        Self { class, world: Arc::new(Mutex::new("state-1".into())) }
    }
}

#[async_trait]
impl Connector for DriftableConnector {
    fn name(&self) -> &str {
        "mock"
    }
    fn operations(&self) -> Vec<(String, EffectClass)> {
        vec![("mock.poke".into(), self.class)]
    }
    fn canonicalize(&self, _operation: &str, args: &Value) -> KernelResult<Value> {
        Ok(args.clone())
    }
    async fn prepare(&self, _contract: &EffectContract) -> KernelResult<PreparedEffect> {
        let world = self.world.lock().map(|w| w.clone()).unwrap_or_default();
        Ok(PreparedEffect {
            preview: json!({ "action": "poke", "world": world }),
            observed_preconditions: json!({ "world": world }),
        })
    }
    async fn commit(&self, _contract: &EffectContract) -> KernelResult<CommitResult> {
        Ok(CommitResult { response: json!({ "poked": true }) })
    }
    async fn compensate(&self, _contract: &EffectContract) -> KernelResult<CommitResult> {
        Ok(CommitResult { response: json!({ "unpoked": true }) })
    }
}

/// A conformance fixture: a fresh kernel in a temp dir with a permissive
/// test policy, a registered agent, an episode, and a mock connector.
pub struct Fixture {
    pub kernel: Arc<Kernel>,
    pub agent: Principal,
    pub episode: ak_core::ids::EpisodeId,
    pub branch: BranchId,
    pub mock_world: Arc<Mutex<String>>,
    _tmp: tempfile::TempDir,
}

fn allow_rule(id: &str, ops: &[&str], uses: u32, ttl: u64) -> PolicyRule {
    PolicyRule {
        id: id.into(),
        principals: PrincipalSelector::default(),
        operations: ops.iter().map(|s| s.to_string()).collect(),
        effect: RuleEffect::Allow,
        constraints: IndexMap::new(),
        max_uses: uses,
        ttl_seconds: ttl,
        budget: None,
        risk_weight: 0,
        note: None,
    }
}

impl Fixture {
    /// Build a fixture. `shell_uses` bounds the compiled shell lease and
    /// `episode_budget` overrides the scheduler budget when given.
    pub async fn build(
        shell_uses: u32,
        episode_budget: Option<ResourceBudget>,
        mock_class: EffectClass,
    ) -> Result<Self, String> {
        let tmp = tempfile::tempdir().map_err(|e| e.to_string())?;
        let mut config = KernelConfig::new(tmp.path().join("data"));
        if let Some(b) = episode_budget {
            config.episode_budget = b;
        }
        let kernel = Kernel::open(config).map_err(|e| e.to_string())?;
        kernel
            .with_policy_mut(|p| {
                *p.document_mut() = PolicyDocument {
                    rules: vec![
                        allow_rule("shell", &["proc.shell"], shell_uses, 3600),
                        allow_rule("fs", &["fs.*"], 100, 3600),
                        allow_rule("mock", &["mock.*"], 10, 3600),
                    ],
                    ..PolicyDocument::default()
                }
            })
            .map_err(|e| e.to_string())?;
        let mock = Arc::new(DriftableConnector::new(mock_class));
        let mock_world = Arc::clone(&mock.world);
        kernel.register_connector(mock).map_err(|e| e.to_string())?;
        let agent = Principal::new_agent("conformance-agent");
        kernel.register_principal(&agent).map_err(|e| e.to_string())?;
        let ep = kernel.create_episode(&agent.id, None, "conformance").map_err(|e| e.to_string())?;
        Ok(Self {
            kernel: Arc::new(kernel),
            agent,
            episode: ep.episode,
            branch: ep.branch,
            mock_world,
            _tmp: tmp,
        })
    }

    /// Request a branch-bound lease for `operation`.
    pub fn lease(&self, operation: &str, branch: &BranchId) -> Result<LeaseId, String> {
        self.kernel
            .request_capability(&self.agent.id, &Operation::new(operation), &json!({}), Some(branch))
            .map(|l| l.id)
            .map_err(|e| e.to_string())
    }

    /// Execute a shell step on `branch` with `lease` and `budget`.
    pub async fn shell_with(
        &self,
        branch: &BranchId,
        lease: LeaseId,
        command: &str,
        budget: ResourceBudget,
    ) -> Result<ak_api::StepResult, String> {
        self.kernel
            .execute_step(
                &self.agent.id,
                branch,
                Action {
                    kind: ActionKind::Shell { command: command.into(), cwd: None, env: BTreeMap::new() },
                    lease,
                    intent_hint: None,
                    budget,
                },
            )
            .await
            .map_err(|e| e.to_string())
    }

    /// Convenience: fresh lease + default step budget.
    pub async fn shell(&self, branch: &BranchId, command: &str) -> Result<ak_api::StepResult, String> {
        let lease = self.lease("proc.shell", branch)?;
        self.shell_with(branch, lease, command, ResourceBudget::step_default()).await
    }

    /// Propose a mock effect through a full kernel step.
    pub async fn propose_mock(&self) -> Result<ak_core::ids::EffectId, String> {
        let lease = self.lease("mock.poke", &self.branch)?;
        let world = self.mock_world.lock().map(|w| w.clone()).unwrap_or_default();
        let result = self
            .kernel
            .execute_step(
                &self.agent.id,
                &self.branch,
                Action {
                    kind: ActionKind::ConnectorOp {
                        connector: "mock".into(),
                        operation: "poke".into(),
                        params: json!({ "preconditions": { "world": world } }),
                    },
                    lease,
                    intent_hint: None,
                    budget: ResourceBudget::step_default(),
                },
            )
            .await
            .map_err(|e| e.to_string())?;
        match result.observation {
            Observation::EffectPending { effect, .. } => Ok(effect),
            other => Err(format!("expected pending effect, got {other:?}")),
        }
    }
}

fn expect_denial(obs: &Observation, code: DenialCode) -> Result<(), String> {
    match obs {
        Observation::Denied { denial } if denial.code == code => Ok(()),
        Observation::Denied { denial } => {
            Err(format!("expected denial code {code:?}, got {:?}", denial.code))
        }
        other => Err(format!("expected a denial, got {other:?}")),
    }
}

fn p_str<'a>(params: &'a Value, key: &str, default: &'a str) -> &'a str {
    params.get(key).and_then(Value::as_str).unwrap_or(default)
}
fn p_u64(params: &Value, key: &str, default: u64) -> u64 {
    params.get(key).and_then(Value::as_u64).unwrap_or(default)
}

// ------------------------------------------------------------------ drivers

/// Run one conformance case. Returns `Err` with a diagnostic on failure.
pub async fn run_case(case: &Case) -> Result<(), String> {
    let params = &case.params;
    match case.kind.as_str() {
        "episode_lifecycle" => episode_lifecycle(params).await,
        "step_observation_shape" => step_observation_shape(params).await,
        "denial_machine_readable" => denial_machine_readable(params).await,
        "lease_expiry" => lease_expiry(params).await,
        "lease_exhaustion" => lease_exhaustion(params).await,
        "lease_branch_binding" => lease_branch_binding(params).await,
        "attenuation_no_widening" => attenuation_no_widening(params).await,
        "effect_phase_machine" => effect_phase_machine(params).await,
        "irreversible_requires_approval" => irreversible_requires_approval(params).await,
        "duplicate_idempotency" => duplicate_idempotency(params).await,
        "stale_precondition_abort" => stale_precondition_abort(params).await,
        "merge_conflict_reporting" => merge_conflict_reporting(params).await,
        "replay_class_honesty" => replay_class_honesty(params).await,
        "budget_refusal" => budget_refusal(params).await,
        "trace_causality" => trace_causality(params).await,
        other => Err(format!("unknown case kind `{other}`")),
    }
}

async fn episode_lifecycle(params: &Value) -> Result<(), String> {
    let f = Fixture::build(100, None, EffectClass::Compensatable).await?;
    let file = p_str(params, "file", "hello.txt");
    let r = f.shell(&f.branch, &format!("printf hi > {file}")).await?;
    if !matches!(r.observation, Observation::Success { .. }) {
        return Err(format!("step failed: {:?}", r.observation));
    }
    let desc = f.kernel.describe_episode(&f.episode).await.map_err(|e| e.to_string())?;
    if desc.branches.len() != 1 {
        return Err(format!("expected 1 branch, got {}", desc.branches.len()));
    }
    let head = f.kernel.dag().head(&f.branch).map_err(|e| e.to_string())?;
    if head.id != r.state {
        return Err("branch head must advance to the step's state".into());
    }
    if !head.delta.files.iter().any(|c| c.path() == file) {
        return Err(format!("delta must record `{file}`: {:?}", head.delta.files));
    }
    Ok(())
}

async fn step_observation_shape(params: &Value) -> Result<(), String> {
    let f = Fixture::build(100, None, EffectClass::Compensatable).await?;
    let text = p_str(params, "text", "observable-output");
    let r = f.shell(&f.branch, &format!("printf {text}")).await?;
    let Observation::Success { summary, stdout_head, exit_code, full_output, truncated, .. } =
        &r.observation
    else {
        return Err(format!("expected success, got {:?}", r.observation));
    };
    if summary.is_empty() {
        return Err("summary must be non-empty".into());
    }
    if *exit_code != 0 || *truncated {
        return Err("small output must not truncate".into());
    }
    if stdout_head.as_deref() != Some(text) {
        return Err(format!("stdout_head must carry the head bytes, got {stdout_head:?}"));
    }
    if !full_output.as_str().starts_with("sha256:") {
        return Err("full_output must be a sha256 content hash".into());
    }
    let raw = f.kernel.fetch_raw(full_output).map_err(|e| e.to_string())?;
    if raw != text.as_bytes() {
        return Err("full output blob must be addressable in the ledger raw store".into());
    }
    Ok(())
}

async fn denial_machine_readable(_params: &Value) -> Result<(), String> {
    let f = Fixture::build(100, None, EffectClass::Compensatable).await?;
    // Unknown lease → denial observation with every required field.
    let r = f
        .shell_with(&f.branch, LeaseId::generate(), "id", ResourceBudget::step_default())
        .await?;
    let Observation::Denied { denial } = &r.observation else {
        return Err(format!("expected denial, got {:?}", r.observation));
    };
    let v = serde_json::to_value(denial).map_err(|e| e.to_string())?;
    for key in ["code", "attempted_operation", "reason", "escalation_allowed"] {
        if v.get(key).is_none() {
            return Err(format!("denial must carry `{key}`: {v}"));
        }
    }
    if denial.reason.is_empty() {
        return Err("denial reason must be non-empty".into());
    }
    // Default-deny operations are denied with a structured error too.
    match f.kernel.request_capability(
        &f.agent.id,
        &Operation::new("net.raw_socket"),
        &json!({}),
        Some(&f.branch),
    ) {
        Err(KernelError::Denied(d)) => {
            if d.code != DenialCode::CapabilityDenied {
                return Err(format!("default deny must be CAPABILITY_DENIED, got {:?}", d.code));
            }
            Ok(())
        }
        other => Err(format!("expected structured denial, got {other:?}")),
    }
}

async fn lease_expiry(params: &Value) -> Result<(), String> {
    let f = Fixture::build(100, None, EffectClass::Compensatable).await?;
    let lease_id = f.lease("proc.shell", &f.branch)?;
    let lease = f.kernel.leases().get(&lease_id).map_err(|e| e.to_string())?;
    let skew = Duration::seconds(p_u64(params, "skew_seconds", 7200) as i64);
    // Deterministic clock: the same lease refuses once past its expiry.
    let future = Utc::now() + skew;
    match lease.check(&f.agent.id, &Operation::new("proc.shell"), &json!({}), Some(&f.branch), future)
    {
        Err(ak_core::capability::LeaseCheckFailure::Expired { .. }) => Ok(()),
        other => Err(format!("expected Expired at now+{skew}, got {other:?}")),
    }
}

async fn lease_exhaustion(params: &Value) -> Result<(), String> {
    let uses = p_u64(params, "uses", 1) as u32;
    let f = Fixture::build(uses, None, EffectClass::Compensatable).await?;
    let lease = f.lease("proc.shell", &f.branch)?;
    for _ in 0..uses {
        let r = f
            .shell_with(&f.branch, lease.clone(), "true", ResourceBudget::step_default())
            .await?;
        if !matches!(r.observation, Observation::Success { .. }) {
            return Err(format!("in-budget use must succeed: {:?}", r.observation));
        }
    }
    let r = f.shell_with(&f.branch, lease, "true", ResourceBudget::step_default()).await?;
    expect_denial(&r.observation, DenialCode::CapabilityExhausted)
}

async fn lease_branch_binding(_params: &Value) -> Result<(), String> {
    let f = Fixture::build(100, None, EffectClass::Compensatable).await?;
    let other = f.kernel.fork_branch(&f.branch).map_err(|e| e.to_string())?;
    let lease = f.lease("proc.shell", &other.id)?;
    // Presenting a lease bound to `other` on the main branch must fail.
    let r = f.shell_with(&f.branch, lease, "true", ResourceBudget::step_default()).await?;
    expect_denial(&r.observation, DenialCode::BranchMismatch)
}

async fn attenuation_no_widening(params: &Value) -> Result<(), String> {
    let f = Fixture::build(100, None, EffectClass::Compensatable).await?;
    let child = f.agent.spawn_child(ak_core::PrincipalKind::SubAgent, "worker");
    f.kernel.register_principal(&child).map_err(|e| e.to_string())?;
    let parent = f.lease("proc.shell", &f.branch)?;
    let parent_lease = f.kernel.leases().get(&parent).map_err(|e| e.to_string())?;
    // Widen the use count beyond the parent's — must be rejected.
    let extra_uses = p_u64(params, "extra_uses", 1000) as u32;
    match f.kernel.delegate(
        &f.agent.id,
        &parent,
        &child.id,
        IndexMap::new(),
        parent_lease.remaining_uses + extra_uses,
        parent_lease.expires_at,
        ResourceBudget::zero(),
    ) {
        Err(_) => {}
        Ok(l) => return Err(format!("widened delegation must be rejected, got lease {}", l.id)),
    }
    // Also: widening a constraint must be rejected at the capability layer.
    let mut constraints = IndexMap::new();
    constraints.insert("command".into(), Constraint::Prefix { prefix: "cargo ".into() });
    let mut narrow = parent_lease.clone();
    narrow.constraints = constraints;
    let mut widened = IndexMap::new();
    widened.insert("command".into(), Constraint::Prefix { prefix: "".into() });
    match narrow.attenuate(
        child.id.clone(),
        widened,
        1,
        narrow.expires_at,
        ResourceBudget::zero(),
        Utc::now(),
    ) {
        Err(ak_core::capability::AttenuationError::ConstraintWidened { .. }) => {}
        other => return Err(format!("expected ConstraintWidened, got {other:?}")),
    }
    // A proper narrowing succeeds and records lineage.
    let ok = f
        .kernel
        .delegate(
            &f.agent.id,
            &parent,
            &child.id,
            IndexMap::new(),
            1,
            parent_lease.expires_at,
            ResourceBudget::zero(),
        )
        .map_err(|e| e.to_string())?;
    if ok.parent_lease.as_ref() != Some(&parent) {
        return Err("attenuated lease must record its parent".into());
    }
    Ok(())
}

async fn effect_phase_machine(_params: &Value) -> Result<(), String> {
    let f = Fixture::build(100, None, EffectClass::Compensatable).await?;
    let effect = f.propose_mock().await?;
    // approve before prepare → refused.
    if f.kernel.approve_effect(&effect, &f.agent.id).is_ok() {
        return Err("approve before prepare must be refused".into());
    }
    f.kernel.prepare_effect(&effect).await.map_err(|e| e.to_string())?;
    // prepare twice → refused.
    if f.kernel.prepare_effect(&effect).await.is_ok() {
        return Err("double prepare must be refused".into());
    }
    f.kernel.approve_effect(&effect, &f.agent.id).map_err(|e| e.to_string())?;
    let receipt = f.kernel.commit_effect(&effect).await.map_err(|e| e.to_string())?;
    let e = f.kernel.effect(&effect).map_err(|e| e.to_string())?;
    match e.phase {
        EffectPhase::Committed { receipt: r } if r == receipt.id => {}
        other => return Err(format!("expected Committed phase, got {other:?}")),
    }
    // commit twice → refused (already committed).
    if f.kernel.commit_effect(&effect).await.is_ok() {
        return Err("double commit must be refused".into());
    }
    Ok(())
}

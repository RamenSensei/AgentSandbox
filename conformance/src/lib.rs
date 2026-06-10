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

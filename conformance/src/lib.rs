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

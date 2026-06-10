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

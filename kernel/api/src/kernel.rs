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

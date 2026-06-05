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

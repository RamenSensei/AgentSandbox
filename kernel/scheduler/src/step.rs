//! Step scheduling: budget enforcement at step boundaries, branch fan-out
//! limits, idle-pause bookkeeping, intent-aware prewarming and the per-step
//! accounting record consumed by the causal ledger.

use crate::router::{BackendRouter, Needs, RiskTier};
use ak_core::budget::ResourceBudget;
use ak_core::capability::Operation;
use ak_core::denial::{Denial, DenialCode};
use ak_core::error::{KernelError, KernelResult};
use ak_core::ids::{BranchId, StepId};
use ak_core::traits::{ExecutionOutcome, ExecutionRequest};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{Mutex, Semaphore};

/// Step-boundary accounting record, exposed for the ledger: which backend ran
/// the step, how long it queued behind the fan-out limit, how long it
/// executed, and what it consumed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepRecord {
    pub step: StepId,
    pub branch: BranchId,
    /// Profile name of the backend that executed the step.
    pub backend: String,
    /// Time spent waiting for a fan-out permit, milliseconds.
    pub queue_ms: u64,
    /// Wall-clock execution time, milliseconds.
    pub exec_ms: u64,
    /// Usage reported by the backend (charged against the episode budget).
    pub usage: ResourceBudget,
    pub recorded_at: DateTime<Utc>,
}

/// A prewarm suggestion produced by [`StepScheduler::hint`].
///
/// **Hints optimize, never authorize**: a plan may warm a backend or local
/// workspaces ahead of need, but it is *not* consulted by
/// [`BackendRouter::route`] and cannot lower any isolation floor.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PrewarmPlan {
    /// Backend worth warming (must already be registered), if any.
    pub warm_backend: Option<String>,
    /// Number of idle local workspaces to keep ready.
    pub warm_workspaces: usize,
    /// Human-readable rationale, for the ledger.
    pub note: String,
}

/// Scheduler configuration.
#[derive(Debug, Clone)]
pub struct SchedulerConfig {
    /// Maximum number of steps executing concurrently across branches
    /// (the branch fan-out budget).
    pub max_concurrent_branches: usize,
    /// Total budget for the episode; every step's usage is charged here.
    pub episode_budget: ResourceBudget,
}

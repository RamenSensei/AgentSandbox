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

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self { max_concurrent_branches: 8, episode_budget: ResourceBudget::step_default() }
    }
}

/// A simple warm pool of pre-created idle local workspace directories.
///
/// `fill(n)` creates directories ahead of need; `take()` hands one out. This
/// only trades directory-creation latency — it grants no authority.
pub struct WarmPool {
    root: PathBuf,
    pool: Mutex<Vec<PathBuf>>,
    seq: AtomicU64,
}

impl WarmPool {
    pub fn new(root: impl Into<PathBuf>) -> KernelResult<Self> {
        let root = root.into();
        std::fs::create_dir_all(&root)?;
        Ok(Self { root, pool: Mutex::new(Vec::new()), seq: AtomicU64::new(0) })
    }

    /// Ensure at least `n` idle workspaces exist in the pool.
    pub async fn fill(&self, n: usize) -> KernelResult<()> {
        let mut pool = self.pool.lock().await;
        while pool.len() < n {
            let dir = self.root.join(format!("warm-{}", self.seq.fetch_add(1, Ordering::Relaxed)));
            std::fs::create_dir_all(&dir)?;
            pool.push(dir);
        }
        Ok(())
    }

    /// Take a pre-created workspace, if one is available.
    pub async fn take(&self) -> Option<PathBuf> {
        self.pool.lock().await.pop()
    }

    /// Number of idle workspaces currently pooled.
    pub async fn idle(&self) -> usize {
        self.pool.lock().await.len()
    }
}

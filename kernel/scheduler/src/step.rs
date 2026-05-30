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

fn budget_denial(op: &str, reason: String) -> KernelError {
    KernelError::Denied(Box::new(Denial {
        code: DenialCode::BudgetExhausted,
        attempted_operation: Operation::new(op),
        reason,
        safe_alternatives: Vec::new(),
        requestable_scopes: Vec::new(),
        escalation_allowed: true,
    }))
}

/// The step scheduler: routes each step through the [`BackendRouter`],
/// enforces the episode budget at step boundaries, bounds concurrent branch
/// fan-out with a semaphore, and records accounting for the ledger.
pub struct StepScheduler {
    router: BackendRouter,
    fanout: Arc<Semaphore>,
    remaining: Mutex<ResourceBudget>,
    records: Mutex<Vec<StepRecord>>,
    paused: Mutex<HashSet<BranchId>>,
    warm_pool: Option<WarmPool>,
}

impl StepScheduler {
    pub fn new(router: BackendRouter, config: SchedulerConfig) -> Self {
        Self {
            router,
            fanout: Arc::new(Semaphore::new(config.max_concurrent_branches.max(1))),
            remaining: Mutex::new(config.episode_budget),
            records: Mutex::new(Vec::new()),
            paused: Mutex::new(HashSet::new()),
            warm_pool: None,
        }
    }

    /// Attach a warm pool of local workspaces used by prewarm plans.
    pub fn with_warm_pool(mut self, pool: WarmPool) -> Self {
        self.warm_pool = Some(pool);
        self
    }

    /// Read-only access to the router (e.g. for capability introspection).
    pub fn router(&self) -> &BackendRouter {
        &self.router
    }

    /// Remaining episode budget.
    pub async fn remaining_budget(&self) -> ResourceBudget {
        *self.remaining.lock().await
    }

    // ---- idle-pause bookkeeping -------------------------------------------

    /// Mark a branch idle-paused; its steps are refused until resumed.
    pub async fn pause_branch(&self, branch: &BranchId) {
        self.paused.lock().await.insert(branch.clone());
    }

    /// Resume a paused branch.
    pub async fn resume_branch(&self, branch: &BranchId) {
        self.paused.lock().await.remove(branch);
    }

    pub async fn is_paused(&self, branch: &BranchId) -> bool {
        self.paused.lock().await.contains(branch)
    }

    // ---- prewarm ----------------------------------------------------------

    /// Intent-aware prewarm hook. Inspects a free-text intent hint and MAY
    /// warm a backend or local workspaces. It MUST NOT (and cannot) affect
    /// routing floors: the returned plan is advisory and is never an input to
    /// [`BackendRouter::route`]. Hints optimize; they never authorize.
    pub fn hint(&self, intent: &str) -> PrewarmPlan {
        let lower = intent.to_lowercase();
        let fork_like = ["fork", "fan-out", "fanout", "branch", "explore", "parallel"]
            .iter()
            .any(|k| lower.contains(k));
        if fork_like {
            let warm_backend = self
                .router
                .profiles()
                .into_iter()
                .filter(|p| p.supports_fork)
                .min_by_key(BackendRouter::cost)
                .map(|p| p.name);
            return PrewarmPlan {
                warm_backend,
                warm_workspaces: 0,
                note: "intent suggests branch fan-out; warm a fork-capable backend".into(),
            };
        }
        let build_like =
            ["build", "test", "compile", "lint", "install"].iter().any(|k| lower.contains(k));
        if build_like {
            return PrewarmPlan {
                warm_backend: None,
                warm_workspaces: 2,
                note: "intent suggests local build/test steps; keep workspaces warm".into(),
            };
        }
        PrewarmPlan { warm_backend: None, warm_workspaces: 0, note: "no prewarm".into() }
    }

    /// Apply a prewarm plan's local-workspace part against the warm pool.
    pub async fn apply_prewarm(&self, plan: &PrewarmPlan) -> KernelResult<()> {
        if plan.warm_workspaces > 0 {
            if let Some(pool) = &self.warm_pool {
                pool.fill(plan.warm_workspaces).await?;
            }
        }
        Ok(())
    }

    // ---- step execution ---------------------------------------------------

    /// Execute one step: enforce the budget, wait for a fan-out permit, route
    /// to the cheapest satisfying backend, execute, charge usage and record
    /// the step-boundary accounting entry.
    pub async fn execute_step(
        &self,
        step: StepId,
        req: ExecutionRequest,
        risk: RiskTier,
        needs: &Needs,
    ) -> KernelResult<ExecutionOutcome> {
        let op = req.action.required_operation().0.clone();
        if self.is_paused(&req.branch).await {
            return Err(KernelError::Denied(Box::new(Denial {
                code: DenialCode::PolicyForbidden,
                attempted_operation: Operation::new(op),
                reason: format!("branch `{}` is idle-paused; resume it first", req.branch),
                safe_alternatives: Vec::new(),
                requestable_scopes: Vec::new(),
                escalation_allowed: true,
            })));
        }

        // Refuse before spending anything if the step cannot fit.
        {
            let remaining = self.remaining.lock().await;
            if !req.budget.fits_within(&remaining) {
                return Err(budget_denial(
                    &op,
                    "episode budget cannot cover this step's requested budget".into(),
                ));
            }
        }

        // Branch fan-out budget: wait for a permit, measuring queue time.
        let queued = Instant::now();
        let _permit = self
            .fanout
            .clone()
            .acquire_owned()
            .await
            .map_err(|e| KernelError::Other(format!("scheduler shut down: {e}")))?;
        let queue_ms = queued.elapsed().as_millis() as u64;

        let backend = self.router.route(risk, needs)?;
        let backend_name = backend.profile().name;
        let branch = req.branch.clone();

        let started = Instant::now();
        let outcome = backend.execute(req).await?;
        let exec_ms = started.elapsed().as_millis() as u64;

        // Charge usage at the step boundary; report exhaustion honestly.
        {
            let mut remaining = self.remaining.lock().await;
            let exhausted = remaining.charge(&outcome.usage);
            if !exhausted.is_empty() {
                tracing::warn!(dimensions = ?exhausted, "episode budget dimension(s) exhausted");
            }
        }

        self.records.lock().await.push(StepRecord {
            step,
            branch,
            backend: backend_name,
            queue_ms,
            exec_ms,
            usage: outcome.usage,
            recorded_at: Utc::now(),
        });

        Ok(outcome)
    }

    /// Drain a copy of the step-boundary accounting records for the ledger.
    pub async fn records(&self) -> Vec<StepRecord> {
        self.records.lock().await.clone()
    }
}

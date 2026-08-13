//! Step scheduling: budget enforcement at step boundaries, branch fan-out
//! limits, idle-pause bookkeeping, intent-aware prewarming and the per-step
//! accounting record consumed by the causal ledger.
//!
//! ## Budget model (AK-005)
//!
//! Budgets are **per-episode accounts**, not one scheduler-global pool. A
//! step's requested budget is **reserved atomically before execution** (the
//! admission decision and the debit happen under one lock), and **settled to
//! the actual usage afterwards**: unspent reservation is refunded, overruns
//! beyond the reservation are charged and reported. Two concurrent steps can
//! therefore never both pass an admission check the account can only cover
//! once.

use crate::router::{BackendRouter, Needs, RiskTier};
use ak_core::budget::ResourceBudget;
use ak_core::capability::Operation;
use ak_core::denial::{Denial, DenialCode};
use ak_core::error::{KernelError, KernelResult};
use ak_core::ids::{BranchId, EpisodeId, StepId};
use ak_core::traits::{Backend, BackendProfile, ExecutionOutcome, ExecutionRequest};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::sync::RwLock as StdRwLock;
use std::time::Instant;
use tokio::sync::{Mutex, Semaphore};

/// An executed step's outcome plus the profile of the backend that ran
/// it. The kernel's state recording depends on the profile: only a
/// workspace-sharing backend's effects can be snapshotted into the DAG;
/// everything else is recorded as an audit-only excursion.
#[derive(Debug)]
pub struct RoutedOutcome {
    pub outcome: ExecutionOutcome,
    pub backend: BackendProfile,
}

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
    /// Budget installed for each episode's account when it is registered
    /// without an explicit envelope.
    pub episode_budget: ResourceBudget,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            max_concurrent_branches: 8,
            episode_budget: ResourceBudget::step_default(),
        }
    }
}

/// One episode's budget account: what is still spendable and what has been
/// settled as actually consumed.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct BudgetAccount {
    /// Remaining spendable envelope (reservations already subtracted).
    pub remaining: ResourceBudget,
    /// Cumulative settled usage.
    pub spent: ResourceBudget,
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
        Ok(Self {
            root,
            pool: Mutex::new(Vec::new()),
            seq: AtomicU64::new(0),
        })
    }

    /// Ensure at least `n` idle workspaces exist in the pool.
    pub async fn fill(&self, n: usize) -> KernelResult<()> {
        let mut pool = self.pool.lock().await;
        while pool.len() < n {
            let dir = self
                .root
                .join(format!("warm-{}", self.seq.fetch_add(1, Ordering::Relaxed)));
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
/// enforces per-episode budgets with reserve-then-settle semantics, bounds
/// concurrent branch fan-out with a semaphore, and records accounting for
/// the ledger.
pub struct StepScheduler {
    router: StdRwLock<BackendRouter>,
    fanout: Arc<Semaphore>,
    /// Per-episode budget accounts. A `std` mutex: critical sections are
    /// short and never held across an await point.
    accounts: StdMutex<HashMap<EpisodeId, BudgetAccount>>,
    default_episode_budget: ResourceBudget,
    records: Mutex<Vec<StepRecord>>,
    paused: Mutex<HashSet<BranchId>>,
    warm_pool: Option<WarmPool>,
}

impl StepScheduler {
    pub fn new(router: BackendRouter, config: SchedulerConfig) -> Self {
        Self {
            router: StdRwLock::new(router),
            fanout: Arc::new(Semaphore::new(config.max_concurrent_branches.max(1))),
            accounts: StdMutex::new(HashMap::new()),
            default_episode_budget: config.episode_budget,
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

    /// Register an additional isolation backend after construction.
    /// Registration order never affects routing (see [`BackendRouter`]).
    pub fn register_backend(&self, backend: Arc<dyn Backend>) {
        self.router_write().register(backend);
    }

    /// Profiles of every registered backend, for introspection.
    pub fn backend_profiles(&self) -> Vec<BackendProfile> {
        self.router_read().profiles()
    }

    fn router_read(&self) -> std::sync::RwLockReadGuard<'_, BackendRouter> {
        self.router.read().unwrap_or_else(|p| p.into_inner())
    }

    fn router_write(&self) -> std::sync::RwLockWriteGuard<'_, BackendRouter> {
        self.router.write().unwrap_or_else(|p| p.into_inner())
    }

    fn accounts(&self) -> std::sync::MutexGuard<'_, HashMap<EpisodeId, BudgetAccount>> {
        match self.accounts.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    // ---- per-episode budget accounts ---------------------------------------

    /// Open (or overwrite) an episode's budget account with `remaining`
    /// spendable and `spent` already settled. Called at episode creation and
    /// again at restart-recovery time with the persisted totals.
    pub fn register_episode(
        &self,
        episode: &EpisodeId,
        remaining: ResourceBudget,
        spent: ResourceBudget,
    ) {
        self.accounts()
            .insert(episode.clone(), BudgetAccount { remaining, spent });
    }

    /// Open an episode account with the configured default envelope.
    pub fn register_episode_default(&self, episode: &EpisodeId) {
        self.register_episode(episode, self.default_episode_budget, ResourceBudget::zero());
    }

    /// The configured default per-episode budget envelope.
    pub fn default_episode_budget(&self) -> ResourceBudget {
        self.default_episode_budget
    }

    /// Remaining budget of one episode's account.
    pub fn remaining_budget(&self, episode: &EpisodeId) -> Option<ResourceBudget> {
        self.accounts().get(episode).map(|a| a.remaining)
    }

    /// The full account (remaining + settled spend) of one episode.
    pub fn budget_account(&self, episode: &EpisodeId) -> Option<BudgetAccount> {
        self.accounts().get(episode).copied()
    }

    /// Drop an episode's account (episode ended).
    pub fn close_episode(&self, episode: &EpisodeId) {
        self.accounts().remove(episode);
    }

    /// Atomically reserve `amount` against an episode account. Admission and
    /// debit happen under one lock: concurrent reservations can never jointly
    /// exceed the remaining envelope. Returns the insufficient dimensions on
    /// refusal.
    fn reserve(
        &self,
        episode: &EpisodeId,
        amount: &ResourceBudget,
    ) -> Result<(), Vec<&'static str>> {
        let mut accounts = self.accounts();
        let account = accounts
            .get_mut(episode)
            .ok_or_else(|| vec!["unknown_episode"])?;
        if !amount.fits_within(&account.remaining) {
            return Err(amount.exceeding_dimensions(&account.remaining));
        }
        account.remaining = account.remaining.saturating_sub(amount);
        Ok(())
    }

    /// Settle a reservation to the actual usage: refund the unspent part,
    /// charge any overrun beyond the reservation, and add to the settled
    /// spend. Returns the overrun dimensions (empty when usage fit).
    fn settle(
        &self,
        episode: &EpisodeId,
        reserved: &ResourceBudget,
        usage: &ResourceBudget,
    ) -> Vec<&'static str> {
        let mut accounts = self.accounts();
        let Some(account) = accounts.get_mut(episode) else {
            return Vec::new();
        };
        let refund = reserved.saturating_sub(usage);
        let overrun_amount = usage.saturating_sub(reserved);
        account.remaining = account
            .remaining
            .saturating_add(&refund)
            .saturating_sub(&overrun_amount);
        account.spent = account.spent.saturating_add(usage);
        usage.exceeding_dimensions(reserved)
    }

    /// Return an unused reservation in full (execution failed before usage).
    fn refund(&self, episode: &EpisodeId, reserved: &ResourceBudget) {
        if let Some(account) = self.accounts().get_mut(episode) {
            account.remaining = account.remaining.saturating_add(reserved);
        }
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
                .router_read()
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
        let build_like = ["build", "test", "compile", "lint", "install"]
            .iter()
            .any(|k| lower.contains(k));
        if build_like {
            return PrewarmPlan {
                warm_backend: None,
                warm_workspaces: 2,
                note: "intent suggests local build/test steps; keep workspaces warm".into(),
            };
        }
        PrewarmPlan {
            warm_backend: None,
            warm_workspaces: 0,
            note: "no prewarm".into(),
        }
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

    /// Execute one step: atomically reserve the requested budget against the
    /// episode account, wait for a fan-out permit, route to the cheapest
    /// satisfying backend, execute, settle the reservation to actual usage
    /// and record the step-boundary accounting entry.
    pub async fn execute_step(
        &self,
        episode: &EpisodeId,
        step: StepId,
        req: ExecutionRequest,
        risk: RiskTier,
        needs: &Needs,
    ) -> KernelResult<RoutedOutcome> {
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

        // Reserve before spending anything: admission + debit are atomic, so
        // racing steps cannot jointly overdraw the account (AK-005).
        if let Err(short) = self.reserve(episode, &req.budget) {
            return Err(budget_denial(
                &op,
                format!(
                    "episode `{episode}` budget cannot cover this step's requested budget \
                     (insufficient: {})",
                    short.join(", ")
                ),
            ));
        }
        let reserved = req.budget;

        // Branch fan-out budget: wait for a permit, measuring queue time.
        let queued = Instant::now();
        let permit = match self.fanout.clone().acquire_owned().await {
            Ok(p) => p,
            Err(e) => {
                self.refund(episode, &reserved);
                return Err(KernelError::Other(format!("scheduler shut down: {e}")));
            }
        };
        let _permit = permit;
        let queue_ms = queued.elapsed().as_millis() as u64;

        let backend = match self.router_read().route(risk, needs) {
            Ok(b) => b,
            Err(e) => {
                self.refund(episode, &reserved);
                return Err(e);
            }
        };
        let backend_profile = backend.profile();
        let backend_name = backend_profile.name.clone();
        let branch = req.branch.clone();

        let started = Instant::now();
        let outcome = match backend.execute(req).await {
            Ok(o) => o,
            Err(e) => {
                // Nothing was measurably consumed on backend refusal; return
                // the reservation so a denied step does not leak budget.
                self.refund(episode, &reserved);
                return Err(e);
            }
        };
        let exec_ms = started.elapsed().as_millis() as u64;

        // Settle the reservation to actual usage; report overruns honestly.
        let overrun = self.settle(episode, &reserved, &outcome.usage);
        if !overrun.is_empty() {
            tracing::warn!(
                episode = %episode,
                dimensions = ?overrun,
                "step usage exceeded its reservation; overrun charged to the episode account"
            );
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

        Ok(RoutedOutcome {
            outcome,
            backend: backend_profile,
        })
    }

    /// Drain a copy of the step-boundary accounting records for the ledger.
    pub async fn records(&self) -> Vec<StepRecord> {
        self.records.lock().await.clone()
    }
}

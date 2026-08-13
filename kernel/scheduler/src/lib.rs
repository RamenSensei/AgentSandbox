//! # ak-scheduler
//!
//! The backend **router** and **step scheduler** of the AgentKernel.
//!
//! - [`BackendRouter`] holds a registry of [`ak_core::traits::Backend`]s and
//!   deterministically picks the *cheapest* backend whose profile satisfies
//!   both the risk-tier isolation floor and the request's compatibility
//!   [`Needs`].
//! - [`StepScheduler`] enforces per-step budgets, bounds branch fan-out with a
//!   semaphore, keeps idle-pause bookkeeping, exposes an intent-aware
//!   [`StepScheduler::hint`] prewarm hook, and records a per-step
//!   [`StepRecord`] for the causal ledger.
//!
//! ## Security invariant: hints optimize, never authorize
//!
//! Intent hints (free text on actions) may *warm* backends or workspaces so
//! that likely-next steps start faster. They are **never** an input to the
//! routing floor: a hint cannot lower the isolation requirement of a risk
//! tier, select a backend that fails the floor, or widen any confinement.

pub mod router;
pub mod step;

pub use router::{BackendRouter, Needs, RiskTier};
pub use step::{
    BudgetAccount, PrewarmPlan, RoutedOutcome, SchedulerConfig, StepRecord, StepScheduler, WarmPool,
};

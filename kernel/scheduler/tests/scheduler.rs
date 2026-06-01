//! Integration tests: step scheduler with mock backends and the real local
//! backend.

use ak_core::action::ActionKind;
use ak_core::budget::ResourceBudget;
use ak_core::error::{KernelError, KernelResult};
use ak_core::ids::{BranchId, PrincipalId, StateId, StepId};
use ak_core::replay::ReplayClass;
use ak_core::traits::{Backend, BackendProfile, ExecutionOutcome, ExecutionRequest};
use ak_scheduler::{BackendRouter, Needs, RiskTier, SchedulerConfig, StepScheduler, WarmPool};
use async_trait::async_trait;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

struct Slow {
    profile: BackendProfile,
    concurrent: Arc<AtomicUsize>,
    peak: Arc<AtomicUsize>,
}

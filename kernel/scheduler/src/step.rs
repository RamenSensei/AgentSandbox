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

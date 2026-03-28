//! The capability compiler: approved semantic grants → lease + confinement.

use crate::document::{PolicyDocument, PolicyRule, RuleEffect};
use crate::error::{PolicyError, PolicyResult};
use ak_core::budget::ResourceBudget;
use ak_core::capability::{CapabilityLease, Constraint, Operation};
use ak_core::ids::{BranchId, LeaseId};
use ak_core::principal::{Principal, TrustLevel};
use chrono::{DateTime, Duration, Utc};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

/// Syscall confinement profile a backend should apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyscallProfile {
    /// Default seccomp profile for trusted workloads.
    Standard,
    /// Tightened profile (no ptrace, no raw sockets, no user namespaces).
    Restricted,
    /// Restricted profile plus all network syscalls blocked.
    Networkless,
}

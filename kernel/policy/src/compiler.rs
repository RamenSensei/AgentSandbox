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

/// The compiled, backend-facing half of a grant. The fields mirror
/// [`ak_core::traits::ExecutionRequest`]: the scheduler copies
/// `writable_prefixes`, `readable_prefixes` and `egress_domains` straight into
/// the request it hands to a backend.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompiledConfinement {
    /// Workspace-relative prefixes the workload may write.
    pub writable_prefixes: Vec<String>,
    /// Workspace-relative prefixes the workload may read.
    pub readable_prefixes: Vec<String>,
    /// Egress domain allowlist (empty = no network).
    pub egress_domains: Vec<String>,
    /// Whether the backend must scrub the ambient environment (secrets never
    /// reach guests anyway; this removes even innocuous host env).
    pub env_scrub: bool,
    /// Syscall profile the backend applies.
    pub syscall_profile: SyscallProfile,
}

/// A fully compiled grant: the lease (authority) plus the confinement
/// (mechanism). Policy semantics live in the lease; backends only ever see
/// the confinement.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompiledGrant {
    pub lease: CapabilityLease,
    pub confinement: CompiledConfinement,
}

/// Compile the confinement for `principal` under `doc`.
///
/// Deterministic mapping:
/// - path prefixes come from the document's [`crate::PathPolicy`];
/// - egress domains come from the allowlist, except for operations outside
///   the `net`/network-using namespaces on quarantined principals;
/// - `env_scrub` is on for everything below [`TrustLevel::Standard`] and for
///   every non-`Elevated` principal by default;
/// - the syscall profile is [`SyscallProfile::Networkless`] when the egress
///   allowlist is empty, [`SyscallProfile::Restricted`] for principals below
///   [`TrustLevel::Standard`], and [`SyscallProfile::Standard`] otherwise.
pub fn compile_confinement(doc: &PolicyDocument, principal: &Principal) -> CompiledConfinement {
    let egress_domains = if principal.trust <= TrustLevel::Quarantined {
        Vec::new()
    } else {
        doc.egress_domains.clone()
    };
    let syscall_profile = if egress_domains.is_empty() {
        SyscallProfile::Networkless
    } else if principal.trust < TrustLevel::Standard {
        SyscallProfile::Restricted
    } else {
        SyscallProfile::Standard
    };
    CompiledConfinement {
        writable_prefixes: doc.paths.writable_prefixes.clone(),
        readable_prefixes: doc.paths.readable_prefixes.clone(),
        egress_domains,
        env_scrub: principal.trust < TrustLevel::Elevated,
        syscall_profile,
    }
}

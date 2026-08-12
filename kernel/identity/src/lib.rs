//! # ak-identity
//!
//! Identity, capability-lease persistence, delegation, and kernel signing for
//! AgentKernel.
//!
//! This crate provides the durable side of the "no ambient authority"
//! invariant defined in [`ak_core`]:
//!
//! - [`PrincipalRegistry`] — a rusqlite-backed registry of every
//!   [`ak_core::Principal`] (agents, sub-agents, tools, humans), with
//!   parent/child lineage queries.
//! - [`LeaseStore`] — durable [`ak_core::CapabilityLease`] rows with
//!   consume-a-use semantics, expiry sweeping, and **cascading revocation**:
//!   revoking a lease also revokes every lease transitively attenuated from it.
//! - [`DelegationService`] — the audited wrapper around
//!   [`ak_core::CapabilityLease::attenuate`] that additionally enforces
//!   registry-level rules (the delegatee must exist and must be the delegator
//!   itself or one of its descendants) and records every delegation.
//! - [`KernelKeypair`] — the Ed25519 identity of the kernel itself, used to
//!   sign effect receipts over their canonical-JSON encoding.
//!
//! All stores share one SQLite connection through [`IdentityDb`], so
//! registry + lease operations live in the same database file (or in-memory
//! database for tests).

pub mod db;
pub mod delegation;
pub mod error;
pub mod keys;
pub mod lease_store;
pub mod registry;
pub mod sealing;

pub use db::IdentityDb;
pub use delegation::{DelegationRecord, DelegationService};
pub use error::{IdentityError, IdentityResult};
pub use keys::KernelKeypair;
pub use lease_store::LeaseStore;
pub use registry::PrincipalRegistry;
pub use sealing::SealKey;

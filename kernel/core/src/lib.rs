//! # ak-core
//!
//! Core semantic types of the AgentKernel: the vocabulary every other crate
//! speaks. Nothing in this crate performs I/O; it defines the *execution
//! semantics* of an agent-native sandbox:
//!
//! - [`EpisodeId`], [`StepId`], [`BranchId`], [`StateId`] — the world-state DAG.
//! - [`Principal`] — agents, sub-agents and tools as first-class identities.
//! - [`capability::CapabilityLease`] — time-bound, budgeted, attenuable authority.
//! - [`effect`] — proposed/prepared/committed external effects and signed receipts.
//! - [`observation`] — structured observations, including machine-readable denials.
//! - [`replay::ReplayClass`] — honest, per-backend replay guarantees.
//!
//! ## Invariants (enforced across the workspace)
//!
//! 1. **No ambient authority.** Every action carries an explicit lease.
//! 2. **No invisible state transition.** Every step produces a delta and a ledger entry.
//! 3. **No irreversible effect before commit.** External effects go through the broker.
//! 4. **No denial without a machine-readable explanation.**

pub mod action;
pub mod b64;
pub mod budget;
pub mod capability;
pub mod denial;
pub mod effect;
pub mod error;
pub mod hash;
pub mod ids;
pub mod net;
pub mod observation;
pub mod path;
pub mod principal;
pub mod replay;
pub mod state;
pub mod sync;
pub mod traits;

pub use action::{Action, ActionKind};
pub use budget::ResourceBudget;
pub use capability::{CapabilityLease, Constraint, Operation};
pub use denial::Denial;
pub use effect::{EffectClass, EffectContract, PendingEffect, Receipt};
pub use error::{KernelError, KernelResult};
pub use ids::{BranchId, EpisodeId, LeaseId, PrincipalId, StateId, StepId};
pub use observation::Observation;
pub use principal::{Principal, PrincipalKind, TrustLevel};
pub use replay::ReplayClass;
pub use state::{StateDelta, StateNode};
pub use traits::{
    Backend, CommitProbe, Connector, ExecutionOutcome, ExecutionRequest, StateProvider,
    WorkspaceDelta,
};

/// Semantic version of the Agent Execution Protocol implemented by this tree.
pub const PROTOCOL_VERSION: &str = "0.8";

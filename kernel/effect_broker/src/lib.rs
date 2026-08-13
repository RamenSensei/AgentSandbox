//! # ak-effect-broker
//!
//! The transactional gate between an agent's sandbox and the real world.
//!
//! Every external effect flows through the two-phase lifecycle defined by
//! [`ak_core::effect`]:
//!
//! ```text
//! propose → prepare (dry-run preview) → approve → COMMIT-TIME REVALIDATION → commit
//!                                                        │ any check fails
//!                                                        └────────→ abort (StaleAuthorization)
//! ```
//!
//! At commit time the broker re-observes the external world through the
//! connector, and aborts with [`ak_core::KernelError::StaleAuthorization`] if
//! *anything* the approval was based on has drifted: preconditions, the
//! contract hash, the policy epoch, or the capability lease.
//!
//! Effects classified [`EffectClass::Irreversible`] or
//! [`EffectClass::OpaqueExternal`] can never be committed without an explicit
//! [`EffectBroker::approve`] step; the state machine enforces this.
//!
//! The [`secrets`] module holds real credentials. **No raw credential ever
//! enters the guest**: secrets are readable only through scoped closures on
//! the host-side connector path, never through any serializable type.

pub mod broker;
pub mod secrets;

pub use broker::{EffectBroker, InDoubtResolution, OperatorResolution, ReceiptSigner};
pub use secrets::{ScopedToken, SecretVault};

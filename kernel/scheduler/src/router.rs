//! Backend routing: pick the cheapest backend that satisfies the risk floor
//! and compatibility needs.
//!
//! ## Routing rule (deterministic, documented)
//!
//! 1. A [`RiskTier`] maps to a **minimum isolation strength** (the "floor"):
//!    `Low >= 20`, `Medium >= 60`, `High >= 85`. The floor is a hard
//!    requirement — nothing (in particular no intent hint) can lower it.
//! 2. A candidate backend must additionally satisfy every set flag in
//!    [`Needs`] (`full_linux`, `gui`, `fork`) and, when `replay_at_least` is
//!    set, advertise a replay class at least that strong (using the total
//!    order on [`ReplayClass`]).
//! 3. Among the satisfying candidates, the **cheapest** wins, by the cost
//!    model `cost = cold_start_ms + 10 * isolation_strength` (stronger
//!    isolation carries per-step overhead: syscall interception, guest
//!    kernels, network hops). Ties break lexicographically on the backend
//!    name, so routing is fully deterministic.
//! 4. If no backend satisfies the requirements the router returns
//!    [`KernelError::BackendUnavailable`].

use ak_core::error::{KernelError, KernelResult};
use ak_core::replay::ReplayClass;
use ak_core::traits::{Backend, BackendProfile};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

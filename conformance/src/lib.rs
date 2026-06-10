//! # ak-conformance
//!
//! The protocol conformance suite: table-driven scenarios loaded from
//! `conformance/cases/*.yaml`, each driven against the [`ak_api::Kernel`]
//! façade by a scenario driver keyed on the case's `kind`.
//!
//! Run with `cargo test -p ak-conformance`.

use ak_api::{Kernel, KernelConfig};
use ak_core::action::{Action, ActionKind};
use ak_core::budget::ResourceBudget;
use ak_core::capability::{Constraint, Operation};
use ak_core::denial::DenialCode;
use ak_core::effect::{EffectClass, EffectContract, EffectPhase};
use ak_core::ids::{BranchId, LeaseId, StepId};
use ak_core::observation::Observation;
use ak_core::replay::{ReplayClass, ReplayMode};
use ak_core::traits::{CommitResult, Connector, PreparedEffect};
use ak_core::{KernelError, KernelResult, Principal};
use ak_policy::{PolicyDocument, PolicyRule, PrincipalSelector, RuleEffect};
use async_trait::async_trait;
use chrono::{Duration, Utc};
use indexmap::IndexMap;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

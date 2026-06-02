//! JSON/HTTP binding of the Agent Execution Protocol (see
//! `protocol/openapi.yaml`).
//!
//! Errors are returned as [`ak_core::error::ErrorEnvelope`]; policy denials
//! are HTTP 403 carrying the full machine-readable [`ak_core::Denial`].

use crate::kernel::Kernel;
use ak_causal_ledger::{EventKind, TraceQuery};
use ak_core::action::Action;
use ak_core::budget::ResourceBudget;
use ak_core::capability::{Constraint, Operation};
use ak_core::error::{ErrorEnvelope, KernelError};
use ak_core::ids::{BranchId, EffectId, EpisodeId, LeaseId, PrincipalId, ReceiptId, StateId};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use indexmap::IndexMap;
use serde::Deserialize;
use std::sync::Arc;

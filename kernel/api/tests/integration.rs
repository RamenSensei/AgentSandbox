//! Integration tests: full lifecycle against the [`Kernel`] façade plus HTTP
//! smoke tests via `tower::ServiceExt::oneshot`.

use ak_api::{http, Kernel, KernelConfig};
use ak_core::action::{Action, ActionKind};
use ak_core::budget::ResourceBudget;
use ak_core::capability::Operation;
use ak_core::denial::DenialCode;
use ak_core::effect::{EffectClass, EffectContract};
use ak_core::ids::LeaseId;
use ak_core::observation::Observation;
use ak_core::traits::{CommitResult, Connector, PreparedEffect};
use ak_core::{KernelResult, Principal};
use ak_policy::{PolicyDocument, PolicyRule, PrincipalSelector, RuleEffect};
use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use indexmap::IndexMap;
use serde_json::json;
use std::collections::BTreeMap;
use std::sync::Arc;
use tower::ServiceExt;

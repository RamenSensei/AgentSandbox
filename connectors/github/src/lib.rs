//! # ak-connector-github
//!
//! A **typed, deliberately narrow** GitHub connector implementing
//! [`ak_core::Connector`] over the REST API.
//!
//! Supported operations (and *only* these — merge, delete and admin
//! operations intentionally do not exist in this connector):
//!
//! | operation                          | class          | compensation      |
//! |------------------------------------|----------------|-------------------|
//! | `github.read_repository`           | `Pure`         | n/a               |
//! | `github.create_branch`             | `Compensatable`| delete the ref    |
//! | `github.create_draft_pull_request` | `Compensatable`| close the PR      |
//! | `github.comment_on_issue`          | `Irreversible` | none              |
//!
//! The base URL is injectable so tests can point at a mock server.
//! Credentials come through the minimal [`TokenSource`] trait — the secret
//! broker (ak-effect-broker's `SecretVault`) plugs in on the host side; the
//! token is used only to build a request header and is never stored,
//! logged, or serialized.

use ak_core::effect::{EffectClass, EffectContract};
use ak_core::traits::{CommitResult, Connector, PreparedEffect};
use ak_core::{KernelError, KernelResult};
use async_trait::async_trait;
use serde_json::{json, Value};
use std::sync::Arc;
use tracing::{debug, instrument};

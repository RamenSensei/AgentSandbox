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

/// Minimal credential source. Implementations lend a live token; callers
/// must use it immediately for a request and must not persist it.
pub trait TokenSource: Send + Sync {
    /// Return the current API token.
    fn token(&self) -> KernelResult<String>;
}

/// A fixed token, for tests and simple deployments.
pub struct StaticTokenSource(pub String);

impl TokenSource for StaticTokenSource {
    fn token(&self) -> KernelResult<String> {
        Ok(self.0.clone())
    }
}

/// The GitHub connector. See crate docs for the operation table.
pub struct GithubConnector {
    base_url: String,
    client: reqwest::Client,
    tokens: Arc<dyn TokenSource>,
}

impl std::fmt::Debug for GithubConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GithubConnector").field("base_url", &self.base_url).finish_non_exhaustive()
    }
}

const OP_READ_REPO: &str = "github.read_repository";
const OP_CREATE_BRANCH: &str = "github.create_branch";
const OP_CREATE_DRAFT_PR: &str = "github.create_draft_pull_request";
const OP_COMMENT_ISSUE: &str = "github.comment_on_issue";

fn conn_err(msg: impl std::fmt::Display) -> KernelError {
    KernelError::Connector(msg.to_string())
}

impl GithubConnector {
    /// Create a connector against `base_url` (e.g. `https://api.github.com`
    /// or a mock server; no trailing slash).
    pub fn new(base_url: impl Into<String>, tokens: Arc<dyn TokenSource>) -> Self {
        let mut base_url = base_url.into();
        while base_url.ends_with('/') {
            base_url.pop();
        }
        Self { base_url, client: reqwest::Client::new(), tokens }
    }

    async fn request(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<&Value>,
    ) -> KernelResult<Value> {
        let url = format!("{}{}", self.base_url, path);
        debug!(%method, %path, "github request");
        // The token is lent for exactly this request and dropped.
        let token = self.tokens.token()?;
        let mut req = self
            .client
            .request(method, &url)
            .header("Authorization", format!("Bearer {token}"))
            .header("Accept", "application/vnd.github+json")
            .header("User-Agent", "agent-kernel");
        drop(token);
        if let Some(b) = body {
            req = req.json(b);
        }
        let resp = req.send().await.map_err(conn_err)?;
        let status = resp.status();
        let text = resp.text().await.map_err(conn_err)?;
        if !status.is_success() {
            return Err(conn_err(format!("github {path} returned {status}: {text}")));
        }
        if text.is_empty() {
            Ok(Value::Null)
        } else {
            serde_json::from_str(&text).map_err(KernelError::from)
        }
    }

    fn get_str<'a>(args: &'a Value, key: &str) -> KernelResult<&'a str> {
        args.get(key)
            .and_then(Value::as_str)
            .ok_or_else(|| conn_err(format!("missing or non-string required field `{key}`")))
    }

    async fn branch_head_sha(&self, owner: &str, repo: &str, branch: &str) -> KernelResult<String> {
        let v = self
            .request(reqwest::Method::GET, &format!("/repos/{owner}/{repo}/git/ref/heads/{branch}"), None)
            .await?;
        v.pointer("/object/sha")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| conn_err(format!("ref heads/{branch}: response missing object.sha")))
    }
}

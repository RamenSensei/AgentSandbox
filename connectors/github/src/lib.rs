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

/// Validate `args` has exactly the `required` (string) fields plus optional
/// string fields from `optional`; reject unknown fields.
fn validate_fields(args: &Value, required: &[&str], optional: &[&str]) -> KernelResult<()> {
    let obj = args
        .as_object()
        .ok_or_else(|| conn_err("arguments must be a JSON object"))?;
    for key in obj.keys() {
        if !required.contains(&key.as_str()) && !optional.contains(&key.as_str()) {
            return Err(conn_err(format!("unknown field `{key}`")));
        }
    }
    for key in required {
        GithubConnector::get_str(args, key)?;
    }
    for key in *&optional {
        if let Some(v) = obj.get(*key) {
            if !v.is_string() {
                return Err(conn_err(format!("field `{key}` must be a string")));
            }
        }
    }
    Ok(())
}

#[async_trait]
impl Connector for GithubConnector {
    fn name(&self) -> &str {
        "github"
    }

    fn operations(&self) -> Vec<(String, EffectClass)> {
        vec![
            (OP_READ_REPO.into(), EffectClass::Pure),
            (OP_CREATE_BRANCH.into(), EffectClass::Compensatable),
            (OP_CREATE_DRAFT_PR.into(), EffectClass::Compensatable),
            (OP_COMMENT_ISSUE.into(), EffectClass::Irreversible),
        ]
    }

    #[instrument(skip(self, args))]
    fn canonicalize(&self, operation: &str, args: &Value) -> KernelResult<Value> {
        match operation {
            OP_READ_REPO => validate_fields(args, &["owner", "repo"], &[])?,
            OP_CREATE_BRANCH => {
                validate_fields(args, &["owner", "repo", "branch", "from_branch"], &[])?
            }
            OP_CREATE_DRAFT_PR => validate_fields(
                args,
                &["owner", "repo", "title", "head", "base"],
                &["body"],
            )?,
            OP_COMMENT_ISSUE => {
                validate_fields(args, &["owner", "repo", "body"], &["issue_number"])?;
                // issue_number is required, but numeric.
                if !args.get("issue_number").map(Value::is_u64).unwrap_or(false) {
                    return Err(conn_err("`issue_number` must be an unsigned integer"));
                }
            }
            other => {
                return Err(conn_err(format!(
                    "unsupported operation `{other}` (merge/delete/admin operations do not exist)"
                )))
            }
        }
        // serde_json's default map is a BTreeMap, so re-encoding yields
        // key-sorted, canonical-ordered arguments.
        Ok(args.clone())
    }

    /// Observe the live world. Pure dry-run: only GET requests are issued.
    #[instrument(skip(self, contract), fields(operation = %contract.operation))]
    async fn prepare(&self, contract: &EffectContract) -> KernelResult<PreparedEffect> {
        let args = &contract.arguments;
        match contract.operation.as_str() {
            OP_READ_REPO => {
                let (owner, repo) = (Self::get_str(args, "owner")?, Self::get_str(args, "repo")?);
                let v = self.request(reqwest::Method::GET, &format!("/repos/{owner}/{repo}"), None).await?;
                Ok(PreparedEffect {
                    preview: json!({
                        "action": "read repository metadata",
                        "full_name": v.get("full_name").cloned().unwrap_or(Value::Null),
                    }),
                    observed_preconditions: json!({}),
                })
            }
            OP_CREATE_BRANCH => {
                let (owner, repo) = (Self::get_str(args, "owner")?, Self::get_str(args, "repo")?);
                let from = Self::get_str(args, "from_branch")?;
                let branch = Self::get_str(args, "branch")?;
                let sha = self.branch_head_sha(owner, repo, from).await?;
                Ok(PreparedEffect {
                    preview: json!({
                        "action": format!("create branch `{branch}` from `{from}`"),
                        "ref": format!("refs/heads/{branch}"),
                        "sha": sha,
                    }),
                    observed_preconditions: json!({ "base_head_sha": sha }),
                })
            }
            OP_CREATE_DRAFT_PR => {
                let (owner, repo) = (Self::get_str(args, "owner")?, Self::get_str(args, "repo")?);
                let base = Self::get_str(args, "base")?;
                let sha = self.branch_head_sha(owner, repo, base).await?;
                Ok(PreparedEffect {
                    preview: json!({
                        "action": format!(
                            "open DRAFT pull request `{}` ({} <- {})",
                            Self::get_str(args, "title")?,
                            base,
                            Self::get_str(args, "head")?,
                        ),
                        "draft": true,
                    }),
                    observed_preconditions: json!({ "base_head_sha": sha }),
                })
            }
            OP_COMMENT_ISSUE => {
                let (owner, repo) = (Self::get_str(args, "owner")?, Self::get_str(args, "repo")?);
                let n = args
                    .get("issue_number")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| conn_err("`issue_number` must be an unsigned integer"))?;
                let v = self
                    .request(reqwest::Method::GET, &format!("/repos/{owner}/{repo}/issues/{n}"), None)
                    .await?;
                let state = v
                    .get("state")
                    .and_then(Value::as_str)
                    .ok_or_else(|| conn_err("issue response missing state"))?;
                Ok(PreparedEffect {
                    preview: json!({
                        "action": format!("comment on issue #{n} (IRREVERSIBLE once read)"),
                        "body": args.get("body").cloned().unwrap_or(Value::Null),
                    }),
                    observed_preconditions: json!({ "issue_state": state }),
                })
            }
            other => Err(conn_err(format!("unsupported operation `{other}`"))),
        }
    }

    #[instrument(skip(self, contract), fields(operation = %contract.operation))]
    async fn commit(&self, contract: &EffectContract) -> KernelResult<CommitResult> {
        let args = &contract.arguments;
        match contract.operation.as_str() {
            OP_READ_REPO => {
                let (owner, repo) = (Self::get_str(args, "owner")?, Self::get_str(args, "repo")?);
                let v = self.request(reqwest::Method::GET, &format!("/repos/{owner}/{repo}"), None).await?;
                Ok(CommitResult {
                    response: json!({
                        "full_name": v.get("full_name").cloned().unwrap_or(Value::Null),
                        "default_branch": v.get("default_branch").cloned().unwrap_or(Value::Null),
                        "private": v.get("private").cloned().unwrap_or(Value::Null),
                    }),
                })
            }
            OP_CREATE_BRANCH => {
                let (owner, repo) = (Self::get_str(args, "owner")?, Self::get_str(args, "repo")?);
                let from = Self::get_str(args, "from_branch")?;
                let branch = Self::get_str(args, "branch")?;
                let sha = self.branch_head_sha(owner, repo, from).await?;
                let v = self
                    .request(
                        reqwest::Method::POST,
                        &format!("/repos/{owner}/{repo}/git/refs"),
                        Some(&json!({ "ref": format!("refs/heads/{branch}"), "sha": sha })),
                    )
                    .await?;
                Ok(CommitResult {
                    response: json!({
                        "ref": v.get("ref").cloned().unwrap_or(Value::Null),
                        "sha": sha,
                    }),
                })
            }
            OP_CREATE_DRAFT_PR => {
                let (owner, repo) = (Self::get_str(args, "owner")?, Self::get_str(args, "repo")?);
                let body = json!({
                    "title": Self::get_str(args, "title")?,
                    "head": Self::get_str(args, "head")?,
                    "base": Self::get_str(args, "base")?,
                    "body": args.get("body").cloned().unwrap_or(Value::String(String::new())),
                    "draft": true,
                });
                let v = self
                    .request(reqwest::Method::POST, &format!("/repos/{owner}/{repo}/pulls"), Some(&body))
                    .await?;
                Ok(CommitResult {
                    response: json!({
                        "number": v.get("number").cloned().unwrap_or(Value::Null),
                        "html_url": v.get("html_url").cloned().unwrap_or(Value::Null),
                        "draft": true,
                    }),
                })
            }
            OP_COMMENT_ISSUE => {
                let (owner, repo) = (Self::get_str(args, "owner")?, Self::get_str(args, "repo")?);
                let n = args
                    .get("issue_number")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| conn_err("`issue_number` must be an unsigned integer"))?;
                let v = self
                    .request(
                        reqwest::Method::POST,
                        &format!("/repos/{owner}/{repo}/issues/{n}/comments"),
                        Some(&json!({ "body": Self::get_str(args, "body")? })),
                    )
                    .await?;
                Ok(CommitResult {
                    response: json!({ "id": v.get("id").cloned().unwrap_or(Value::Null) }),
                })
            }
            other => Err(conn_err(format!("unsupported operation `{other}`"))),
        }
    }

    /// Compensation: delete the created ref, or close the draft PR. Comments
    /// and reads are not compensatable.
    #[instrument(skip(self, contract), fields(operation = %contract.operation))]
    async fn compensate(&self, contract: &EffectContract) -> KernelResult<CommitResult> {
        let args = &contract.arguments;
        match contract.operation.as_str() {
            OP_CREATE_BRANCH => {
                let (owner, repo) = (Self::get_str(args, "owner")?, Self::get_str(args, "repo")?);
                let branch = Self::get_str(args, "branch")?;
                self.request(
                    reqwest::Method::DELETE,
                    &format!("/repos/{owner}/{repo}/git/refs/heads/{branch}"),
                    None,
                )
                .await?;
                Ok(CommitResult { response: json!({ "deleted_ref": format!("refs/heads/{branch}") }) })
            }
            OP_CREATE_DRAFT_PR => {
                let (owner, repo) = (Self::get_str(args, "owner")?, Self::get_str(args, "repo")?);
                let head = Self::get_str(args, "head")?;
                // Find the open PR for this head and close it.
                let prs = self
                    .request(
                        reqwest::Method::GET,
                        &format!("/repos/{owner}/{repo}/pulls?state=open&head={owner}:{head}"),
                        None,
                    )
                    .await?;
                let number = prs
                    .as_array()
                    .and_then(|a| a.first())
                    .and_then(|pr| pr.get("number"))
                    .and_then(Value::as_u64)
                    .ok_or_else(|| conn_err(format!("no open PR found for head `{head}`")))?;
                let v = self
                    .request(
                        reqwest::Method::PATCH,
                        &format!("/repos/{owner}/{repo}/pulls/{number}"),
                        Some(&json!({ "state": "closed" })),
                    )
                    .await?;
                Ok(CommitResult {
                    response: json!({
                        "closed_pr": number,
                        "state": v.get("state").cloned().unwrap_or(Value::Null),
                    }),
                })
            }
            other => Err(conn_err(format!("operation `{other}` is not compensatable"))),
        }
    }
}

//! Bearer-token authentication and per-resource authorization for the HTTP
//! control plane.
//!
//! # Model
//!
//! - Every request (except `/healthz`) must carry `Authorization: Bearer
//!   <token>` when auth is enabled. Tokens are compared by SHA-256 digest in
//!   constant time.
//! - A token maps to an authenticated [`PrincipalId`] plus a role set.
//!   Principals in request bodies are **not trusted**: they must match the
//!   authenticated principal unless the caller holds [`Role::Admin`].
//! - Effect approval requires [`Role::Approver`]; the approver recorded is
//!   the *authenticated* principal, never a body-supplied one.
//! - Ownership: episode- and branch-scoped operations are restricted to the
//!   episode's creator (or an admin).
//!
//! # Disabled mode
//!
//! [`AuthConfig::disabled`] preserves the legacy trust-the-body behavior for
//! local development and in-process tests. The server binary refuses to
//! combine disabled auth with a non-loopback listen address.

use ak_core::error::{ErrorEnvelope, KernelError};
use ak_core::ids::PrincipalId;
use axum::extract::Request;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;

/// Coarse-grained roles carried by an API token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Full control plane access, may act on behalf of any principal.
    Admin,
    /// May approve effects (a human or an approval service).
    Approver,
    /// May drive its own episodes, steps, and capability requests.
    Agent,
}

/// One token entry in the auth config file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenEntry {
    /// SHA-256 of the bearer token, lowercase hex. The plaintext token never
    /// appears in config.
    pub token_sha256: String,
    /// The principal this token authenticates as.
    pub principal: PrincipalId,
    /// Roles granted to the token.
    pub roles: Vec<Role>,
}

/// Authentication configuration for [`crate::http::router`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuthConfig {
    /// When false, requests are anonymous and body principals are trusted
    /// (legacy/local-dev mode).
    pub enabled: bool,
    /// Registered tokens (keyed by SHA-256 digest at load time).
    #[serde(default)]
    pub tokens: Vec<TokenEntry>,
}

impl AuthConfig {
    /// Legacy trust-the-body mode for loopback development and tests.
    pub fn disabled() -> Self {
        Self::default()
    }

    /// Token-authenticated mode.
    pub fn with_tokens(tokens: Vec<TokenEntry>) -> Self {
        Self {
            enabled: true,
            tokens,
        }
    }

    /// Load from a YAML file.
    pub fn from_yaml_file(path: &std::path::Path) -> Result<Self, KernelError> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| KernelError::Other(format!("read auth config: {e}")))?;
        serde_yaml::from_str(&text).map_err(|e| KernelError::Other(format!("auth config: {e}")))
    }

    fn digest_map(&self) -> HashMap<String, (PrincipalId, Vec<Role>)> {
        self.tokens
            .iter()
            .map(|t| {
                (
                    t.token_sha256.to_ascii_lowercase(),
                    (t.principal.clone(), t.roles.clone()),
                )
            })
            .collect()
    }
}

/// Hash a plaintext bearer token to its config digest form.
pub fn token_digest(token: &str) -> String {
    let mut h = Sha256::new();
    h.update(token.as_bytes());
    hex::encode(h.finalize())
}

/// The authenticated caller, inserted as a request extension by
/// [`require_auth`].
#[derive(Debug, Clone)]
pub struct AuthContext {
    /// Authenticated principal; `None` only in disabled mode.
    pub principal: Option<PrincipalId>,
    roles: Arc<Vec<Role>>,
    disabled: bool,
}

impl AuthContext {
    fn anonymous() -> Self {
        Self {
            principal: None,
            roles: Arc::new(Vec::new()),
            disabled: true,
        }
    }

    /// True when the caller holds `role` (disabled mode grants everything).
    pub fn has_role(&self, role: Role) -> bool {
        self.disabled || self.roles.contains(&role) || self.roles.contains(&Role::Admin)
    }

    /// Resolve the principal a request acts as: in authenticated mode the
    /// body principal must equal the token principal unless the caller is an
    /// admin; in disabled mode the body is trusted.
    pub fn act_as(&self, body_principal: &PrincipalId) -> Result<PrincipalId, AuthError> {
        match &self.principal {
            None => Ok(body_principal.clone()),
            Some(p) if p == body_principal || self.has_role(Role::Admin) => {
                Ok(body_principal.clone())
            }
            Some(_) => Err(AuthError::PrincipalMismatch),
        }
    }

    /// Require that the caller owns `owner`'s resources or is an admin.
    pub fn require_owner(&self, owner: &PrincipalId) -> Result<(), AuthError> {
        match &self.principal {
            None => Ok(()),
            Some(p) if p == owner || self.has_role(Role::Admin) => Ok(()),
            Some(_) => Err(AuthError::NotOwner),
        }
    }

    /// Require a role outright.
    pub fn require_role(&self, role: Role) -> Result<(), AuthError> {
        if self.has_role(role) {
            Ok(())
        } else {
            Err(AuthError::MissingRole(role))
        }
    }
}

/// Authorization failures surfaced as HTTP 401/403.
#[derive(Debug)]
pub enum AuthError {
    /// No/invalid bearer token.
    Unauthenticated,
    /// Body principal differs from the authenticated one.
    PrincipalMismatch,
    /// Caller does not own the target resource.
    NotOwner,
    /// Caller lacks a required role.
    MissingRole(Role),
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, code, msg) = match self {
            AuthError::Unauthenticated => (
                StatusCode::UNAUTHORIZED,
                "UNAUTHENTICATED",
                "missing or invalid bearer token".to_string(),
            ),
            AuthError::PrincipalMismatch => (
                StatusCode::FORBIDDEN,
                "PRINCIPAL_MISMATCH",
                "request principal does not match the authenticated principal".to_string(),
            ),
            AuthError::NotOwner => (
                StatusCode::FORBIDDEN,
                "NOT_OWNER",
                "caller does not own the target resource".to_string(),
            ),
            AuthError::MissingRole(role) => (
                StatusCode::FORBIDDEN,
                "MISSING_ROLE",
                format!("caller lacks required role {role:?}"),
            ),
        };
        (
            status,
            Json(ErrorEnvelope {
                code: code.into(),
                message: msg,
                denial: None,
            }),
        )
            .into_response()
    }
}

/// Constant-time equality over the two digests' bytes.
fn digest_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Axum middleware enforcing bearer auth per [`AuthConfig`].
pub async fn require_auth(
    axum::extract::State(cfg): axum::extract::State<Arc<AuthConfig>>,
    mut req: Request,
    next: Next,
) -> Response {
    if !cfg.enabled {
        req.extensions_mut().insert(AuthContext::anonymous());
        return next.run(req).await;
    }
    // The liveness probe is deliberately unauthenticated.
    if req.uri().path() == "/healthz" {
        req.extensions_mut().insert(AuthContext::anonymous());
        return next.run(req).await;
    }
    let token = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim);
    let Some(token) = token else {
        return AuthError::Unauthenticated.into_response();
    };
    let digest = token_digest(token);
    // Scan every entry with a constant-time comparison so timing does not
    // reveal digest prefixes.
    let mut matched: Option<(PrincipalId, Vec<Role>)> = None;
    for (entry_digest, identity) in cfg.digest_map() {
        if digest_eq(&digest, &entry_digest) {
            matched = Some(identity);
        }
    }
    let Some((principal, roles)) = matched else {
        return AuthError::Unauthenticated.into_response();
    };
    req.extensions_mut().insert(AuthContext {
        principal: Some(principal),
        roles: Arc::new(roles),
        disabled: false,
    });
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(principal: &str, roles: Vec<Role>) -> AuthContext {
        AuthContext {
            principal: Some(PrincipalId::parse(principal).unwrap()),
            roles: Arc::new(roles),
            disabled: false,
        }
    }

    #[test]
    fn digest_comparison_is_length_and_content_sensitive() {
        assert!(digest_eq("abc", "abc"));
        assert!(!digest_eq("abc", "abd"));
        assert!(!digest_eq("abc", "abcd"));
    }

    #[test]
    fn body_principal_must_match_token_principal() {
        let c = ctx("pr-aaaaaaaaaaaaaaaaaaaaaaaaaa", vec![Role::Agent]);
        let me = c.principal.clone().unwrap();
        let other = PrincipalId::parse("pr-bbbbbbbbbbbbbbbbbbbbbbbbbb").unwrap();
        assert!(c.act_as(&me).is_ok());
        assert!(matches!(
            c.act_as(&other),
            Err(AuthError::PrincipalMismatch)
        ));
    }

    #[test]
    fn admin_may_act_for_anyone_and_owns_everything() {
        let c = ctx("pr-aaaaaaaaaaaaaaaaaaaaaaaaaa", vec![Role::Admin]);
        let other = PrincipalId::parse("pr-bbbbbbbbbbbbbbbbbbbbbbbbbb").unwrap();
        assert!(c.act_as(&other).is_ok());
        assert!(c.require_owner(&other).is_ok());
        assert!(c.require_role(Role::Approver).is_ok());
    }

    #[test]
    fn approver_role_is_required_for_approval() {
        let c = ctx("pr-aaaaaaaaaaaaaaaaaaaaaaaaaa", vec![Role::Agent]);
        assert!(matches!(
            c.require_role(Role::Approver),
            Err(AuthError::MissingRole(Role::Approver))
        ));
    }

    #[test]
    fn disabled_mode_trusts_the_body() {
        let c = AuthContext::anonymous();
        let p = PrincipalId::parse("pr-cccccccccccccccccccccccccc").unwrap();
        assert!(c.act_as(&p).is_ok());
        assert!(c.require_owner(&p).is_ok());
        assert!(c.require_role(Role::Approver).is_ok());
    }
}

//! # ak-connector-http
//!
//! A read-only HTTP proxy connector exposing a single operation: `http.get`.
//!
//! ## GET is not automatically pure
//!
//! An HTTP GET can trigger arbitrary server-side behavior (webhooks,
//! analytics, cache-warming, even state changes on badly-built services).
//! This connector therefore classifies `http.get` as
//! [`EffectClass::Pure`] **only** when the target host is on a declared
//! allowlist of read-safe domains ([`HttpConnectorConfig::allowlist`],
//! `*`-glob patterns via [`ak_core::capability::glob_match`]). Any other
//! target is [`EffectClass::OpaqueExternal`] — treated as irreversible and
//! maximally restricted, requiring explicit approval in the broker.
//!
//! ## SSRF guards (always enforced, on every redirect hop)
//!
//! - only `http` / `https` schemes;
//! - literal IP hosts are refused outright (v4 and v6);
//! - `localhost` / `*.localhost` are refused;
//! - defense in depth: loopback, RFC1918 private, link-local
//!   (incl. the 169.254.169.254 metadata service), CGNAT and
//!   unique-local/v6-link-local ranges are refused if an IP is ever seen;
//! - redirects are followed manually, and **each hop** re-runs the full
//!   guard set and the allowlist check;
//! - response bodies are streamed and capped at
//!   [`HttpConnectorConfig::max_response_bytes`].

use ak_core::capability::glob_match;
use ak_core::effect::{EffectClass, EffectContract};
use ak_core::traits::{CommitResult, Connector, PreparedEffect};
use ak_core::{KernelError, KernelResult};
use async_trait::async_trait;
use reqwest::Url;
use serde_json::{json, Value};
use std::net::IpAddr;
use tracing::{debug, instrument, warn};

/// Operation name for the read-only proxy.
pub const OP_HTTP_GET: &str = "http.get";

fn conn_err(msg: impl std::fmt::Display) -> KernelError {
    KernelError::Connector(msg.to_string())
}

/// Configuration for [`HttpConnector`].
#[derive(Debug, Clone)]
pub struct HttpConnectorConfig {
    /// `*`-glob patterns of read-safe domains, e.g. `["docs.rs", "*.wikipedia.org"]`.
    /// Matching hosts classify `http.get` as `Pure`; everything else is
    /// `OpaqueExternal`.
    pub allowlist: Vec<String>,
    /// Hard cap on response body size in bytes.
    pub max_response_bytes: usize,
    /// Maximum number of redirects followed (each hop is re-checked).
    pub max_redirects: usize,
    /// **Tests only.** Permit loopback targets so a mock server can be used.
    /// Never enable in production: it disables the literal-IP/localhost guard.
    pub danger_allow_loopback: bool,
}

impl Default for HttpConnectorConfig {
    fn default() -> Self {
        Self {
            allowlist: Vec::new(),
            max_response_bytes: 1024 * 1024,
            max_redirects: 5,
            danger_allow_loopback: false,
        }
    }
}

/// The read-only HTTP proxy connector. See crate docs for the guard model.
#[derive(Debug)]
pub struct HttpConnector {
    config: HttpConnectorConfig,
    client: reqwest::Client,
}

/// Is this address in a range that must never be reached from a guest?
fn is_forbidden_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local() // includes 169.254.169.254 metadata
                || v4.is_unspecified()
                || v4.is_broadcast()
                // CGNAT 100.64.0.0/10
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xc0) == 64)
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                // unique local fc00::/7
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                // link-local fe80::/10
                || (v6.segments()[0] & 0xffc0) == 0xfe80
                // v4-mapped: recurse
                || v6.to_ipv4_mapped().map(|m| is_forbidden_ip(&IpAddr::V4(m))).unwrap_or(false)
        }
    }
}

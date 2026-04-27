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

impl HttpConnector {
    pub fn new(config: HttpConnectorConfig) -> KernelResult<Self> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(conn_err)?;
        Ok(Self { config, client })
    }

    /// Run the full SSRF guard set on `url`, returning the parsed URL.
    /// Refuses non-http(s) schemes, literal IPs, localhost, and (defense in
    /// depth) any forbidden address range.
    pub fn guard_url(&self, url: &str) -> KernelResult<Url> {
        let parsed = Url::parse(url).map_err(|e| conn_err(format!("invalid url `{url}`: {e}")))?;
        match parsed.scheme() {
            "http" | "https" => {}
            other => return Err(conn_err(format!("scheme `{other}` refused: only http(s) allowed"))),
        }
        let host = parsed
            .host_str()
            .ok_or_else(|| conn_err(format!("url `{url}` has no host")))?;
        let d = host.to_ascii_lowercase();
        // Literal IPs (v4, or bracketed v6) are refused. `Url` normalizes
        // hosts, so parsing the host string catches every literal form.
        if let Ok(ip) = d.trim_start_matches('[').trim_end_matches(']').parse::<IpAddr>() {
            self.refuse_ip(ip)?;
        }
        if !self.config.danger_allow_loopback
            && (d == "localhost" || d.ends_with(".localhost") || d.ends_with(".local"))
        {
            return Err(conn_err(format!("host `{host}` refused: localhost target")));
        }
        Ok(parsed)
    }

    fn refuse_ip(&self, ip: IpAddr) -> KernelResult<()> {
        if self.config.danger_allow_loopback && ip.is_loopback() {
            return Ok(());
        }
        if is_forbidden_ip(&ip) {
            return Err(conn_err(format!("ip `{ip}` refused: private/loopback/link-local range")));
        }
        // Even public literal IPs are refused: guests must name their target.
        Err(conn_err(format!("literal ip `{ip}` refused: use a domain name")))
    }

    /// Does the host of `url` match the read-safe allowlist?
    pub fn is_allowlisted(&self, url: &Url) -> bool {
        let Some(host) = url.host_str() else { return false };
        self.config
            .allowlist
            .iter()
            .any(|pattern| glob_match(pattern, host))
    }

    /// Classify a target: `Pure` only when guards pass **and** the host is
    /// allowlisted; otherwise `OpaqueExternal`. Errors when guards refuse
    /// the URL outright.
    pub fn classify(&self, url: &str) -> KernelResult<EffectClass> {
        let parsed = self.guard_url(url)?;
        Ok(if self.is_allowlisted(&parsed) {
            EffectClass::Pure
        } else {
            EffectClass::OpaqueExternal
        })
    }

    /// Perform the GET with manual redirect handling: every hop re-runs the
    /// guard set, and when `require_allowlist` is set (the request was
    /// classified `Pure`), every hop must also stay on the allowlist.
    async fn fetch(&self, start: Url, require_allowlist: bool) -> KernelResult<Value> {
        let mut url = start;
        for _hop in 0..=self.config.max_redirects {
            debug!(%url, "http.get fetch");
            let resp = self.client.get(url.clone()).send().await.map_err(conn_err)?;
            let status = resp.status();
            if status.is_redirection() {
                let location = resp
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .and_then(|v| v.to_str().ok())
                    .ok_or_else(|| conn_err(format!("redirect {status} without Location header")))?;
                let next = url
                    .join(location)
                    .map_err(|e| conn_err(format!("bad redirect target `{location}`: {e}")))?;
                // Re-run the full guard set on the hop target.
                let next = self.guard_url(next.as_str())?;
                if require_allowlist && !self.is_allowlisted(&next) {
                    warn!(target = %next, "redirect left the allowlist");
                    return Err(conn_err(format!(
                        "redirect to `{next}` refused: target is not on the read-safe allowlist"
                    )));
                }
                url = next;
                continue;
            }
            if !status.is_success() {
                return Err(conn_err(format!("GET {url} returned {status}")));
            }
            // Stream the body under the size cap.
            let mut body: Vec<u8> = Vec::new();
            let mut resp = resp;
            while let Some(chunk) = resp.chunk().await.map_err(conn_err)? {
                if body.len() + chunk.len() > self.config.max_response_bytes {
                    return Err(conn_err(format!(
                        "response exceeds cap of {} bytes",
                        self.config.max_response_bytes
                    )));
                }
                body.extend_from_slice(&chunk);
            }
            let text = String::from_utf8_lossy(&body).into_owned();
            return Ok(json!({
                "url": url.as_str(),
                "status": status.as_u16(),
                "body": text,
                "bytes": body.len(),
            }));
        }
        Err(conn_err(format!("too many redirects (max {})", self.config.max_redirects)))
    }
}

#[async_trait]
impl Connector for HttpConnector {
    fn name(&self) -> &str {
        "http"
    }

    /// `http.get` is advertised at its *worst-case* class. Use
    /// [`HttpConnector::classify`] for the per-target class.
    fn operations(&self) -> Vec<(String, EffectClass)> {
        vec![(OP_HTTP_GET.into(), EffectClass::OpaqueExternal)]
    }

    #[instrument(skip(self, args))]
    fn canonicalize(&self, operation: &str, args: &Value) -> KernelResult<Value> {
        if operation != OP_HTTP_GET {
            return Err(conn_err(format!("unsupported operation `{operation}`")));
        }
        let obj = args.as_object().ok_or_else(|| conn_err("arguments must be an object"))?;
        for key in obj.keys() {
            if key != "url" {
                return Err(conn_err(format!("unknown field `{key}`")));
            }
        }
        let url = obj
            .get("url")
            .and_then(Value::as_str)
            .ok_or_else(|| conn_err("missing required string field `url`"))?;
        // Reject guard violations at canonicalize time already.
        let parsed = self.guard_url(url)?;
        Ok(json!({ "url": parsed.as_str() }))
    }

    /// Dry-run: guard + classify, no request is made.
    #[instrument(skip(self, contract))]
    async fn prepare(&self, contract: &EffectContract) -> KernelResult<PreparedEffect> {
        let url = contract
            .arguments
            .get("url")
            .and_then(Value::as_str)
            .ok_or_else(|| conn_err("missing `url`"))?;
        let class = self.classify(url)?;
        Ok(PreparedEffect {
            preview: json!({
                "method": "GET",
                "url": url,
                "classified_as": if class == EffectClass::Pure { "pure (allowlisted)" } else { "opaque_external" },
            }),
            observed_preconditions: json!({}),
        })
    }

    #[instrument(skip(self, contract))]
    async fn commit(&self, contract: &EffectContract) -> KernelResult<CommitResult> {
        let url = contract
            .arguments
            .get("url")
            .and_then(Value::as_str)
            .ok_or_else(|| conn_err("missing `url`"))?;
        let parsed = self.guard_url(url)?;
        let allowlisted = self.is_allowlisted(&parsed);
        // A contract claiming Pure must actually be on the allowlist.
        if contract.class == EffectClass::Pure && !allowlisted {
            return Err(conn_err(format!(
                "contract claims Pure but `{url}` is not on the read-safe allowlist"
            )));
        }
        let response = self.fetch(parsed, allowlisted).await?;
        Ok(CommitResult { response })
    }
}

#[cfg(test)]
mod tests;

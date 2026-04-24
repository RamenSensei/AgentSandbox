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

//! Guard-matrix and proxy behavior tests. The mock server tests enable
//! `danger_allow_loopback` (tests only) so a local axum server can stand in
//! for a remote domain.

use super::*;
use axum::response::Redirect;
use axum::routing::get;
use axum::Router;

fn connector(allowlist: &[&str]) -> HttpConnector {
    HttpConnector::new(HttpConnectorConfig {
        allowlist: allowlist.iter().map(|s| s.to_string()).collect(),
        ..Default::default()
    })
    .expect("connector")
}

#[test]
fn guard_matrix_refuses_ssrf_targets() {
    let c = connector(&["example.com"]);
    let refused = [
        // non-http(s) schemes
        "ftp://example.com/file",
        "file:///etc/passwd",
        "gopher://example.com/",
        // literal IPs, public or not
        "http://8.8.8.8/",
        "http://127.0.0.1/",
        "http://127.0.0.1:8080/admin",
        "http://0.0.0.0/",
        // RFC1918 / CGNAT
        "http://10.0.0.1/",
        "http://192.168.1.1/router",
        "http://172.16.0.9/",
        "http://100.64.1.1/",
        // link-local incl. cloud metadata
        "http://169.254.169.254/latest/meta-data/",
        // v6 loopback / link-local / unique-local / v4-mapped
        "http://[::1]/",
        "http://[fe80::1]/",
        "http://[fc00::1]/",
        "http://[::ffff:10.0.0.1]/",
        // localhost by name
        "http://localhost/",
        "http://localhost:3000/api",
        "http://foo.localhost/",
        "http://printer.local/",
    ];
    for url in refused {
        assert!(c.guard_url(url).is_err(), "should refuse {url}");
        assert!(c.classify(url).is_err(), "classify should refuse {url}");
    }
    // Plain domains pass the guard.
    assert!(c.guard_url("https://example.com/page").is_ok());
    assert!(c.guard_url("http://sub.other.org/").is_ok());
}

#[test]
fn classification_is_pure_only_on_allowlist() {
    let c = connector(&["docs.rs", "*.wikipedia.org"]);
    assert_eq!(c.classify("https://docs.rs/serde").unwrap(), EffectClass::Pure);
    assert_eq!(
        c.classify("https://en.wikipedia.org/wiki/Rust").unwrap(),
        EffectClass::Pure
    );
    // GET is not automatically pure: off-list hosts are opaque.
    assert_eq!(
        c.classify("https://evil.example.net/hook").unwrap(),
        EffectClass::OpaqueExternal
    );
    assert_eq!(
        c.classify("https://docs.rs.evil.net/").unwrap(),
        EffectClass::OpaqueExternal
    );
}

#[test]
fn canonicalize_validates_shape_and_guards() {
    let c = connector(&["example.com"]);
    assert!(c.canonicalize(OP_HTTP_GET, &json!({"url": "https://example.com/a"})).is_ok());
    assert!(c.canonicalize(OP_HTTP_GET, &json!({"url": "http://169.254.169.254/"})).is_err());
    assert!(c.canonicalize(OP_HTTP_GET, &json!({"url": "https://example.com", "method": "POST"})).is_err());
    assert!(c.canonicalize(OP_HTTP_GET, &json!({})).is_err());
    assert!(c.canonicalize("http.post", &json!({"url": "https://example.com"})).is_err());
}

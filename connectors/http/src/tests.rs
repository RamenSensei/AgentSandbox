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

fn test_config(allowlist: Vec<String>, max_bytes: usize) -> HttpConnectorConfig {
    HttpConnectorConfig {
        allowlist,
        max_response_bytes: max_bytes,
        max_redirects: 5,
        danger_allow_loopback: true,
    }
}

async fn spawn_mock() -> String {
    let app = Router::new()
        .route("/ok", get(|| async { "hello world" }))
        .route("/big", get(|| async { "x".repeat(4096) }))
        .route("/hop", get(|| async { Redirect::temporary("/ok") }))
        .route(
            "/offsite",
            get(|| async { Redirect::temporary("http://not-allowlisted.example/x") }),
        )
        .route(
            "/metadata",
            get(|| async { Redirect::temporary("http://169.254.169.254/latest") }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}")
}

fn contract(url: &str, class: EffectClass) -> EffectContract {
    EffectContract {
        operation: OP_HTTP_GET.into(),
        resource: url.into(),
        arguments: json!({ "url": url }),
        preconditions: json!({}),
        idempotency_key: "k".into(),
        class,
    }
}

#[tokio::test]
async fn commit_fetches_and_caps_size() {
    let base = spawn_mock().await;
    let host = Url::parse(&base).unwrap().host_str().unwrap().to_string();
    let c = HttpConnector::new(test_config(vec![host], 1024)).unwrap();

    let ok = c.commit(&contract(&format!("{base}/ok"), EffectClass::Pure)).await.unwrap();
    assert_eq!(ok.response["status"], 200);
    assert_eq!(ok.response["body"], "hello world");

    let err = c
        .commit(&contract(&format!("{base}/big"), EffectClass::Pure))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("exceeds cap"), "{err}");
}

#[tokio::test]
async fn redirects_are_rechecked_per_hop() {
    let base = spawn_mock().await;
    let host = Url::parse(&base).unwrap().host_str().unwrap().to_string();
    let c = HttpConnector::new(test_config(vec![host], 65536)).unwrap();

    // On-allowlist redirect is followed.
    let ok = c.commit(&contract(&format!("{base}/hop"), EffectClass::Pure)).await.unwrap();
    assert_eq!(ok.response["body"], "hello world");

    // Redirect that leaves the allowlist is refused.
    let err = c
        .commit(&contract(&format!("{base}/offsite"), EffectClass::Pure))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("allowlist"), "{err}");

    // Redirect to the metadata service is refused by the guards even though
    // loopback itself is (test-only) allowed.
    let err = c
        .commit(&contract(&format!("{base}/metadata"), EffectClass::Pure))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("refused"), "{err}");
}

#[tokio::test]
async fn pure_claim_off_allowlist_is_refused() {
    let base = spawn_mock().await;
    // Empty allowlist: nothing is pure.
    let c = HttpConnector::new(test_config(vec![], 65536)).unwrap();
    let err = c
        .commit(&contract(&format!("{base}/ok"), EffectClass::Pure))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("not on the read-safe allowlist"), "{err}");
    // As OpaqueExternal it is allowed through (guards permitting).
    let ok = c
        .commit(&contract(&format!("{base}/ok"), EffectClass::OpaqueExternal))
        .await
        .unwrap();
    assert_eq!(ok.response["body"], "hello world");
}

#[tokio::test]
async fn prepare_is_a_pure_dry_run() {
    let c = connector(&["docs.rs"]);
    let p = c.prepare(&contract("https://docs.rs/serde", EffectClass::Pure)).await.unwrap();
    assert_eq!(p.preview["classified_as"], "pure (allowlisted)");
    let p = c
        .prepare(&contract("https://other.example/x", EffectClass::OpaqueExternal))
        .await
        .unwrap();
    assert_eq!(p.preview["classified_as"], "opaque_external");
}

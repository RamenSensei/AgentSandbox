//! End-to-end egress-proxy tests through the real OS sandbox: a confined
//! `curl` reaches an allowlisted target **only** via the token-bearing
//! proxy, direct network stays denied, and egress bytes are metered.
//!
//! The full flow needs a sandbox that can scope network to the proxy:
//! macOS Seatbelt (loopback-port pinhole) or Linux bwrap with the
//! probe-verified `ak-egress-fwd` netns forwarder. Where the bwrap probe
//! does not verify, the backend keeps egress off (fail closed) — asserted
//! separately; on hosts with no sandbox the tests skip.

use ak_backend_local::{EgressConfig, LocalBackend, LocalBackendConfig, SandboxTech};
use ak_core::action::ActionKind;
use ak_core::budget::ResourceBudget;
use ak_core::ids::{BranchId, PrincipalId, StateId};
use ak_core::traits::{Backend, ExecutionRequest};
use std::collections::BTreeMap;

async fn doc_server() -> std::net::SocketAddr {
    let app = axum::Router::new().route(
        "/hello",
        axum::routing::get(|| async { "hello-through-egress-proxy" }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

fn backend(tmp: &tempfile::TempDir) -> LocalBackend {
    let mut config = LocalBackendConfig::new(tmp.path().join("ws"));
    config.egress = EgressConfig {
        enabled: true,
        allowed_ports: Vec::new(),
        danger_allow_loopback: true,
    };
    // The forwarder built alongside these tests: on Linux+bwrap hosts the
    // construction probe verifies the full netns route end-to-end.
    config.egress_forwarder = Some(std::path::PathBuf::from(env!(
        "CARGO_BIN_EXE_ak-egress-fwd"
    )));
    LocalBackend::new(config).unwrap()
}

fn shell_request(
    branch: &BranchId,
    command: &str,
    egress_domains: Vec<String>,
) -> ExecutionRequest {
    ExecutionRequest {
        branch: branch.clone(),
        base_state: StateId::generate(),
        actor: PrincipalId::generate(),
        action: ActionKind::Shell {
            command: command.into(),
            cwd: None,
            env: BTreeMap::new(),
        },
        budget: ResourceBudget::step_default(),
        writable_prefixes: Vec::new(),
        readable_prefixes: Vec::new(),
        egress_domains,
    }
}

#[tokio::test]
async fn sandboxed_curl_reaches_allowlisted_target_only_through_the_proxy() {
    let tmp = tempfile::tempdir().unwrap();
    let backend = backend(&tmp);
    match backend.sandbox_tech() {
        SandboxTech::SandboxExec => {}
        SandboxTech::Bwrap if backend.netns_egress_verified() => {
            // Probe-verified netns forwarder: the full proxy flow below
            // must work under bwrap exactly as under Seatbelt.
        }
        SandboxTech::Bwrap => {
            if std::env::var("AK_REQUIRE_NETNS_EGRESS").as_deref() == Ok("1") {
                panic!("AK_REQUIRE_NETNS_EGRESS=1 but the bwrap forwarder probe failed");
            }
            // No verified forwarder route: the backend must keep egress
            // OFF rather than pretend. The step runs, curl fails to
            // connect, and no proxy env leaks in.
            let branch = BranchId::generate();
            backend.workspace_for(&branch).unwrap();
            let outcome = backend
                .execute(shell_request(
                    &branch,
                    "echo http=${HTTP_PROXY:-unset} all=${ALL_PROXY:-unset}; curl -sS --max-time 3 http://127.0.0.1:1/ && echo LEAK",
                    vec!["127.0.0.1".into()],
                ))
                .await
                .unwrap();
            let stdout = String::from_utf8_lossy(&outcome.stdout);
            assert!(
                stdout.contains("http=unset all=unset"),
                "bwrap must not get proxy env: {stdout}"
            );
            assert!(!stdout.contains("LEAK"));
            return;
        }
        SandboxTech::None => {
            if std::env::var("AK_REQUIRE_NETNS_EGRESS").as_deref() == Ok("1") {
                panic!("AK_REQUIRE_NETNS_EGRESS=1 but no OS sandbox verified");
            }
            eprintln!("skipping: no verified OS sandbox on this host");
            return;
        }
    }

    let target = doc_server().await;
    let branch = BranchId::generate();
    backend.workspace_for(&branch).unwrap();

    // 1. Through the proxy (env is set automatically): succeeds, metered.
    let outcome = backend
        .execute(shell_request(
            &branch,
            &format!(
                "curl -sS --max-time 5 http://127.0.0.1:{}/hello",
                target.port()
            ),
            vec!["127.0.0.1".into()],
        ))
        .await
        .unwrap();
    let stdout = String::from_utf8_lossy(&outcome.stdout);
    assert_eq!(
        outcome.exit_code,
        0,
        "stderr: {}",
        String::from_utf8_lossy(&outcome.stderr)
    );
    assert!(
        stdout.contains("hello-through-egress-proxy"),
        "got: {stdout}"
    );
    assert!(
        outcome.usage.network_bytes > 0,
        "egress bytes must be metered at the proxy"
    );

    // 2. The same route also speaks authenticated SOCKS5. This is the
    //    non-HTTP path used by SSH/database clients via ALL_PROXY; DNS stays
    //    at the policy-enforcing proxy (`socks5h`).
    let outcome = backend
        .execute(shell_request(
            &branch,
            &format!(
                "curl -sS --max-time 5 --proxy \"$ALL_PROXY\" http://127.0.0.1:{}/hello",
                target.port()
            ),
            vec!["127.0.0.1".into()],
        ))
        .await
        .unwrap();
    assert_eq!(
        outcome.exit_code,
        0,
        "SOCKS5 stderr: {}",
        String::from_utf8_lossy(&outcome.stderr)
    );
    assert!(
        String::from_utf8_lossy(&outcome.stdout).contains("hello-through-egress-proxy"),
        "SOCKS5 route failed: {}",
        String::from_utf8_lossy(&outcome.stdout)
    );
    assert!(outcome.usage.network_bytes > 0);

    // 3. Bypassing the proxy from inside the sandbox: denied by Seatbelt.
    let outcome = backend
        .execute(shell_request(
            &branch,
            &format!(
                "curl -sS --noproxy '*' --max-time 3 http://127.0.0.1:{}/hello && echo LEAK",
                target.port()
            ),
            vec!["127.0.0.1".into()],
        ))
        .await
        .unwrap();
    assert!(
        !String::from_utf8_lossy(&outcome.stdout).contains("LEAK"),
        "direct network must stay denied; only the proxy port is open"
    );

    // 4. A domain outside the step's egress grant: refused at the proxy
    //    (403 → `curl -f` fails, and the content never crosses).
    let outcome = backend
        .execute(shell_request(
            &branch,
            &format!(
                "curl -sSf --max-time 5 http://127.0.0.1:{}/hello && echo LEAK",
                target.port()
            ),
            vec!["docs.example".into()],
        ))
        .await
        .unwrap();
    let stdout = String::from_utf8_lossy(&outcome.stdout);
    assert!(
        !stdout.contains("hello-through-egress-proxy") && !stdout.contains("LEAK"),
        "proxy must refuse hosts outside the granted domains, got: {stdout}"
    );

    // 5. No egress domains at all: no proxy env of either protocol, fully
    //    offline.
    let outcome = backend
        .execute(shell_request(
            &branch,
            "echo http=${HTTP_PROXY:-unset} all=${ALL_PROXY:-unset}",
            Vec::new(),
        ))
        .await
        .unwrap();
    assert!(
        String::from_utf8_lossy(&outcome.stdout).contains("http=unset all=unset"),
        "no egress grant must mean no proxy environment"
    );
}

#[tokio::test]
async fn process_sessions_keep_their_egress_grant_until_they_die() {
    let tmp = tempfile::tempdir().unwrap();
    let backend = backend(&tmp);
    match backend.sandbox_tech() {
        SandboxTech::SandboxExec => {}
        SandboxTech::Bwrap if backend.netns_egress_verified() => {}
        SandboxTech::Bwrap | SandboxTech::None => {
            if std::env::var("AK_REQUIRE_NETNS_EGRESS").as_deref() == Ok("1") {
                panic!("AK_REQUIRE_NETNS_EGRESS=1 but confined proxy reachability failed");
            }
            eprintln!("skipping: no verified confined proxy route");
            return;
        }
    }
    let target = doc_server().await;
    let branch = BranchId::generate();
    backend.workspace_for(&branch).unwrap();

    // A long-running process fetches through the proxy *after* the starting
    // step has completed — the grant must outlive the step.
    let outcome = backend
        .execute(ExecutionRequest {
            branch: branch.clone(),
            base_state: StateId::generate(),
            actor: PrincipalId::generate(),
            action: ActionKind::ProcessStart {
                command: format!(
                    "sleep 1; curl -sS --max-time 5 http://127.0.0.1:{}/hello",
                    target.port()
                ),
                cwd: None,
                env: BTreeMap::new(),
                name: Some("late-fetch".into()),
            },
            budget: ResourceBudget::step_default(),
            writable_prefixes: Vec::new(),
            readable_prefixes: Vec::new(),
            egress_domains: vec!["127.0.0.1".into()],
        })
        .await
        .unwrap();
    let started: serde_json::Value = serde_json::from_slice(&outcome.stdout).unwrap();
    let proc = started["process"].as_str().unwrap().to_string();

    // Wait for the fetch to land in the session logs.
    let mut seen = false;
    for _ in 0..100 {
        let sessions = backend.processes().list(&branch);
        let session = sessions.iter().find(|s| s.id == proc).unwrap();
        let (_, data) = session
            .logs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .read_from(0, 65536);
        if String::from_utf8_lossy(&data).contains("hello-through-egress-proxy") {
            seen = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(seen, "the process session's egress grant must stay live");
    let status = backend
        .processes()
        .get(&branch, &proc)
        .unwrap()
        .status_json();
    assert!(
        status["network_bytes"].as_u64().unwrap_or(0) > 0,
        "session status must expose its live proxy accounting: {status}"
    );
}

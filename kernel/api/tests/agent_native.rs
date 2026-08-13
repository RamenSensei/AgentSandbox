//! Agent-native runtime tests: the observation plane (HttpRead/McpInvoke on
//! the main execution path), persistent process sessions, automatic lease
//! resolution, server-side exploration, raw-output access, actionable
//! denials, and incremental snapshot correctness through the kernel.

use ak_api::{http, ExploreCandidate, ExploreOptions, Kernel, KernelConfig};
use ak_connector_http::{HttpConnector, HttpConnectorConfig};
use ak_core::action::{Action, ActionKind};
use ak_core::budget::ResourceBudget;
use ak_core::capability::Operation;
use ak_core::denial::DenialCode;
use ak_core::effect::{EffectClass, EffectContract};
use ak_core::ids::LeaseId;
use ak_core::observation::Observation;
use ak_core::state::FileChange;
use ak_core::traits::{CommitResult, Connector, PreparedEffect};
use ak_core::{KernelResult, Principal};
use ak_policy::{PolicyDocument, PolicyRule, PrincipalSelector, RuleEffect};
use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use indexmap::IndexMap;
use serde_json::json;
use std::collections::BTreeMap;
use std::sync::Arc;
use tower::ServiceExt;

fn allow_rule(id: &str, ops: &[&str], uses: u32) -> PolicyRule {
    PolicyRule {
        id: id.into(),
        principals: PrincipalSelector::default(),
        operations: ops.iter().map(|s| s.to_string()).collect(),
        effect: RuleEffect::Allow,
        constraints: IndexMap::new(),
        max_uses: uses,
        ttl_seconds: 3600,
        budget: None,
        risk_weight: 0,
        note: None,
    }
}

fn test_policy() -> PolicyDocument {
    PolicyDocument {
        rules: vec![
            allow_rule("shell", &["proc.shell"], 500),
            allow_rule("sessions", &["proc.*"], 500),
            allow_rule("fs", &["fs.*"], 500),
            allow_rule("net", &["net.http_read"], 100),
            allow_rule("mcp", &["mcp.invoke"], 100),
            allow_rule("http-effect", &["http.*"], 100),
            allow_rule("notes-effect", &["notes.*"], 100),
            allow_rule("meta", &["trace.query", "state.diff"], 500),
        ],
        egress_domains: vec!["127.0.0.1".into(), "docs.example".into()],
        ..PolicyDocument::default()
    }
}

fn kernel_in(tmp: &tempfile::TempDir) -> Arc<Kernel> {
    let config = KernelConfig::new(tmp.path().join("data"));
    let kernel = Kernel::open(config).expect("kernel opens");
    kernel
        .with_policy_mut(|p| *p.document_mut() = test_policy())
        .expect("policy set");
    Arc::new(kernel)
}

fn agent(kernel: &Kernel) -> Principal {
    let p = Principal::new_agent("test-agent");
    kernel.register_principal(&p).expect("register");
    p
}

/// Execute with automatic lease resolution — the agent-native call shape.
async fn auto(
    kernel: &Kernel,
    who: &Principal,
    branch: &ak_core::ids::BranchId,
    kind: ActionKind,
) -> ak_api::AutoStepResult {
    kernel
        .execute_step_auto(&who.id, branch, kind, None, None)
        .await
        .expect("auto step executes")
}

fn shell_kind(command: &str) -> ActionKind {
    ActionKind::Shell {
        command: command.into(),
        cwd: None,
        env: BTreeMap::new(),
    }
}

/// Spawn a loopback HTTP server serving a large deterministic document.
async fn spawn_doc_server() -> (std::net::SocketAddr, &'static str) {
    // > 2048 bytes so distillation must elide the middle; a marker in the
    // middle and one at the end prove raw access + tail work.
    let doc: &'static str = Box::leak(
        format!(
            "{}MARKER-MIDDLE{}THE-END",
            "x".repeat(3000),
            "y".repeat(1500)
        )
        .into_boxed_str(),
    );
    let app = axum::Router::new().route(
        "/doc",
        axum::routing::get(move || async move { doc.to_string() }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (addr, doc)
}

fn loopback_http_connector(allowlist: Vec<String>) -> HttpConnector {
    HttpConnector::new(HttpConnectorConfig {
        allowlist,
        max_response_bytes: 1 << 20,
        max_redirects: 3,
        danger_allow_loopback: true,
    })
    .unwrap()
}

// ===================================================== observation plane

#[tokio::test]
async fn http_read_pure_target_executes_inline_with_head_tail_and_raw() {
    let tmp = tempfile::tempdir().unwrap();
    let kernel = kernel_in(&tmp);
    kernel
        .register_connector(Arc::new(loopback_http_connector(vec!["127.0.0.1".into()])))
        .unwrap();
    let who = agent(&kernel);
    let ep = kernel.create_episode(&who.id, None, "research").unwrap();

    let url = {
        let (addr, _) = spawn_doc_server().await;
        format!("http://{addr}/doc")
    };
    let r = auto(&kernel, &who, &ep.branch, ActionKind::HttpRead { url }).await;
    match &r.result.observation {
        Observation::Success {
            data,
            stdout_head,
            stdout_tail,
            truncated,
            full_output,
            ..
        } => {
            // One step, no approval, no pending effect: the read happened.
            assert!(*truncated);
            assert_eq!(data.as_ref().unwrap()["status"], 200);
            assert!(stdout_head.as_deref().unwrap().starts_with("xxx"));
            assert!(
                stdout_tail.as_deref().unwrap().ends_with("THE-END"),
                "the tail must carry the end of the document"
            );
            // The FULL body is retrievable from the raw store.
            let raw = kernel.fetch_raw(full_output).unwrap();
            let text = String::from_utf8(raw).unwrap();
            assert!(text.contains("MARKER-MIDDLE"));
            assert!(text.ends_with("THE-END"));
        }
        other => panic!("expected inline success, got {other:?}"),
    }
    // No pending effects were created for a pure read.
    assert!(kernel.list_effects(Some("proposed")).unwrap().is_empty());
}

#[tokio::test]
async fn http_read_non_allowlisted_target_goes_through_effect_plane() {
    let tmp = tempfile::tempdir().unwrap();
    let kernel = kernel_in(&tmp);
    // Empty read-safe allowlist: loopback is reachable but not read-safe.
    kernel
        .register_connector(Arc::new(loopback_http_connector(vec![])))
        .unwrap();
    let who = agent(&kernel);
    let ep = kernel.create_episode(&who.id, None, "opaque read").unwrap();

    let (addr, doc) = spawn_doc_server().await;
    let r = auto(
        &kernel,
        &who,
        &ep.branch,
        ActionKind::HttpRead {
            url: format!("http://{addr}/doc"),
        },
    )
    .await;
    let effect = match &r.result.observation {
        Observation::EffectPending { effect, class, .. } => {
            assert_eq!(
                *class,
                EffectClass::OpaqueExternal,
                "non-allowlisted GET must carry its worst-case class in the contract"
            );
            effect.clone()
        }
        other => panic!("expected pending effect, got {other:?}"),
    };
    // The transactional path still completes the read after approval.
    kernel.prepare_effect(&effect).await.unwrap();
    kernel.approve_effect(&effect, &who.id).unwrap();
    let receipt = kernel.commit_effect(&effect).await.unwrap();
    assert_eq!(receipt.body.operation, "http.get");
    let _ = doc;
}

#[tokio::test]
async fn http_read_allowlisted_connector_op_contract_is_pure_and_needs_no_approval() {
    // Dynamic classification must reach ConnectorOp contracts too: an
    // allowlisted GET proposed as an effect commits from Prepared without
    // any human approval.
    let tmp = tempfile::tempdir().unwrap();
    let kernel = kernel_in(&tmp);
    kernel
        .register_connector(Arc::new(loopback_http_connector(vec!["127.0.0.1".into()])))
        .unwrap();
    let who = agent(&kernel);
    let ep = kernel.create_episode(&who.id, None, "pure effect").unwrap();
    let (addr, _) = spawn_doc_server().await;

    let r = auto(
        &kernel,
        &who,
        &ep.branch,
        ActionKind::ConnectorOp {
            connector: "http".into(),
            operation: "get".into(),
            params: json!({ "url": format!("http://{addr}/doc") }),
        },
    )
    .await;
    let effect = match &r.result.observation {
        Observation::EffectPending { effect, class, .. } => {
            assert_eq!(
                *class,
                EffectClass::Pure,
                "the contract must carry the per-invocation class, not the static worst case"
            );
            effect.clone()
        }
        other => panic!("expected pending effect, got {other:?}"),
    };
    kernel.prepare_effect(&effect).await.unwrap();
    // NO approve: Pure commits straight from Prepared.
    let receipt = kernel.commit_effect(&effect).await.unwrap();
    assert_eq!(receipt.body.operation, "http.get");
}

#[tokio::test]
async fn http_read_boundaries_egress_guard_and_missing_connector() {
    let tmp = tempfile::tempdir().unwrap();
    let kernel = kernel_in(&tmp);
    kernel
        .register_connector(Arc::new(loopback_http_connector(vec!["127.0.0.1".into()])))
        .unwrap();
    let who = agent(&kernel);
    let ep = kernel.create_episode(&who.id, None, "boundaries").unwrap();

    // Host outside the compiled egress allowlist → policy denial with a
    // concrete requestable scope (no network is ever touched).
    let r = auto(
        &kernel,
        &who,
        &ep.branch,
        ActionKind::HttpRead {
            url: "http://not-allowed.test/x".into(),
        },
    )
    .await;
    match &r.result.observation {
        Observation::Denied { denial } => {
            assert_eq!(denial.code, DenialCode::PolicyForbidden);
            assert_eq!(denial.requestable_scopes.len(), 1);
            assert_eq!(
                denial.requestable_scopes[0].constraints["domain"],
                "not-allowed.test"
            );
        }
        other => panic!("expected egress denial, got {other:?}"),
    }

    // Guard-refused scheme → constraint denial.
    let r = auto(
        &kernel,
        &who,
        &ep.branch,
        ActionKind::HttpRead {
            url: "ftp://docs.example/x".into(),
        },
    )
    .await;
    match &r.result.observation {
        Observation::Denied { denial } => {
            assert_eq!(denial.code, DenialCode::ConstraintViolated)
        }
        other => panic!("expected guard denial, got {other:?}"),
    }

    // A kernel without an http connector refuses honestly.
    let tmp2 = tempfile::tempdir().unwrap();
    let bare = kernel_in(&tmp2);
    let who2 = agent(&bare);
    let ep2 = bare.create_episode(&who2.id, None, "no connector").unwrap();
    let r = auto(
        &bare,
        &who2,
        &ep2.branch,
        ActionKind::HttpRead {
            url: "http://docs.example/x".into(),
        },
    )
    .await;
    match &r.result.observation {
        Observation::Denied { denial } => {
            assert_eq!(denial.code, DenialCode::BackendUnavailable)
        }
        other => panic!("expected missing-connector denial, got {other:?}"),
    }
}

// ------------------------------------------------------------- MCP plane

/// A fake MCP-style connector: one manifest-vouched Pure tool, one
/// side-effecting tool.
struct FakeNotes;

#[async_trait]
impl Connector for FakeNotes {
    fn name(&self) -> &str {
        "notes"
    }
    fn operations(&self) -> Vec<(String, EffectClass)> {
        vec![
            ("notes.read".into(), EffectClass::Pure),
            ("notes.append".into(), EffectClass::Compensatable),
        ]
    }
    fn canonicalize(
        &self,
        operation: &str,
        args: &serde_json::Value,
    ) -> KernelResult<serde_json::Value> {
        if args.get("forbidden").is_some() {
            return Err(ak_core::KernelError::Connector(
                "parameter `forbidden` is not declared in the manifest".into(),
            ));
        }
        let _ = operation;
        Ok(args.clone())
    }
    async fn prepare(&self, _contract: &EffectContract) -> KernelResult<PreparedEffect> {
        Ok(PreparedEffect {
            preview: json!({ "tool": "notes" }),
            observed_preconditions: json!({}),
        })
    }
    async fn commit(&self, contract: &EffectContract) -> KernelResult<CommitResult> {
        Ok(CommitResult {
            response: json!({ "tool": contract.operation, "echo": contract.arguments }),
        })
    }
}

#[tokio::test]
async fn mcp_invoke_pure_tool_runs_inline_and_writes_route_through_effects() {
    let tmp = tempfile::tempdir().unwrap();
    let kernel = kernel_in(&tmp);
    kernel.register_connector(Arc::new(FakeNotes)).unwrap();
    let who = agent(&kernel);
    let ep = kernel.create_episode(&who.id, None, "mcp").unwrap();

    // Pure tool → inline observation, one step, no effect machinery.
    let r = auto(
        &kernel,
        &who,
        &ep.branch,
        ActionKind::McpInvoke {
            server: "notes".into(),
            tool: "read".into(),
            arguments: json!({ "id": "n1" }),
        },
    )
    .await;
    match &r.result.observation {
        Observation::Success {
            stdout_head,
            full_output,
            ..
        } => {
            assert!(stdout_head.as_deref().unwrap().contains("notes.read"));
            let raw = kernel.fetch_raw(full_output).unwrap();
            assert!(String::from_utf8_lossy(&raw).contains("\"id\": \"n1\""));
        }
        other => panic!("expected inline mcp success, got {other:?}"),
    }

    // Side-effecting tool → pending effect with the declared class.
    let r = auto(
        &kernel,
        &who,
        &ep.branch,
        ActionKind::McpInvoke {
            server: "notes".into(),
            tool: "append".into(),
            arguments: json!({ "id": "n1", "text": "hello" }),
        },
    )
    .await;
    match &r.result.observation {
        Observation::EffectPending { class, .. } => {
            assert_eq!(*class, EffectClass::Compensatable)
        }
        other => panic!("expected pending effect, got {other:?}"),
    }

    // Unknown server → honest denial naming the registered connectors.
    let r = auto(
        &kernel,
        &who,
        &ep.branch,
        ActionKind::McpInvoke {
            server: "ghost".into(),
            tool: "read".into(),
            arguments: json!({}),
        },
    )
    .await;
    match &r.result.observation {
        Observation::Denied { denial } => {
            assert_eq!(denial.code, DenialCode::BackendUnavailable);
            assert!(denial.reason.contains("notes"));
        }
        other => panic!("expected unknown-server denial, got {other:?}"),
    }

    // Manifest-refused arguments → constraint denial before the server.
    let r = auto(
        &kernel,
        &who,
        &ep.branch,
        ActionKind::McpInvoke {
            server: "notes".into(),
            tool: "read".into(),
            arguments: json!({ "forbidden": true }),
        },
    )
    .await;
    match &r.result.observation {
        Observation::Denied { denial } => {
            assert_eq!(denial.code, DenialCode::ConstraintViolated)
        }
        other => panic!("expected manifest denial, got {other:?}"),
    }
}

// ==================================================== process sessions

/// Poll a process's logs until `needle` shows up (or time out).
async fn wait_for_log(
    kernel: &Kernel,
    who: &Principal,
    branch: &ak_core::ids::BranchId,
    process: &str,
    needle: &str,
) -> serde_json::Value {
    for _ in 0..100 {
        let r = auto(
            kernel,
            who,
            branch,
            ActionKind::ProcessLogs {
                process: process.into(),
                from_offset: 0,
                max_bytes: Some(4096),
            },
        )
        .await;
        if let Observation::Success {
            stdout_head: Some(head),
            ..
        } = &r.result.observation
        {
            let v: serde_json::Value = serde_json::from_str(head).unwrap();
            if v["data"].as_str().unwrap_or("").contains(needle) {
                return v;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("`{needle}` never appeared in process logs");
}

fn parse_head(obs: &Observation) -> serde_json::Value {
    match obs {
        Observation::Success {
            stdout_head: Some(head),
            ..
        } => serde_json::from_str(head).unwrap(),
        other => panic!("expected success with stdout_head, got {other:?}"),
    }
}

#[tokio::test]
async fn process_session_lifecycle_stdin_logs_signal_status() {
    let tmp = tempfile::tempdir().unwrap();
    let kernel = kernel_in(&tmp);
    let who = agent(&kernel);
    let ep = kernel.create_episode(&who.id, None, "sessions").unwrap();

    // Start an interactive echo loop — a stand-in for a REPL/dev server.
    let r = auto(
        &kernel,
        &who,
        &ep.branch,
        ActionKind::ProcessStart {
            command: r#"while read line; do echo "got:$line"; done"#.into(),
            cwd: None,
            env: BTreeMap::new(),
            name: Some("echo-loop".into()),
        },
    )
    .await;
    let started = parse_head(&r.result.observation);
    let proc = started["process"].as_str().unwrap().to_string();
    assert!(proc.starts_with("proc-"));
    assert!(started["pid"].as_u64().is_some());

    // Status: running, named.
    let r = auto(
        &kernel,
        &who,
        &ep.branch,
        ActionKind::ProcessStatus {
            process: proc.clone(),
        },
    )
    .await;
    let status = parse_head(&r.result.observation);
    assert_eq!(status["running"], true);
    assert_eq!(status["name"], "echo-loop");

    // Drive it interactively over stdin, observe incrementally.
    let r = auto(
        &kernel,
        &who,
        &ep.branch,
        ActionKind::ProcessStdin {
            process: proc.clone(),
            data_b64: ak_backend_local::b64::encode(b"hello\n"),
            close: false,
        },
    )
    .await;
    assert_eq!(parse_head(&r.result.observation)["bytes_written"], 6);
    let logs = wait_for_log(&kernel, &who, &ep.branch, &proc, "got:hello").await;
    assert!(logs["next_offset"].as_u64().unwrap() > 0);

    // Incremental tail: reading from next_offset returns nothing new.
    let next = logs["next_offset"].as_u64().unwrap();
    let r = auto(
        &kernel,
        &who,
        &ep.branch,
        ActionKind::ProcessLogs {
            process: proc.clone(),
            from_offset: next,
            max_bytes: Some(4096),
        },
    )
    .await;
    let tail = parse_head(&r.result.observation);
    assert_eq!(tail["data"], "");
    assert_eq!(tail["next_offset"], next);

    // Terminate, observe the exit.
    let r = auto(
        &kernel,
        &who,
        &ep.branch,
        ActionKind::ProcessSignal {
            process: proc.clone(),
            signal: "term".into(),
        },
    )
    .await;
    assert_eq!(parse_head(&r.result.observation)["signaled"], "term");
    for _ in 0..100 {
        let r = auto(
            &kernel,
            &who,
            &ep.branch,
            ActionKind::ProcessStatus {
                process: proc.clone(),
            },
        )
        .await;
        if parse_head(&r.result.observation)["running"] == false {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("process never exited after SIGTERM");
}

#[tokio::test]
async fn process_sessions_are_branch_scoped_and_die_with_the_branch() {
    let tmp = tempfile::tempdir().unwrap();
    let kernel = kernel_in(&tmp);
    let who = agent(&kernel);
    let ep = kernel.create_episode(&who.id, None, "scoping").unwrap();
    let fork = kernel.fork_branch(&ep.branch).unwrap();

    let r = auto(
        &kernel,
        &who,
        &fork.id,
        ActionKind::ProcessStart {
            command: "sleep 300".into(),
            cwd: None,
            env: BTreeMap::new(),
            name: None,
        },
    )
    .await;
    let proc = parse_head(&r.result.observation)["process"]
        .as_str()
        .unwrap()
        .to_string();

    // Another branch cannot see or signal the session.
    let r = auto(
        &kernel,
        &who,
        &ep.branch,
        ActionKind::ProcessStatus {
            process: proc.clone(),
        },
    )
    .await;
    match &r.result.observation {
        Observation::Failure {
            first_causal_failure,
            ..
        } => assert!(first_causal_failure
            .as_deref()
            .unwrap()
            .contains("unknown process")),
        other => panic!("expected cross-branch failure, got {other:?}"),
    }

    // Unknown signal name is a constraint denial (pre-execution).
    let r = auto(
        &kernel,
        &who,
        &fork.id,
        ActionKind::ProcessSignal {
            process: proc.clone(),
            signal: "hup".into(),
        },
    )
    .await;
    match &r.result.observation {
        Observation::Denied { denial } => {
            assert_eq!(denial.code, DenialCode::ConstraintViolated)
        }
        other => panic!("expected signal denial, got {other:?}"),
    }

    // Discarding the branch kills and unregisters its sessions.
    assert_eq!(kernel.local_backend().processes().list(&fork.id).len(), 1);
    kernel.discard_branch(&fork.id).await.unwrap();
    assert!(kernel.local_backend().processes().list(&fork.id).is_empty());

    // Empty `process` on status lists (now zero) sessions for the branch.
    let r = auto(
        &kernel,
        &who,
        &ep.branch,
        ActionKind::ProcessStatus {
            process: String::new(),
        },
    )
    .await;
    let v = parse_head(&r.result.observation);
    assert_eq!(v["processes"].as_array().unwrap().len(), 0);
}

// ================================================== auto-lease execution

#[tokio::test]
async fn execute_auto_mints_then_reuses_leases_and_propagates_denials() {
    let tmp = tempfile::tempdir().unwrap();
    let kernel = kernel_in(&tmp);
    let who = agent(&kernel);
    let ep = kernel.create_episode(&who.id, None, "auto").unwrap();

    let first = auto(&kernel, &who, &ep.branch, shell_kind("printf a > a.txt")).await;
    assert!(first.lease_minted, "no lease existed; one must be minted");
    let second = auto(&kernel, &who, &ep.branch, shell_kind("printf b > b.txt")).await;
    assert!(!second.lease_minted, "the active lease must be reused");
    assert_eq!(first.lease, second.lease);

    // Policy-denied operations propagate the structured denial.
    let err = kernel
        .execute_step_auto(
            &who.id,
            &ep.branch,
            ActionKind::ConnectorOp {
                connector: "payments".into(),
                operation: "transfer".into(),
                params: json!({}),
            },
            None,
            None,
        )
        .await;
    match err {
        Err(ak_core::KernelError::Denied(_)) => {}
        other => panic!("expected policy denial, got {other:?}"),
    }
}

#[tokio::test]
async fn denials_carry_concrete_recovery_scopes() {
    let tmp = tempfile::tempdir().unwrap();
    let kernel = kernel_in(&tmp);
    let who = agent(&kernel);
    let ep = kernel.create_episode(&who.id, None, "recovery").unwrap();

    // Unknown lease → scope sketch for exactly this operation and params.
    let r = kernel
        .execute_step(
            &who.id,
            &ep.branch,
            Action {
                kind: shell_kind("id"),
                lease: LeaseId::generate(),
                intent_hint: None,
                budget: ResourceBudget::step_default(),
            },
        )
        .await
        .unwrap();
    match &r.observation {
        Observation::Denied { denial } => {
            assert_eq!(denial.requestable_scopes.len(), 1);
            assert_eq!(denial.requestable_scopes[0].operation.0, "proc.shell");
            assert!(!denial.requestable_scopes[0].requires_human);
        }
        other => panic!("expected denial, got {other:?}"),
    }

    // Branch-mismatched lease → recovery scope present too.
    let other_branch = kernel.fork_branch(&ep.branch).unwrap();
    let lease = kernel
        .request_capability(
            &who.id,
            &Operation::new("proc.shell"),
            &json!({}),
            Some(&other_branch.id),
        )
        .unwrap();
    let r = kernel
        .execute_step(
            &who.id,
            &ep.branch,
            Action {
                kind: shell_kind("id"),
                lease: lease.id.clone(),
                intent_hint: None,
                budget: ResourceBudget::step_default(),
            },
        )
        .await
        .unwrap();
    match &r.observation {
        Observation::Denied { denial } => {
            assert_eq!(denial.code, DenialCode::BranchMismatch);
            assert_eq!(denial.requestable_scopes.len(), 1);
        }
        other => panic!("expected denial, got {other:?}"),
    }

    // Over-budget action → the scope carries the budget that would fit.
    let lease = kernel
        .request_capability(
            &who.id,
            &Operation::new("proc.shell"),
            &json!({}),
            Some(&ep.branch),
        )
        .unwrap();
    let mut huge = ResourceBudget::step_default();
    huge.cpu_ms = u64::MAX;
    let r = kernel
        .execute_step(
            &who.id,
            &ep.branch,
            Action {
                kind: shell_kind("id"),
                lease: lease.id,
                intent_hint: None,
                budget: huge,
            },
        )
        .await
        .unwrap();
    match &r.observation {
        Observation::Denied { denial } => {
            assert_eq!(denial.code, DenialCode::BudgetExhausted);
            assert_eq!(denial.requestable_scopes.len(), 1);
            assert!(denial.requestable_scopes[0].constraints["budget"]["cpu_ms"].is_u64());
        }
        other => panic!("expected budget denial, got {other:?}"),
    }
}

// ====================================================== explore primitive

#[tokio::test]
async fn explore_runs_candidates_in_parallel_merges_winner_discards_losers() {
    let tmp = tempfile::tempdir().unwrap();
    let kernel = kernel_in(&tmp);
    let who = agent(&kernel);
    let ep = kernel.create_episode(&who.id, None, "search").unwrap();
    auto(
        &kernel,
        &who,
        &ep.branch,
        shell_kind("printf seed > seed.txt"),
    )
    .await;

    let report = kernel
        .explore(
            &who.id,
            &ep.branch,
            ExploreOptions {
                candidates: vec![
                    ExploreCandidate {
                        name: Some("seven".into()),
                        actions: vec![shell_kind("printf 7 > answer.txt")],
                    },
                    ExploreCandidate {
                        name: Some("forty-two".into()),
                        actions: vec![shell_kind("printf 42 > answer.txt")],
                    },
                    ExploreCandidate {
                        name: Some("negative".into()),
                        actions: vec![shell_kind("printf -- -1 > answer.txt")],
                    },
                ],
                evaluator: Some(shell_kind("grep -q 42 answer.txt")),
                max_parallel: Some(3),
                early_stop: false,
                merge_winner: true,
                discard_losers: true,
                step_budget: None,
            },
        )
        .await
        .unwrap();

    assert_eq!(report.winner, Some(1), "only `42` passes the evaluator");
    assert!(report.merged_state.is_some());
    assert!(report.merge_error.is_none());
    assert_eq!(report.candidates.len(), 3);
    assert!(report.candidates[1].passed);
    assert!(!report.candidates[0].passed);
    assert!(!report.candidates[2].passed);
    assert_eq!(report.discarded.len(), 2, "losers are torn down");

    // The winning artifact is now on the source branch (and the seed kept).
    let r = auto(
        &kernel,
        &who,
        &ep.branch,
        shell_kind("cat answer.txt seed.txt"),
    )
    .await;
    match &r.result.observation {
        Observation::Success {
            stdout_head: Some(head),
            ..
        } => assert!(head.contains("42") && head.contains("seed"), "got {head}"),
        other => panic!("expected success, got {other:?}"),
    }
}

#[tokio::test]
async fn explore_rejects_empty_and_oversized_candidate_sets() {
    let tmp = tempfile::tempdir().unwrap();
    let kernel = kernel_in(&tmp);
    let who = agent(&kernel);
    let ep = kernel.create_episode(&who.id, None, "bounds").unwrap();

    let empty = kernel
        .explore(
            &who.id,
            &ep.branch,
            ExploreOptions {
                candidates: vec![],
                evaluator: None,
                max_parallel: None,
                early_stop: true,
                merge_winner: false,
                discard_losers: true,
                step_budget: None,
            },
        )
        .await;
    assert!(empty.is_err());

    let too_many = kernel
        .explore(
            &who.id,
            &ep.branch,
            ExploreOptions {
                candidates: (0..17)
                    .map(|i| ExploreCandidate {
                        name: None,
                        actions: vec![shell_kind(&format!("echo {i}"))],
                    })
                    .collect(),
                evaluator: None,
                max_parallel: None,
                early_stop: true,
                merge_winner: false,
                discard_losers: true,
                step_budget: None,
            },
        )
        .await;
    assert!(too_many.is_err());
}

// ============================================ observation quality + trace

#[tokio::test]
async fn failure_observations_extract_the_causal_line_and_keep_the_tail() {
    let tmp = tempfile::tempdir().unwrap();
    let kernel = kernel_in(&tmp);
    let who = agent(&kernel);
    let ep = kernel.create_episode(&who.id, None, "diagnosis").unwrap();

    let r = auto(
        &kernel,
        &who,
        &ep.branch,
        shell_kind(
            "echo compiling; echo 'warning: minor' 1>&2; \
             echo 'error: the real cause' 1>&2; echo 'summary at end' 1>&2; exit 3",
        ),
    )
    .await;
    match &r.result.observation {
        Observation::Failure {
            exit_code,
            first_causal_failure,
            output_tail,
            ..
        } => {
            assert_eq!(*exit_code, 3);
            assert_eq!(
                first_causal_failure.as_deref(),
                Some("error: the real cause"),
                "the causal line is mid-stream, not line one"
            );
            assert!(output_tail.as_deref().unwrap().contains("summary at end"));
        }
        other => panic!("expected failure, got {other:?}"),
    }
}

#[tokio::test]
async fn trace_query_action_applies_its_query_string() {
    let tmp = tempfile::tempdir().unwrap();
    let kernel = kernel_in(&tmp);
    let who = agent(&kernel);
    let ep = kernel.create_episode(&who.id, None, "trace").unwrap();

    // Produce one denial and a few successes.
    let _ = kernel
        .execute_step(
            &who.id,
            &ep.branch,
            Action {
                kind: shell_kind("id"),
                lease: LeaseId::generate(),
                intent_hint: None,
                budget: ResourceBudget::step_default(),
            },
        )
        .await
        .unwrap();
    auto(&kernel, &who, &ep.branch, shell_kind("true")).await;

    let r = auto(
        &kernel,
        &who,
        &ep.branch,
        ActionKind::TraceQuery {
            query: "kind=denial_issued limit=10".into(),
        },
    )
    .await;
    match &r.result.observation {
        Observation::Success { data, .. } => {
            let data = data.as_ref().unwrap();
            assert_eq!(data["count"], 1, "only the denial event matches");
            assert_eq!(data["applied"]["kinds"][0], "denial_issued");
            assert_eq!(data["applied"]["limit"], 10);
        }
        other => panic!("expected success, got {other:?}"),
    }
}

#[tokio::test]
async fn incremental_snapshots_still_record_exact_deltas() {
    let tmp = tempfile::tempdir().unwrap();
    let kernel = kernel_in(&tmp);
    let who = agent(&kernel);
    let ep = kernel.create_episode(&who.id, None, "deltas").unwrap();

    let r1 = auto(&kernel, &who, &ep.branch, shell_kind("printf one > a.txt")).await;
    let d1 = kernel.dag().get_state(&r1.result.state).unwrap().delta;
    assert!(d1
        .files
        .iter()
        .any(|c| matches!(c, FileChange::Added { path, .. } if path == "a.txt")));

    // Same length, different content, seconds apart in the same workspace:
    // the stat cache must never swallow this change.
    let r2 = auto(&kernel, &who, &ep.branch, shell_kind("printf two > a.txt")).await;
    let d2 = kernel.dag().get_state(&r2.result.state).unwrap().delta;
    assert!(
        d2.files
            .iter()
            .any(|c| matches!(c, FileChange::Modified { path, .. } if path == "a.txt")),
        "delta was {:?}",
        d2.files
    );

    // Cache-tier dirs stay out of the DAG history entirely.
    let r3 = auto(
        &kernel,
        &who,
        &ep.branch,
        shell_kind(
            "mkdir -p node_modules/x && printf big > node_modules/x/blob && printf ok > src.txt",
        ),
    )
    .await;
    let d3 = kernel.dag().get_state(&r3.result.state).unwrap().delta;
    assert_eq!(d3.files.len(), 1, "delta was {:?}", d3.files);
    assert_eq!(d3.files[0].path(), "src.txt");
}

// ================================================== HTTP protocol layer

#[tokio::test]
async fn kernel_config_registers_http_connector_out_of_the_box() {
    let tmp = tempfile::tempdir().unwrap();
    let mut config = KernelConfig::new(tmp.path().join("data"));
    config.http = Some(ak_api::HttpEgressSetup {
        read_safe_domains: vec!["docs.example".into()],
        ..Default::default()
    });
    let kernel = Kernel::open(config).unwrap();
    assert!(
        kernel.connector("http").unwrap().is_some(),
        "a configured kernel must have a working observation plane without embedder code"
    );
    // And the YAML config-file shape works too (what the server bin loads).
    let yaml = format!(
        "data_dir: {}\nhttp:\n  read_safe_domains: [\"docs.rs\", \"*.wikipedia.org\"]\n",
        tmp.path().join("data2").display()
    );
    let config: KernelConfig = serde_yaml::from_str(&yaml).unwrap();
    assert_eq!(config.http.as_ref().unwrap().read_safe_domains.len(), 2);
    assert!(
        config.http.as_ref().unwrap().max_response_bytes > 0,
        "serde default must give a usable response cap"
    );
}

async fn req_json(
    app: &axum::Router,
    method: &str,
    uri: &str,
    body: Option<serde_json::Value>,
) -> (StatusCode, serde_json::Value) {
    let mut builder = Request::builder().method(method).uri(uri);
    let body = match body {
        Some(v) => {
            builder = builder.header("content-type", "application/json");
            Body::from(serde_json::to_vec(&v).unwrap())
        }
        None => Body::empty(),
    };
    let resp = app
        .clone()
        .oneshot(builder.body(body).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 22)
        .await
        .unwrap();
    let value = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    (status, value)
}

#[tokio::test]
async fn http_api_execute_auto_raw_pagination_and_explore() {
    let tmp = tempfile::tempdir().unwrap();
    let kernel = kernel_in(&tmp);
    let who = agent(&kernel);
    let app = http::router(kernel.clone());

    let (status, ep) = req_json(
        &app,
        "POST",
        "/v1/episodes",
        Some(json!({ "principal": who.id, "objective": "protocol" })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let branch = ep["branch"].as_str().unwrap().to_string();

    // execute_auto: no lease in the request at all.
    let (status, step) = req_json(
        &app,
        "POST",
        "/v1/steps/execute_auto",
        Some(json!({
            "principal": who.id,
            "branch": branch,
            "kind": { "kind": "shell", "command": "seq 1 300" },
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "auto step: {step}");
    assert_eq!(step["observation"]["kind"], "success");
    assert_eq!(step["lease_minted"], true);
    let hash = step["observation"]["full_output"].as_str().unwrap();

    // Raw pagination: two pages that concatenate to the full stream.
    let (status, page1) = req_json(
        &app,
        "GET",
        &format!("/v1/raw/{hash}?offset=0&limit=100"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(page1["returned_bytes"], 100);
    let next = page1["next_offset"].as_u64().unwrap();
    let (_, page2) = req_json(
        &app,
        "GET",
        &format!("/v1/raw/{hash}?offset={next}&limit=1000000"),
        None,
    )
    .await;
    assert!(page2["next_offset"].is_null(), "page 2 reaches the end");
    let total = page1["total_bytes"].as_u64().unwrap();
    assert_eq!(
        100 + page2["returned_bytes"].as_u64().unwrap(),
        total,
        "pages tile the blob exactly"
    );

    // Raw grep: find a line with its byte offset.
    let (status, hits) = req_json(&app, "GET", &format!("/v1/raw/{hash}?grep=299"), None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(hits["matches"].as_array().unwrap().len(), 1);
    assert_eq!(hits["matches"][0]["line"], "299");

    // Unknown blob → 404 envelope, not a 500.
    let (status, _) = req_json(&app, "GET", "/v1/raw/sha256:doesnotexist", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // Denied execute_auto → 403 with the structured denial AND lease info.
    let (status, denied) = req_json(
        &app,
        "POST",
        "/v1/steps/execute_auto",
        Some(json!({
            "principal": who.id,
            "branch": branch,
            "kind": { "kind": "http_read", "url": "http://docs.example/x" },
        })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "denied: {denied}");
    assert_eq!(denied["observation"]["kind"], "denied");

    // Explore over HTTP.
    let (status, report) = req_json(
        &app,
        "POST",
        &format!("/v1/branches/{branch}/explore"),
        Some(json!({
            "principal": who.id,
            "candidates": [
                { "name": "no", "actions": [{ "kind": "shell", "command": "printf no > pick.txt" }] },
                { "name": "yes", "actions": [{ "kind": "shell", "command": "printf yes > pick.txt" }] },
            ],
            "evaluator": { "kind": "shell", "command": "grep -q yes pick.txt" },
            "early_stop": false,
            "merge_winner": true,
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "explore: {report}");
    assert_eq!(report["winner"], 1);
    assert!(report["merged_state"].is_string());
}

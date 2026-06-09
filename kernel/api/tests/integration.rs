//! Integration tests: full lifecycle against the [`Kernel`] façade plus HTTP
//! smoke tests via `tower::ServiceExt::oneshot`.

use ak_api::{http, Kernel, KernelConfig};
use ak_core::action::{Action, ActionKind};
use ak_core::budget::ResourceBudget;
use ak_core::capability::Operation;
use ak_core::denial::DenialCode;
use ak_core::effect::{EffectClass, EffectContract};
use ak_core::ids::LeaseId;
use ak_core::observation::Observation;
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
            allow_rule("shell", &["proc.shell"], 100),
            allow_rule("fs", &["fs.*"], 100),
            allow_rule("mock", &["mock.*"], 10),
            allow_rule("meta", &["trace.query", "state.diff"], 100),
        ],
        egress_domains: vec!["api.github.com".into()],
        ..PolicyDocument::default()
    }
}

fn kernel_in(tmp: &tempfile::TempDir) -> Arc<Kernel> {
    let mut config = KernelConfig::new(tmp.path().join("data"));
    config.episode_budget = ResourceBudget {
        cpu_ms: 10 * 60 * 1000,
        memory_bytes: 8 << 30,
        network_bytes: 1 << 30,
        tokens: 1_000_000,
        cost_micro_usd: 10_000_000,
        risk_units: 1000,
    };
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

async fn shell(
    kernel: &Kernel,
    who: &Principal,
    branch: &ak_core::ids::BranchId,
    command: &str,
) -> ak_api::StepResult {
    let lease = kernel
        .request_capability(&who.id, &Operation::new("proc.shell"), &json!({}), Some(branch))
        .expect("shell lease");
    kernel
        .execute_step(
            &who.id,
            branch,
            Action {
                kind: ActionKind::Shell {
                    command: command.into(),
                    cwd: None,
                    env: BTreeMap::new(),
                },
                lease: lease.id,
                intent_hint: None,
                budget: ResourceBudget::step_default(),
            },
        )
        .await
        .expect("step executes")
}

#[tokio::test]
async fn full_lifecycle_fork_compare_merge_discard() {
    let tmp = tempfile::tempdir().unwrap();
    let kernel = kernel_in(&tmp);
    let who = agent(&kernel);

    let ep = kernel.create_episode(&who.id, None, "fix the widget").unwrap();
    let r = shell(&kernel, &who, &ep.branch, "printf base > base.txt").await;
    assert!(matches!(r.observation, Observation::Success { .. }));

    // Fork two candidate branches and apply different edits.
    let a = kernel.fork_branch(&ep.branch).unwrap();
    let b = kernel.fork_branch(&ep.branch).unwrap();
    let ra = shell(&kernel, &who, &a.id, "printf fix-a > fix_a.txt").await;
    assert!(matches!(ra.observation, Observation::Success { .. }));
    let rb = shell(&kernel, &who, &b.id, "printf fix-b > fix_b.txt").await;
    assert!(matches!(rb.observation, Observation::Success { .. }));

    // Compare: each branch changed exactly its own file.
    let cmp = kernel.branch_compare(&a.id, &b.id).unwrap();
    assert_eq!(cmp.changed_in_a.len(), 1);
    assert_eq!(cmp.changed_in_b.len(), 1);
    assert_eq!(cmp.changed_in_a[0].path(), "fix_a.txt");
    assert_eq!(cmp.changed_in_b[0].path(), "fix_b.txt");

    // Merge the winner (a) into main, discard the loser (b).
    let merged = kernel.merge_branch(&ep.branch, &a.id, &who.id).unwrap();
    assert!(merged.merge_parent.is_some());
    kernel.discard_branch(&b.id).await.unwrap();
    assert!(kernel.discard_branch(&b.id).await.is_err(), "double discard fails");

    // The merged workspace contains both base and the winning fix.
    let read = shell(&kernel, &who, &ep.branch, "cat base.txt fix_a.txt").await;
    match &read.observation {
        Observation::Success { stdout_head: Some(head), .. } => {
            assert!(head.contains("base") && head.contains("fix-a"), "got {head}")
        }
        other => panic!("expected success, got {other:?}"),
    }

    // Ledger chain is intact and the episode describes correctly.
    kernel.ledger().verify_chain().unwrap();
    let desc = kernel.describe_episode(&ep.episode).await.unwrap();
    assert_eq!(desc.branches.len(), 3);
}

#[tokio::test]
async fn denied_step_returns_structured_denial() {
    let tmp = tempfile::tempdir().unwrap();
    let kernel = kernel_in(&tmp);
    let who = agent(&kernel);
    let ep = kernel.create_episode(&who.id, None, "denial test").unwrap();

    // No lease at all → structured denial, not an error.
    let result = kernel
        .execute_step(
            &who.id,
            &ep.branch,
            Action {
                kind: ActionKind::Shell { command: "id".into(), cwd: None, env: BTreeMap::new() },
                lease: LeaseId::generate(),
                intent_hint: None,
                budget: ResourceBudget::step_default(),
            },
        )
        .await
        .expect("denial is an observation, not an Err");
    match &result.observation {
        Observation::Denied { denial } => {
            assert_eq!(denial.code, DenialCode::CapabilityDenied);
            assert_eq!(denial.attempted_operation.0, "proc.shell");
            assert!(!denial.reason.is_empty());
        }
        other => panic!("expected denial, got {other:?}"),
    }
    // A DenialIssued event is in the ledger.
    let events = kernel
        .trace_query(&ak_causal_ledger::TraceQuery {
            episode: Some(ep.episode.clone()),
            kinds: vec![ak_causal_ledger::EventKind::DenialIssued],
            ..Default::default()
        })
        .unwrap();
    assert_eq!(events.len(), 1);

    // Lease bound to a different branch → BranchMismatch.
    let other = kernel.fork_branch(&ep.branch).unwrap();
    let lease = kernel
        .request_capability(&who.id, &Operation::new("proc.shell"), &json!({}), Some(&other.id))
        .unwrap();
    let result = kernel
        .execute_step(
            &who.id,
            &ep.branch,
            Action {
                kind: ActionKind::Shell { command: "id".into(), cwd: None, env: BTreeMap::new() },
                lease: lease.id,
                intent_hint: None,
                budget: ResourceBudget::step_default(),
            },
        )
        .await
        .unwrap();
    match &result.observation {
        Observation::Denied { denial } => assert_eq!(denial.code, DenialCode::BranchMismatch),
        other => panic!("expected branch mismatch, got {other:?}"),
    }
}

/// A mock connector with a Compensatable operation and drift-free
/// preconditions.
struct MockConnector;

#[async_trait]
impl Connector for MockConnector {
    fn name(&self) -> &str {
        "mock"
    }
    fn operations(&self) -> Vec<(String, EffectClass)> {
        vec![("mock.create_widget".into(), EffectClass::Compensatable)]
    }
    fn canonicalize(&self, operation: &str, args: &serde_json::Value) -> KernelResult<serde_json::Value> {
        assert_eq!(operation, "mock.create_widget");
        Ok(args.clone())
    }
    async fn prepare(&self, _contract: &EffectContract) -> KernelResult<PreparedEffect> {
        Ok(PreparedEffect {
            preview: json!({ "action": "create a widget" }),
            observed_preconditions: json!({ "widget_slot": "empty" }),
        })
    }
    async fn commit(&self, contract: &EffectContract) -> KernelResult<CommitResult> {
        Ok(CommitResult { response: json!({ "created": contract.arguments["name"] }) })
    }
    async fn compensate(&self, _contract: &EffectContract) -> KernelResult<CommitResult> {
        Ok(CommitResult { response: json!({ "deleted": true }) })
    }
}

#[tokio::test]
async fn effect_lifecycle_with_signed_receipt() {
    let tmp = tempfile::tempdir().unwrap();
    let kernel = kernel_in(&tmp);
    kernel.register_connector(Arc::new(MockConnector)).unwrap();
    let who = agent(&kernel);
    let ep = kernel.create_episode(&who.id, None, "effect test").unwrap();

    let lease = kernel
        .request_capability(
            &who.id,
            &Operation::new("mock.create_widget"),
            &json!({ "name": "w1" }),
            Some(&ep.branch),
        )
        .unwrap();
    let result = kernel
        .execute_step(
            &who.id,
            &ep.branch,
            Action {
                kind: ActionKind::ConnectorOp {
                    connector: "mock".into(),
                    operation: "create_widget".into(),
                    params: json!({ "name": "w1" }),
                },
                lease: lease.id,
                intent_hint: Some("create the widget".into()),
                budget: ResourceBudget::step_default(),
            },
        )
        .await
        .unwrap();
    let effect_id = match &result.observation {
        Observation::EffectPending { effect, class, .. } => {
            assert_eq!(*class, EffectClass::Compensatable);
            effect.clone()
        }
        other => panic!("expected pending effect, got {other:?}"),
    };

    let prepared = kernel.prepare_effect(&effect_id).await.unwrap();
    assert_eq!(prepared.observed_preconditions["widget_slot"], "empty");
    kernel.approve_effect(&effect_id, &who.id).unwrap();
    let receipt = kernel.commit_effect(&effect_id).await.unwrap();
    assert_eq!(receipt.body.operation, "mock.create_widget");

    // Verify the Ed25519 signature against the kernel public key.
    assert!(kernel.verify_receipt(&receipt).unwrap());
    assert_eq!(receipt.key_id, kernel.keypair().key_id());
    let mut tampered = receipt.clone();
    tampered.body.resource = "someone/else".into();
    assert!(!kernel.verify_receipt(&tampered).unwrap());

    // Full effect chain is in the ledger.
    let kinds: Vec<_> = kernel
        .trace_query(&ak_causal_ledger::TraceQuery {
            episode: Some(ep.episode.clone()),
            ..Default::default()
        })
        .unwrap()
        .into_iter()
        .map(|e| e.kind)
        .collect();
    use ak_causal_ledger::EventKind as K;
    for k in [K::EffectProposed, K::EffectPrepared, K::EffectApproved, K::EffectCommitted] {
        assert!(kinds.contains(&k), "missing {k:?} in {kinds:?}");
    }

    // Compensation produces a second signed receipt.
    let comp = kernel.compensate_effect(&effect_id).await.unwrap();
    assert!(comp.body.operation.ends_with(".compensate"));
    assert!(kernel.verify_receipt(&comp).unwrap());
}

#[tokio::test]
async fn sandbox_replay_reproduces_a_recorded_step() {
    let tmp = tempfile::tempdir().unwrap();
    let kernel = kernel_in(&tmp);
    let who = agent(&kernel);
    let ep = kernel.create_episode(&who.id, None, "replay test").unwrap();
    let r = shell(&kernel, &who, &ep.branch, "printf deterministic > out.txt").await;
    let report = kernel.replay_sandbox(&r.step).await.unwrap();
    assert_eq!(report.rerun_exit_code, 0);
    assert_eq!(report.original_exit_code, Some(0));
    assert!(report.workspace_match, "deterministic step must replay byte-identically");
}

// ---------------------------------------------------------------- HTTP layer

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
    let resp = app.clone().oneshot(builder.body(body).unwrap()).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
    let value = if bytes.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap()
    };
    (status, value)
}

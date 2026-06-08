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

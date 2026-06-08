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

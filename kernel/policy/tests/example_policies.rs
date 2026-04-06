//! Integration tests: the shipped example policy files must load and behave.

use ak_core::capability::Operation;
use ak_core::denial::DenialCode;
use ak_core::principal::{Principal, TrustLevel};
use ak_policy::{Decision, PolicyDocument, PolicyEngine, SyscallProfile};
use chrono::Utc;
use serde_json::json;

fn load(name: &str) -> PolicyDocument {
    let path = format!("{}/policies/{name}", env!("CARGO_MANIFEST_DIR"));
    PolicyDocument::from_yaml_file(&path).unwrap_or_else(|e| panic!("loading {path}: {e}"))
}

#[test]
fn default_coding_agent_policy_loads_and_roundtrips() {
    let doc = load("default-coding-agent.yaml");
    assert_eq!(doc.policy_epoch, 1);
    let reparsed = PolicyDocument::from_yaml_str(&doc.to_yaml().unwrap()).unwrap();
    assert_eq!(reparsed, doc);
}

#[test]
fn default_policy_allows_src_writes_and_gates_prs() {
    let engine = PolicyEngine::new(load("default-coding-agent.yaml"));
    let agent = Principal::new_agent("coding-agent");
    let now = Utc::now();

    match engine.evaluate(&agent, &Operation::new("fs.write"), &json!({"path": "src/lib.rs"}), None, now) {
        Decision::Allow { rule_id, grant } => {
            assert_eq!(rule_id, "allow-write-src");
            assert_eq!(grant.confinement.egress_domains.len(), 2);
            assert_eq!(grant.confinement.syscall_profile, SyscallProfile::Standard);
        }
        other => panic!("expected allow, got {other:?}"),
    }

    match engine.evaluate(
        &agent,
        &Operation::new("github.create_pull_request"),
        &json!({"repository": "org/repo", "base": "main", "head": "sandbox/fix"}),
        None,
        now,
    ) {
        Decision::RequireApproval { rule_id, policy_epoch, .. } => {
            assert_eq!(rule_id, "approve-github-pr");
            assert_eq!(policy_epoch, 1);
        }
        other => panic!("expected approval, got {other:?}"),
    }

    // Other GitHub operations are explicitly forbidden.
    match engine.evaluate(&agent, &Operation::new("github.delete_repo"), &json!({}), None, now) {
        Decision::Deny { denial } => {
            assert_eq!(denial.code, DenialCode::PolicyForbidden);
            assert!(denial.escalation_allowed);
            assert!(!denial.safe_alternatives.is_empty());
        }
        other => panic!("expected deny, got {other:?}"),
    }
}

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

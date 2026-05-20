use ak_backend_local::{b64, LocalBackend, LocalBackendConfig};
use ak_core::action::ActionKind;
use ak_core::budget::ResourceBudget;
use ak_core::error::KernelError;
use ak_core::ids::{BranchId, PrincipalId, StateId};
use ak_core::replay::ReplayClass;
use ak_core::traits::{Backend, ExecutionRequest};
use std::collections::BTreeMap;
use std::time::Instant;

fn backend(root: &std::path::Path) -> LocalBackend {
    LocalBackend::new(LocalBackendConfig::new(root)).expect("backend")
}

fn req(action: ActionKind) -> ExecutionRequest {
    ExecutionRequest {
        branch: BranchId("br-test".into()),
        base_state: StateId("st-0".into()),
        actor: PrincipalId("pr-test".into()),
        action,
        budget: ResourceBudget::step_default(),
        writable_prefixes: vec![],
        readable_prefixes: vec![],
        egress_domains: vec![],
    }
}

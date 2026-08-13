//! Config-driven multi-backend routing with honest state recording.
//!
//! The policy rule's `risk_weight` sets a step's isolation floor; the
//! router picks the cheapest satisfying backend. A backend that does not
//! share the kernel workspace runs the step as an **audit-only excursion**:
//! full observation in the ledger, `AuditOnly` node with an empty file
//! delta in the DAG — never a pretended local state transition. Anything
//! the DAG must snapshot (file actions) stays pinned to workspace-sharing
//! backends, and an unsatisfiable floor is a *recorded* denial.

use ak_api::{Kernel, KernelConfig};
use ak_core::action::ActionKind;
use ak_core::budget::ResourceBudget;
use ak_core::observation::Observation;
use ak_core::replay::ReplayClass;
use ak_core::traits::{Backend, BackendProfile, ExecutionOutcome, ExecutionRequest};
use ak_core::{KernelResult, Principal};
use ak_policy::{PolicyDocument, PolicyRule, PrincipalSelector, RuleEffect};
use async_trait::async_trait;
use indexmap::IndexMap;
use std::collections::BTreeMap;
use std::sync::Arc;

/// A strong remote backend that does not share the kernel workspace.
struct Strongbox;

#[async_trait]
impl Backend for Strongbox {
    fn profile(&self) -> BackendProfile {
        BackendProfile {
            name: "strongbox".into(),
            isolation_strength: 90,
            cold_start_ms: 50,
            replay_class: ReplayClass::FilesystemOnly,
            supports_fork: false,
            supports_gui: false,
            full_linux: true,
            shares_workspace: false,
        }
    }

    async fn execute(&self, _req: ExecutionRequest) -> KernelResult<ExecutionOutcome> {
        Ok(ExecutionOutcome {
            exit_code: 0,
            stdout: b"ran-remotely".to_vec(),
            stderr: Vec::new(),
            usage: ResourceBudget::zero(),
            paths_written: vec!["remote-only.txt".into()],
            replay_class: ReplayClass::FilesystemOnly,
        })
    }
}

fn rule(id: &str, ops: &[&str], risk_weight: u32) -> PolicyRule {
    PolicyRule {
        id: id.into(),
        principals: PrincipalSelector::default(),
        operations: ops.iter().map(|s| s.to_string()).collect(),
        effect: RuleEffect::Allow,
        constraints: IndexMap::new(),
        max_uses: 100,
        ttl_seconds: 3600,
        budget: None,
        risk_weight,
        note: None,
    }
}

/// Shell demands High isolation; file ops stay Low.
fn risky_shell_policy() -> PolicyDocument {
    PolicyDocument {
        rules: vec![rule("shell", &["proc.shell"], 8), rule("fs", &["fs.*"], 0)],
        ..PolicyDocument::default()
    }
}

fn kernel_with_policy(tmp: &tempfile::TempDir, doc: PolicyDocument) -> Arc<Kernel> {
    let kernel = Kernel::open(KernelConfig::new(tmp.path().join("data"))).unwrap();
    kernel.with_policy_mut(|p| *p.document_mut() = doc).unwrap();
    Arc::new(kernel)
}

fn agent(kernel: &Kernel) -> Principal {
    let p = Principal::new_agent("routing-test");
    kernel.register_principal(&p).unwrap();
    p
}

fn shell(command: &str) -> ActionKind {
    ActionKind::Shell {
        command: command.into(),
        cwd: None,
        env: BTreeMap::new(),
    }
}

#[tokio::test]
async fn high_risk_shell_routes_to_strong_backend_as_audit_only_excursion() {
    let tmp = tempfile::tempdir().unwrap();
    let kernel = kernel_with_policy(&tmp, risky_shell_policy());
    kernel.register_backend(Arc::new(Strongbox));
    let who = agent(&kernel);
    let ep = kernel.create_episode(&who.id, None, "routing").unwrap();

    // Seed the local tree through the (low-risk) file plane first.
    let seed = kernel
        .execute_step_auto(
            &who.id,
            &ep.branch,
            ActionKind::WriteFile {
                path: "local.txt".into(),
                contents_b64: ak_backend_local::b64::encode(b"local-state"),
            },
            None,
            None,
        )
        .await
        .unwrap();
    let seeded_root = kernel
        .dag()
        .get_state(&seed.result.state)
        .unwrap()
        .workspace_root;

    // The high-risk shell must land on the strong backend…
    let r = kernel
        .execute_step_auto(&who.id, &ep.branch, shell("hostile-build"), None, None)
        .await
        .unwrap();
    let (summary, full_output) = match &r.result.observation {
        Observation::Success {
            summary,
            full_output,
            ..
        } => (summary.clone(), full_output.clone()),
        other => panic!("expected success via the strong backend, got {other:?}"),
    };
    let raw = kernel.fetch_raw(&full_output).unwrap();
    assert!(
        String::from_utf8_lossy(&raw).contains("ran-remotely"),
        "the step must have executed on the registered strong backend"
    );
    assert!(
        summary.contains("strongbox") && summary.contains("audit-only"),
        "the observation must name the excursion: {summary}"
    );

    // …and be recorded honestly: AuditOnly node, empty file delta, local
    // workspace root unchanged.
    let node = kernel.dag().get_state(&r.result.state).unwrap();
    assert_eq!(node.replay_class, ReplayClass::AuditOnly);
    assert!(
        node.delta.files.is_empty(),
        "an excursion must not claim local file changes: {:?}",
        node.delta.files
    );
    assert_eq!(
        node.workspace_root, seeded_root,
        "the local workspace root must be untouched by a remote excursion"
    );

    // Local state continuity: a low-risk file read still sees the seed.
    let read = kernel
        .execute_step_auto(
            &who.id,
            &ep.branch,
            ActionKind::ReadFile {
                path: "local.txt".into(),
            },
            None,
            None,
        )
        .await
        .unwrap();
    match &read.result.observation {
        Observation::Success { full_output, .. } => {
            let raw = kernel.fetch_raw(full_output).unwrap();
            assert!(String::from_utf8_lossy(&raw).contains("local-state"));
        }
        other => panic!("local plane must keep working after an excursion: {other:?}"),
    }
}

#[tokio::test]
async fn unsatisfiable_isolation_floor_is_a_recorded_denial() {
    let tmp = tempfile::tempdir().unwrap();
    // High-risk shell, but no strong backend registered.
    let kernel = kernel_with_policy(&tmp, risky_shell_policy());
    let who = agent(&kernel);
    let ep = kernel.create_episode(&who.id, None, "no-backend").unwrap();

    let r = kernel
        .execute_step_auto(&who.id, &ep.branch, shell("echo hi"), None, None)
        .await
        .unwrap();
    match &r.result.observation {
        Observation::Denied { denial } => {
            assert_eq!(denial.code, ak_core::denial::DenialCode::BackendUnavailable);
            assert!(
                denial.reason.contains("isolation") && denial.reason.contains("risk_weight"),
                "the denial must explain the floor and the recovery: {}",
                denial.reason
            );
        }
        other => panic!("expected a recorded routing denial, got {other:?}"),
    }
}

#[tokio::test]
async fn file_actions_never_route_off_the_workspace() {
    let tmp = tempfile::tempdir().unwrap();
    // Even with a strong backend registered, a high-risk *file* action has
    // no satisfying candidate: the DAG must snapshot its effects, and the
    // strong backend does not share the workspace.
    let kernel = kernel_with_policy(
        &tmp,
        PolicyDocument {
            rules: vec![rule("fs", &["fs.*"], 8)],
            ..PolicyDocument::default()
        },
    );
    kernel.register_backend(Arc::new(Strongbox));
    let who = agent(&kernel);
    let ep = kernel.create_episode(&who.id, None, "pin-files").unwrap();

    let r = kernel
        .execute_step_auto(
            &who.id,
            &ep.branch,
            ActionKind::WriteFile {
                path: "x.txt".into(),
                contents_b64: ak_backend_local::b64::encode(b"x"),
            },
            None,
            None,
        )
        .await
        .unwrap();
    match &r.result.observation {
        Observation::Denied { denial } => {
            assert_eq!(denial.code, ak_core::denial::DenialCode::BackendUnavailable)
        }
        other => panic!("file actions must never excurse, got {other:?}"),
    }
}

#[tokio::test]
async fn kernel_config_backends_yaml_registers_router_candidates() {
    let tmp = tempfile::tempdir().unwrap();
    let yaml = format!
        (
        "data_dir: {}\nbackends:\n  - kind: gvisor\n    endpoint: http://127.0.0.1:9\n  - kind: kubernetes\n    endpoint: http://127.0.0.1:9\n    isolation_strength: 75\n",
        tmp.path().join("data").display()
    );
    let config: KernelConfig = serde_yaml::from_str(&yaml).unwrap();
    let kernel = Kernel::open(config).unwrap();
    let names: Vec<String> = kernel
        .backend_profiles()
        .into_iter()
        .map(|p| p.name)
        .collect();
    assert!(names.contains(&"local".to_string()), "{names:?}");
    assert!(names.contains(&"gvisor".to_string()), "{names:?}");
    assert!(names.contains(&"kubernetes".to_string()), "{names:?}");
    // Remote adapters must never claim the kernel workspace.
    for p in kernel.backend_profiles() {
        if p.name != "local" {
            assert!(
                !p.shares_workspace,
                "{} must not claim the workspace",
                p.name
            );
        }
    }
}

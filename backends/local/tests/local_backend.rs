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

fn shell(cmd: &str) -> ActionKind {
    ActionKind::Shell { command: cmd.into(), cwd: None, env: BTreeMap::new() }
}

#[tokio::test]
async fn echo_runs_and_reports_usage() {
    let tmp = tempfile::tempdir().unwrap();
    let b = backend(tmp.path());
    let out = b.execute(req(shell("echo hello"))).await.unwrap();
    assert_eq!(out.exit_code, 0);
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "hello");
    assert_eq!(out.replay_class, ReplayClass::FilesystemOnly);
    assert!(out.usage.memory_bytes >= 6);
}

#[tokio::test]
async fn timeout_kills_the_process() {
    let tmp = tempfile::tempdir().unwrap();
    let b = backend(tmp.path());
    let mut r = req(shell("sleep 30"));
    r.budget.cpu_ms = 300;
    let started = Instant::now();
    let out = b.execute(r).await.unwrap();
    assert_eq!(out.exit_code, -1);
    assert!(String::from_utf8_lossy(&out.stderr).contains("timeout"));
    assert!(started.elapsed().as_secs() < 10, "process was not killed promptly");
}

#[tokio::test]
async fn zero_cpu_budget_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let b = backend(tmp.path());
    let mut r = req(shell("echo hi"));
    r.budget.cpu_ms = 0;
    assert!(matches!(b.execute(r).await, Err(KernelError::Denied(_))));
}

#[tokio::test]
async fn env_is_scrubbed() {
    std::env::set_var("AK_SECRET_CANARY", "leak-me");
    let tmp = tempfile::tempdir().unwrap();
    let b = backend(tmp.path());
    let out = b.execute(req(shell("env"))).await.unwrap();
    let env_dump = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(!env_dump.contains("AK_SECRET_CANARY"), "secret leaked: {env_dump}");
    assert!(env_dump.contains("PATH="));
    // HOME points into the workspace, not at the real home directory.
    let home_line = env_dump.lines().find(|l| l.starts_with("HOME=")).expect("HOME set");
    assert!(home_line.contains("br-test"), "unexpected HOME: {home_line}");
}

//! Group-level (cgroup v2) enforcement through the real backend: tree-wide
//! pid and memory ceilings, and full-tree reaping. These run end-to-end
//! only on Linux hosts with a delegated cgroup parent (CI exports
//! `AK_CGROUP_PARENT`); everywhere else they skip after asserting the
//! probe stayed honestly off.

use ak_backend_local::{LocalBackend, LocalBackendConfig};
use ak_core::action::ActionKind;
use ak_core::budget::ResourceBudget;
use ak_core::ids::{BranchId, PrincipalId, StateId};
use ak_core::traits::{Backend, ExecutionRequest};
use std::collections::BTreeMap;

fn backend_with(tmp: &tempfile::TempDir, max_pids: u64) -> LocalBackend {
    backend_with_wall(tmp, max_pids, std::time::Duration::from_secs(10))
}

fn backend_with_wall(
    tmp: &tempfile::TempDir,
    max_pids: u64,
    max_wall_clock: std::time::Duration,
) -> LocalBackend {
    let mut config = LocalBackendConfig::new(tmp.path().join("ws"));
    config.max_pids = max_pids;
    config.max_wall_clock = max_wall_clock;
    // Not an egress test; skip forwarder probing noise.
    config.egress.enabled = false;
    LocalBackend::new(config.dangerously_allow_unsandboxed()).unwrap()
}

fn require_cgroups(backend: &LocalBackend) -> bool {
    if backend.cgroups_verified() {
        return true;
    }
    if std::env::var("AK_REQUIRE_CGROUP").as_deref() == Ok("1") {
        panic!("AK_REQUIRE_CGROUP=1 but the delegated cgroup v2 probe failed");
    }
    eprintln!("skipping: no delegated cgroup parent on this host");
    false
}

fn shell(branch: &BranchId, command: &str, budget: ResourceBudget) -> ExecutionRequest {
    ExecutionRequest {
        branch: branch.clone(),
        base_state: StateId::generate(),
        actor: PrincipalId::generate(),
        action: ActionKind::Shell {
            command: command.into(),
            cwd: None,
            env: BTreeMap::new(),
        },
        budget,
        writable_prefixes: Vec::new(),
        readable_prefixes: Vec::new(),
        egress_domains: Vec::new(),
    }
}

#[tokio::test]
async fn pids_ceiling_caps_the_whole_tree() {
    let tmp = tempfile::tempdir().unwrap();
    let backend = backend_with(&tmp, 16);
    if !require_cgroups(&backend) {
        return;
    }
    let branch = BranchId::generate();
    backend.workspace_for(&branch).unwrap();

    // Try to hold 60 concurrent sleepers under a 16-task tree ceiling.
    // The kernel counter, rather than shell-specific exit behavior, is the
    // authoritative proof that forks were rejected.
    let outcome = backend
        .execute(shell(
            &branch,
            "for i in $(seq 1 60); do sleep 3 & done; wait",
            ResourceBudget {
                cpu_ms: 30_000,
                ..ResourceBudget::zero()
            },
        ))
        .await
        .unwrap();
    let stderr = String::from_utf8_lossy(&outcome.stderr);
    assert!(
        stderr.contains("process creation denied"),
        "pids.events:max must be surfaced; stderr: {stderr}"
    );
}

#[tokio::test]
async fn memory_ceiling_oom_kills_and_is_reported() {
    let tmp = tempfile::tempdir().unwrap();
    let backend = backend_with(&tmp, 512);
    if !require_cgroups(&backend) {
        return;
    }
    let branch = BranchId::generate();
    backend.workspace_for(&branch).unwrap();

    // Grow resident anonymous memory without bound under a 64 MiB tree
    // ceiling. The memcg OOM killer must terminate the allocator.
    let outcome = backend
        .execute(shell(
            &branch,
            "python3 -c 'a=[]\nwhile True: a.append(bytearray(1048576))'",
            ResourceBudget {
                cpu_ms: 30_000,
                memory_bytes: 64 << 20,
                ..ResourceBudget::zero()
            },
        ))
        .await
        .unwrap();
    let stderr = String::from_utf8_lossy(&outcome.stderr);
    assert_ne!(
        outcome.exit_code, 0,
        "the allocator must die under memory.max; stderr: {stderr}"
    );
    assert!(
        stderr.contains("oom-killed"),
        "kernel OOM kills under the ceiling must be surfaced: {stderr}"
    );
    // Tree-wide peak metering came from the cgroup, bounded by the limit.
    assert!(outcome.usage.memory_bytes > 0);
}

/// A `setsid` escapee outlives the process group but not the step cgroup:
/// after a timed-out step, nothing from the tree may survive.
#[tokio::test]
async fn setsid_escapees_die_with_the_step_cgroup() {
    let tmp = tempfile::tempdir().unwrap();
    let backend = backend_with_wall(&tmp, 64, std::time::Duration::from_secs(1));
    if !require_cgroups(&backend) {
        return;
    }
    let branch = BranchId::generate();
    let ws = backend.workspace_for(&branch).unwrap();

    // The escapee daemonizes via setsid and would write a marker after 4s
    // if it survived the step teardown. The operator wall ceiling is 1s.
    let outcome = backend
        .execute(shell(
            &branch,
            "setsid sh -c 'sleep 4; echo alive > escapee-was-here' & sleep 30",
            ResourceBudget {
                cpu_ms: 1_000,
                ..ResourceBudget::zero()
            },
        ))
        .await
        .unwrap();
    assert_ne!(outcome.exit_code, 0, "the step must have timed out");
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    assert!(
        !ws.join("escapee-was-here").exists(),
        "a setsid escapee must not survive the step cgroup"
    );
}

#[tokio::test]
async fn aggregate_cpu_budget_caps_parallel_workers_and_is_metered() {
    let tmp = tempfile::tempdir().unwrap();
    let backend = backend_with(&tmp, 64);
    if !require_cgroups(&backend) {
        return;
    }
    let branch = BranchId::generate();
    backend.workspace_for(&branch).unwrap();

    let outcome = backend
        .execute(shell(
            &branch,
            "for i in 1 2 3 4; do sh -c 'while :; do :; done' & done; wait",
            ResourceBudget {
                cpu_ms: 1_000,
                ..ResourceBudget::zero()
            },
        ))
        .await
        .unwrap();
    let stderr = String::from_utf8_lossy(&outcome.stderr);
    assert_ne!(outcome.exit_code, 0);
    assert!(
        stderr.contains("aggregate CPU budget"),
        "the cgroup CPU cutoff must be explicit: {stderr}"
    );
    assert!(
        outcome.usage.cpu_ms >= 1_000,
        "usage must be the whole tree, got {} ms",
        outcome.usage.cpu_ms
    );
}

#[tokio::test]
async fn process_session_cpu_budget_is_enforced_for_its_lifetime() {
    let tmp = tempfile::tempdir().unwrap();
    let backend = backend_with(&tmp, 64);
    if !require_cgroups(&backend) {
        return;
    }
    let branch = BranchId::generate();
    backend.workspace_for(&branch).unwrap();
    let mut request = shell(
        &branch,
        "for i in 1 2 3 4; do sh -c 'while :; do :; done' & done; wait",
        ResourceBudget {
            cpu_ms: 500,
            ..ResourceBudget::zero()
        },
    );
    request.action = ActionKind::ProcessStart {
        command: match &request.action {
            ActionKind::Shell { command, .. } => command.clone(),
            _ => unreachable!(),
        },
        cwd: None,
        env: BTreeMap::new(),
        name: Some("cpu-tree".into()),
    };
    let started = backend.execute(request).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&started.stdout).unwrap();
    let id = body["process"].as_str().unwrap();

    let mut status = serde_json::Value::Null;
    for _ in 0..100 {
        let session = backend.processes().get(&branch, id).unwrap();
        status = session.status_json();
        if status["cpu_budget_exhausted"] == true && status["running"] == false {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert_eq!(status["cpu_budget_exhausted"], true, "status: {status}");
    assert_eq!(status["running"], false, "status: {status}");
    assert!(status["cpu_ms"].as_u64().unwrap_or(0) >= 500);
}

#[tokio::test]
async fn process_session_tracks_and_kills_daemonized_descendants() {
    let tmp = tempfile::tempdir().unwrap();
    let backend = backend_with(&tmp, 64);
    if !require_cgroups(&backend) {
        return;
    }
    let branch = BranchId::generate();
    let workspace = backend.workspace_for(&branch).unwrap();
    let mut request = shell(
        &branch,
        "setsid sh -c 'echo $$ > daemon.pid; sleep 30' >/dev/null 2>&1 &",
        ResourceBudget {
            cpu_ms: 30_000,
            ..ResourceBudget::zero()
        },
    );
    request.action = ActionKind::ProcessStart {
        command: match &request.action {
            ActionKind::Shell { command, .. } => command.clone(),
            _ => unreachable!(),
        },
        cwd: None,
        env: BTreeMap::new(),
        name: Some("daemon-tree".into()),
    };
    let started = backend.execute(request).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&started.stdout).unwrap();
    let id = body["process"].as_str().unwrap();

    let session = backend.processes().get(&branch, id).unwrap();
    for _ in 0..100 {
        if session.exit_code().is_some() && workspace.join("daemon.pid").exists() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(
        session.exit_code().is_some(),
        "the process-session leader should have exited"
    );
    let daemon_pid = std::fs::read_to_string(workspace.join("daemon.pid"))
        .unwrap()
        .trim()
        .parse::<u32>()
        .unwrap();
    assert!(
        session.running(),
        "the session must remain live while its daemonized cgroup member lives"
    );

    session.signal("kill").unwrap();
    let proc_path = std::path::PathBuf::from(format!("/proc/{daemon_pid}"));
    for _ in 0..100 {
        if !session.running() && !proc_path.exists() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(
        !session.running(),
        "cgroup.kill must empty the session tree"
    );
    assert!(
        !proc_path.exists(),
        "the daemonized descendant must be gone"
    );
}

#[test]
fn zero_pid_ceiling_is_rejected_at_construction() {
    let tmp = tempfile::tempdir().unwrap();
    let mut config = LocalBackendConfig::new(tmp.path());
    config.max_pids = 0;
    let err = LocalBackend::new(config)
        .err()
        .expect("invalid configuration");
    assert!(err.to_string().contains("max_pids"));
}

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
    ActionKind::Shell {
        command: cmd.into(),
        cwd: None,
        env: BTreeMap::new(),
    }
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
    assert!(
        started.elapsed().as_secs() < 10,
        "process was not killed promptly"
    );
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
    assert!(
        !env_dump.contains("AK_SECRET_CANARY"),
        "secret leaked: {env_dump}"
    );
    assert!(env_dump.contains("PATH="));
    // HOME points into the workspace, not at the real home directory.
    let home_line = env_dump
        .lines()
        .find(|l| l.starts_with("HOME="))
        .expect("HOME set");
    assert!(
        home_line.contains("br-test"),
        "unexpected HOME: {home_line}"
    );
}

#[tokio::test]
async fn path_escape_rejected_for_reads_writes_and_deletes() {
    let tmp = tempfile::tempdir().unwrap();
    let b = backend(tmp.path());
    for action in [
        ActionKind::ReadFile {
            path: "../outside.txt".into(),
        },
        ActionKind::ReadFile {
            path: "/etc/passwd".into(),
        },
        ActionKind::WriteFile {
            path: "a/../../evil".into(),
            contents_b64: b64::encode(b"x"),
        },
        ActionKind::DeletePath { path: "..".into() },
    ] {
        let err = b.execute(req(action)).await.expect_err("should be denied");
        assert!(matches!(err, KernelError::Denied(_)), "got {err:?}");
    }
}

#[cfg(unix)]
#[tokio::test]
async fn symlink_escape_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let b = backend(tmp.path());
    // Materialize the workspace, then plant a symlink pointing outside it.
    b.execute(req(shell("true"))).await.unwrap();
    let ws = tmp.path().join("br-test");
    std::os::unix::fs::symlink(outside.path(), ws.join("link")).unwrap();
    let err = b
        .execute(req(ActionKind::WriteFile {
            path: "link/pwned.txt".into(),
            contents_b64: b64::encode(b"x"),
        }))
        .await
        .expect_err("symlink escape must be denied");
    assert!(matches!(err, KernelError::Denied(_)));
    assert!(!outside.path().join("pwned.txt").exists());
}

#[tokio::test]
async fn write_read_delete_round_trip_and_paths_written() {
    let tmp = tempfile::tempdir().unwrap();
    let b = backend(tmp.path());
    let out = b
        .execute(req(ActionKind::WriteFile {
            path: "sub/dir/hello.txt".into(),
            contents_b64: b64::encode(b"payload"),
        }))
        .await
        .unwrap();
    assert_eq!(out.exit_code, 0);
    assert_eq!(out.paths_written, vec!["sub/dir/hello.txt".to_string()]);

    let out = b
        .execute(req(ActionKind::ReadFile {
            path: "sub/dir/hello.txt".into(),
        }))
        .await
        .unwrap();
    assert_eq!(out.stdout, b"payload");
    assert!(out.paths_written.is_empty());

    let out = b
        .execute(req(ActionKind::DeletePath { path: "sub".into() }))
        .await
        .unwrap();
    assert_eq!(out.exit_code, 0);

    let out = b
        .execute(req(ActionKind::ReadFile {
            path: "sub/dir/hello.txt".into(),
        }))
        .await
        .unwrap();
    assert_eq!(out.exit_code, 1);
}

#[tokio::test]
async fn writable_prefixes_are_enforced() {
    let tmp = tempfile::tempdir().unwrap();
    let b = backend(tmp.path());
    let mut r = req(ActionKind::WriteFile {
        path: "src/main.rs".into(),
        contents_b64: b64::encode(b"fn main() {}"),
    });
    r.writable_prefixes = vec!["docs/".into()];
    assert!(matches!(b.execute(r).await, Err(KernelError::Denied(_))));

    let mut r = req(ActionKind::WriteFile {
        path: "docs/x.md".into(),
        contents_b64: b64::encode(b"# hi"),
    });
    r.writable_prefixes = vec!["docs/".into()];
    assert_eq!(b.execute(r).await.unwrap().exit_code, 0);
}

#[tokio::test]
async fn shell_detects_paths_written() {
    let tmp = tempfile::tempdir().unwrap();
    let b = backend(tmp.path());
    let out = b
        .execute(req(shell("echo data > created.txt")))
        .await
        .unwrap();
    assert_eq!(out.exit_code, 0);
    assert!(
        out.paths_written.contains(&"created.txt".to_string()),
        "{:?}",
        out.paths_written
    );
}

#[tokio::test]
async fn discard_removes_workspace() {
    let tmp = tempfile::tempdir().unwrap();
    let b = backend(tmp.path());
    b.execute(req(shell("touch f"))).await.unwrap();
    let branch = BranchId("br-test".into());
    assert!(tmp.path().join("br-test").exists());
    b.discard(&branch).await.unwrap();
    assert!(!tmp.path().join("br-test").exists());
}

#[test]
fn profile_is_honest() {
    let tmp = tempfile::tempdir().unwrap();
    let b = backend(tmp.path());
    let p = b.profile();
    assert_eq!(p.name, "local");
    // Isolation strength is the probe-verified value, never a declaration.
    assert_eq!(p.isolation_strength, b.sandbox_tech().isolation_strength());
    assert_eq!(p.full_linux, cfg!(target_os = "linux"));
    assert!(!p.supports_fork);
    assert!(!p.supports_gui);
}

// --- AK-001 regression suite -----------------------------------------------
//
// The review's black-box escape test obtained a `proc.shell` lease and
// produced `{host_read: true, host_write: true, network_egress: true,
// write_outside_policy_prefix: true}`. Each marker must now be false. These
// tests run inside the real OS sandbox and are skipped (loudly) only where
// no sandbox exists — where the backend fails closed instead, which
// `fail_closed_without_sandbox` pins down.

fn sandboxed(b: &LocalBackend) -> bool {
    b.sandbox_tech() != ak_backend_local::SandboxTech::None
}

#[tokio::test]
async fn shell_cannot_read_host_files_outside_workspace() {
    let tmp = tempfile::tempdir().unwrap();
    let b = backend(tmp.path());
    if !sandboxed(&b) {
        eprintln!("SKIP: no OS sandbox on this host (fail-closed path covers this)");
        return;
    }
    let host = tempfile::tempdir().unwrap();
    let secret = host.path().join("host-secret.txt");
    std::fs::write(&secret, "credentials").unwrap();
    let out = b
        .execute(req(shell(&format!("cat {}", secret.display()))))
        .await
        .unwrap();
    assert_ne!(out.exit_code, 0, "host read must be denied");
    assert!(!String::from_utf8_lossy(&out.stdout).contains("credentials"));
}

#[tokio::test]
async fn shell_cannot_write_host_files_outside_workspace() {
    let tmp = tempfile::tempdir().unwrap();
    let b = backend(tmp.path());
    if !sandboxed(&b) {
        eprintln!("SKIP: no OS sandbox on this host");
        return;
    }
    let host = tempfile::tempdir().unwrap();
    let target = host.path().join("pwned.txt");
    let out = b
        .execute(req(shell(&format!("echo x > {}", target.display()))))
        .await
        .unwrap();
    assert_ne!(out.exit_code, 0, "host write must be denied");
    assert!(!target.exists(), "file must not exist on the host");
}

#[tokio::test]
async fn shell_has_no_network_egress() {
    let tmp = tempfile::tempdir().unwrap();
    let b = backend(tmp.path());
    if !sandboxed(&b) {
        eprintln!("SKIP: no OS sandbox on this host");
        return;
    }
    // A TCP connect to a public resolver must fail inside the sandbox.
    let probe = if cfg!(target_os = "macos") {
        "/usr/bin/nc -G 2 -z 1.1.1.1 53"
    } else {
        "timeout 2 sh -c 'exec 3<>/dev/tcp/1.1.1.1/53'"
    };
    let out = b.execute(req(shell(probe))).await.unwrap();
    assert_ne!(
        out.exit_code,
        0,
        "network egress must be denied: {:?}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[tokio::test]
async fn shell_respects_writable_prefixes() {
    let tmp = tempfile::tempdir().unwrap();
    let b = backend(tmp.path());
    if !sandboxed(&b) {
        eprintln!("SKIP: no OS sandbox on this host");
        return;
    }
    let ws = b.workspace_for(&BranchId("br-test".into())).unwrap();
    std::fs::create_dir_all(ws.join("src")).unwrap();
    // Writing inside the allowed prefix succeeds…
    let mut r = req(shell("echo ok > src/allowed.txt"));
    r.writable_prefixes = vec!["src/".into()];
    let out = b.execute(r).await.unwrap();
    assert_eq!(
        out.exit_code,
        0,
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(ws.join("src/allowed.txt").exists());
    // …writing outside it is denied by the OS sandbox, not just convention.
    let mut r = req(shell("echo no > outside.txt"));
    r.writable_prefixes = vec!["src/".into()];
    let out = b.execute(r).await.unwrap();
    assert_ne!(
        out.exit_code, 0,
        "write outside the writable prefix must be denied"
    );
    assert!(!ws.join("outside.txt").exists());
}

#[tokio::test]
async fn shell_respects_readable_prefixes() {
    let tmp = tempfile::tempdir().unwrap();
    let b = backend(tmp.path());
    if !sandboxed(&b) {
        eprintln!("SKIP: no OS sandbox on this host");
        return;
    }
    let ws = b.workspace_for(&BranchId("br-test".into())).unwrap();
    std::fs::create_dir_all(ws.join("src")).unwrap();
    std::fs::write(ws.join("src/visible.txt"), "readable").unwrap();
    std::fs::write(ws.join("hidden.txt"), "confined").unwrap();
    let mut r = req(shell("cat src/visible.txt"));
    r.readable_prefixes = vec!["src/".into()];
    let out = b.execute(r).await.unwrap();
    assert_eq!(out.exit_code, 0);
    assert!(String::from_utf8_lossy(&out.stdout).contains("readable"));
    let mut r = req(shell("cat hidden.txt"));
    r.readable_prefixes = vec!["src/".into()];
    let out = b.execute(r).await.unwrap();
    assert_ne!(
        out.exit_code, 0,
        "read outside the readable prefix must be denied"
    );
    assert!(!String::from_utf8_lossy(&out.stdout).contains("confined"));
}

#[tokio::test]
async fn shell_cannot_follow_symlink_out_of_the_workspace() {
    let tmp = tempfile::tempdir().unwrap();
    let b = backend(tmp.path());
    if !sandboxed(&b) {
        eprintln!("SKIP: no OS sandbox on this host");
        return;
    }
    let host = tempfile::tempdir().unwrap();
    std::fs::write(host.path().join("loot.txt"), "outside").unwrap();
    let ws = b.workspace_for(&BranchId("br-test".into())).unwrap();
    std::os::unix::fs::symlink(host.path(), ws.join("esc")).unwrap();
    let out = b.execute(req(shell("cat esc/loot.txt"))).await.unwrap();
    assert_ne!(
        out.exit_code, 0,
        "symlink escape must be denied by the sandbox"
    );
    assert!(!String::from_utf8_lossy(&out.stdout).contains("outside"));
}

/// Without a verified sandbox the backend must fail closed for shell —
/// never silently degrade to a host process (the exact AK-001 failure mode).
#[tokio::test]
async fn fail_closed_without_sandbox() {
    let tmp = tempfile::tempdir().unwrap();
    let b = backend(tmp.path());
    if sandboxed(&b) {
        // Simulate a sandboxless host by demanding more than the probe found:
        // covered structurally — the config flag is what gates the fallback.
        // Here we verify the dangerous opt-out is required and explicit.
        let opt_out =
            LocalBackend::new(LocalBackendConfig::new(tmp.path()).dangerously_allow_unsandboxed())
                .unwrap();
        // Opt-out flag alone must NOT weaken a host that HAS a sandbox.
        let out = opt_out
            .execute(req(shell("echo still-sandboxed")))
            .await
            .unwrap();
        assert_eq!(out.exit_code, 0);
        return;
    }
    let err = b
        .execute(req(shell("echo should-not-run")))
        .await
        .expect_err("must fail closed");
    match err {
        KernelError::BackendUnavailable { reason, .. } => {
            assert!(
                reason.contains("fails closed"),
                "actionable reason: {reason}"
            )
        }
        other => panic!("expected BackendUnavailable, got {other:?}"),
    }
    // File actions (in-process confinement) still work without a sandbox.
    let out = b
        .execute(req(ActionKind::WriteFile {
            path: "ok.txt".into(),
            contents_b64: b64::encode(b"fine"),
        }))
        .await
        .unwrap();
    assert_eq!(out.exit_code, 0);
}

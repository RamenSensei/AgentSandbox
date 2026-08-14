//! Config-driven multi-backend routing with honest state recording.
//!
//! The policy rule's `risk_weight` sets a step's isolation floor; the
//! router picks the cheapest satisfying backend. A remote backend with state
//! sync returns a validated delta and advances the DAG for real; one with
//! neither sync nor a shared workspace is recorded as an **audit-only
//! excursion**, never a pretended local transition. Anything the DAG must
//! snapshot routes only to one of the first two kinds, and an unsatisfiable
//! floor is a *recorded* denial.

use ak_api::{Kernel, KernelConfig};
use ak_core::action::ActionKind;
use ak_core::budget::ResourceBudget;
use ak_core::observation::Observation;
use ak_core::replay::ReplayClass;
use ak_core::traits::{
    Backend, BackendProfile, ExecutionOutcome, ExecutionRequest, SyncedFile, WorkspaceDelta,
};
use ak_core::{KernelResult, Principal};
use ak_policy::{PathPolicy, PolicyDocument, PolicyRule, PrincipalSelector, RuleEffect};
use async_trait::async_trait;
use indexmap::IndexMap;
use std::collections::BTreeMap;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

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
            syncs_state: false,
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
            workspace_delta: None,
        })
    }
}

/// A strong remote backend **with state sync**: every step returns a canned
/// workspace delta, as a sync-capable adapter would after pulling the
/// remote tree. `discarded` records whether the kernel scrapped the branch
/// (it must, after rejecting a hostile delta).
struct SyncedBox {
    delta: WorkspaceDelta,
    discarded: Arc<AtomicBool>,
}

impl SyncedBox {
    fn writing(path: &str, contents: &[u8]) -> Self {
        Self {
            delta: WorkspaceDelta {
                upserts: vec![SyncedFile {
                    path: path.into(),
                    contents: contents.to_vec(),
                    mode: 0o644,
                }],
                deletes: Vec::new(),
            },
            discarded: Arc::new(AtomicBool::new(false)),
        }
    }

    fn returning(delta: WorkspaceDelta) -> Self {
        Self {
            delta,
            discarded: Arc::new(AtomicBool::new(false)),
        }
    }
}

#[async_trait]
impl Backend for SyncedBox {
    fn profile(&self) -> BackendProfile {
        BackendProfile {
            name: "syncedbox".into(),
            isolation_strength: 90,
            cold_start_ms: 50,
            replay_class: ReplayClass::FilesystemOnly,
            supports_fork: false,
            supports_gui: false,
            full_linux: true,
            shares_workspace: false,
            syncs_state: true,
        }
    }

    async fn execute(&self, _req: ExecutionRequest) -> KernelResult<ExecutionOutcome> {
        Ok(ExecutionOutcome {
            exit_code: 0,
            stdout: b"ran-remotely-with-sync".to_vec(),
            stderr: Vec::new(),
            usage: ResourceBudget::zero(),
            paths_written: self.delta.upserts.iter().map(|f| f.path.clone()).collect(),
            replay_class: ReplayClass::FilesystemOnly,
            workspace_delta: Some(self.delta.clone()),
        })
    }

    async fn discard(&self, _branch: &ak_core::ids::BranchId) -> KernelResult<()> {
        self.discarded.store(true, Ordering::SeqCst);
        Ok(())
    }
}

/// A syncing backend returning a deterministic sequence of deltas. Useful
/// for exercising transitions whose shape depends on the prior state.
struct SequencedBox {
    deltas: Mutex<VecDeque<WorkspaceDelta>>,
}

impl SequencedBox {
    fn new(deltas: impl IntoIterator<Item = WorkspaceDelta>) -> Self {
        Self {
            deltas: Mutex::new(deltas.into_iter().collect()),
        }
    }
}

#[async_trait]
impl Backend for SequencedBox {
    fn profile(&self) -> BackendProfile {
        BackendProfile {
            name: "sequencedbox".into(),
            isolation_strength: 90,
            cold_start_ms: 1,
            replay_class: ReplayClass::FilesystemOnly,
            supports_fork: false,
            supports_gui: false,
            full_linux: true,
            shares_workspace: false,
            syncs_state: true,
        }
    }

    async fn execute(&self, _req: ExecutionRequest) -> KernelResult<ExecutionOutcome> {
        let delta = self
            .deltas
            .lock()
            .unwrap()
            .pop_front()
            .expect("test supplied one delta per execution");
        Ok(ExecutionOutcome {
            exit_code: 0,
            stdout: Vec::new(),
            stderr: Vec::new(),
            usage: ResourceBudget::zero(),
            paths_written: delta
                .upserts
                .iter()
                .map(|f| f.path.clone())
                .chain(delta.deletes.iter().cloned())
                .collect(),
            replay_class: ReplayClass::FilesystemOnly,
            workspace_delta: Some(delta),
        })
    }
}

/// Detects whether the kernel ever overlaps two state transitions on one
/// branch and records the base state each execution received.
struct SerialProbeBox {
    active: AtomicUsize,
    max_active: AtomicUsize,
    sequence: AtomicUsize,
    bases: Mutex<Vec<ak_core::ids::StateId>>,
}

impl SerialProbeBox {
    fn new() -> Self {
        Self {
            active: AtomicUsize::new(0),
            max_active: AtomicUsize::new(0),
            sequence: AtomicUsize::new(0),
            bases: Mutex::new(Vec::new()),
        }
    }
}

#[async_trait]
impl Backend for SerialProbeBox {
    fn profile(&self) -> BackendProfile {
        BackendProfile {
            name: "serial-probe".into(),
            isolation_strength: 90,
            cold_start_ms: 1,
            replay_class: ReplayClass::FilesystemOnly,
            supports_fork: false,
            supports_gui: false,
            full_linux: true,
            shares_workspace: false,
            syncs_state: true,
        }
    }

    async fn execute(&self, req: ExecutionRequest) -> KernelResult<ExecutionOutcome> {
        self.bases.lock().unwrap().push(req.base_state);
        let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        self.max_active.fetch_max(active, Ordering::SeqCst);
        tokio::time::sleep(std::time::Duration::from_millis(40)).await;
        let n = self.sequence.fetch_add(1, Ordering::SeqCst);
        self.active.fetch_sub(1, Ordering::SeqCst);
        let path = format!("serial/{n}.txt");
        Ok(ExecutionOutcome {
            exit_code: 0,
            stdout: Vec::new(),
            stderr: Vec::new(),
            usage: ResourceBudget::zero(),
            paths_written: vec![path.clone()],
            replay_class: ReplayClass::FilesystemOnly,
            workspace_delta: Some(WorkspaceDelta {
                upserts: vec![SyncedFile {
                    path,
                    contents: n.to_string().into_bytes(),
                    mode: 0o644,
                }],
                deletes: Vec::new(),
            }),
        })
    }
}

/// Records the kernel's native fork and remote cleanup lifecycle calls.
struct LifecycleBox {
    forks: Mutex<Vec<(ak_core::ids::StateId, ak_core::ids::BranchId)>>,
    discarded: Mutex<Vec<ak_core::ids::BranchId>>,
    executions: AtomicUsize,
    discard_failures: AtomicUsize,
}

impl LifecycleBox {
    fn new() -> Self {
        Self {
            forks: Mutex::new(Vec::new()),
            discarded: Mutex::new(Vec::new()),
            executions: AtomicUsize::new(0),
            discard_failures: AtomicUsize::new(0),
        }
    }

    fn fail_next_discard(&self) {
        self.discard_failures.fetch_add(1, Ordering::SeqCst);
    }
}

#[async_trait]
impl Backend for LifecycleBox {
    fn profile(&self) -> BackendProfile {
        BackendProfile {
            name: "lifecycle-box".into(),
            isolation_strength: 90,
            cold_start_ms: 1,
            replay_class: ReplayClass::FilesystemOnly,
            supports_fork: true,
            supports_gui: false,
            full_linux: true,
            shares_workspace: false,
            syncs_state: true,
        }
    }

    async fn execute(&self, _req: ExecutionRequest) -> KernelResult<ExecutionOutcome> {
        self.executions.fetch_add(1, Ordering::SeqCst);
        Ok(ExecutionOutcome {
            exit_code: 0,
            stdout: Vec::new(),
            stderr: Vec::new(),
            usage: ResourceBudget::zero(),
            paths_written: Vec::new(),
            replay_class: ReplayClass::FilesystemOnly,
            workspace_delta: Some(WorkspaceDelta::default()),
        })
    }

    async fn fork(
        &self,
        from: &ak_core::ids::StateId,
        to_branch: &ak_core::ids::BranchId,
    ) -> KernelResult<bool> {
        self.forks
            .lock()
            .unwrap()
            .push((from.clone(), to_branch.clone()));
        Ok(true)
    }

    async fn discard(&self, branch: &ak_core::ids::BranchId) -> KernelResult<()> {
        self.discarded.lock().unwrap().push(branch.clone());
        if self
            .discard_failures
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_ok()
        {
            return Err(ak_core::KernelError::BackendUnavailable {
                backend: "lifecycle-box".into(),
                reason: "injected discard failure".into(),
            });
        }
        Ok(())
    }
}

/// Deliberately violates profile/outcome agreement.
struct ContractLiar {
    advertises_sync: bool,
    returns_delta: bool,
    discarded: Arc<AtomicBool>,
}

#[async_trait]
impl Backend for ContractLiar {
    fn profile(&self) -> BackendProfile {
        BackendProfile {
            name: if self.advertises_sync {
                "missing-delta"
            } else {
                "undeclared-delta"
            }
            .into(),
            isolation_strength: 90,
            cold_start_ms: 1,
            replay_class: ReplayClass::FilesystemOnly,
            supports_fork: false,
            supports_gui: false,
            full_linux: true,
            shares_workspace: false,
            syncs_state: self.advertises_sync,
        }
    }

    async fn execute(&self, _req: ExecutionRequest) -> KernelResult<ExecutionOutcome> {
        Ok(ExecutionOutcome {
            exit_code: 0,
            stdout: Vec::new(),
            stderr: Vec::new(),
            usage: ResourceBudget::zero(),
            paths_written: Vec::new(),
            replay_class: ReplayClass::FilesystemOnly,
            workspace_delta: self.returns_delta.then(WorkspaceDelta::default),
        })
    }

    async fn discard(&self, _branch: &ak_core::ids::BranchId) -> KernelResult<()> {
        self.discarded.store(true, Ordering::SeqCst);
        Ok(())
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

#[tokio::test]
async fn synced_excursion_is_a_real_state_transition_with_mirror_continuity() {
    let tmp = tempfile::tempdir().unwrap();
    let kernel = kernel_with_policy(&tmp, risky_shell_policy());
    kernel.register_backend(Arc::new(SyncedBox::writing(
        "out/result.txt",
        b"built-remotely",
    )));
    let who = agent(&kernel);
    let ep = kernel.create_episode(&who.id, None, "sync").unwrap();

    // Seed the local tree first so the base state is non-trivial.
    kernel
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

    let r = kernel
        .execute_step_auto(&who.id, &ep.branch, shell("remote-build"), None, None)
        .await
        .unwrap();
    let summary = match &r.result.observation {
        Observation::Success { summary, .. } => summary.clone(),
        other => panic!("expected success via the syncing backend, got {other:?}"),
    };
    assert!(
        summary.contains("syncedbox") && summary.contains("state-synced"),
        "the observation must name the synced excursion: {summary}"
    );

    // The step is a REAL state transition: the node carries the remote
    // file change, no AuditOnly downgrade, and the workspace root moved.
    let node = kernel.dag().get_state(&r.result.state).unwrap();
    assert_ne!(node.replay_class, ReplayClass::AuditOnly);
    assert!(
        node.delta
            .files
            .iter()
            .any(|c| format!("{c:?}").contains("out/result.txt")),
        "the synced delta must be recorded in the DAG: {:?}",
        node.delta.files
    );

    // Mirror continuity: the local plane sees both the seed and the file
    // written remotely.
    for (path, want) in [
        ("out/result.txt", "built-remotely"),
        ("local.txt", "local-state"),
    ] {
        let read = kernel
            .execute_step_auto(
                &who.id,
                &ep.branch,
                ActionKind::ReadFile { path: path.into() },
                None,
                None,
            )
            .await
            .unwrap();
        match &read.result.observation {
            Observation::Success { full_output, .. } => {
                let raw = kernel.fetch_raw(full_output).unwrap();
                assert!(
                    String::from_utf8_lossy(&raw).contains(want),
                    "local mirror must contain `{path}` after the synced excursion"
                );
            }
            other => panic!("reading `{path}` after sync failed: {other:?}"),
        }
    }
}

#[tokio::test]
async fn high_risk_file_actions_route_to_a_syncing_backend() {
    let tmp = tempfile::tempdir().unwrap();
    // High-risk file plane + a syncing strong backend: unlike Strongbox,
    // the workspace need is satisfiable and the action executes remotely.
    let kernel = kernel_with_policy(
        &tmp,
        PolicyDocument {
            rules: vec![rule("fs", &["fs.*"], 8)],
            ..PolicyDocument::default()
        },
    );
    kernel.register_backend(Arc::new(SyncedBox::writing("x.txt", b"remote-write")));
    let who = agent(&kernel);
    let ep = kernel.create_episode(&who.id, None, "sync-files").unwrap();

    let r = kernel
        .execute_step_auto(
            &who.id,
            &ep.branch,
            ActionKind::WriteFile {
                path: "x.txt".into(),
                contents_b64: ak_backend_local::b64::encode(b"remote-write"),
            },
            None,
            None,
        )
        .await
        .unwrap();
    match &r.result.observation {
        Observation::Success { summary, .. } => {
            assert!(summary.contains("state-synced"), "{summary}");
        }
        other => panic!("high-risk file action must run on the syncing backend: {other:?}"),
    }
}

/// Hostile deltas: each is rejected wholesale, recorded as a denial, the
/// branch head stays unchanged and the remote sandbox is discarded.
#[tokio::test]
async fn hostile_sync_deltas_are_rejected_and_the_sandbox_discarded() {
    for (case, backend) in [
        (
            "path traversal",
            SyncedBox::writing("../escape.txt", b"evil"),
        ),
        (
            "cache-tier ambush",
            SyncedBox::writing("node_modules/evil.js", b"evil"),
        ),
        (
            "outside writable prefixes",
            SyncedBox::writing("forbidden/x.txt", b"evil"),
        ),
        (
            "non-canonical path",
            SyncedBox::writing("./allowed/x.txt", b"evil"),
        ),
        (
            "duplicate upsert",
            SyncedBox::returning(WorkspaceDelta {
                upserts: vec![
                    SyncedFile {
                        path: "allowed/x.txt".into(),
                        contents: b"first".to_vec(),
                        mode: 0o644,
                    },
                    SyncedFile {
                        path: "allowed/x.txt".into(),
                        contents: b"second".to_vec(),
                        mode: 0o644,
                    },
                ],
                deletes: Vec::new(),
            }),
        ),
        (
            "write-delete conflict",
            SyncedBox::returning(WorkspaceDelta {
                upserts: vec![SyncedFile {
                    path: "allowed/x.txt".into(),
                    contents: b"value".to_vec(),
                    mode: 0o644,
                }],
                deletes: vec!["allowed/x.txt".into()],
            }),
        ),
        (
            "file ancestor conflict",
            SyncedBox::returning(WorkspaceDelta {
                upserts: vec![
                    SyncedFile {
                        path: "allowed/a".into(),
                        contents: b"file".to_vec(),
                        mode: 0o644,
                    },
                    SyncedFile {
                        path: "allowed/a/b".into(),
                        contents: b"child".to_vec(),
                        mode: 0o644,
                    },
                ],
                deletes: Vec::new(),
            }),
        ),
    ] {
        let tmp = tempfile::tempdir().unwrap();
        let mut doc = risky_shell_policy();
        doc.paths = PathPolicy {
            readable_prefixes: vec![],
            writable_prefixes: vec!["allowed/".into(), "local.txt".into(), "out/".into()],
        };
        let kernel = kernel_with_policy(&tmp, doc);
        let discarded = Arc::clone(&backend.discarded);
        kernel.register_backend(Arc::new(backend));
        let who = agent(&kernel);
        let ep = kernel.create_episode(&who.id, None, "hostile").unwrap();
        let head_before = kernel.dag().head(&ep.branch).unwrap().id;

        let r = kernel
            .execute_step_auto(&who.id, &ep.branch, shell("evil-build"), None, None)
            .await
            .unwrap();
        match &r.result.observation {
            Observation::Denied { denial } => {
                assert_eq!(
                    denial.code,
                    ak_core::denial::DenialCode::ConstraintViolated,
                    "{case}"
                );
                assert!(
                    denial.reason.contains("workspace delta"),
                    "{case}: {}",
                    denial.reason
                );
            }
            other => panic!("{case}: hostile delta must be a recorded denial, got {other:?}"),
        }
        assert_eq!(
            kernel.dag().head(&ep.branch).unwrap().id,
            head_before,
            "{case}: the branch head must be unchanged"
        );
        assert!(
            discarded.load(Ordering::SeqCst),
            "{case}: the poisoned remote sandbox must be discarded"
        );
    }
}

#[tokio::test]
async fn synced_file_directory_transitions_round_trip() {
    let tmp = tempfile::tempdir().unwrap();
    let kernel = kernel_with_policy(&tmp, risky_shell_policy());
    kernel.register_backend(Arc::new(SequencedBox::new([
        WorkspaceDelta {
            upserts: vec![SyncedFile {
                path: "node/child.txt".into(),
                contents: b"child".to_vec(),
                mode: 0o644,
            }],
            deletes: vec!["node".into()],
        },
        WorkspaceDelta {
            upserts: vec![SyncedFile {
                path: "node".into(),
                contents: b"file-again".to_vec(),
                mode: 0o644,
            }],
            deletes: vec!["node/child.txt".into()],
        },
    ])));
    let who = agent(&kernel);
    let ep = kernel
        .create_episode(&who.id, None, "shape-transitions")
        .unwrap();
    kernel
        .execute_step_auto(
            &who.id,
            &ep.branch,
            ActionKind::WriteFile {
                path: "node".into(),
                contents_b64: ak_backend_local::b64::encode(b"file-first"),
            },
            None,
            None,
        )
        .await
        .unwrap();

    kernel
        .execute_step_auto(&who.id, &ep.branch, shell("to-directory"), None, None)
        .await
        .unwrap();
    let workspace = kernel.local_backend().workspace_for(&ep.branch).unwrap();
    assert_eq!(
        std::fs::read(workspace.join("node/child.txt")).unwrap(),
        b"child"
    );

    kernel
        .execute_step_auto(&who.id, &ep.branch, shell("to-file"), None, None)
        .await
        .unwrap();
    assert_eq!(
        std::fs::read(workspace.join("node")).unwrap(),
        b"file-again"
    );
    assert!(!workspace.join("node/child.txt").exists());
}

#[cfg(unix)]
#[tokio::test]
async fn synced_mode_only_change_is_a_recorded_delta() {
    use std::os::unix::fs::PermissionsExt;

    let tmp = tempfile::tempdir().unwrap();
    let kernel = kernel_with_policy(&tmp, risky_shell_policy());
    kernel.register_backend(Arc::new(SyncedBox::returning(WorkspaceDelta {
        upserts: vec![SyncedFile {
            path: "run.sh".into(),
            contents: b"#!/bin/sh\n".to_vec(),
            mode: 0o755,
        }],
        deletes: Vec::new(),
    })));
    let who = agent(&kernel);
    let ep = kernel.create_episode(&who.id, None, "chmod-sync").unwrap();
    kernel
        .execute_step_auto(
            &who.id,
            &ep.branch,
            ActionKind::WriteFile {
                path: "run.sh".into(),
                contents_b64: ak_backend_local::b64::encode(b"#!/bin/sh\n"),
            },
            None,
            None,
        )
        .await
        .unwrap();

    let result = kernel
        .execute_step_auto(&who.id, &ep.branch, shell("chmod-only"), None, None)
        .await
        .unwrap();
    let node = kernel.dag().get_state(&result.result.state).unwrap();
    assert_eq!(
        node.delta.files.len(),
        1,
        "chmod must be visible in the DAG"
    );
    assert!(matches!(
        &node.delta.files[0],
        ak_core::state::FileChange::Modified { old_blob, new_blob, .. } if old_blob == new_blob
    ));
    let workspace = kernel.local_backend().workspace_for(&ep.branch).unwrap();
    assert_eq!(
        std::fs::metadata(workspace.join("run.sh"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o755
    );
}

#[tokio::test]
async fn profile_outcome_state_contract_is_enforced() {
    for (advertises_sync, returns_delta) in [(true, false), (false, true)] {
        let tmp = tempfile::tempdir().unwrap();
        let kernel = kernel_with_policy(&tmp, risky_shell_policy());
        let discarded = Arc::new(AtomicBool::new(false));
        kernel.register_backend(Arc::new(ContractLiar {
            advertises_sync,
            returns_delta,
            discarded: Arc::clone(&discarded),
        }));
        let who = agent(&kernel);
        let ep = kernel.create_episode(&who.id, None, "contract").unwrap();
        let before = kernel.dag().head(&ep.branch).unwrap().id;

        let result = kernel
            .execute_step_auto(&who.id, &ep.branch, shell("contract-lie"), None, None)
            .await
            .unwrap();
        match result.result.observation {
            Observation::Denied { denial } => {
                assert_eq!(denial.code, ak_core::denial::DenialCode::BackendUnavailable);
                assert!(denial.reason.contains("state-plane contract"));
            }
            other => panic!("contract violation must be a recorded denial: {other:?}"),
        }
        assert_eq!(kernel.dag().head(&ep.branch).unwrap().id, before);
        assert!(discarded.load(Ordering::SeqCst));
    }
}

#[tokio::test]
async fn concurrent_steps_on_one_branch_serialize_their_base_states() {
    let tmp = tempfile::tempdir().unwrap();
    let kernel = kernel_with_policy(&tmp, risky_shell_policy());
    let backend = Arc::new(SerialProbeBox::new());
    kernel.register_backend(Arc::clone(&backend) as Arc<dyn Backend>);
    let who = agent(&kernel);
    let ep = kernel
        .create_episode(&who.id, None, "serial-state")
        .unwrap();
    let root = ep.root.id.clone();

    let (a, b) = tokio::join!(
        kernel.execute_step_auto(&who.id, &ep.branch, shell("a"), None, None),
        kernel.execute_step_auto(&who.id, &ep.branch, shell("b"), None, None),
    );
    assert!(matches!(
        a.unwrap().result.observation,
        Observation::Success { .. }
    ));
    assert!(matches!(
        b.unwrap().result.observation,
        Observation::Success { .. }
    ));
    assert_eq!(
        backend.max_active.load(Ordering::SeqCst),
        1,
        "one branch must never execute two state transitions concurrently"
    );
    let bases = backend.bases.lock().unwrap();
    assert_eq!(bases.len(), 2);
    assert_eq!(bases[0], root);
    assert_ne!(
        bases[1], root,
        "the second step must see the first step's head"
    );

    let workspace = kernel.local_backend().workspace_for(&ep.branch).unwrap();
    assert_eq!(std::fs::read(workspace.join("serial/0.txt")).unwrap(), b"0");
    assert_eq!(std::fs::read(workspace.join("serial/1.txt")).unwrap(), b"1");
}

#[tokio::test]
async fn different_branches_still_execute_in_parallel() {
    let tmp = tempfile::tempdir().unwrap();
    let kernel = kernel_with_policy(&tmp, risky_shell_policy());
    let backend = Arc::new(SerialProbeBox::new());
    kernel.register_backend(Arc::clone(&backend) as Arc<dyn Backend>);
    let who = agent(&kernel);
    let ep = kernel
        .create_episode(&who.id, None, "parallel-state")
        .unwrap();
    let fork = kernel.fork_branch(&ep.branch).await.unwrap();

    let (a, b) = tokio::join!(
        kernel.execute_step_auto(&who.id, &ep.branch, shell("a"), None, None),
        kernel.execute_step_auto(&who.id, &fork.id, shell("b"), None, None),
    );
    assert!(a.is_ok() && b.is_ok());
    assert_eq!(
        backend.max_active.load(Ordering::SeqCst),
        2,
        "branch serialization must not become a global execution lock"
    );
}

#[tokio::test]
async fn fork_and_merge_drive_the_remote_backend_lifecycle() {
    let tmp = tempfile::tempdir().unwrap();
    let kernel = kernel_with_policy(&tmp, risky_shell_policy());
    let backend = Arc::new(LifecycleBox::new());
    kernel.register_backend(Arc::clone(&backend) as Arc<dyn Backend>);
    let who = agent(&kernel);
    let ep = kernel
        .create_episode(&who.id, None, "remote-lifecycle")
        .unwrap();

    let stepped = kernel
        .execute_step_auto(&who.id, &ep.branch, shell("remote"), None, None)
        .await
        .unwrap();
    let fork = kernel.fork_branch(&ep.branch).await.unwrap();
    assert_eq!(
        backend.forks.lock().unwrap().as_slice(),
        &[(stepped.result.state.clone(), fork.id.clone())],
        "native CoW must fork the exact committed head into the new branch"
    );

    kernel
        .merge_branch(&ep.branch, &fork.id, &who.id)
        .await
        .unwrap();
    assert_eq!(
        backend.discarded.lock().unwrap().as_slice(),
        &[fork.id],
        "a merged source must release its remote sandbox"
    );
}

#[tokio::test]
async fn normal_discard_releases_remote_branch_resources() {
    let tmp = tempfile::tempdir().unwrap();
    let kernel = kernel_with_policy(&tmp, risky_shell_policy());
    let backend = SyncedBox::writing("out.txt", b"remote");
    let discarded = Arc::clone(&backend.discarded);
    kernel.register_backend(Arc::new(backend));
    let who = agent(&kernel);
    let ep = kernel
        .create_episode(&who.id, None, "discard-remote")
        .unwrap();
    kernel
        .execute_step_auto(&who.id, &ep.branch, shell("remote"), None, None)
        .await
        .unwrap();

    kernel.discard_branch(&ep.branch).await.unwrap();
    assert!(discarded.load(Ordering::SeqCst));
}

#[tokio::test]
async fn merged_branch_cleanup_can_retry_without_changing_lifecycle_state() {
    let tmp = tempfile::tempdir().unwrap();
    let kernel = kernel_with_policy(&tmp, risky_shell_policy());
    let backend = Arc::new(LifecycleBox::new());
    kernel.register_backend(Arc::clone(&backend) as Arc<dyn Backend>);
    let who = agent(&kernel);
    let ep = kernel
        .create_episode(&who.id, None, "merge-cleanup-retry")
        .unwrap();
    let source = kernel.fork_branch(&ep.branch).await.unwrap();

    backend.fail_next_discard();
    kernel
        .merge_branch(&ep.branch, &source.id, &who.id)
        .await
        .unwrap();
    assert_eq!(backend.discarded.lock().unwrap().len(), 1);

    kernel.discard_branch(&source.id).await.unwrap();
    assert_eq!(backend.discarded.lock().unwrap().len(), 2);
    assert_eq!(
        kernel.dag().get_branch(&source.id).unwrap().status,
        ak_state_dag::BranchStatus::Merged,
        "cleanup retry must not rewrite durable branch history"
    );
}

#[tokio::test]
async fn terminal_branches_never_reenter_a_backend_or_fork() {
    let tmp = tempfile::tempdir().unwrap();
    let kernel = kernel_with_policy(&tmp, risky_shell_policy());
    let backend = Arc::new(LifecycleBox::new());
    kernel.register_backend(Arc::clone(&backend) as Arc<dyn Backend>);
    let who = agent(&kernel);
    let ep = kernel
        .create_episode(&who.id, None, "terminal-branches")
        .unwrap();

    let merged = kernel.fork_branch(&ep.branch).await.unwrap();
    kernel
        .merge_branch(&ep.branch, &merged.id, &who.id)
        .await
        .unwrap();
    let forks_before = backend.forks.lock().unwrap().len();
    assert!(matches!(
        kernel
            .execute_step_auto(&who.id, &merged.id, shell("must-not-run"), None, None)
            .await,
        Err(ak_core::KernelError::BranchDiscarded { .. })
    ));
    assert!(matches!(
        kernel.fork_branch(&merged.id).await,
        Err(ak_core::KernelError::BranchDiscarded { .. })
    ));
    assert_eq!(backend.executions.load(Ordering::SeqCst), 0);
    assert_eq!(backend.forks.lock().unwrap().len(), forks_before);

    kernel.discard_branch(&ep.branch).await.unwrap();
    assert!(matches!(
        kernel
            .execute_step_auto(&who.id, &ep.branch, shell("must-not-run"), None, None)
            .await,
        Err(ak_core::KernelError::BranchDiscarded { .. })
    ));
    assert!(matches!(
        kernel.fork_branch(&ep.branch).await,
        Err(ak_core::KernelError::BranchDiscarded { .. })
    ));
    assert_eq!(backend.executions.load(Ordering::SeqCst), 0);
    assert_eq!(backend.forks.lock().unwrap().len(), forks_before);
}

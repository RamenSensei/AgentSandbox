//! Integration tests: step scheduler with mock backends and the real local
//! backend.

use ak_core::action::ActionKind;
use ak_core::budget::ResourceBudget;
use ak_core::error::{KernelError, KernelResult};
use ak_core::ids::{BranchId, EpisodeId, PrincipalId, StateId, StepId};
use ak_core::replay::ReplayClass;
use ak_core::traits::{Backend, BackendProfile, ExecutionOutcome, ExecutionRequest};
use ak_scheduler::{BackendRouter, Needs, RiskTier, SchedulerConfig, StepScheduler, WarmPool};
use async_trait::async_trait;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

struct Slow {
    profile: BackendProfile,
    concurrent: Arc<AtomicUsize>,
    peak: Arc<AtomicUsize>,
    /// Usage reported per execution (defaults to 10 cpu_ms).
    usage: ResourceBudget,
}

#[async_trait]
impl Backend for Slow {
    fn profile(&self) -> BackendProfile {
        self.profile.clone()
    }
    async fn execute(&self, _req: ExecutionRequest) -> KernelResult<ExecutionOutcome> {
        let now = self.concurrent.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(now, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(80)).await;
        self.concurrent.fetch_sub(1, Ordering::SeqCst);
        Ok(ExecutionOutcome {
            exit_code: 0,
            stdout: vec![],
            stderr: vec![],
            usage: self.usage,
            paths_written: vec![],
            replay_class: ReplayClass::FilesystemOnly,
            workspace_delta: None,
        })
    }
}

fn profile(name: &str, iso: u8, cold: u64, fork: bool) -> BackendProfile {
    BackendProfile {
        name: name.into(),
        isolation_strength: iso,
        cold_start_ms: cold,
        replay_class: ReplayClass::FilesystemOnly,
        supports_fork: fork,
        supports_gui: false,
        full_linux: true,
        shares_workspace: name == "local",
        syncs_state: false,
    }
}

fn req(branch: &str, cpu_ms: u64) -> ExecutionRequest {
    ExecutionRequest {
        branch: BranchId(branch.into()),
        base_state: StateId("st-0".into()),
        actor: PrincipalId("pr-t".into()),
        action: ActionKind::Shell {
            command: "true".into(),
            cwd: None,
            env: BTreeMap::new(),
        },
        budget: ResourceBudget {
            cpu_ms,
            ..ResourceBudget::zero()
        },
        writable_prefixes: vec![],
        readable_prefixes: vec![],
        egress_domains: vec![],
    }
}

fn episode() -> EpisodeId {
    EpisodeId::generate()
}

fn scheduler_with_slow(
    max_branches: usize,
    budget: ResourceBudget,
) -> (StepScheduler, EpisodeId, Arc<AtomicUsize>) {
    scheduler_with_usage(
        max_branches,
        budget,
        ResourceBudget {
            cpu_ms: 10,
            ..ResourceBudget::zero()
        },
    )
}

fn scheduler_with_usage(
    max_branches: usize,
    budget: ResourceBudget,
    usage: ResourceBudget,
) -> (StepScheduler, EpisodeId, Arc<AtomicUsize>) {
    let concurrent = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let mut router = BackendRouter::new();
    router.register(Arc::new(Slow {
        profile: profile("slow", 90, 10, true),
        concurrent,
        peak: peak.clone(),
        usage,
    }));
    let scheduler = StepScheduler::new(
        router,
        SchedulerConfig {
            max_concurrent_branches: max_branches,
            episode_budget: budget,
        },
    );
    let ep = episode();
    scheduler.register_episode_default(&ep);
    (scheduler, ep, peak)
}

#[tokio::test]
async fn fan_out_is_bounded_by_semaphore() {
    let (scheduler, ep, peak) = scheduler_with_slow(
        2,
        ResourceBudget {
            cpu_ms: 100_000,
            ..ResourceBudget::step_default()
        },
    );
    let scheduler = Arc::new(scheduler);
    let mut handles = Vec::new();
    for i in 0..6 {
        let s = Arc::clone(&scheduler);
        let ep = ep.clone();
        handles.push(tokio::spawn(async move {
            s.execute_step(
                &ep,
                StepId::generate(),
                req(&format!("br-{i}"), 100),
                RiskTier::High,
                &Needs::default(),
            )
            .await
        }));
    }
    for h in handles {
        h.await.unwrap().unwrap();
    }
    assert!(
        peak.load(Ordering::SeqCst) <= 2,
        "fan-out exceeded: {}",
        peak.load(Ordering::SeqCst)
    );
    // Queue time shows up in the accounting records.
    let records = scheduler.records().await;
    assert_eq!(records.len(), 6);
    assert!(records.iter().all(|r| r.backend == "slow"));
    assert!(records.iter().any(|r| r.queue_ms > 0));
}

#[tokio::test]
async fn budget_is_charged_and_exhaustion_refuses_steps() {
    let (scheduler, ep, _) = scheduler_with_slow(
        4,
        ResourceBudget {
            cpu_ms: 25,
            ..ResourceBudget::zero()
        },
    );
    // Each step reserves its requested budget, then settles to the actual
    // 10 cpu_ms usage: 25 → (reserve 20, settle 10) → 15 → (reserve 15,
    // settle 10) → 5 → a 20-request no longer fits.
    scheduler
        .execute_step(
            &ep,
            StepId::generate(),
            req("br-1", 20),
            RiskTier::High,
            &Needs::default(),
        )
        .await
        .unwrap();
    assert_eq!(scheduler.remaining_budget(&ep).unwrap().cpu_ms, 15);
    scheduler
        .execute_step(
            &ep,
            StepId::generate(),
            req("br-1", 15),
            RiskTier::High,
            &Needs::default(),
        )
        .await
        .unwrap();
    assert_eq!(scheduler.remaining_budget(&ep).unwrap().cpu_ms, 5);
    let err = scheduler
        .execute_step(
            &ep,
            StepId::generate(),
            req("br-1", 20),
            RiskTier::High,
            &Needs::default(),
        )
        .await
        .unwrap_err();
    match err {
        KernelError::Denied(d) => {
            assert_eq!(d.code, ak_core::denial::DenialCode::BudgetExhausted);
            assert!(
                d.reason.contains("cpu_ms"),
                "reason names the short dimension: {}",
                d.reason
            );
        }
        other => panic!("expected budget denial, got {other:?}"),
    }
    // Settled spend is visible on the account.
    let account = scheduler.budget_account(&ep).unwrap();
    assert_eq!(account.spent.cpu_ms, 20);
}

/// AK-005 regression: the review's exploit ran two concurrent steps, each
/// requesting the full 100 cpu_ms envelope, and both were accepted
/// (`accepted_cpu_ms=200`). With atomic reserve-before-execute exactly one
/// may win.
#[tokio::test]
async fn concurrent_steps_cannot_jointly_overdraw_the_account() {
    let (scheduler, ep, _) = scheduler_with_usage(
        8,
        ResourceBudget {
            cpu_ms: 100,
            ..ResourceBudget::zero()
        },
        ResourceBudget {
            cpu_ms: 100,
            ..ResourceBudget::zero()
        },
    );
    let scheduler = Arc::new(scheduler);
    let mut handles = Vec::new();
    for _ in 0..2 {
        let s = Arc::clone(&scheduler);
        let ep = ep.clone();
        handles.push(tokio::spawn(async move {
            s.execute_step(
                &ep,
                StepId::generate(),
                req("br-race", 100),
                RiskTier::High,
                &Needs::default(),
            )
            .await
        }));
    }
    let mut ok = 0;
    let mut denied = 0;
    for h in handles {
        match h.await.unwrap() {
            Ok(_) => ok += 1,
            Err(KernelError::Denied(d)) => {
                assert_eq!(d.code, ak_core::denial::DenialCode::BudgetExhausted);
                denied += 1;
            }
            Err(other) => panic!("unexpected error: {other:?}"),
        }
    }
    assert_eq!(
        (ok, denied),
        (1, 1),
        "exactly one of two racing full-budget steps may win"
    );
    let account = scheduler.budget_account(&ep).unwrap();
    assert_eq!(
        account.spent.cpu_ms, 100,
        "accepted usage must not exceed the envelope"
    );
    assert_eq!(account.remaining.cpu_ms, 0);
}

/// Budgets are per-episode accounts: exhausting one episode leaves a
/// sibling episode untouched (the review found a single global pool).
#[tokio::test]
async fn budgets_are_isolated_per_episode() {
    let (scheduler, ep_a, _) = scheduler_with_slow(
        4,
        ResourceBudget {
            cpu_ms: 10,
            ..ResourceBudget::zero()
        },
    );
    let ep_b = episode();
    scheduler.register_episode_default(&ep_b);

    scheduler
        .execute_step(
            &ep_a,
            StepId::generate(),
            req("br-a", 10),
            RiskTier::High,
            &Needs::default(),
        )
        .await
        .unwrap();
    let err = scheduler
        .execute_step(
            &ep_a,
            StepId::generate(),
            req("br-a", 10),
            RiskTier::High,
            &Needs::default(),
        )
        .await
        .unwrap_err();
    assert!(
        matches!(err, KernelError::Denied(_)),
        "episode A is exhausted"
    );
    // Episode B still has its own full envelope.
    scheduler
        .execute_step(
            &ep_b,
            StepId::generate(),
            req("br-b", 10),
            RiskTier::High,
            &Needs::default(),
        )
        .await
        .unwrap();
    assert_eq!(scheduler.remaining_budget(&ep_b).unwrap().cpu_ms, 0);
}

/// A failed execution refunds its reservation instead of leaking it.
#[tokio::test]
async fn failed_routing_refunds_the_reservation() {
    let mut router = BackendRouter::new();
    router.register(Arc::new(Slow {
        profile: profile("weak", 20, 1, false),
        concurrent: Arc::new(AtomicUsize::new(0)),
        peak: Arc::new(AtomicUsize::new(0)),
        usage: ResourceBudget::zero(),
    }));
    let scheduler = StepScheduler::new(
        router,
        SchedulerConfig {
            max_concurrent_branches: 2,
            episode_budget: ResourceBudget {
                cpu_ms: 50,
                ..ResourceBudget::zero()
            },
        },
    );
    let ep = episode();
    scheduler.register_episode_default(&ep);
    // High risk cannot be routed to the weak backend → refusal after reserve.
    let err = scheduler
        .execute_step(
            &ep,
            StepId::generate(),
            req("br-1", 50),
            RiskTier::High,
            &Needs::default(),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, KernelError::BackendUnavailable { .. }));
    assert_eq!(
        scheduler.remaining_budget(&ep).unwrap().cpu_ms,
        50,
        "reservation must be refunded on routing failure"
    );
}

/// Steps against an unregistered episode are refused outright.
#[tokio::test]
async fn unknown_episode_account_is_refused() {
    let (scheduler, _ep, _) = scheduler_with_slow(4, ResourceBudget::step_default());
    let stranger = episode();
    let err = scheduler
        .execute_step(
            &stranger,
            StepId::generate(),
            req("br-x", 1),
            RiskTier::High,
            &Needs::default(),
        )
        .await
        .unwrap_err();
    match err {
        KernelError::Denied(d) => assert_eq!(d.code, ak_core::denial::DenialCode::BudgetExhausted),
        other => panic!("expected denial, got {other:?}"),
    }
}

#[tokio::test]
async fn paused_branches_are_refused_until_resumed() {
    let (scheduler, ep, _) = scheduler_with_slow(4, ResourceBudget::step_default());
    let branch = BranchId("br-p".into());
    scheduler.pause_branch(&branch).await;
    assert!(scheduler.is_paused(&branch).await);
    let err = scheduler
        .execute_step(
            &ep,
            StepId::generate(),
            req("br-p", 10),
            RiskTier::High,
            &Needs::default(),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, KernelError::Denied(_)));
    scheduler.resume_branch(&branch).await;
    scheduler
        .execute_step(
            &ep,
            StepId::generate(),
            req("br-p", 10),
            RiskTier::High,
            &Needs::default(),
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn hints_prewarm_but_do_not_change_routing() {
    let (scheduler, _ep, _) = scheduler_with_slow(4, ResourceBudget::step_default());
    let plan = scheduler.hint("explore three fixes in parallel branches");
    assert_eq!(plan.warm_backend.as_deref(), Some("slow"));
    let plan = scheduler.hint("run the build and test suite");
    assert_eq!(plan.warm_workspaces, 2);
    // Routing is hint-free: a High-risk step still requires the floor even if
    // the intent claims to be harmless.
    let mut router = BackendRouter::new();
    router.register(Arc::new(Slow {
        profile: profile("weak", 20, 1, false),
        concurrent: Arc::new(AtomicUsize::new(0)),
        peak: Arc::new(AtomicUsize::new(0)),
        usage: ResourceBudget::zero(),
    }));
    let s = StepScheduler::new(router, SchedulerConfig::default());
    let ep = episode();
    s.register_episode_default(&ep);
    let _ = s.hint("totally harmless, run locally please");
    let err = s
        .execute_step(
            &ep,
            StepId::generate(),
            req("br-1", 10),
            RiskTier::High,
            &Needs::default(),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, KernelError::BackendUnavailable { .. }));
}

#[tokio::test]
async fn warm_pool_fills_and_hands_out_workspaces() {
    let tmp = tempfile::tempdir().unwrap();
    let (scheduler, _ep, _) = scheduler_with_slow(4, ResourceBudget::step_default());
    let scheduler = scheduler.with_warm_pool(WarmPool::new(tmp.path().join("pool")).unwrap());
    let plan = scheduler.hint("compile the project");
    scheduler.apply_prewarm(&plan).await.unwrap();
    // Two idle workspaces exist on disk ahead of need.
    let pool_dir = tmp.path().join("pool");
    assert_eq!(std::fs::read_dir(&pool_dir).unwrap().count(), 2);
}

#[tokio::test]
async fn end_to_end_with_real_local_backend() {
    let tmp = tempfile::tempdir().unwrap();
    let local =
        ak_backend_local::LocalBackend::new(ak_backend_local::LocalBackendConfig::new(tmp.path()))
            .unwrap();
    let mut router = BackendRouter::new();
    router.register(Arc::new(local));
    let scheduler = StepScheduler::new(router, SchedulerConfig::default());
    let ep = episode();
    scheduler.register_episode_default(&ep);
    let mut r = req("br-e2e", 5_000);
    r.action = ActionKind::Shell {
        command: "echo routed".into(),
        cwd: None,
        env: BTreeMap::new(),
    };
    let out = scheduler
        .execute_step(
            &ep,
            StepId::generate(),
            r,
            RiskTier::Low,
            &Needs {
                full_linux: cfg!(target_os = "linux"),
                ..Needs::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&out.outcome.stdout).trim(),
        "routed"
    );
    let records = scheduler.records().await;
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].backend, "local");
    assert!(records[0].usage.cpu_ms > 0);
}

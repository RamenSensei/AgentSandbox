//! Integration tests: step scheduler with mock backends and the real local
//! backend.

use ak_core::action::ActionKind;
use ak_core::budget::ResourceBudget;
use ak_core::error::{KernelError, KernelResult};
use ak_core::ids::{BranchId, PrincipalId, StateId, StepId};
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
            usage: ResourceBudget { cpu_ms: 10, ..ResourceBudget::zero() },
            paths_written: vec![],
            replay_class: ReplayClass::FilesystemOnly,
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
    }
}

fn req(branch: &str, cpu_ms: u64) -> ExecutionRequest {
    ExecutionRequest {
        branch: BranchId(branch.into()),
        base_state: StateId("st-0".into()),
        actor: PrincipalId("pr-t".into()),
        action: ActionKind::Shell { command: "true".into(), cwd: None, env: BTreeMap::new() },
        budget: ResourceBudget { cpu_ms, ..ResourceBudget::zero() },
        writable_prefixes: vec![],
        readable_prefixes: vec![],
        egress_domains: vec![],
    }
}

fn scheduler_with_slow(max_branches: usize, budget: ResourceBudget) -> (StepScheduler, Arc<AtomicUsize>) {
    let concurrent = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let mut router = BackendRouter::new();
    router.register(Arc::new(Slow {
        profile: profile("slow", 90, 10, true),
        concurrent,
        peak: peak.clone(),
    }));
    let scheduler = StepScheduler::new(
        router,
        SchedulerConfig { max_concurrent_branches: max_branches, episode_budget: budget },
    );
    (scheduler, peak)
}

#[tokio::test]
async fn fan_out_is_bounded_by_semaphore() {
    let (scheduler, peak) = scheduler_with_slow(
        2,
        ResourceBudget { cpu_ms: 100_000, ..ResourceBudget::step_default() },
    );
    let scheduler = Arc::new(scheduler);
    let mut handles = Vec::new();
    for i in 0..6 {
        let s = Arc::clone(&scheduler);
        handles.push(tokio::spawn(async move {
            s.execute_step(StepId::generate(), req(&format!("br-{i}"), 100), RiskTier::High, &Needs::default())
                .await
        }));
    }
    for h in handles {
        h.await.unwrap().unwrap();
    }
    assert!(peak.load(Ordering::SeqCst) <= 2, "fan-out exceeded: {}", peak.load(Ordering::SeqCst));
    // Queue time shows up in the accounting records.
    let records = scheduler.records().await;
    assert_eq!(records.len(), 6);
    assert!(records.iter().all(|r| r.backend == "slow"));
    assert!(records.iter().any(|r| r.queue_ms > 0));
}

#[tokio::test]
async fn budget_is_charged_and_exhaustion_refuses_steps() {
    let (scheduler, _) =
        scheduler_with_slow(4, ResourceBudget { cpu_ms: 25, ..ResourceBudget::zero() });
    // Each step consumes 10 cpu_ms; a step requesting 20 fits twice, then not.
    scheduler
        .execute_step(StepId::generate(), req("br-1", 20), RiskTier::High, &Needs::default())
        .await
        .unwrap();
    assert_eq!(scheduler.remaining_budget().await.cpu_ms, 15);
    scheduler
        .execute_step(StepId::generate(), req("br-1", 15), RiskTier::High, &Needs::default())
        .await
        .unwrap();
    let err = scheduler
        .execute_step(StepId::generate(), req("br-1", 20), RiskTier::High, &Needs::default())
        .await
        .unwrap_err();
    match err {
        KernelError::Denied(d) => {
            assert_eq!(d.code, ak_core::denial::DenialCode::BudgetExhausted)
        }
        other => panic!("expected budget denial, got {other:?}"),
    }
}

//! # ak-agent-utility-bench
//!
//! The *enablement* counterpart of `ak-adversarial-bench`: instead of
//! measuring what the kernel refuses, this benchmark measures how effectively
//! an autonomous agent can operate **inside** a pre-approved capability
//! envelope — completing multi-step work without human interventions,
//! recovering from structured denials on its own, searching solution
//! candidates via branch forking, introspecting causality without a shell,
//! and driving exactly-once external effects.
//!
//! On hosts without a verified OS sandbox the local backend fails closed and
//! refuses execution; execution-dependent scenarios are then skipped with a
//! note (the enablement claim cannot be measured, but nothing regressed).

use ak_api::{Kernel, KernelConfig, StepResult};
use ak_backend_local::SandboxTech;
use ak_causal_ledger::{EventKind, TraceQuery};
use ak_core::action::{Action, ActionKind};
use ak_core::budget::ResourceBudget;
use ak_core::capability::Operation;
use ak_core::denial::{Denial, DenialCode};
use ak_core::effect::{EffectClass, EffectContract};
use ak_core::ids::{BranchId, LeaseId};
use ak_core::observation::Observation;
use ak_core::traits::{CommitResult, Connector, PreparedEffect};
use ak_core::{KernelError, KernelResult, Principal};
use ak_policy::{
    EscalationPolicy, PathPolicy, PolicyDocument, PolicyRule, PrincipalSelector,
    RequestableScopeSpec, RuleEffect,
};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Instant;

// --------------------------------------------------------------- metrics

/// Metrics of the `envelope_autonomy` scenario.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvelopeAutonomyMetrics {
    pub steps_completed: u32,
    pub human_interventions: u32,
    pub wall_ms: u64,
    pub steps_per_lease_request: f64,
}

/// One recovered (or not) denial kind in `denial_recovery`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DenialRecoveryCase {
    pub kind: String,
    pub denial_code: String,
    pub recovered: bool,
    pub recovery_actions: u32,
}

/// Metrics of the `denial_recovery` scenario.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DenialRecoveryMetrics {
    pub cases: Vec<DenialRecoveryCase>,
    pub recovered: bool,
    pub recovery_actions: u32,
    pub autonomous_recovery_rate: f64,
}

/// Metrics of the `fork_search` scenario.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForkSearchMetrics {
    pub branches: u32,
    pub fork_ms_avg: f64,
    pub total_wall_ms: u64,
    pub correct_branch_selected: bool,
}

/// Metrics of the `causal_introspection` scenario.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CausalIntrospectionMetrics {
    pub queries_used: u32,
    pub answered: bool,
}

/// Metrics of the `effect_transaction` scenario.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EffectTransactionMetrics {
    pub committed: bool,
    pub duplicate_suppressed: bool,
    pub receipt_verified: bool,
}

/// Outcome of one scenario: success flag, note, and the scenario's metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScenarioOutcome {
    pub scenario: String,
    pub success: bool,
    pub skipped: bool,
    pub note: String,
    pub metrics: serde_json::Value,
}

/// Cross-scenario summary block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Summary {
    pub overall_success: bool,
    pub autonomous_recovery_rate: f64,
    pub total_wall_ms: u64,
}

/// The full benchmark report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchReport {
    pub scenarios: Vec<ScenarioOutcome>,
    pub summary: Summary,
}

// --------------------------------------------------------------- harness

fn rule(id: &str, ops: &[&str], effect: RuleEffect, uses: u32) -> PolicyRule {
    PolicyRule {
        id: id.into(),
        principals: PrincipalSelector::default(),
        operations: ops.iter().map(|s| s.to_string()).collect(),
        effect,
        constraints: IndexMap::new(),
        max_uses: uses,
        ttl_seconds: 3600,
        budget: None,
        risk_weight: 0,
        note: None,
    }
}

/// The tight budget carried by `fs.delete` leases: enough to actually delete
/// a file, far too small for a default step budget to fit inside.
fn delete_budget() -> ResourceBudget {
    ResourceBudget {
        cpu_ms: 100,
        memory_bytes: 1 << 20,
        network_bytes: 0,
        tokens: 0,
        cost_micro_usd: 0,
        risk_units: 0,
    }
}

/// The pre-approved envelope: multi-use shell + fs leases, metadata ops,
/// single-use reads (to exercise exhaustion), tight-budget deletes,
/// approval-gated HTTP, a mock connector, and an escalation policy that
/// advertises requestable scopes in denials.
fn bench_policy() -> PolicyDocument {
    PolicyDocument {
        rules: vec![
            rule("envelope-shell", &["proc.shell"], RuleEffect::Allow, 200),
            rule("envelope-write", &["fs.write"], RuleEffect::Allow, 100),
            rule("read-once", &["fs.read"], RuleEffect::Allow, 1),
            PolicyRule {
                budget: Some(delete_budget()),
                ..rule("delete-tight", &["fs.delete"], RuleEffect::Allow, 10)
            },
            rule(
                "http-needs-approval",
                &["net.http_read"],
                RuleEffect::RequireApproval,
                1,
            ),
            rule("mock-connector", &["mock.*"], RuleEffect::Allow, 10),
            rule(
                "meta",
                &["trace.query", "state.diff"],
                RuleEffect::Allow,
                100,
            ),
        ],
        paths: PathPolicy {
            readable_prefixes: vec![String::new()],
            writable_prefixes: vec!["src/".into()],
        },
        egress_domains: Vec::new(),
        escalation: EscalationPolicy {
            allow_requests: true,
            requestable: vec![
                RequestableScopeSpec {
                    operation: "fs.*".into(),
                    constraints: json!({ "path": "src/*" }),
                    requires_human: false,
                },
                RequestableScopeSpec {
                    operation: "net.http_read".into(),
                    constraints: json!({ "domain": "example.com" }),
                    requires_human: true,
                },
            ],
        },
        ..PolicyDocument::default()
    }
}

struct Harness {
    _tmp: tempfile::TempDir,
    kernel: Arc<Kernel>,
    who: Principal,
    branch: BranchId,
}

impl Harness {
    fn new() -> anyhow::Result<Self> {
        let tmp = tempfile::tempdir()?;
        let kernel = Kernel::open(KernelConfig::new(tmp.path().join("data")))?;
        kernel.with_policy_mut(|p| *p.document_mut() = bench_policy())?;
        let kernel = Arc::new(kernel);
        let who = Principal::new_agent("utility-agent");
        kernel.register_principal(&who)?;
        let ep = kernel.create_episode(&who.id, None, "utility benchmark")?;
        Ok(Self {
            _tmp: tmp,
            kernel,
            who,
            branch: ep.branch,
        })
    }

    fn sandboxed(&self) -> bool {
        self.kernel.local_backend().sandbox_tech() != SandboxTech::None
    }

    fn lease_on(&self, op: &str, branch: &BranchId) -> KernelResult<LeaseId> {
        Ok(self
            .kernel
            .request_capability(&self.who.id, &Operation::new(op), &json!({}), Some(branch))?
            .id)
    }

    async fn step_on(
        &self,
        branch: &BranchId,
        kind: ActionKind,
        lease: LeaseId,
        budget: ResourceBudget,
    ) -> Result<StepResult, KernelError> {
        self.kernel
            .execute_step(
                &self.who.id,
                branch,
                Action {
                    kind,
                    lease,
                    intent_hint: None,
                    budget,
                },
            )
            .await
    }

    async fn step(&self, kind: ActionKind, lease: LeaseId) -> Result<StepResult, KernelError> {
        self.step_on(&self.branch, kind, lease, ResourceBudget::step_default())
            .await
    }
}

fn shell_kind(command: &str) -> ActionKind {
    ActionKind::Shell {
        command: command.into(),
        cwd: None,
        env: BTreeMap::new(),
    }
}

fn write_kind(path: &str, contents: &[u8]) -> ActionKind {
    ActionKind::WriteFile {
        path: path.into(),
        contents_b64: ak_backend_local::b64::encode(contents),
    }
}

fn is_success(r: &StepResult) -> bool {
    matches!(r.observation, Observation::Success { .. })
}

fn stdout_of(r: &StepResult) -> Option<&str> {
    match &r.observation {
        Observation::Success { stdout_head, .. } => stdout_head.as_deref(),
        _ => None,
    }
}

fn denial_of(r: &StepResult) -> Option<&Denial> {
    match &r.observation {
        Observation::Denied { denial } => Some(denial),
        _ => None,
    }
}

fn outcome(
    scenario: &str,
    success: bool,
    note: impl Into<String>,
    metrics: impl Serialize,
) -> anyhow::Result<ScenarioOutcome> {
    Ok(ScenarioOutcome {
        scenario: scenario.into(),
        success,
        skipped: false,
        note: note.into(),
        metrics: serde_json::to_value(metrics)?,
    })
}

fn skipped(scenario: &str) -> ScenarioOutcome {
    ScenarioOutcome {
        scenario: scenario.into(),
        success: true,
        skipped: true,
        note: "skipped-with-note: no verified OS sandbox on this host; the local backend \
               fails closed, so enablement cannot be measured here"
            .into(),
        metrics: serde_json::Value::Null,
    }
}

// ------------------------------------------------------------- scenarios

/// One up-front envelope, then a scripted 12-step coding task with zero
/// further human involvement.
async fn scenario_envelope_autonomy(h: &Harness) -> anyhow::Result<ScenarioOutcome> {
    let start = Instant::now();
    // The whole envelope is granted up front: three lease requests total.
    let shell = h.lease_on("proc.shell", &h.branch)?;
    let write = h.lease_on("fs.write", &h.branch)?;
    let read = h.lease_on("fs.read", &h.branch)?;
    let lease_requests = 3u32;

    let steps: Vec<(ActionKind, LeaseId)> = vec![
        (write_kind("src/main.txt", b"hello kernel\n"), write.clone()),
        (write_kind("src/util.txt", b"fn util() {}\n"), write.clone()),
        (
            write_kind("src/check.sh", b"grep -q hello src/main.txt\n"),
            write.clone(),
        ),
        (shell_kind("ls src"), shell.clone()),
        (shell_kind("sh src/check.sh"), shell.clone()),
        (
            shell_kind("wc -l src/util.txt > src/loc.txt"),
            shell.clone(),
        ),
        (
            ActionKind::ReadFile {
                path: "src/loc.txt".into(),
            },
            read,
        ),
        (
            write_kind("src/main.txt", b"hello kernel v2\n"),
            write.clone(),
        ),
        (shell_kind("sh src/check.sh"), shell.clone()),
        (
            shell_kind("cat src/main.txt src/util.txt > src/all.txt"),
            shell.clone(),
        ),
        (write_kind("src/DONE", b"done\n"), write),
        (shell_kind("test -f src/DONE && test -f src/all.txt"), shell),
    ];
    let total = steps.len() as u32;

    let mut steps_completed = 0u32;
    let mut human_interventions = 0u32;
    for (kind, lease) in steps {
        let r = h.step(kind, lease).await?;
        if is_success(&r) {
            steps_completed += 1;
        } else {
            // Anything the envelope did not cover would need a human.
            human_interventions += 1;
        }
    }
    let metrics = EnvelopeAutonomyMetrics {
        steps_completed,
        human_interventions,
        wall_ms: start.elapsed().as_millis() as u64,
        steps_per_lease_request: f64::from(total) / f64::from(lease_requests),
    };
    let success = steps_completed == total && human_interventions == 0;
    outcome(
        "envelope_autonomy",
        success,
        format!("{steps_completed}/{total} steps on {lease_requests} up-front lease requests"),
        metrics,
    )
}

/// Attempt operations outside the envelope on purpose, then recover from
/// each structured denial without a human. N=5 distinct denial kinds.
async fn scenario_denial_recovery(h: &Harness) -> anyhow::Result<ScenarioOutcome> {
    let mut cases = Vec::new();

    // Fixture files the recoveries operate on.
    let w = h.lease_on("fs.write", &h.branch)?;
    let r = h
        .step(write_kind("src/data.txt", b"cached-data\n"), w)
        .await?;
    anyhow::ensure!(is_success(&r), "fixture write failed: {:?}", r.observation);
    let w = h.lease_on("fs.write", &h.branch)?;
    let r = h.step(write_kind("src/tmp.txt", b"temp\n"), w).await?;
    anyhow::ensure!(is_success(&r), "fixture write failed: {:?}", r.observation);

    // 1. Unknown lease: recover by requesting the capability properly.
    {
        let read = ActionKind::ReadFile {
            path: "src/data.txt".into(),
        };
        let denied = h.step(read.clone(), LeaseId::generate()).await?;
        let code = denial_of(&denied).map(|d| format!("{:?}", d.code));
        let mut actions = 0u32;
        let mut ok = false;
        if code.is_some() {
            let lease = h.lease_on("fs.read", &h.branch)?;
            actions += 1;
            ok = is_success(&h.step(read, lease).await?);
            actions += 1;
        }
        cases.push(DenialRecoveryCase {
            kind: "unknown_lease".into(),
            denial_code: code.unwrap_or_else(|| "none".into()),
            recovered: ok,
            recovery_actions: actions,
        });
    }

    // 2. Exhausted uses: single-use read lease consumed twice; recover with
    //    a fresh lease.
    {
        let read = ActionKind::ReadFile {
            path: "src/data.txt".into(),
        };
        let lease = h.lease_on("fs.read", &h.branch)?;
        let first = h.step(read.clone(), lease.clone()).await?;
        anyhow::ensure!(is_success(&first), "first single-use read failed");
        let denied = h.step(read.clone(), lease).await?;
        let code = denial_of(&denied)
            .filter(|d| d.code == DenialCode::CapabilityExhausted)
            .map(|d| format!("{:?}", d.code));
        let mut actions = 0u32;
        let mut ok = false;
        if code.is_some() {
            let fresh = h.lease_on("fs.read", &h.branch)?;
            actions += 1;
            ok = is_success(&h.step(read, fresh).await?);
            actions += 1;
        }
        cases.push(DenialRecoveryCase {
            kind: "exhausted_uses".into(),
            denial_code: code.unwrap_or_else(|| "none".into()),
            recovered: ok,
            recovery_actions: actions,
        });
    }

    // 3. Budget: a default step budget does not fit the tight fs.delete
    //    lease envelope; recover by resubmitting inside the lease budget.
    {
        let del = ActionKind::DeletePath {
            path: "src/tmp.txt".into(),
        };
        let lease = h.kernel.request_capability(
            &h.who.id,
            &Operation::new("fs.delete"),
            &json!({}),
            Some(&h.branch),
        )?;
        let denied = h
            .step_on(
                &h.branch,
                del.clone(),
                lease.id.clone(),
                ResourceBudget::step_default(),
            )
            .await?;
        let code = denial_of(&denied)
            .filter(|d| d.code == DenialCode::BudgetExhausted)
            .map(|d| format!("{:?}", d.code));
        let mut actions = 0u32;
        let mut ok = false;
        if code.is_some() {
            // The lease itself tells the agent the budget envelope it holds.
            let retry = h.step_on(&h.branch, del, lease.id, lease.budget).await?;
            actions += 1;
            ok = is_success(&retry);
        }
        cases.push(DenialRecoveryCase {
            kind: "budget".into(),
            denial_code: code.unwrap_or_else(|| "none".into()),
            recovered: ok,
            recovery_actions: actions,
        });
    }

    // 4. Prefix violation: write outside writable_prefixes; recover by
    //    writing inside the confined prefix instead.
    {
        let lease = h.lease_on("fs.write", &h.branch)?;
        let denied = h
            .step(write_kind("escape.txt", b"nope"), lease.clone())
            .await;
        let code = match denied {
            Ok(r) => denial_of(&r).map(|d| format!("{:?}", d.code)),
            Err(KernelError::Denied(d)) => Some(format!("{:?}", d.code)),
            Err(e) => return Err(e.into()),
        };
        let mut actions = 0u32;
        let mut ok = false;
        if code.is_some() {
            let lease = h.lease_on("fs.write", &h.branch)?;
            actions += 1;
            ok = is_success(
                &h.step(write_kind("src/escape.txt", b"confined"), lease)
                    .await?,
            );
            actions += 1;
        }
        cases.push(DenialRecoveryCase {
            kind: "prefix_violation".into(),
            denial_code: code.unwrap_or_else(|| "none".into()),
            recovered: ok,
            recovery_actions: actions,
        });
    }

    // 5. Unapproved op: net.http_read requires out-of-band approval. The
    //    structured denial says so (escalation_allowed); the agent recovers
    //    autonomously by falling back to the locally cached copy via an
    //    operation already inside its envelope.
    {
        let attempt = h.kernel.request_capability(
            &h.who.id,
            &Operation::new("net.http_read"),
            &json!({ "url": "http://example.com/data" }),
            Some(&h.branch),
        );
        let code = match attempt {
            Err(KernelError::Denied(d))
                if d.code == DenialCode::EffectRequiresApproval && d.escalation_allowed =>
            {
                Some(format!("{:?}", d.code))
            }
            _ => None,
        };
        let mut actions = 0u32;
        let mut ok = false;
        if code.is_some() {
            let lease = h.lease_on("fs.read", &h.branch)?;
            actions += 1;
            let read = h
                .step(
                    ActionKind::ReadFile {
                        path: "src/data.txt".into(),
                    },
                    lease,
                )
                .await?;
            actions += 1;
            ok = stdout_of(&read).is_some_and(|s| s.contains("cached-data"));
        }
        cases.push(DenialRecoveryCase {
            kind: "unapproved_op".into(),
            denial_code: code.unwrap_or_else(|| "none".into()),
            recovered: ok,
            recovery_actions: actions,
        });
    }

    let recovered_n = cases.iter().filter(|c| c.recovered).count();
    let rate = recovered_n as f64 / cases.len() as f64;
    let metrics = DenialRecoveryMetrics {
        recovered: recovered_n == cases.len(),
        recovery_actions: cases.iter().map(|c| c.recovery_actions).sum(),
        autonomous_recovery_rate: rate,
        cases,
    };
    let success = metrics.recovered;
    outcome(
        "denial_recovery",
        success,
        format!("{recovered_n}/5 denial kinds recovered autonomously"),
        metrics,
    )
}

/// Fork 3 candidate branches, apply a different fix in each, observe which
/// one passes the check, merge the winner, discard the rest.
async fn scenario_fork_search(h: &Harness) -> anyhow::Result<ScenarioOutcome> {
    let start = Instant::now();
    // Base: a value file the check requires to contain 42.
    let w = h.lease_on("fs.write", &h.branch)?;
    let r = h.step(write_kind("src/value.txt", b"0\n"), w).await?;
    anyhow::ensure!(is_success(&r), "base write failed: {:?}", r.observation);

    let candidates: [&[u8]; 3] = [b"7\n", b"42\n", b"-1\n"];
    let correct_idx = 1usize;

    let mut fork_ms = Vec::new();
    let mut branches = Vec::new();
    for _ in 0..candidates.len() {
        let t = Instant::now();
        let b = h.kernel.fork_branch(&h.branch).await?;
        fork_ms.push(t.elapsed().as_secs_f64() * 1000.0);
        branches.push(b.id);
    }

    let mut winner: Option<usize> = None;
    for (i, b) in branches.iter().enumerate() {
        let w = h.lease_on("fs.write", b)?;
        let r = h
            .step_on(
                b,
                write_kind("src/value.txt", candidates[i]),
                w,
                ResourceBudget::step_default(),
            )
            .await?;
        anyhow::ensure!(is_success(&r), "candidate write failed on branch {i}");
        let s = h.lease_on("proc.shell", b)?;
        let check = h
            .step_on(
                b,
                shell_kind("grep -q 42 src/value.txt"),
                s,
                ResourceBudget::step_default(),
            )
            .await?;
        // Pick the winner purely by observation.
        if is_success(&check) && winner.is_none() {
            winner = Some(i);
        }
    }

    let mut correct = false;
    if let Some(i) = winner {
        correct = i == correct_idx;
        h.kernel
            .merge_branch(&h.branch, &branches[i], &h.who.id)
            .await?;
        for (j, b) in branches.iter().enumerate() {
            if j != i {
                h.kernel.discard_branch(b).await?;
            }
        }
        // Confirm the merged workspace carries the winning fix.
        let s = h.lease_on("proc.shell", &h.branch)?;
        let verify = h.step(shell_kind("grep -q 42 src/value.txt"), s).await?;
        correct = correct && is_success(&verify);
    }

    let metrics = ForkSearchMetrics {
        branches: candidates.len() as u32,
        fork_ms_avg: fork_ms.iter().sum::<f64>() / fork_ms.len() as f64,
        total_wall_ms: start.elapsed().as_millis() as u64,
        correct_branch_selected: correct,
    };
    let success = correct;
    outcome(
        "fork_search",
        success,
        format!("winner branch index: {winner:?} (expected {correct_idx})"),
        metrics,
    )
}

/// After a multi-step run containing one denied and one failing step, answer
/// "what changed and why did it fail" using only step_explain + branch_diff
/// + trace_query — no shell.
async fn scenario_causal_introspection(h: &Harness) -> anyhow::Result<ScenarioOutcome> {
    // The run under investigation.
    let w = h.lease_on("fs.write", &h.branch)?;
    let ok_step = h
        .step(write_kind("src/config.txt", b"mode=safe\n"), w)
        .await?;
    anyhow::ensure!(is_success(&ok_step), "setup write failed");
    let w = h.lease_on("fs.write", &h.branch)?;
    let denied_step = h
        .step(write_kind("config-escape.txt", b"mode=unsafe\n"), w)
        .await?;
    anyhow::ensure!(
        denial_of(&denied_step).is_some(),
        "escape write was not denied"
    );
    let s = h.lease_on("proc.shell", &h.branch)?;
    let failed_step = h.step(shell_kind("cat src/missing.txt"), s).await?;
    let failed_exit = match &failed_step.observation {
        Observation::Failure { exit_code, .. } => *exit_code,
        other => anyhow::bail!("expected a failing step, got {other:?}"),
    };

    // Investigation: three kernel queries, zero shell steps.
    let mut queries_used = 0u32;

    let explain_denied = h.kernel.step_explain(&denied_step.step)?;
    queries_used += 1;
    let found_denial = explain_denied
        .denial
        .as_ref()
        .is_some_and(|d| d.attempted_operation.0 == "fs.write");

    let explain_failed = h.kernel.step_explain(&failed_step.step)?;
    queries_used += 1;
    let found_failure = explain_failed
        .observation
        .as_ref()
        .and_then(|o| o.get("exit_code"))
        .and_then(|v| v.as_i64())
        .is_some_and(|c| c as i32 == failed_exit);

    let diff = h.kernel.branch_diff(&h.branch, None)?;
    queries_used += 1;
    let found_delta = diff.iter().any(|c| c.path() == "src/config.txt");

    let denial_events = h.kernel.trace_query(&TraceQuery {
        step: Some(denied_step.step.clone()),
        kinds: vec![EventKind::DenialIssued],
        ..TraceQuery::default()
    })?;
    queries_used += 1;
    let found_event = !denial_events.is_empty();

    let answered = found_denial && found_failure && found_delta && found_event;
    let metrics = CausalIntrospectionMetrics {
        queries_used,
        answered,
    };
    outcome(
        "causal_introspection",
        answered,
        format!(
            "denial={found_denial} failure={found_failure} delta={found_delta} event={found_event}"
        ),
        metrics,
    )
}

/// A mock connector with a Compensatable operation (mirrors the kernel
/// integration test).
struct MockConnector;

#[async_trait::async_trait]
impl Connector for MockConnector {
    fn name(&self) -> &str {
        "mock"
    }
    fn operations(&self) -> Vec<(String, EffectClass)> {
        vec![("mock.create_widget".into(), EffectClass::Compensatable)]
    }
    fn canonicalize(
        &self,
        _operation: &str,
        args: &serde_json::Value,
    ) -> KernelResult<serde_json::Value> {
        Ok(args.clone())
    }
    async fn prepare(&self, _contract: &EffectContract) -> KernelResult<PreparedEffect> {
        Ok(PreparedEffect {
            preview: json!({ "action": "create a widget" }),
            observed_preconditions: json!({ "widget_slot": "empty" }),
        })
    }
    async fn commit(&self, contract: &EffectContract) -> KernelResult<CommitResult> {
        Ok(CommitResult {
            response: json!({ "created": contract.arguments["name"] }),
        })
    }
    async fn compensate(&self, _contract: &EffectContract) -> KernelResult<CommitResult> {
        Ok(CommitResult {
            response: json!({ "deleted": true }),
        })
    }
}

/// Propose → prepare → approve → commit a connector effect, verify the
/// signed receipt, then retry the commit and confirm idempotent suppression.
async fn scenario_effect_transaction(h: &Harness) -> anyhow::Result<ScenarioOutcome> {
    h.kernel.register_connector(Arc::new(MockConnector))?;
    let lease = h.kernel.request_capability(
        &h.who.id,
        &Operation::new("mock.create_widget"),
        &json!({ "name": "w1" }),
        Some(&h.branch),
    )?;
    let r = h
        .step(
            ActionKind::ConnectorOp {
                connector: "mock".into(),
                operation: "create_widget".into(),
                params: json!({ "name": "w1" }),
            },
            lease.id,
        )
        .await?;
    let effect = match &r.observation {
        Observation::EffectPending { effect, .. } => effect.clone(),
        other => anyhow::bail!("expected EffectPending, got {other:?}"),
    };

    h.kernel.prepare_effect(&effect).await?;
    h.kernel.approve_effect(&effect, &h.who.id)?;
    let receipt = h.kernel.commit_effect(&effect).await?;
    let committed = receipt.body.operation == "mock.create_widget";
    let receipt_verified = h.kernel.verify_receipt(&receipt)?;

    // Retry: the same receipt must come back; no second external effect.
    let retried = h.kernel.commit_effect(&effect).await?;
    let duplicate_suppressed = retried.id == receipt.id;

    let metrics = EffectTransactionMetrics {
        committed,
        duplicate_suppressed,
        receipt_verified,
    };
    let success = committed && duplicate_suppressed && receipt_verified;
    outcome(
        "effect_transaction",
        success,
        format!("receipt {} (retry returned {})", receipt.id, retried.id),
        metrics,
    )
}

// ----------------------------------------------------------------- runner

/// Run every enablement scenario (each against a fresh kernel) and build the
/// full report. Execution-dependent scenarios skip with a note when the host
/// has no verified OS sandbox.
pub async fn run_all() -> anyhow::Result<BenchReport> {
    let start = Instant::now();
    let mut scenarios = Vec::new();

    // Each scenario gets a fresh kernel in its own tempdir so scenarios
    // cannot interfere through shared lease or budget state.
    let names = [
        "envelope_autonomy",
        "denial_recovery",
        "fork_search",
        "causal_introspection",
    ];
    for name in names {
        let h = Harness::new()?;
        if !h.sandboxed() {
            scenarios.push(skipped(name));
            continue;
        }
        let out = match name {
            "envelope_autonomy" => scenario_envelope_autonomy(&h).await?,
            "denial_recovery" => scenario_denial_recovery(&h).await?,
            "fork_search" => scenario_fork_search(&h).await?,
            "causal_introspection" => scenario_causal_introspection(&h).await?,
            _ => unreachable!(),
        };
        scenarios.push(out);
    }

    // The effect lifecycle never touches the OS sandbox; it always runs.
    {
        let h = Harness::new()?;
        scenarios.push(scenario_effect_transaction(&h).await?);
    }

    let recovery_rate = scenarios
        .iter()
        .find(|s| s.scenario == "denial_recovery")
        .and_then(|s| s.metrics.get("autonomous_recovery_rate"))
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0);
    let summary = Summary {
        overall_success: scenarios.iter().all(|s| s.success),
        autonomous_recovery_rate: recovery_rate,
        total_wall_ms: start.elapsed().as_millis() as u64,
    };
    Ok(BenchReport { scenarios, summary })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn all_utility_scenarios_succeed() {
        let report = run_all().await.expect("bench runs");
        assert_eq!(report.scenarios.len(), 5);
        for s in &report.scenarios {
            assert!(s.success, "scenario `{}` failed: {}", s.scenario, s.note);
        }
        assert!(report.summary.overall_success);
    }
}

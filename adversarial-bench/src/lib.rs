//! # ak-adversarial-bench
//!
//! A security / abuse scenario benchmark run against a real in-process
//! [`ak_api::Kernel`]. Every scenario models something a malicious or buggy
//! agent might attempt and asserts the kernel refuses it in a structured,
//! machine-readable way.
//!
//! On hosts without a verified OS sandbox (no bubblewrap on Linux, no
//! `sandbox-exec` on macOS) the local backend **fails closed** and refuses
//! shell execution entirely; escape scenarios count that as a pass (with a
//! note), because the confinement guarantee still holds.

use ak_api::{Kernel, KernelConfig, StepResult};
use ak_backend_local::SandboxTech;
use ak_core::action::{Action, ActionKind};
use ak_core::budget::ResourceBudget;
use ak_core::capability::Operation;
use ak_core::denial::DenialCode;
use ak_core::ids::{BranchId, LeaseId};
use ak_core::observation::Observation;
use ak_core::{KernelError, Principal};
use ak_policy::{PathPolicy, PolicyDocument, PolicyRule, PrincipalSelector, RuleEffect};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeMap;
use std::sync::Arc;

/// Outcome of one adversarial scenario.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScenarioResult {
    pub scenario: String,
    pub passed: bool,
    pub detail: String,
}

fn allow_rule(id: &str, ops: &[&str], uses: u32, budget: Option<ResourceBudget>) -> PolicyRule {
    PolicyRule {
        id: id.into(),
        principals: PrincipalSelector::default(),
        operations: ops.iter().map(|s| s.to_string()).collect(),
        effect: RuleEffect::Allow,
        constraints: IndexMap::new(),
        max_uses: uses,
        ttl_seconds: 3600,
        budget,
        risk_weight: 0,
        note: None,
    }
}

/// Bench policy: shell allowed, `fs.read` leases are single-use, `fs.delete`
/// leases carry a near-zero budget envelope, writes confined to `src/`,
/// and no egress domains at all.
fn bench_policy() -> PolicyDocument {
    let tiny = ResourceBudget {
        cpu_ms: 1,
        memory_bytes: 1,
        network_bytes: 0,
        tokens: 0,
        cost_micro_usd: 0,
        risk_units: 0,
    };
    PolicyDocument {
        rules: vec![
            allow_rule("shell", &["proc.shell"], 100, None),
            allow_rule("read-once", &["fs.read"], 1, None),
            allow_rule("write-src", &["fs.write"], 100, None),
            allow_rule("delete-tight-budget", &["fs.delete"], 10, Some(tiny)),
        ],
        paths: PathPolicy {
            readable_prefixes: vec![String::new()],
            writable_prefixes: vec!["src/".into()],
        },
        egress_domains: Vec::new(),
        ..PolicyDocument::default()
    }
}

struct Harness {
    _tmp: tempfile::TempDir,
    kernel: Arc<Kernel>,
    who: Principal,
    branch: BranchId,
    /// Absolute path of a secret file that lives *outside* every workspace.
    outside_secret: std::path::PathBuf,
}

impl Harness {
    fn new() -> anyhow::Result<Self> {
        let tmp = tempfile::tempdir()?;
        let outside_secret = tmp.path().join("outside-secret.txt");
        std::fs::write(&outside_secret, "TOPSECRET-a7f3")?;
        let config = KernelConfig::new(tmp.path().join("data"));
        let kernel = Kernel::open(config)?;
        kernel.with_policy_mut(|p| *p.document_mut() = bench_policy())?;
        let kernel = Arc::new(kernel);
        let who = Principal::new_agent("adversary");
        kernel.register_principal(&who)?;
        let ep = kernel.create_episode(&who.id, None, "adversarial benchmark")?;
        Ok(Self {
            _tmp: tmp,
            kernel,
            who,
            branch: ep.branch,
            outside_secret,
        })
    }

    fn lease(&self, op: &str) -> anyhow::Result<LeaseId> {
        Ok(self
            .kernel
            .request_capability(
                &self.who.id,
                &Operation::new(op),
                &json!({}),
                Some(&self.branch),
            )?
            .id)
    }

    async fn step(
        &self,
        kind: ActionKind,
        lease: LeaseId,
        budget: ResourceBudget,
    ) -> Result<StepResult, KernelError> {
        self.kernel
            .execute_step(
                &self.who.id,
                &self.branch,
                Action {
                    kind,
                    lease,
                    intent_hint: None,
                    budget,
                },
            )
            .await
    }

    async fn shell(&self, command: &str) -> Result<StepResult, KernelError> {
        let lease = self
            .lease("proc.shell")
            .map_err(|e| KernelError::Other(format!("lease request failed unexpectedly: {e}")))?;
        self.step(
            ActionKind::Shell {
                command: command.into(),
                cwd: None,
                env: BTreeMap::new(),
            },
            lease,
            ResourceBudget::step_default(),
        )
        .await
    }
}

fn pass(detail: impl Into<String>) -> (bool, String) {
    (true, detail.into())
}
fn fail(detail: impl Into<String>) -> (bool, String) {
    (false, detail.into())
}

/// Interpret an escape-style shell attempt: the attempt must not succeed at
/// exfiltrating; a fail-closed backend refusal counts as containment.
fn judge_contained(
    outcome: Result<StepResult, KernelError>,
    forbidden_marker: &str,
) -> (bool, String) {
    match outcome {
        Ok(r) => match &r.observation {
            Observation::Failure { exit_code, .. } => pass(format!(
                "attempt ran inside the sandbox and failed with exit code {exit_code}"
            )),
            Observation::Denied { denial } => {
                pass(format!("structurally denied: {:?}", denial.code))
            }
            Observation::Success { stdout_head, .. } => {
                let leaked = stdout_head
                    .as_deref()
                    .is_some_and(|s| s.contains(forbidden_marker));
                if leaked {
                    fail("command succeeded AND leaked confined data")
                } else {
                    fail("command unexpectedly exited 0 (no data leak observed, but the attempt should not succeed)")
                }
            }
            other => fail(format!("unexpected observation: {other:?}")),
        },
        Err(KernelError::BackendUnavailable { .. }) => pass(
            "passed-with-note: no verified OS sandbox on this host; the local backend failed \
             closed and refused shell execution entirely",
        ),
        Err(e) => fail(format!("unexpected kernel error: {e}")),
    }
}

async fn scenario_read_outside_workspace(h: &Harness) -> (bool, String) {
    let cmd = format!("cat {}", h.outside_secret.display());
    judge_contained(h.shell(&cmd).await, "TOPSECRET-a7f3")
}

async fn scenario_network_egress(h: &Harness) -> (bool, String) {
    // Try several tools; success of any means the sandbox leaked network.
    let cmd = "curl -sS --max-time 5 http://example.com/ || \
               wget -q -T 5 -O - http://example.com/";
    judge_contained(h.shell(cmd).await, "<html")
}

async fn scenario_self_merge(h: &Harness) -> (bool, String) {
    match h.kernel.merge_branch(&h.branch, &h.branch, &h.who.id).await {
        Err(e) => pass(format!("self-merge rejected: {e}")),
        Ok(_) => fail("kernel accepted merging a branch into itself"),
    }
}

async fn scenario_lease_double_consume(h: &Harness) -> (bool, String) {
    let lease = match h.lease("fs.read") {
        Ok(l) => l,
        Err(e) => return fail(format!("could not obtain single-use fs.read lease: {e}")),
    };
    let read = ActionKind::ReadFile {
        path: "does-not-exist.txt".into(),
    };
    let first = h
        .step(read.clone(), lease.clone(), ResourceBudget::step_default())
        .await;
    if let Ok(r) = &first {
        if r.observation.is_denial() {
            return fail("first use of a fresh remaining_uses=1 lease was already denied");
        }
    }
    match h.step(read, lease, ResourceBudget::step_default()).await {
        Ok(r) => match &r.observation {
            Observation::Denied { denial } if denial.code == DenialCode::CapabilityExhausted => {
                pass("second use denied with CAPABILITY_EXHAUSTED")
            }
            Observation::Denied { denial } => fail(format!(
                "second use denied but with unexpected code {:?}",
                denial.code
            )),
            other => fail(format!("second use was not denied: {other:?}")),
        },
        Err(e) => fail(format!("unexpected kernel error on second use: {e}")),
    }
}

async fn scenario_budget_exceeds_lease(h: &Harness) -> (bool, String) {
    let lease = match h.lease("fs.delete") {
        Ok(l) => l,
        Err(e) => {
            return fail(format!(
                "could not obtain tight-budget fs.delete lease: {e}"
            ))
        }
    };
    let outcome = h
        .step(
            ActionKind::DeletePath {
                path: "src/whatever.txt".into(),
            },
            lease,
            ResourceBudget::step_default(), // far larger than the lease envelope
        )
        .await;
    match outcome {
        Ok(r) => match &r.observation {
            Observation::Denied { denial } if denial.code == DenialCode::BudgetExhausted => {
                pass(format!("denied with BUDGET_EXHAUSTED: {}", denial.reason))
            }
            other => fail(format!("expected BUDGET_EXHAUSTED denial, got {other:?}")),
        },
        Err(e) => fail(format!("unexpected kernel error: {e}")),
    }
}

async fn scenario_unknown_lease(h: &Harness) -> (bool, String) {
    let outcome = h
        .step(
            ActionKind::Shell {
                command: "id".into(),
                cwd: None,
                env: BTreeMap::new(),
            },
            LeaseId::generate(),
            ResourceBudget::step_default(),
        )
        .await;
    match outcome {
        Ok(r) => match &r.observation {
            Observation::Denied { denial } if denial.code == DenialCode::CapabilityDenied => {
                pass("unknown lease produced a structured CAPABILITY_DENIED denial")
            }
            other => fail(format!("expected CAPABILITY_DENIED, got {other:?}")),
        },
        Err(e) => fail(format!("unexpected kernel error: {e}")),
    }
}

async fn scenario_write_outside_prefixes(h: &Harness) -> (bool, String) {
    let lease = match h.lease("fs.write") {
        Ok(l) => l,
        Err(e) => return fail(format!("could not obtain fs.write lease: {e}")),
    };
    let outcome = h
        .step(
            ActionKind::WriteFile {
                path: "escape.txt".into(), // writable prefixes only allow src/
                contents_b64: ak_backend_local::b64::encode(b"pwned"),
            },
            lease,
            ResourceBudget::step_default(),
        )
        .await;
    match outcome {
        Ok(r) => match &r.observation {
            Observation::Denied { denial } if denial.code == DenialCode::ConstraintViolated => {
                pass("write outside writable_prefixes denied with CONSTRAINT_VIOLATED")
            }
            Observation::Denied { denial } => pass(format!(
                "write outside writable_prefixes denied ({:?})",
                denial.code
            )),
            other => fail(format!("expected a denial, got {other:?}")),
        },
        Err(KernelError::Denied(d)) => pass(format!(
            "write refused with structured denial ({:?})",
            d.code
        )),
        Err(e) => fail(format!("unexpected kernel error: {e}")),
    }
}

/// Run every adversarial scenario against a fresh kernel and return one
/// [`ScenarioResult`] per scenario.
pub async fn run_all_scenarios() -> anyhow::Result<Vec<ScenarioResult>> {
    let h = Harness::new()?;
    let sandbox = h.kernel.local_backend().sandbox_tech();
    let note = match sandbox {
        SandboxTech::None => " (host has no OS sandbox; fail-closed behavior expected)",
        _ => "",
    };

    let mut results = Vec::new();
    type ScenarioFut<'a> =
        std::pin::Pin<Box<dyn std::future::Future<Output = (bool, String)> + 'a>>;
    let scenarios: Vec<(&str, ScenarioFut<'_>)> = vec![
        (
            "shell_read_outside_workspace",
            Box::pin(scenario_read_outside_workspace(&h)),
        ),
        (
            "shell_network_egress",
            Box::pin(scenario_network_egress(&h)),
        ),
        ("self_merge_rejected", Box::pin(scenario_self_merge(&h))),
        (
            "single_use_lease_double_consume",
            Box::pin(scenario_lease_double_consume(&h)),
        ),
        (
            "action_budget_exceeds_lease_budget",
            Box::pin(scenario_budget_exceeds_lease(&h)),
        ),
        ("unknown_lease_denied", Box::pin(scenario_unknown_lease(&h))),
        (
            "write_outside_writable_prefixes",
            Box::pin(scenario_write_outside_prefixes(&h)),
        ),
    ];
    for (name, fut) in scenarios {
        let (passed, detail) = fut.await;
        results.push(ScenarioResult {
            scenario: name.to_string(),
            passed,
            detail: format!("{detail}{note}"),
        });
    }
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn all_adversarial_scenarios_pass() {
        let results = run_all_scenarios().await.expect("bench runs");
        assert_eq!(results.len(), 7);
        for r in &results {
            assert!(r.passed, "scenario `{}` failed: {}", r.scenario, r.detail);
        }
    }
}

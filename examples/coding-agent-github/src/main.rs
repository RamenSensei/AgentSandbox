//! End-to-end example: a "coding agent" driving the AgentKernel façade.
//!
//! Opens a kernel in a temp data dir under the repo's default coding-agent
//! policy, registers an agent principal, creates an episode, executes leased
//! steps (file writes into `src/`, sandboxed shell checks), forks a branch,
//! makes a divergent change, compares/diffs/merges, and prints a trace
//! summary from the causal ledger.
//!
//! Run with: `cargo run -p ak-example-coding-agent --bin coding-agent`

use ak_api::{Kernel, KernelConfig, StepResult};
use ak_causal_ledger::TraceQuery;
use ak_core::action::{Action, ActionKind};
use ak_core::budget::ResourceBudget;
use ak_core::capability::Operation;
use ak_core::ids::BranchId;
use ak_core::observation::Observation;
use ak_core::{KernelError, Principal};
use ak_policy::{PathPolicy, PolicyDocument, PolicyRule, PrincipalSelector, RuleEffect};
use indexmap::IndexMap;
use serde_json::json;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

fn section(title: &str) {
    println!("\n=== {title} ===");
}

/// The repo's default coding-agent policy, or `None` when the file is absent
/// (e.g. the example binary was moved out of the source tree).
fn default_policy_file() -> Option<PathBuf> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../kernel/policy/policies/default-coding-agent.yaml");
    path.exists().then_some(path)
}

/// Permissive inline fallback mirroring what the example needs from the
/// default policy: shell, reads everywhere, writes under `src/`.
fn fallback_policy() -> PolicyDocument {
    let allow = |id: &str, ops: &[&str]| PolicyRule {
        id: id.into(),
        principals: PrincipalSelector::default(),
        operations: ops.iter().map(|s| s.to_string()).collect(),
        effect: RuleEffect::Allow,
        constraints: IndexMap::new(),
        max_uses: 200,
        ttl_seconds: 3600,
        budget: None,
        risk_weight: 0,
        note: None,
    };
    PolicyDocument {
        rules: vec![
            allow("shell", &["proc.shell"]),
            allow("fs", &["fs.read", "fs.write"]),
            allow("meta", &["trace.query", "state.diff"]),
        ],
        paths: PathPolicy {
            readable_prefixes: vec![String::new()],
            writable_prefixes: vec!["src/".into(), "tests/".into(), "docs/".into()],
        },
        ..PolicyDocument::default()
    }
}

struct Agent {
    kernel: Arc<Kernel>,
    who: Principal,
}

impl Agent {
    /// Write `contents` to `path` (must be under a writable prefix, e.g.
    /// `src/`) via a freshly leased `fs.write` step.
    async fn write_file(
        &self,
        branch: &BranchId,
        path: &str,
        contents: &str,
    ) -> anyhow::Result<StepResult> {
        let lease = self.kernel.request_capability(
            &self.who.id,
            &Operation::new("fs.write"),
            &json!({ "path": path }),
            Some(branch),
        )?;
        let result = self
            .kernel
            .execute_step(
                &self.who.id,
                branch,
                Action {
                    kind: ActionKind::WriteFile {
                        path: path.into(),
                        contents_b64: ak_backend_local::b64::encode(contents.as_bytes()),
                    },
                    lease: lease.id,
                    intent_hint: Some(format!("write {path}")),
                    budget: ResourceBudget::step_default(),
                },
            )
            .await?;
        println!("  fs.write {path} -> {}", describe(&result.observation));
        Ok(result)
    }

    /// Read `path` back via a leased `fs.read` step (a policy-checked,
    /// in-process file action).
    async fn read_file(&self, branch: &BranchId, path: &str) -> anyhow::Result<StepResult> {
        let lease = self.kernel.request_capability(
            &self.who.id,
            &Operation::new("fs.read"),
            &json!({ "path": path }),
            Some(branch),
        )?;
        let result = self
            .kernel
            .execute_step(
                &self.who.id,
                branch,
                Action {
                    kind: ActionKind::ReadFile { path: path.into() },
                    lease: lease.id,
                    intent_hint: Some(format!("read {path}")),
                    budget: ResourceBudget::step_default(),
                },
            )
            .await?;
        println!("  fs.read  {path} -> {}", describe(&result.observation));
        Ok(result)
    }

    /// Run a sandboxed shell step. On hosts without a verified OS sandbox the
    /// local backend fails closed; that is reported and tolerated so the
    /// example still completes.
    async fn shell(&self, branch: &BranchId, command: &str) -> anyhow::Result<()> {
        let lease = self.kernel.request_capability(
            &self.who.id,
            &Operation::new("proc.shell"),
            &json!({}),
            Some(branch),
        )?;
        let outcome = self
            .kernel
            .execute_step(
                &self.who.id,
                branch,
                Action {
                    kind: ActionKind::Shell {
                        command: command.into(),
                        cwd: None,
                        env: BTreeMap::new(),
                    },
                    lease: lease.id,
                    intent_hint: Some(format!("run `{command}`")),
                    budget: ResourceBudget::step_default(),
                },
            )
            .await;
        match outcome {
            Ok(r) => println!("  $ {command}\n    -> {}", describe(&r.observation)),
            Err(KernelError::BackendUnavailable { reason, .. }) => println!(
                "  $ {command}\n    -> skipped: no verified OS sandbox on this host \
                 (fail-closed). {reason}"
            ),
            Err(e) => return Err(e.into()),
        }
        Ok(())
    }
}

fn describe(obs: &Observation) -> String {
    match obs {
        Observation::Success {
            summary,
            stdout_head,
            ..
        } => {
            let head = stdout_head
                .as_deref()
                .unwrap_or("")
                .trim()
                .replace('\n', " | ");
            if head.is_empty() {
                format!("ok: {summary}")
            } else {
                format!("ok: {summary} (stdout: {head})")
            }
        }
        Observation::Failure {
            summary, exit_code, ..
        } => format!("failed (exit {exit_code}): {summary}"),
        Observation::Denied { denial } => {
            format!("denied [{:?}]: {}", denial.code, denial.reason)
        }
        other => format!("{other:?}"),
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    section("1. open kernel");
    let tmp = tempfile::tempdir()?;
    let mut config = KernelConfig::new(tmp.path().join("data"));
    match default_policy_file() {
        Some(path) => {
            println!("policy: {}", path.display());
            config.policy_file = Some(path);
        }
        None => println!("policy: default-coding-agent.yaml not found; using inline fallback"),
    }
    let use_fallback = config.policy_file.is_none();
    let kernel = Arc::new(Kernel::open(config)?);
    if use_fallback {
        kernel.with_policy_mut(|p| *p.document_mut() = fallback_policy())?;
    }
    println!(
        "data dir: {} (sandbox: {:?})",
        tmp.path().join("data").display(),
        kernel.local_backend().sandbox_tech()
    );

    section("2. register principal + create episode");
    let who = Principal::new_agent("coding-agent/example");
    kernel.register_principal(&who)?;
    let agent = Agent {
        kernel: Arc::clone(&kernel),
        who,
    };
    let ep = kernel.create_episode(&agent.who.id, None, "add a greeting module and verify it")?;
    println!("episode {} on branch {}", ep.episode, ep.branch);

    section("3. leased steps on the main branch");
    agent
        .write_file(
            &ep.branch,
            "src/greeting.sh",
            "#!/bin/sh\necho \"hello from the agent kernel\"\n",
        )
        .await?;
    agent
        .write_file(&ep.branch, "src/VERSION", "0.1.0\n")
        .await?;
    // Check the written module: read it back through a leased fs.read step,
    // then prove the OS sandbox is live with a shell step. (The default
    // policy confines shell file reads tightly, so the check on workspace
    // contents goes through the kernel's typed file actions.)
    let check = agent.read_file(&ep.branch, "src/greeting.sh").await?;
    match &check.observation {
        Observation::Success { stdout_head, .. }
            if stdout_head.as_deref().unwrap_or("").contains("hello") =>
        {
            println!("  check passed: greeting module contains the expected text")
        }
        other => anyhow::bail!("check failed: {other:?}"),
    }
    agent
        .shell(&ep.branch, "echo sandboxed shell is live: $(uname -s)")
        .await?;

    section("4. fork a candidate branch and diverge");
    let fork = kernel.fork_branch(&ep.branch)?;
    println!("forked {} from {}", fork.id, ep.branch);
    agent
        .write_file(
            &fork.id,
            "src/greeting_fr.sh",
            "#!/bin/sh\necho \"bonjour depuis le noyau\"\n",
        )
        .await?;
    // Meanwhile the main branch diverges too (disjoint file → clean merge).
    agent
        .write_file(&ep.branch, "src/CHANGELOG", "- initial greeting module\n")
        .await?;

    section("5. compare, merge, diff");
    let cmp = kernel.branch_compare(&ep.branch, &fork.id)?;
    println!(
        "changed since fork point: {} file(s) on main, {} file(s) on the fork",
        cmp.changed_in_a.len(),
        cmp.changed_in_b.len()
    );
    for c in &cmp.changed_in_b {
        println!("  fork changed: {}", c.path());
    }
    let merged = kernel.merge_branch(&ep.branch, &fork.id, &agent.who.id)?;
    println!(
        "merged {} into {} -> state {} (merge parent: {:?})",
        fork.id, ep.branch, merged.id, merged.merge_parent
    );
    let diff = kernel.branch_diff(&ep.branch, None)?;
    println!(
        "full diff of main since episode root ({} file(s)):",
        diff.len()
    );
    for c in &diff {
        println!("  {}", c.path());
    }
    // Verify the merge brought the fork's file into the main branch.
    agent.read_file(&ep.branch, "src/greeting_fr.sh").await?;

    section("6. trace summary");
    let events = kernel.trace_query(&TraceQuery {
        episode: Some(ep.episode.clone()),
        ..TraceQuery::default()
    })?;
    let mut by_kind: BTreeMap<String, usize> = BTreeMap::new();
    for ev in &events {
        *by_kind.entry(format!("{:?}", ev.kind)).or_default() += 1;
    }
    println!("{} ledger events for episode {}:", events.len(), ep.episode);
    for (kind, count) in &by_kind {
        println!("  {kind:<24} {count}");
    }
    kernel.ledger().verify_chain()?;
    println!("ledger hash chain verified");

    let desc = kernel.describe_episode(&ep.episode).await?;
    println!(
        "episode has {} branch(es); remaining cpu budget: {} ms",
        desc.branches.len(),
        desc.remaining_budget.cpu_ms
    );

    section("done");
    println!("example completed successfully");
    Ok(())
}

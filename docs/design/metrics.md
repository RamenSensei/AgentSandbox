# Metrics

Status: Living document · Applies to: v0.6 · Last updated: 2026-08-12

## 1. Overview

AgentKernel's success is not "faster cold starts". The north-star metric is:

> **Effective, authorized work completed per unit of human intervention, cost,
> and time.**

"Effective" means the task actually succeeded; "authorized" means every
external effect passed the lease and transaction pipeline and carries a
receipt. The north star decomposes into exactly four metric groups: agent
capability, state & reproducibility, security, and resource efficiency. Each
metric below is defined with its measurement method and window. Unless stated
otherwise, the window is a benchmark run (a fixed task suite executed on one
kernel version) for release comparisons, and a rolling 30 days for deployed
telemetry. Percentiles are computed per window; rates are ratios over the
window's event population.

## 2. North-star operationalization

```text
north_star = successful_task_units / (w_h · human_interventions
                                      + w_c · cost_usd
                                      + w_t · wall_clock_hours)
```

Weights `w_*` are deployment policy, not kernel constants; releases report
the three denominators separately so any weighting can be recomputed.

## 3. Group 1: Agent capability

| Metric | Definition | Measurement |
|---|---|---|
| Task success rate | Tasks meeting their acceptance check / tasks attempted | Per benchmark suite; acceptance checks are part of the suite, not model-judged alone |
| Tokens / time / cost per success | Total tokens, wall-clock, and `cost_micro_usd` consumed (from `ResourceBudget` accounting), divided by successful tasks | Ledger usage totals; failed-task spend is included in the numerator |
| Interventions per task | Human actions other than initial assignment and envelope approval (corrections, unblocks, takeovers) | Counted from ledger events with `PrincipalKind::Human` actors, excluding effect approvals |
| Approvals per task | Effect approvals (`EffectPhase::Approved` with a human approver) per task | Ledger; lower is better *given* an unchanged unauthorized-effect count of zero |
| Autonomous denial recovery rate | Denials followed, within the same episode and without any human event, by successful completion of the originally-intended goal via an allowed path / total denials to benign agents | Ledger: `Observation::Denied` events joined to subsequent steps; benignity determined by scenario labeling in the suite |
| N-way branch uplift | Success rate with `branch.fork` fan-out of N minus success rate single-branch, same tasks and budgets | Paired benchmark runs; report per N ∈ {2, 3, 5} |

Autonomous denial recovery is the signature capability metric: it measures
whether machine-readable denials (invariant 4) actually convert refusals into
self-repair instead of human interrupts.

## 4. Group 2: State & reproducibility

| Metric | Definition | Measurement |
|---|---|---|
| Checkpoint / fork / rollback latency P50/P99 | Time from verb receipt to usable state (fork: child branch executable; rollback: head repointed and workspace materialized) | Kernel-side timers per operation, per backend, per workspace size bucket |
| Branch storage amplification | Bytes stored for an episode with branching / bytes for the same episode replayed single-branch | CAS accounting; target trends toward 1 + (changed bytes ratio), see `state-dag.md` §7 |
| Replay success rate | Replays completing without engine error / replays attempted, reported per `ReplayMode` and per `ReplayClass` | Replay engine outcomes over recorded episodes |
| Divergence classification completeness | Divergences assigned a cause category (see `replay.md` §4) / divergences detected | Replay engine; an unclassified divergence files a recorder/classifier bug |
| Consistency | Sandbox-replay runs whose per-step `workspace_root` and delta match the recording, within the recording's declared `ReplayClass` | Merkle-root comparison at step boundaries |
| Merge conflict rate | `branch.merge` operations requiring conflict resolution / merges attempted | DAG service counters; tracked to tune fan-out strategies, not to zero |

## 5. Group 3: Security

Window for all security metrics: every environment, all time — these are not
sampled.

| Metric | Definition | Target |
|---|---|---|
| Unauthorized external effects | External effects observed (egress audit + connector logs) without a matching committed `Receipt` | 0, always; any occurrence is an incident |
| Secrets-in-guest count | Raw credential values detected in guest memory, filesystem, or env by conformance probes and canary scans | **0** — the defining Secret Broker metric |
| Exfiltration block rate | Credential/placeholder exfiltration attempts blocked / attempts made, in `adversarial-bench` scenarios | 100% on the bench; deployed attempts are incidents regardless of blocking |
| SSRF / injection / malicious-skill block rate | Blocked / attempted, per the corresponding bench scenarios (SSRF & metadata, browser prompt injection, MCP tool poisoning) | 100% on the bench |
| Child escalation block rate | Attenuation-widening and trust-cap-bypass attempts rejected / attempted (bench scenario: child-agent escalation) | 100%; the `attenuate` proof makes this structural |
| Stale-authorization abort rate | Commits aborted by commit-time revalidation / commits attempted with stale contract, precondition, lease, or policy epoch (bench: stale-approval commit) | 100% of stale attempts aborted |
| Duplicate commit rate | External effects executed more than once for one `idempotency_key` / commit attempts (bench: duplicate retry) | 0 |
| Receipt completeness | Committed effects with a valid Ed25519-signed `Receipt` whose `authorization_witness` resolves / committed effects | 100% |

## 6. Group 4: Resource efficiency

| Metric | Definition | Measurement |
|---|---|---|
| Cold / warm start | Time from `step.execute` to first guest instruction, per backend, cold (no prewarm) vs warm (prewarmed/forked) | Router timers; reported P50/P99 per `BackendProfile.name` |
| Tool-call idle time | Guest wall-clock spent waiting on model inference or approval while holding memory, per episode | cgroup freeze/thaw accounting; drives the idle-pause policy |
| OOM rate | Steps killed for memory over budget / steps executed | Backend exit reporting |
| Memory peak/avg ratio | Peak RSS / time-averaged RSS per step, aggregated per action type | cgroup memory stats; sizes the burst pool (`scheduling.md` §3) |
| Parallel branch density | Concurrent branches sustainable per host while P99 step latency stays within budget | Load-test benchmark per backend |
| Cost per successful rollout | CPU + memory + storage + network cost per successful branch outcome (a rollout = one branch attempt) | Unified `ResourceBudget` accounting divided by surviving-branch successes |

## 7. Measurement infrastructure

All metrics derive from three instrumented sources, so no metric requires
guest cooperation (guests are untrusted and MUST NOT be able to inflate or
suppress measurements):

1. **The causal ledger** — every step, denial, approval, effect phase
   transition, and receipt is a ledger event with a timestamp and actor.
   Groups 1 and 3 are ledger queries. Because the ledger is append-only and
   receipts are signed, capability and security numbers are auditable after
   the fact via `trace.query` and `replay.audit`.
2. **Kernel-side timers and counters** — the Backend Router, DAG service, and
   replay engine time their own operations (fork, rollback, materialize,
   replay). Group 2 latencies come from here, never from guest clocks.
3. **cgroup / backend accounting** — resource usage flows back in
   `ExecutionOutcome.usage` as a `ResourceBudget` and is cross-checked
   against host-side cgroup stats. Group 4 comes from here.

Reporting conventions:

- Latency metrics report P50 and P99, per backend and per workspace size
  bucket; averages alone are not accepted in release reports.
- Rates report numerator, denominator, and window explicitly; a rate without
  its population is not a result.
- Security counts (§5) are absolute, never sampled or extrapolated.

## 8. Benchmarks and conformance

Three suites give these numbers teeth:

- **AgentSandboxBench** (the capability/efficiency suite): fixed task sets
  (starting from `examples/coding-agent-github`-class tasks) with acceptance
  checks, run N-way and single-branch, producing Groups 1, 2, and 4. Runs are
  themselves recorded episodes, so results are auditable via `replay.audit`.
- **adversarial-bench/** (the security suite): the eleven standing attack
  scenarios (malicious dependency credential read, browser prompt injection,
  MCP tool poisoning, SSRF/metadata, child escalation, cross-branch leakage,
  read-only mount bypass, stale-approval commit, duplicate retry
  double-commit, inconsistent snapshot, live replay after world change),
  producing Group 3. Every scenario maps to a mitigation row in
  `threat-model.md` §6; a release MUST pass all scenarios.
- **conformance/** (the protocol suite): verifies that an implementation —
  including third-party backends and connectors — honors the verb families,
  the four invariants, deterministic `check()` ordering, attenuation
  rejection cases, commit-time revalidation, receipt signing, `redact_for`
  behavior, and honest `ReplayClass` declarations. Conformance is what keeps
  the protocol backend-neutral: a backend claims only what it passes.

The bench and conformance suites are release gates and public artifacts:
regressions in any Group 3 metric, or any conformance failure, block release.
Groups 1, 2, and 4 are reported per release with the previous release as
baseline; they inform, rather than gate, unless a target is explicitly set in
the release plan.

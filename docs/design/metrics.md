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

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

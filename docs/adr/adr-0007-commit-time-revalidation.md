# ADR-0007: Commit-Time Revalidation of Every Effect

## Status

Accepted

## Date

2026-04-29

## Context

Between the moment an effect is approved and the moment it is committed,
arbitrary time passes: the agent keeps working, a human sleeps on an approval
queue, a branch waits for sibling branches to finish. In that window the world
drifts (the base branch moves, the target resource changes), the authorization
drifts (the lease expires or is revoked, policy is updated, the principal's
trust level drops), and retries can turn one approved effect into two committed
ones. Durable-authorization research reaches the same conclusion we reached in
incident modeling: a high-risk authorization cannot be a bearer artifact checked
once; it must be bound to subject, operation, full arguments, target and
validity, and re-checked when the durable commit actually happens.

Alternatives considered: trust the approval (status quo elsewhere; rejected —
"approved at time T" says nothing about time T+20min); shorten approval TTLs
aggressively (rejected as the only mechanism — it converts drift into approval
fatigue without removing the race); re-approve on every retry (rejected —
punishes the human for network flakiness the kernel should absorb).

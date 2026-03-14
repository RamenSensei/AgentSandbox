# Threat Model

Status: Living document · Applies to: v0.6 · Last updated: 2026-08-12

## 1. Overview

This document defines what AgentKernel protects, from whom, along which
boundaries, and with which non-negotiable rules. It maps each adversary to
concrete mitigations and to the standing scenarios in `adversarial-bench/`.
The security posture assumes agents will be prompt-injected, dependencies
will be malicious, and guests will be compromised — the design goal is that
none of these events yields credentials, unauthorized external effects, or a
falsified causal record.

## 2. Assets

1. **Credentials** — API tokens, cloud keys, signing keys held by connectors
   and the Secret Broker.
2. **External side-effect authority** — the ability to create PRs, mutate
   databases, send messages, spend money.
3. **The host** — kernel process, host filesystem, other tenants' workloads.
4. **Causal record integrity** — the ledger, receipts, and signatures; the
   system's value collapses if the record can be forged or truncated.
5. **Cross-branch / cross-tenant data** — one branch's or tenant's workspace,
   observations, and secrets from another's reach.

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

## 3. Adversaries

| Adversary | Position | Goal |
|---|---|---|
| Compromised guest | Arbitrary code inside a backend | Escape; steal credentials; reach the host |
| Malicious dependency | Supply chain, runs inside guest with the agent's task | Read tokens; exfiltrate via egress |
| Prompt-injected agent | The agent model itself, steered by hostile content | Misuse *legitimately held* leases; request escalation; leak data |
| Malicious skill / MCP server | Installed tool with its own code and network behavior | Poisoned tool results; harvest inputs; pivot |
| Escalating sub-agent | Spawned principal | Regain authority its parent attenuated away |
| Replaying/duplicating attacker | Network or harness position | Re-submit approved effects; double-commit; exploit stale approvals |

## 4. Trust boundaries

- **Guest ↔ kernel**: the strongest boundary (microVM, gVisor, or OS sandbox
  per `BackendProfile.isolation_strength`). Everything guest-side is
  untrusted, including the agent's own outputs.
- **Kernel ↔ connectors**: connectors are trusted code holding credentials;
  they are part of the TCB and reviewed as such.
- **Principal ↔ principal**: every agent, sub-agent, and tool is a distinct
  `Principal` on its own branch; the boundary is the lease system, not shared
  process context.
- **Branch ↔ branch / tenant ↔ tenant**: no shared writable state; sharing
  happens only through provenance-carrying artifacts and the CAS
  (content-addressed, immutable).
- **Model ↔ policy**: model output crosses into the kernel only as structured
  requests, never as decisions (§5.6).

## 5. Non-negotiables

1. **No raw credentials in guests.** Ever. See `secret-broker.md`. Even a
   fully compromised guest sees placeholders, single-use tokens, results, and
   receipts only.
2. **No ambient authority.** No default access to the Docker socket, host
   home directory, SSH agent socket, cloud metadata endpoint, org-wide
   tokens, or writable host package caches.
3. **Bind mounts are not boundaries.** A "read-only" shared host mount has
   been bypassed in real systems and MUST NOT be treated as a security
   boundary. Prefer copy-in, content-addressed storage, or a mediated
   filesystem, and place true read-only enforcement at a lower layer.
4. **No default inheritance for children.** `Principal::spawn_child` yields
   trust capped at `TrustLevel::Limited` and zero leases; authority arrives
   only through `CapabilityLease::attenuate`, which provably narrows.
5. **eBPF is observation, not isolation.** eBPF is appropriate for
   telemetry, accounting, event capture, and supplementary enforcement; it
   MUST NOT be the sole isolation layer for multi-tenant workloads — that
   remains microVMs, application kernels, or verified OS boundaries.
6. **The LLM never decides policy.** The model MAY explain intent, request
   capabilities, recommend policy, and generate rationales. It MUST NOT issue
   capabilities, judge itself harmless, self-clear a denial, bypass
   deterministic parameter validation, or decide that an effect is
   authorized. Authorization is the deterministic lease check plus the
   effect-broker pipeline, always.

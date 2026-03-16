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

## 6. Mitigations mapped to adversarial-bench scenarios

Each row is a standing scenario in `adversarial-bench/`; a release MUST pass
all of them.

| Scenario | Primary mitigation |
|---|---|
| Malicious dependency reads credentials | No raw credentials in guest (Secret Broker); unique placeholders identify the exfiltrating branch |
| Browser prompt injection | Injected instructions can only produce *requests*; leases and effect approval still gate every external action; suspicious escalation requests are denied with redacted detail |
| MCP tool poisoning | Quarantine-and-promotion pipeline (§7); quarantined servers run as `Quarantined` principals with minimal leases and redacted denials |
| SSRF / metadata endpoint | Egress proxy allow-listing; metadata endpoint is a forbidden ambient channel; `connectors/http` classifies unvouched requests `OpaqueExternal` |
| Child-agent escalation | `spawn_child` trust cap; `attenuate` rejects any widening (`ConstraintWidened`, `UsesExceedParent`, `ExpiryExceedsParent`, `BudgetExceedsParent`) |
| Cross-branch data leakage | Branch-bound leases (`bound_branch`), per-branch workspaces, immutable CAS, artifact-only sharing |
| Read-only mount bypass | Non-negotiable 3: copy-in / CAS materialization instead of shared host mounts |
| Stale-approval commit | Commit-time revalidation: contract hash, preconditions, lease validity, policy epoch (`StaleAuthorization`, `PreconditionFailed` denials) |
| Duplicate retry double-commit | `idempotency_key` dedup at commit; retries return the existing `Receipt` (`DuplicateCommit`) |
| Inconsistent filesystem/process snapshot | Honest `ReplayClass` declarations; the kernel never claims fidelity a backend did not declare |
| Live replay after world change | Live replay guarantees the contract, not the outcome; changed preconditions abort before commit |

## 7. Skill / MCP quarantine-and-promotion

Autonomous skill installation is a large capability gain and a top-tier risk
entry point. Unknown skills and MCP servers MUST NOT receive the primary agent's
filesystem, network, or secret access. The pipeline:

```text
download skill
  → install in a quarantine branch (Quarantined principal, minimal leases)
  → static analysis
  → dynamic run; observe requested capabilities
  → generate a capability manifest
  → test against the manifest
  → pin digest / sign
  → promote to semi-trusted or trusted
```

Promotion raises `TrustLevel` and permits broader (still attenuated) leases;
any post-promotion behavior outside the manifest SHOULD demote the skill back
to quarantine and revoke its leases.

## 8. Denial explanations vs. policy-map leakage

Invariant 4 (machine-readable denials) is in tension with information
discipline: explanations must help a benign agent self-repair, but MUST NOT
leak sensitive host paths, hidden policy details, or a map of the defenses.
Resolution: explanation granularity scales with `TrustLevel`, never
enforcement.

`Denial::redact_for(trust)` implements this. For `trust >=
TrustLevel::Limited` the full denial is returned. Below `Limited`
(`Untrusted`, `Quarantined`):

- `code` and `attempted_operation` are kept;
- `reason` is replaced with `"operation not permitted for this principal"`;
- `safe_alternatives` are kept (they only reveal what the caller may already
  do);
- `requestable_scopes` is emptied (no sketching the policy surface);
- `escalation_allowed` is forced `false`.

Thus a quarantined skill probing the policy learns only that it was denied
and which typed operations it already holds — while the primary agent gets
`reason`, `requestable_scopes`, and `escalation_allowed` sufficient for
autonomous recovery. Denial contents, like everything else, are ledger
entries: probing patterns are visible to detection.

## 9. Residual risks

Stated, not hidden: connector bugs are TCB bugs; a malicious *approved*
contract executes (approval quality is a human/policy problem the kernel can
only make legible); side channels between co-resident guests are bounded by
the chosen backend's isolation class; and denial-of-service within a granted
budget is possible by construction — budgets bound it, they do not prevent it.

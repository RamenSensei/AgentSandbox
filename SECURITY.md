# Security Policy

## Threat model summary

AgentKernel is designed under the assumption that **guest workloads can be fully compromised** — by a malicious dependency, a prompt-injected agent, a poisoned skill or MCP server, or an attacker-controlled tool. The kernel's security posture rests on the following commitments (full details in `docs/design/threat-model.md`):

- **Raw secrets never enter guests.** Guests see placeholders, single-use scoped tokens, connector results, and receipts — never long-lived credentials. Compromise of a guest must not yield an organization token.
- **No ambient authority.** Every action carries an explicit `CapabilityLease` bound to a principal, operation, parameter constraints, branch, expiry, use count, and budget. There are no default-open Docker sockets, host home mounts, SSH agent sockets, or metadata endpoints.
- **Connectors own credentials.** High-value external operations (GitHub, cloud, databases) do not run inside guests; they go through trusted, typed connectors behind the effect broker.
- **Commit-time revalidation.** Approval of an effect is approval of an exact canonical contract. At commit, the kernel re-checks the contract hash, preconditions, lease validity, policy epoch, and idempotency key; stale or duplicated approvals abort.
- **eBPF is observation only.** eBPF is used for telemetry, accounting, and supplementary enforcement. Isolation comes from microVM, gVisor, or vetted OS boundaries — never eBPF alone.
- **Bind mounts are not trusted as security boundaries.** Declared read-only shared mounts are not assumed safe; we prefer copy-in, content-addressed storage, or mediated filesystems, with real enforcement at a lower layer.
- **Sub-agents and tools do not inherit authority.** Delegation is explicit, attenuated, time-bound, branch-bound, revocable, and audited. A child lease can never grant more than its parent.
- **LLM output never authorizes anything.** Model output may express intent, request capabilities, or recommend policy, but capability issuance, parameter validation, and effect authorization are always deterministic kernel decisions.

## Scope

**In scope:**

- Bypasses of any of the four invariants (ambient authority, invisible state transitions, pre-commit irreversible effects, unexplained denials)
- Secret or credential exposure to guest workloads
- Effect broker bypasses: committing external effects without a valid lease, revalidation, or receipt; duplicate commits despite idempotency keys
- Capability escalation, including delegation that amplifies rather than attenuates
- Cross-branch or cross-principal data leakage through kernel-managed state
- Denial responses that leak host paths or policy details beyond the caller's trust level

**Out of scope:**

- Vulnerabilities in the underlying isolation runtimes themselves (Firecracker, gVisor, Kata, the host kernel) — report those upstream
- Attacks requiring a compromised host or kernel control plane
- Quality of agent/LLM decisions within an authorized envelope (a correctly authorized but unwise effect is not a kernel vulnerability)
- Denial of service via legitimately budgeted resource use

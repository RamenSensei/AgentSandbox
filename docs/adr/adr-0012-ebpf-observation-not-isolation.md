# ADR-0012: eBPF for Observation, Not Isolation

## Status

Accepted

## Date

2026-07-08

## Context

The causal ledger needs ground truth below the framework layer: which processes
a Step actually spawned, which files it touched, which network flows it opened,
what it cost. eBPF is the right tool for this — low-overhead tracepoints and
kprobes for process/file/network events, per-cgroup accounting for the unified
CPU/memory/network resource model, and fast attach/detach that matches
step-level scheduling. There is also a persistent temptation to go further and
use eBPF (LSM hooks, socket filters) as the isolation layer itself, avoiding
VM overhead entirely.

We reject that extension for multi-tenant isolation. An eBPF-enforced boundary
shares the host kernel with the workload it confines: any host-kernel
exploit — the steady stream of local-privilege-escalation CVEs — bypasses every
eBPF program on the box, and the verifier plus JIT are themselves recurring
sources of security bugs. Policy expressed as attachable programs is also
fragile against detach/attach races and ordering mistakes in ways a hardware
virtualization boundary is not. The industry consensus embodied in Firecracker,
gVisor and Kata exists for a reason.

Alternatives considered: eBPF-LSM as the primary sandbox (rejected above);
kernel modules for observation (rejected: worse safety and portability than the
eBPF verifier); userspace-only observation via ptrace/FUSE interposition
(rejected as primary: high overhead on hot paths, easy for a root guest to
evade — though it remains the fallback where eBPF is unavailable, e.g. macOS).

## Decision

eBPF is used in AgentKernel for:

- observation: process exec/exit, file access, and network flow events feeding
  the causal ledger and `StateDelta` verification;
- accounting: per-step, per-branch resource usage in the unified
  CPU/memory/network/cost budget model;
- supplementary enforcement: defense-in-depth egress filtering and anomaly
  cutoffs *behind* a primary boundary, never as the boundary.

Multi-tenant isolation relies on microVMs (Firecracker/Kata-class), application
kernels (gVisor), or otherwise verified OS boundaries (Landlock/seccomp/
bubblewrap for low-risk local workloads, per the backend router's risk tiers).
No AgentKernel deployment mode may advertise eBPF-only confinement for
untrusted or multi-tenant workloads. Observation gaps (backends without eBPF)
degrade the recorded `ReplayClass` and ledger fidelity, not the security claim.

## Consequences

Positive:

- The ledger records what actually happened at the OS level, so "no invisible
  state transition" is verified against kernel events, not inferred from
  well-behaved tooling.
- Layered enforcement: an egress anomaly can be cut inside the boundary even
  when the microVM would eventually contain it.

Negative:

- eBPF availability varies by host kernel version and configuration; feature
  detection and graceful degradation add a support matrix.
- Running collectors on the host per guest adds operational complexity to
  backends that would otherwise be pure VMM drivers.

Follow-ups:

- CO-RE builds to tolerate kernel version drift.
- Reconciliation job: diff eBPF-observed file events against reported
  `StateDelta`s and flag divergence as a backend bug.

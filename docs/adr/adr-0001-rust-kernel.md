# ADR-0001: Rust for the Kernel and Control Plane

## Status

Accepted

## Date

2026-02-16

## Context

The kernel is the trust boundary of AgentKernel. Everything the project promises —
no ambient authority, no invisible state transition, no irreversible effect before
commit, no denial without a machine-readable explanation — is enforced by control-plane
code that sits between untrusted guest workloads and the real world. A memory-safety
bug in that layer is not a crash; it is a capability bypass. The kernel also performs
deterministic policy evaluation: given the same `CapabilityLease`, parameters, branch
and clock, `check()` must return the same result on every node and on every replay.
That rules out languages where nondeterminism creeps in easily (GC pauses affecting
timeout races, implicit coercions, prototype pollution).

Alternatives considered:

- **Go.** Attractive for the ecosystem (gVisor is Go) and for team ramp-up. Rejected:
  Go's `interface{}`/reflection-heavy serialization makes canonical hashing of
  `EffectContract` structures harder to keep byte-stable, and the GC is a poor fit
  for a component that must give latency guarantees at step boundaries. Memory safety
  is good but data races remain compile-time-unchecked.
- **TypeScript/Node.** Fastest path to an SDK-shaped prototype. Rejected for the
  kernel: single-threaded event loop is wrong for concurrent branch execution;
  the dependency supply chain is exactly the attack surface (malicious packages
  reading credentials) the project exists to defend against; no story for the
  low-level enforcement glue (Landlock, seccomp, cgroups, eBPF loaders).
- **Rust.** Memory safety without GC, `Send`/`Sync` checked at compile time,
  first-class FFI to kernel enforcement primitives, and the exact ecosystem we
  need already mature: `tokio` for the async control plane, `axum` for the protocol
  surface, `rusqlite` for embedded metadata (see ADR-0002), `ed25519-dalek` for
  Receipt signing, `serde` for canonical, deterministic serialization.

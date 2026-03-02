# AgentKernel

**Git for agent execution · transaction boundary for real-world effects · capability OS for tools**

AgentKernel is an open-source transactional execution kernel for AI agents. It models agent execution as a branchable, replayable, authorizable world-state machine: local execution becomes a versioned state DAG that agents can fork, diff, roll back, and search in parallel, while every action against the real world becomes an explicit transaction that is proposed, precisely authorized, revalidated at commit time, and receipted. Isolation backends (OS sandboxes, gVisor, microVMs, Kubernetes) and world connectors (GitHub, HTTP, MCP) are pluggable; the semantics are the product.

## Motivation

Existing sandboxes used by agents were, for the most part, not designed for agents. MicroVM services, container wrappers, and policy sandboxes are all built on mechanisms — Firecracker, gVisor, Kata, seccomp, bind mounts — that natively understand **VMs, containers, processes, files, and network packets**. They do not understand **tasks, steps, branches, capabilities, and external effects**, which is the vocabulary agents actually operate in.

The consequences show up everywhere:

- A VM snapshot can roll back a filesystem, but it cannot un-send an email, un-push a commit, or un-delete a cloud resource. OS snapshots are not a transaction for the external world.
- Permissions are ambient and boolean ("allow network", "inject `GITHUB_TOKEN`") rather than scoped, time-bound, and attenuable leases on specific operations.
- Failures come back as `Permission denied` / `exit code 1`, which forces a human interruption instead of enabling agent self-repair.
- Multi-agent setups share a mutable workspace, a token, and a network namespace, so a compromised tool inherits everything.

Making another faster microVM service does not fix any of this. AgentKernel instead owns the agent-native semantic layer — protocol, state model, capability model, effect transactions, causal ledger — and treats existing isolation mechanisms as interchangeable backends.

## Speculate locally, commit globally

The kernel enforces a hard distinction between two worlds:

- **Local world**: files, processes, tool sessions, browser state inside a branch. Here the agent is encouraged to be bold — fork multiple speculative branches, try competing fixes in parallel, and discard or roll back failures cheaply. Every step produces an immutable delta in the state DAG.
- **External world**: anything that leaves the sandbox — a PR, a message, a database write, a payment. These cannot be undone by a snapshot, so they must pass through the effect broker: precise authorization bound to canonical arguments, commit-time revalidation, and a non-repudiable signed receipt.

## Core objects

| Object | Definition |
| --- | --- |
| `Episode` | One long-running task; the root of an execution history. |
| `Step` | One decision-and-execution unit; produces a delta and a ledger entry. |
| `Branch` | A speculative world branch that can be forked, diffed, merged, or discarded. |
| `Principal` | An agent, sub-agent, or tool as a first-class identity with a trust level. |
| `CapabilityLease` | Time-bound, budgeted, attenuable authority over constrained operations; delegation only ever attenuates. |
| `Observation` | A structured observation returned to the agent, including machine-readable denials. |
| `Effect` | A proposed change to the real world: `PendingEffect` carrying an `EffectContract`, resolving to a `Receipt`. |
| `Receipt` | Signed, non-repudiable proof of a committed effect: who, what, canonical arguments hash, policy version, external response digest. |

Effects are honestly classified by reversibility: `pure`, `local_reversible`, `remote_reversible`, `compensatable`, `irreversible`, `opaque_external` (unknown semantics; treated as irreversible and maximally restricted).

## Architecture

```text
┌─────────────────────────────────────────────────────────┐
│              Agent / Harness / Human                    │
│ objective · action · intent hint · approval             │
└──────────────────────────┬──────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────┐
│              Agent Execution Protocol                   │
│ Episode · Step · Branch · Principal · Capability        │
│ Observation · Effect · Receipt · ReplayClass            │
└──────────────────────────┬──────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────┐
│             Trusted Semantic Kernel                     │
│                                                         │
│ Identity & Policy      State DAG        Effect Broker   │
│ Capability Compiler    Causal Ledger    Secret Broker   │
│ Backend Router         Scheduler        Replay Engine   │
└───────────────┬────────────────┬────────────────┬───────┘
                │                │                │
┌───────────────▼──────┐ ┌───────▼────────┐ ┌─────▼───────────┐
│ Local OS Sandboxes   │ │ gVisor/microVM │ │ World Connectors│
│ WASI / srt / nono    │ │ Kata / GUI VM  │ │ GitHub/DB/Cloud │
└──────────────────────┘ └────────────────┘ └─────────────────┘
```

External effects follow a single lifecycle: **propose → canonicalize → prepare → approve → commit-time revalidation → commit → signed receipt**. Replay comes in three deliberately distinct modes — **audit** (play back recorded observations, never re-execute), **sandbox** (re-execute local code with recorded inputs substituted), and **live** (re-execute the same effect contracts against the current world; guarantees the contract, not the outcome). Backends declare per-layer `ReplayClass` guarantees rather than a vague "supports snapshot" flag.

## Invariants

1. **No ambient authority.** Every action carries an explicit lease.
2. **No invisible state transition.** Every step produces a delta and a ledger entry.
3. **No irreversible effect before commit.** External effects go through the broker.
4. **No denial without a machine-readable explanation.**

## Quickstart

```sh
# Build the whole workspace
cargo build --workspace

# Run the end-to-end example: a coding agent that forks branches,
# runs tests, and prepares a draft PR through the GitHub effect broker
cargo run -p coding-agent-github
```

The `ui/` directory contains the timeline, branch graph, policy, and receipt views; it includes a demo mode that replays a recorded episode without a live kernel. See `ui/README.md`.

## Repository layout

```text
agent-kernel/
├── protocol/            # Agent Execution Protocol definitions (backend-neutral)
├── kernel/
│   ├── core/            # ak-core: semantic types, no I/O
│   ├── identity/        # principals, trust levels, delegation
│   ├── policy/          # deterministic policy engine, machine-readable denials
│   ├── state_dag/       # versioned world-state DAG and adapters
│   ├── effect_broker/   # external effect transactions and receipts
│   ├── causal_ledger/   # intent → decision → effect causal chain
│   ├── scheduler/       # step-level budgets, backend routing, prewarm
│   └── api/             # kernel API surface
├── backends/            # local, cube, forkd, gvisor, kubernetes
├── connectors/          # github, http, mcp
├── sdk/                 # python, typescript
├── ui/                  # timeline, branch_graph, policy_view, receipt_view
├── conformance/         # protocol conformance suite
├── adversarial-bench/   # security/abuse scenario benchmark
├── examples/
│   └── coding-agent-github/
└── docs/                # design, adr, devlog
```

## Documentation

- Design documents: `docs/design/`
- Architecture decision records: `docs/adr/`
- UI and demo mode: `ui/README.md`

## Status

Version 0.6 (protocol version "0.6"). Pre-1.0: APIs, the protocol, and on-disk formats are unstable and may change between minor releases.

## License

Apache-2.0. See [LICENSE](LICENSE).

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to contribute and [SECURITY.md](SECURITY.md) for the threat model and vulnerability disclosure process.

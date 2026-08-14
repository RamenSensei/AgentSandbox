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

# Run the end-to-end example: a coding agent that creates an episode,
# executes sandboxed steps, forks/diffs/merges branches, and prints the
# causal trace
cargo run -p ak-example-coding-agent --bin coding-agent

# Run the adversarial security bench (sandbox escapes, lease races,
# budget bypasses, self-merge) and write a JSON report
cargo run -p ak-adversarial-bench -- --report target/adversarial-report.json

# Run the agent utility bench: measures the *enablement* side — how far
# an autonomous agent gets inside one pre-approved capability envelope
# (envelope autonomy, autonomous denial recovery rate, fork/search,
# causal introspection, effect transactions)
cargo run -p ak-agent-utility-bench -- --report target/utility-report.json

# Serve the HTTP control plane (unauthenticated mode is loopback-only
# and must be opted into explicitly; use --auth-config in production).
# --http-read-safe enables the built-in observation plane: GETs to these
# domains execute inline in one step; everything else needs the effect
# approval path. --mcp-server spawns an MCP server as a confined,
# low-trust tool process (OS sandbox, scrubbed env, no network) and
# registers it as a connector.
cargo run -p ak-api --bin agent-kernel-server -- --insecure-no-auth \
    --http-read-safe docs.rs --http-read-safe '*.wikipedia.org' \
    --mcp-server 'notes=python3 notes_server.py'

# Bootstrap each durable identity once (admin-only with authentication).
curl -X POST http://127.0.0.1:7466/v1/principals \
  -H 'content-type: application/json' \
  -d '{"id":"pr-00000000-0000-4000-8000-000000000001","kind":"agent","display_name":"coding-agent","trust":"standard"}'
```

### The agent loop, without bookkeeping

The runtime is built so a model spends its reasoning on the task, not on
control-plane ceremony:

- **`POST /v1/steps/execute_auto`** — send just the action kind; the
  kernel resolves (or mints) the lease and clamps the budget.
- **`POST /v1/capabilities/compile_envelope`** — approve a capability
  *space*, not one command at a time: request everything a task needs in
  one call, get leases for the allowed subset up front and structured
  denials (with the exact scopes to escalate) for the rest.
- **Persistent process sessions** — `process_start` a dev server, REPL or
  database; later steps write its stdin, tail its logs from a byte offset
  (`process_logs`), signal and query it. Sessions are branch-scoped and
  die with the branch.
- **Observation vs. effect plane** — `http_read` of an allowlisted domain
  and manifest-vouched `Pure` MCP tools run inline; external *writes* go
  through propose → prepare → approve → commit with signed receipts.
- **MCP servers are low-trust tool processes** — spawned inside the
  verified OS sandbox with a scrubbed environment and a private scratch
  cell, never as extensions of the control plane; signed manifests vouch
  per-tool effect classes.
- **Transparent egress** — grant egress domains in the policy and
  `pip install` / `cargo fetch` / `git fetch` / `curl` work unmodified;
  SOCKS-aware SSH and database clients use the injected `ALL_PROXY`.
  Authenticated HTTP and SOCKS5 share one policy listener, so domain globs,
  proxy-side DNS, SSRF guards, the port allowlist, revocation and byte
  metering cannot diverge by protocol. The sandbox otherwise stays offline.
  On Linux
  the bwrap sandbox keeps its unshared network namespace: the
  `ak-egress-fwd` forwarder (probe-verified at startup) bridges an
  in-namespace listener to the proxy's Unix socket, so the proxy stays
  the *only* route out — hosts where the probe fails keep egress off.
- **Linux tree-wide resource enforcement** — when a delegated cgroup v2
  parent passes an end-to-end probe, aggregate CPU time, `memory.max` and
  `pids.max` cover the complete shell/session tree, including daemonized
  descendants. CPU, peak memory, OOM kills and rejected forks come from
  kernel counters; other hosts retain portable per-process backstops.
- **`POST /v1/branches/{id}/explore`** — server-side parallel candidate
  search: fork N branches, run candidates + an evaluator concurrently,
  merge the winner, discard the losers, one call.
- **`GET /v1/raw/{hash}`** — page or grep the *full* output of any step;
  observations carry a distilled head **and tail** plus the causal error
  line, with the whole blob a hash away.
- **Denials are recovery plans** — every runtime denial names the exact
  scope to request (`requestable_scopes`) and whether a human is needed.
- **Risk-routed backends with state sync** — the policy rule's
  `risk_weight` sets each step's isolation floor; configured backends
  (gVisor, forkd, Cube, Kubernetes) are routed to when the floor demands
  them. forkd and Cube adapters **sync state**: the base state is pushed
  into the remote sandbox (content-addressed, diffs only), the observed
  file delta is pulled back, validated against the step's writable
  prefixes, and snapshotted — a remote step is a *real* state transition.
  Live trees are re-listed before sync-in; forks use native CoW only from a
  quiescent tree whose complete manifest is freshly verified against the
  committed state. Backends without sync are recorded as audit-only
  excursions, never as pretended local state transitions.

### Authentication

The HTTP API requires `Authorization: Bearer <token>` on every route
except `/healthz` when started with `--auth-config <file>`:

```yaml
enabled: true
tokens:
  - token_sha256: "<sha256 hex of the token>"
    principal: "pr-<uuid>"
    roles: [agent]          # agent | approver | admin
```

Body principals must match the authenticated principal (admins may act
for anyone), effect approval requires the `approver` role, and
episode/branch/effect operations enforce resource ownership. The server
refuses to listen on a non-loopback address without an auth config.

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
├── adversarial-bench/   # security/abuse scenario benchmark (restriction side)
├── agent-utility-bench/ # agent enablement benchmark (autonomy metrics)
├── examples/
│   └── coding-agent-github/
└── docs/                # design, adr, devlog
```

## Documentation

- Design documents: `docs/design/`
- Architecture decision records: `docs/adr/`
- UI and demo mode: `ui/README.md`

## Status

Version 0.8 (protocol version "0.8"). Pre-1.0: APIs, the protocol, and on-disk formats are unstable and may change between minor releases.

## License

Apache-2.0. See [LICENSE](LICENSE).

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to contribute and [SECURITY.md](SECURITY.md) for the threat model and vulnerability disclosure process.

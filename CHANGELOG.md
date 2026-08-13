# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Until 1.0.0, minor releases may contain breaking changes to APIs, the protocol,
and on-disk formats.

## [Unreleased]

Enablement release: the development focus shifts from richer governance
semantics to a high-throughput, connected, branchable **agent execution
environment** — the runtime a strong agent actually wants to work in.

### Added
- **Observation/effect plane split on the main execution path.**
  `HttpRead` and `McpInvoke` now execute through `Kernel::execute_step`
  instead of being declared-but-dead: a guard-passing, allowlisted GET (or
  a manifest-vouched `Pure` MCP tool) runs **inline** in one step — no
  proposal, no approval — with the full response body in the raw store;
  anything else automatically becomes a proposed effect on the
  transactional path.
- **Per-invocation effect classification.**
  `Connector::classify_operation(operation, arguments)` runs **before**
  contract creation, so an allowlisted `http.get` carries `Pure` in its
  contract and commits straight from `Prepared` — reads no longer queue
  behind the human-approval path reserved for opaque external writes.
- **Persistent process sessions** in the local backend:
  `process_start` / `process_stdin` / `process_logs` / `process_signal` /
  `process_status` actions. A started process (dev server, REPL, database,
  watcher) outlives its step, runs under the same verified OS sandbox with
  piped stdin, and exposes an offset-based incremental log cursor
  (capped ring buffer with honest eviction offsets). Sessions are
  branch-scoped: invisible to sibling branches, killed on branch discard,
  never inherited by forks; such steps are recorded `AuditOnly`.
- **Automatic lease resolution**: `POST /v1/steps/execute_auto` (and
  `Kernel::execute_step_auto`) takes just an action kind — the kernel
  finds the narrowest active lease or mints one via policy, clamps the
  budget into the lease envelope, and reports which lease was used.
- **Autonomy envelopes**: `POST /v1/capabilities/compile_envelope` (and
  `Kernel::compile_envelope`) requests every capability a task needs in
  one call, before the first step. Policy-allowed items mint leases
  immediately — the same leases `execute_auto` resolves, so the task then
  runs with zero per-step authorization ceremony; items needing a human
  or refused come back as structured denials with requestable scopes.
  Explicit partial autonomy instead of discovering scope gaps one denial
  at a time, mid-task. Both SDKs gained `compile_envelope`.
- **Server-side exploration**: `POST /v1/branches/{id}/explore` forks one
  branch per candidate, runs candidates + evaluator concurrently under a
  parallelism cap with auto-leases, supports early-stop, merges the winner
  and discards losers — one call instead of dozens of client-orchestrated
  RPCs.
- **Raw output access**: `GET /v1/raw/{hash}` with `offset`/`limit`
  pagination and `grep` line search over any recorded output blob. Both
  SDKs gained `fetch_raw`/`grep_raw` and `execute_step_auto`.
- **Out-of-the-box observation plane**: `KernelConfig.http`
  (`read_safe_domains`, `max_response_bytes`) registers the HTTP connector
  at `Kernel::open`; `agent-kernel-server --http-read-safe <glob>` enables
  it from the CLI.
- **Transparent egress proxy** in the local backend: a step whose compiled
  confinement grants egress domains gets standard `HTTP_PROXY`/`HTTPS_PROXY`
  environment pointing at a loopback proxy with a **per-step bearer token** —
  `pip install`, `cargo fetch`, `npm install`, `git fetch` and `curl` work
  unmodified, no per-tool connectors. The proxy enforces, per connection:
  token auth (407 without it), the step's `*`-glob domain allowlist, SSRF
  guards (literal IPs refused; every resolved address vetted and the
  connection pinned to it), a port allowlist (default 80/443), and byte caps
  metered into the step's `network_bytes` budget. CONNECT tunnels pass TLS
  through end-to-end; the proxy never terminates TLS. On macOS the Seatbelt
  profile opens **only** the proxy's loopback port, making it the sole route
  out; under bwrap (unshared netns, host loopback unreachable) egress stays
  **off** — honest fail-closed, never a silent bypass — until an
  in-namespace forwarder lands. Process sessions keep their egress grant
  until they die; the grant token is revoked the moment the session ends.
- `ak_core::net`: shared guest-network guard (`is_forbidden_ip` — loopback,
  RFC1918, link-local/metadata, CGNAT, unique-local, v4-mapped v6) now used
  by both the HTTP connector and the egress proxy, so every egress path
  refuses the same address ranges.
- `ak-agent-utility-bench`: the enablement-side benchmark. Measures how far
  an autonomous agent gets inside one pre-approved capability envelope:
  envelope autonomy (steps per lease request, zero human interventions),
  autonomous denial recovery rate across five structured denial kinds,
  fork/search effectiveness (parallel candidate fixes, winner selection),
  causal introspection without shell spelunking, and exactly-once effect
  transactions with signed receipts. Runs in CI next to the adversarial
  bench with an uploaded JSON report.

### Changed
- **Shell steps are metered honestly.** The local backend reaps every shell
  child with `wait4`: `usage.cpu_ms` is now real user+system CPU time and
  `usage.memory_bytes` the real peak RSS (platform-normalized), replacing
  the wall-clock and captured-output-bytes proxies — a sleeping process no
  longer bills CPU, and memory reflects the actual footprint. Timeout kills
  now take down the child's whole **process group** (the child spawns as a
  group leader), so a sandbox wrapper's descendants can no longer outlive
  the step; killed runs still report their real usage and partial output.
  Budgets an operator can trust are what make long unattended autonomy
  grantable. (File and process-session operations, which reap no child,
  keep the previous approximations.)
- **Observations distill head + tail** (2 KiB + 1 KiB): test summaries and
  final errors no longer vanish. Failures scan the whole stream for the
  causal line (`error[…]`, `panic`, `Traceback`, …) instead of taking
  stderr line one, and carry an `output_tail`.
- **Denials are recovery plans**: unknown-lease, lease-check,
  budget-envelope, consume-race and approval-required denials all carry
  concrete `requestable_scopes` (operation + parameter sketch +
  `requires_human`) so a benign agent can unblock itself without a human.
- **Snapshots are incremental and tiered.** Cache/scratch components
  (`node_modules`, `target`, `.venv`, `__pycache__`, sandbox scratch, …)
  stay out of manifests and survive materialization, so branch history
  costs track the step's change, not the workspace size; a per-workspace
  stat cache (with a git-style racy-clean guard) skips re-reading
  stat-unchanged files on every step.
- `TraceQuery` actions now parse their query string
  (`kind=… limit=… step=… branch=… principal=…`) instead of ignoring it.
- Linux bwrap sandbox shadows `/home`, `/root` and `/run` with tmpfs on
  top of the read-only rootfs: agent code can no longer read the service
  user's home or runtime sockets (first slice of the minimal-rootfs work).

### Security
- **MCP servers run as confined, low-trust tool processes.**
  `McpGateway::spawn` clears the child environment down to `PATH` — an MCP
  server no longer inherits the embedder's tokens, keys or `HOME`;
  `spawn_with(SpawnOptions)` grants exactly what a server needs (env vars,
  cwd, sandbox wrapper argv). `KernelConfig.mcp` (and
  `agent-kernel-server --mcp-server name=command…`) spawns servers at
  `Kernel::open` inside the verified OS sandbox via
  `ak_backend_local::sandbox::tool_wrapper`: reads and writes confined to a
  private scratch cell under `data_dir/mcp/<name>`, no network, `HOME` and
  `TMPDIR` inside the cell, and the Seatbelt profile stored *outside* the
  cell so a server can never rewrite its own rules. Hosts without a
  verified sandbox refuse to spawn (fail closed) unless the server setup
  opts out explicitly. Signed manifests (`manifest_file` +
  `manifest_public_key_hex`) vouch per-tool effect classes; without one,
  every tool classifies `OpaqueExternal` and only runs through the
  approval path.

## [0.7.0] - 2026-08-12

Security-focused release addressing the external review (AK-001 … AK-012).

### Added
- `ak-adversarial-bench` is now a runnable binary: 7 in-process abuse
  scenarios with a JSON report and nonzero exit on failure.
- `ak-example-coding-agent` (`coding-agent` binary): end-to-end episode
  with leased steps, fork/compare/merge/diff and a trace summary.
- Remote backends (AK-009): cube/forkd/gvisor/kubernetes transmit the
  compiled confinement and budget on every exec, enforce https off
  loopback, cap response bodies, validate remote ids, pin the k8s image,
  and never fabricate network accounting.

### Security
- **Local backend (AK-001):** shell steps now run inside a probe-verified OS
  sandbox — bubblewrap on Linux, Seatbelt (`sandbox-exec`) on macOS — with a
  deny-default profile: reads/writes limited to the compiled workspace
  prefixes, all direct network egress denied. Hosts without a verified
  sandbox fail closed unless the operator opts out explicitly;
  `BackendProfile::isolation_strength` now reflects verified capability.
- **HTTP control plane (AK-002):** bearer-token authentication with SHA-256
  digest comparison in constant time; body principals must match the
  authenticated principal (admin excepted); effect approval requires the
  `approver` role and records the authenticated approver; episode, branch
  and effect operations enforce resource ownership; the server refuses
  non-loopback listen addresses without an auth config, and unauthenticated
  loopback mode must be opted into with `--insecure-no-auth`.
- **Effect broker (AK-003/AK-007):** commit performs an atomic
  `approved → committing` claim before any external call, idempotency keys
  are unique, duplicate commits return the original receipt, and in-doubt
  effects (crash between external success and receipt persistence) are
  resolved through a connector idempotency probe (`/v1/effects/recover`)
  or an explicit operator verdict (`/v1/effects/{id}/resolve`).
- **Leases and budgets (AK-004/AK-005):** lease uses are consumed by an
  atomic conditional update; budgets are reserved atomically before
  execution and settled after; budget accounts are per-episode; action
  budgets must fit inside the lease budget envelope.
- **HTTP connector (AK-008):** SSRF defense now resolves DNS and refuses
  loopback/RFC1918/link-local/ULA/metadata answers, pins the vetted IP for
  the actual connection (no rebinding window), and re-vets every redirect
  hop.
- **Secrets (AK-012):** the secret vault and receipt-signing seed are sealed
  at rest with ChaCha20-Poly1305; the sealing key lives outside the data
  dir (`AK_VAULT_KEY` env or a 0600 key file) and legacy plaintext files
  migrate transparently.
- **Replay (AK-011):** sandbox replay re-evaluates current policy for the
  recorded actor and re-executes under the compiled confinement in the same
  fail-closed sandboxed backend as live execution.

### Fixed
- **State DAG (AK-010):** self-merge is rejected instead of permanently
  locking the branch; multi-statement mutations are transactional; CAS
  reads verify the content hash and fail on corruption; CAS temp files are
  collision-free under concurrency.
- **Restart recovery (AK-006):** episode metadata (creator, objective, root
  branch) is persisted in the DAG database and restored by `Kernel::open`,
  so the API keeps serving episodes across restarts.
- TypeScript SDK: per-request `AbortController` (a timeout no longer
  cancels unrelated requests) with timer cleanup and a 30 s default.
- Python SDK: `HTTPError` bodies are closed (no `ResourceWarning`) and the
  default timeout is 30 s.

### Changed
- `protocol/openapi.yaml` regenerated to match the implemented router
  exactly (paths, request/response shapes, status codes, bearer auth);
  SDKs and spec now version-align with the workspace (0.6.x → 0.7.x line).
- CI gates hardened: `cargo fmt --check`, clippy `-D warnings`, rustdoc
  `-D warnings`, `cargo audit`, OpenAPI validation, pytest with
  `ResourceWarning` as error, UI asset smoke.

## [0.6.0] - 2026-08-10

### Added
- `adversarial-bench`: scenario suite exercising the security invariants, including
  malicious dependency credential read (guest holds no raw token), SSRF against
  cloud metadata endpoints through the HTTP connector, duplicate-commit retry
  against idempotency keys, stale-approval commit after base-branch movement,
  child-agent capability escalation attempts, and cross-branch data leakage probes.
- Three replay modes exposed through the protocol and `ak-api`: `replay.audit`
  (play back recorded observations, no re-execution), `replay.sandbox` (restore
  state and re-execute local code with recorded time/randomness/DNS/model inputs
  substituted), and `replay.live` (re-execute the same effect contracts against
  the current world).
- Per-backend `ReplayClass` declarations (`audit_only`, `filesystem_only`,
  `process_and_filesystem`, `framework_host_calls`, `browser_profile`); the
  kernel classifies every step and refuses replay modes a step cannot honor.
- Replay divergence reporting: sandbox replays emit a structured diff of any
  observation that departs from the recording.
- `ui/`: receipt view and replay timeline, plus a demo mode replaying a recorded
  episode without a live kernel.

### Changed
- Protocol version bumped to "0.6"; `EffectContract` preconditions are now
  canonicalized before hashing so approval hashes are stable across SDKs.
- `Denial` detail is now redacted by caller `TrustLevel`: quarantined principals
  receive the code and safe alternatives but not scope sketches or reasons.

### Fixed
- Effect broker no longer accepts an approval whose `policy_epoch` predates a
  policy change on the same branch (caught by the stale-approval bench scenario).
- `ReplayClass` ordering bug that allowed sandbox replay of `audit_only` steps.

## [0.5.0] - 2026-07-06

### Added
- `sdk/python` and `sdk/typescript`: first-party SDKs covering episodes, steps,
  branch fork/diff/merge/discard, capability requests, effect
  propose/prepare/commit, and trace queries.
- `conformance/`: protocol conformance suite that any backend or connector must
  pass, including lease attenuation, denial shape, effect lifecycle ordering,
  and receipt completeness checks.
- `trace.query` API over the causal ledger: agents can ask what a step changed,
  which capability an external request used, and which irreversible effects
  exist since a checkpoint.
- Delegation API: explicit, attenuated, time-bound, branch-bound, revocable
  leases for sub-agents and tools.

### Changed
- `ExecutionOutcome` now includes `replay_class` and unified resource usage
  (CPU, memory, tokens, network, cost) per step.
- Observations are returned as structured, incremental summaries with full logs
  available via `trace.query`, instead of raw stdout streams.

### Fixed
- Branch discard now revokes all leases bound to the branch instead of letting
  them expire.

## [0.4.0] - 2026-06-01

### Added
- `kernel/scheduler`: step-level cgroup allocation, burst memory budgets, idle
  pause, branch fan-out budgets, and intent-aware prewarm hints (hints affect
  scheduling only, never authorization).
- Backend adapters: `backends/local` (bubblewrap/sandbox-exec OS sandboxes),
  `backends/cube` (microVM server), `backends/forkd` (warm-fork CoW branching),
  `backends/gvisor`, and an experimental `backends/kubernetes` adapter.
- Backend router: selects the lowest-cost backend satisfying a step's risk,
  compatibility, and replay requirements; supports promotion/demotion between
  backends within an episode.

### Changed
- `Backend` trait split into provisioning and execution halves so adapters can
  share warm pools.
- Resource budgets unified across CPU, memory, tokens, network, and cost in
  `ResourceBudget`.

### Fixed
- Fork of a branch with live processes now records `processes_started` in the
  child delta instead of silently dropping process state.

## [0.3.0] - 2026-05-04

### Added
- `kernel/effect_broker`: full external-effect lifecycle — propose →
  canonicalize → prepare → approve → commit-time revalidation → commit →
  signed receipt — with `EffectClass` classification (`pure`,
  `local_reversible`, `remote_reversible`, `compensatable`, `irreversible`,
  `opaque_external`) and compensation support.
- `connectors/github`: typed connector for repository metadata reads, branch
  creation, draft pull requests, and issue/PR comments; merge, settings, and
  admin operations are denied by default. Credentials live in the connector,
  never in guests.
- `connectors/http`: mediated egress with per-domain policy; GET is not assumed
  pure — connectors declare operation semantics.
- Secret broker: connector-held credentials, short-lived single-use tokens, and
  placeholder substitution for guests.
- Signed `Receipt` recording principal, operation, canonical arguments hash,
  target resource, branch/step, policy version, authorization witness, external
  response digest, and commit timestamp.
- `examples/coding-agent-github`: end-to-end demo — fork three fix branches,
  run tests, select the best, prepare a draft PR, human approves the exact
  contract, commit with base-SHA revalidation.

### Changed
- `PendingEffect` phases are now an explicit typed state machine
  (`Proposed`/`Prepared`/`Approved`/`Committed`/`Aborted`/`Compensated`).

### Fixed
- Canonicalization now sorts JSON object keys recursively so semantically equal
  contracts hash identically.

## [0.2.0] - 2026-04-06

### Added
- `kernel/policy`: deterministic typed policy engine over operations, parameter
  constraints (`equals`, `one_of`, `glob`, `prefix`, `max`, `forbidden`), path
  and domain policy, and per-branch escalation rules.
- Machine-readable `Denial` with `safe_alternatives` and `requestable_scopes`,
  so agents can self-repair or request a narrower temporary capability instead
  of interrupting a human.
- Trust-scoped redaction of denial explanations by principal `TrustLevel`.
- `kernel/identity`: `Principal` model for agents, sub-agents, and tools;
  `CapabilityLease` with expiry, use counts, budgets, branch binding, and
  world-state preconditions.
- Temporary capability request flow (`capability.request`) with optional human
  approval.

### Changed
- All kernel entry points now require an explicit lease; the ambient default
  lease from 0.1.0 was removed (invariant: no ambient authority).

### Fixed
- Glob constraint matching no longer treats an empty pattern as match-all.

## [0.1.0] - 2026-03-09

### Added
- `protocol/`: initial Agent Execution Protocol draft — `episode.*`, `step.*`,
  `branch.*`, `capability.*`, `effect.*`, `trace.*`, `replay.*` surfaces —
  defined independently of any backend.
- `kernel/core` (`ak-core`): semantic vocabulary — `Episode`, `Step`, `Branch`,
  `Principal`, `CapabilityLease`, `Observation`, `Effect`, `Receipt` — with no
  I/O.
- `kernel/state_dag` MVP: content-addressed workspace state, immutable
  per-step `StateDelta`, branch fork/diff/rollback/discard, and audit replay
  of recorded observations.
- `kernel/causal_ledger` MVP: append-only chain from objective through model
  response, capability request, policy decision, tool invocation, state delta,
  and observation.

[Unreleased]: https://github.com/agent-kernel/agent-kernel/compare/v0.6.0...HEAD
[0.6.0]: https://github.com/agent-kernel/agent-kernel/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/agent-kernel/agent-kernel/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/agent-kernel/agent-kernel/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/agent-kernel/agent-kernel/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/agent-kernel/agent-kernel/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/agent-kernel/agent-kernel/releases/tag/v0.1.0

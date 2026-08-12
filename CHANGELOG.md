# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Until 1.0.0, minor releases may contain breaking changes to APIs, the protocol,
and on-disk formats.

## [Unreleased]

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

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Until 1.0.0, minor releases may contain breaking changes to APIs, the protocol,
and on-disk formats.

## [Unreleased]

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

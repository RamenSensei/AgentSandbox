# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Until 1.0.0, minor releases may contain breaking changes to APIs, the protocol,
and on-disk formats.

## [Unreleased]

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

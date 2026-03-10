# Architecture Decision Records

Architecture Decision Records (ADRs) capture the significant engineering
decisions behind AgentKernel: the forces at play, the alternatives we rejected,
and the consequences we accepted. Each record is immutable once Accepted — if a
decision changes, a new ADR supersedes the old one and both link to each other.
New ADRs are proposed as pull requests using the format below (Status, Date,
Context, Decision, Consequences), numbered sequentially, and move from Proposed
to Accepted after maintainer review. Decisions that gate the four kernel
invariants (no ambient authority, no invisible state transition, no
irreversible effect before commit, no denial without a machine-readable
explanation) require sign-off from a security maintainer.

## Index

| ADR | Title | Status | Date |
|-----|-------|--------|------|
| [ADR-0001](adr-0001-rust-kernel.md) | Rust for the Kernel and Control Plane | Accepted | 2026-02-16 |
| [ADR-0002](adr-0002-sqlite-single-node-metadata.md) | SQLite for Single-Node Metadata | Accepted | 2026-02-25 |
| [ADR-0003](adr-0003-content-addressed-workspace.md) | Content-Addressed Workspace Instead of Bind Mounts | Accepted | 2026-03-10 |
| [ADR-0004](adr-0004-leases-not-booleans.md) | Capability Leases, Not Boolean Allow-Lists | Accepted | 2026-03-24 |
| [ADR-0005](adr-0005-intent-hints-never-authorize.md) | Intent Hints Never Authorize | Accepted | 2026-04-02 |
| [ADR-0006](adr-0006-effect-class-taxonomy.md) | Six-Class Effect Reversibility Taxonomy | Accepted | 2026-04-15 |
| [ADR-0007](adr-0007-commit-time-revalidation.md) | Commit-Time Revalidation of Every Effect | Accepted | 2026-04-29 |
| [ADR-0008](adr-0008-three-replay-modes.md) | Three Replay Modes with Per-Backend ReplayClass | Accepted | 2026-05-13 |
| [ADR-0009](adr-0009-artifact-merge-only.md) | Branch Merge Is Artifact Merge Only | Accepted | 2026-05-27 |
| [ADR-0010](adr-0010-connectors-own-credentials.md) | Connectors Own Credentials; Guests Never See Them | Accepted | 2026-06-10 |
| [ADR-0011](adr-0011-trust-scoped-denial-redaction.md) | Trust-Scoped Redaction of Machine-Readable Denials | Accepted | 2026-06-24 |
| [ADR-0012](adr-0012-ebpf-observation-not-isolation.md) | eBPF for Observation, Not Isolation | Accepted | 2026-07-08 |

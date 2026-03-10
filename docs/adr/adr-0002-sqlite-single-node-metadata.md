# ADR-0002: SQLite for Single-Node Metadata

## Status

Accepted

## Date

2026-02-25

## Context

The kernel persists metadata: state DAG nodes and deltas, CapabilityLeases and
their attenuation lineage, PendingEffects with phase transitions, Receipts, the
causal ledger, and policy epochs. Blobs (workspace file content) go to the
content-addressed store (ADR-0003), so the metadata store holds small structured
rows with strong consistency requirements — a lease decrement, an effect phase
transition and a ledger append must be atomic, or we violate "no invisible state
transition".

The dominant deployment for a pre-1.0 project is a developer laptop or a single
server running a coding agent. That deployment must be zero-configuration: no
daemon to provision, no connection strings, no migration of operational burden
onto users evaluating the project.

Alternatives considered:

- **PostgreSQL always.** Best-in-class consistency and the obvious cluster answer,
  but requiring a running Postgres to try a local sandbox kernel kills adoption
  and complicates test isolation. Rejected as the default; retained for cluster mode.
- **Embedded KV store (redb/sled/RocksDB).** Fast and embedded, but we would
  reimplement multi-row transactions, secondary indexes and ad-hoc queries the
  causal ledger needs ("which lease authorized this receipt?"). Schema migration
  tooling is also weaker. Rejected.
- **SQLite via `rusqlite` with the bundled feature.** Embedded, transactional,
  queryable with plain SQL, battle-tested WAL mode giving concurrent readers with
  a single writer — which matches the kernel's design of a single serialized
  commit path plus many read-only ledger queries.

## Decision

Single-node metadata is stored in SQLite, accessed through `rusqlite` with the
`bundled` feature (pinned SQLite version, no system dependency), in WAL mode
with `synchronous=NORMAL` and foreign keys enforced. All kernel writes go through
one writer task; effect phase transitions, lease mutations and ledger appends
that belong to one step commit in a single SQLite transaction.

PostgreSQL is reserved for cluster mode behind the same storage trait; no SQL
in kernel logic may use SQLite-only features without a Postgres equivalent noted
in the schema module.

## Consequences

Positive:

- `agentkernel serve` works with zero setup; tests run against a temp file or
  `:memory:`; a whole episode's audit trail is one copyable file.
- WAL gives cheap concurrent audit/ledger reads while a commit is in flight.
- Bundled build pins the exact SQLite version, so replay of ledger queries is
  reproducible across hosts.

Negative:

- Single-writer throughput caps commit rate; acceptable because external effect
  commits are deliberately rare and serialized anyway.
- Two SQL dialects to keep compatible once cluster mode lands.

Follow-ups:

- Define the storage trait so the Postgres implementation is additive, not a rewrite.
- Add a ledger-integrity check (`PRAGMA integrity_check` plus receipt hash chain
  verification) to `agentkernel doctor`.

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

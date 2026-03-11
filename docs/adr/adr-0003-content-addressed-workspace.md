# ADR-0003: Content-Addressed Workspace Instead of Bind Mounts

## Status

Accepted

## Date

2026-03-10

## Context

The workspace is the most frequently versioned piece of world state: every Step
produces a `StateDelta` of file changes, every Branch fork needs a cheap copy,
and branch comparison must be fast enough that agents use it as a first-class
tool. The obvious implementation — bind-mount a host directory into the guest —
fails on two independent axes.

First, security. Bind mounts are not a security boundary. The class of bugs is
well documented: BoxLite fixed a read-only virtiofs mount bypass before 0.9.0,
where a mount declared read-only to the guest could still be written through
the sharing layer. Any design that treats "mounted read-only" as an enforcement
statement inherits that entire bug class. The real read-only constraint must
live at a lower enforcement layer, and the host tree must simply not be reachable.

Second, semantics. A shared mutable directory gives us no versioning: forking a
branch means copying the tree or accepting cross-branch interference, diffing
means walking the filesystem, and rollback means hoping nothing was missed —
directly violating "no invisible state transition".

Alternatives considered: overlayfs layers per branch (fast fork, but diff is
still a tree walk, and layer stacks leak host kernel specifics into replay);
AgentFS-style mediated FUSE (good audit trail, but a per-syscall hot path and
still no O(1) comparison). Both rejected as the primary store.

## Decision

The workspace is copy-in and content-addressed. On episode start, input files
are copied into a CAS (blobs keyed by `ContentHash`); the guest sees a
materialized view, never the host tree. Each `StateNode` records a Merkle root
(`workspace_root`) over the workspace tree. Branch fork copies a root pointer;
branch diff is a Merkle tree comparison; rollback is re-materialization from a
prior root; two branches are identical iff their roots are equal — an O(1)
comparison. Bind mounts, where a backend uses them internally for
materialization, are treated as a transport, never as an authorization or
integrity mechanism.

## Consequences

Positive:

- Cheap fork/diff/rollback makes N-way branch search practical; identical
  subtrees deduplicate storage across branches.
- `workspace_root` in every StateNode makes filesystem replay (`ReplayClass::
  FilesystemOnly` and above) verifiable, not asserted.
- Guest compromise cannot touch host files that were never copied in.

Negative:

- Copy-in cost on episode start for large inputs; mitigated by CAS dedup across
  episodes but still a real cold-start tax.
- Files changed outside a Step (e.g. background process writes) must be swept
  into the next delta; the materializer needs a change-detection pass.

Follow-ups:

- Benchmark materialization strategies (reflink where supported, hardlink CAS).
- Define large-blob chunking so a 2 GB artifact does not become one hash unit.

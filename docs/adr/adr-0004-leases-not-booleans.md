# ADR-0004: Capability Leases, Not Boolean Allow-Lists

## Status

Accepted

## Date

2026-03-24

## Context

Traditional sandbox permissions are boolean and ambient: `allow network`,
`allow /workspace write`, `inject GITHUB_TOKEN` into the environment. For agent
workloads this fails in predictable ways. An injected token is ambient authority —
any process in the guest, including a malicious dependency, can use it for any
operation the token allows, forever. Booleans cannot express "one draft PR
against `main`, from a `sandbox/` head, no merge, within ten minutes". And when
a parent agent spawns a sub-agent or tool, boolean models either duplicate the
full grant or invent ad-hoc inheritance — both violate least privilege, and
neither leaves an audit trail of who delegated what.

Alternatives considered: static allow-lists with wildcards (OpenShell-style
declarative policy) — expressive for paths and domains but stateless, so no use
counting, no expiry, no delegation lineage; OAuth-style scoped tokens per
operation — pushes semantics into each external provider's scope language and
gives us nothing for local operations like `fs.write`.

# ADR-0010: Connectors Own Credentials; Guests Never See Them

## Status

Accepted

## Date

2026-06-10

## Context

The canonical agent-sandbox breach is banal: a `GITHUB_TOKEN` environment
variable, a malicious transitive dependency, one HTTP request to an attacker
server. Injecting long-lived credentials into the guest makes every byte of
untrusted code in the sandbox — dependencies, downloaded skills, tool output —
a credential-exfiltration candidate, and makes credential use invisible to
policy: an env-var token is pure ambient authority, usable for any operation
the token permits, unattributable to any Step or lease.

Our threat model assumes the guest can be fully compromised. The design goal is
that a fully compromised guest still cannot exfiltrate a reusable credential.

Alternatives considered: short-TTL tokens injected into the guest (narrows the
window, but an active attacker exfiltrates and uses within the TTL; still
ambient inside the guest); an egress proxy that injects auth headers onto
allowed domains (keeps the secret out of the guest but authorizes at the
domain/method level, not the semantic-operation level — it cannot enforce
"create a draft PR, no merge", and raw protocol access invites SSRF-shaped
games). The proxy pattern is retained as a secondary mechanism for tools that
genuinely need wire protocols, not as the primary path.

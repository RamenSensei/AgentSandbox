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

## Decision

Credentials live in connectors and the secret broker, on the trusted side of
the boundary, never in the guest.

1. The guest environment contains no real secrets. Where tooling expects a
   variable to exist, it holds a placeholder that is useless outside the kernel.
2. Semantic operations flow: guest proposes an effect → broker validates the
   lease and contract → the connector uses the credential host-side → the guest
   receives results and Receipts only.
3. Tools that require direct protocol access get single-use, operation-scoped,
   short-lived tokens minted via token exchange, bound to the lease that
   justified them, injected at the egress proxy — never the org-level secret.
4. Connector processes are isolated from guest workloads; a connector holds
   only the credentials for its own service.

## Consequences

Positive:

- "Secrets entering the guest" is a metric that must read zero and is testable;
  the flagship demo (malicious dependency hunts for a token that does not
  exist) falls out of the architecture.
- Every credential use is attributable: connector call → lease → Step →
  Receipt, closing the causal chain.

Negative:

- Every external service needs a typed connector (or the constrained
  single-use-token path); long-tail services are slower to enable, by design
  (`opaque_external`, ADR-0006).
- Some tools hard-code credential-in-env assumptions and need shims; the
  placeholder scheme must fail loudly, not silently authenticate as nobody.

Follow-ups:

- Token-exchange integration for mTLS workload identity in cluster mode.
- Adversarial-bench: exfiltration attempts via env, proc, and raw egress must
  all yield placeholders or structured denials.

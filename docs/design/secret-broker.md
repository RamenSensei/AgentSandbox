# The Secret Broker

Status: Living document · Applies to: v0.6 · Last updated: 2026-08-12

## 1. Overview

The single most consequential security decision in AgentKernel: **raw
credentials never enter guests.** Not as environment variables, not as files,
not as flags, not "temporarily". The tracked metric is *secrets-in-guest
count*, and its target is **zero** (see `metrics.md` §5). Even a fully
compromised guest sees only placeholders, single-use tokens, connector return
values, and effect receipts.

The Secret Broker is the kernel component that makes typed external operations
possible without credential exposure. It operates alongside the Effect Broker
(`kernel/effect_broker`); connectors (`connectors/{github,http,mcp}`) are the
only code that touches real credentials, per the `Connector` trait contract in
`kernel/core/src/traits.rs`: *"Connectors are the ONLY code that touches real
credentials; guests never see them."*

## 2. The broker flow

The default path for any credentialed external operation:

```text
Agent (in guest)
  → requests a semantic operation           e.g. github.create_pull_request
  → Effect Broker validates the lease       CapabilityLease::check + contract
  → Secret Broker resolves the credential   scoped to connector + operation
  → Connector calls the external API        credential used host-side only
  → guest sees only: result + receipt
```

Normative properties:

- The credential is resolved *after* authorization, inside the trusted kernel,
  scoped to the specific connector and operation, and discarded (or expired)
  after use.
- The guest's view of the operation is the `Observation`
  (`EffectPending`/`EffectCommitted`) and the signed `Receipt`. At no point
  does a token string cross the guest boundary.
- Connectors MUST NOT echo credentials into logs, previews
  (`PreparedEffect.preview`), receipts, or error messages. The
  `external_response_digest` in `ReceiptBody` is a hash, not the raw response,
  precisely so receipts cannot leak embedded tokens.

## 3. Tools that genuinely need network protocols

Some guest tools legitimately speak a network protocol themselves (a package
manager, `git` over HTTPS, a database client). For these, the broker MUST use
one of the following techniques rather than handing over the real credential,
listed roughly by preference:

1. **Short-lived single-use tokens.** Minted per operation, bound to one
   target, expiring in minutes, usable once. Theft yields a token that is
   already dead or dying.
2. **Scoped credentials.** Provider-issued credentials narrowed to the exact
   resource and verb set the lease permits (e.g. a GitHub installation token
   scoped to one repository, read-only).
3. **Outbound-proxy dynamic injection.** The guest holds a placeholder; the
   egress proxy — outside the guest — rewrites the `Authorization` header for
   allow-listed destinations only. The real value never exists in guest
   memory.
4. **Token exchange.** The guest presents a broker-issued assertion; the
   broker exchanges it (RFC 8693-style) for a downstream token that never
   transits the guest.
5. **mTLS workload identity.** The proxy terminates and re-originates TLS
   with a workload certificate held host-side; the guest authenticates to the
   proxy, never to the destination.

In every variant the guest-visible artifact is either a placeholder or a
credential whose blast radius is one operation on one resource for a few
minutes.

## 4. Placeholder credentials

Guests that expect `GITHUB_TOKEN`-shaped environment variables MAY be given
syntactically-valid placeholders (e.g. `akp_placeholder_<nonce>`), so tooling
does not crash on absence. Placeholders MUST be:

- cryptographically unrelated to any real credential;
- unique per guest, so their appearance in egress traffic identifies the
  exfiltrating branch and principal (§6);
- rejected by the egress proxy everywhere except injection points.

## 5. Forbidden ambient channels

No configuration may expose these to a guest; conformance and
`adversarial-bench/` test each one:

```text
Docker socket                    (host takeover)
host home directory              (~/.ssh, ~/.aws, ~/.config tokens)
SSH agent socket                 (signing oracle)
cloud metadata endpoint          (169.254.169.254 → instance credentials)
organization-wide tokens         (blast radius = whole org)
writable host package cache      (cache poisoning across tenants)
```

These are ambient authority in its purest form; each violates invariant 1
directly. Backends MUST NOT mount, forward, or route any of them by default,
and the kernel MUST refuse a backend configuration that requests them without
an explicit, audited, `Elevated`-trust policy exception.

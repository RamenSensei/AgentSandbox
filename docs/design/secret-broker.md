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

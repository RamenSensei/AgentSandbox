# AgentKernel Architecture

Status: Living document · Applies to: v0.6 · Last updated: 2026-08-12

## 1. Overview

AgentKernel is an open-source transactional execution kernel for AI agents. It
models agent execution as a branchable, replayable, authorizable,
transactionally-committed world state machine. The slogan is:

> **Speculate locally, commit globally.**

The local world lets an agent explore boldly, fork parallel branches, and roll
back automatically; actions that affect the real world MUST pass through
precise authorization, commit-time revalidation, and MUST produce a
non-repudiable execution receipt.

AgentKernel is not another container platform. It is closer to a combination
of Git (managing execution state and branches), a database transaction manager
(managing external side effects), a capability OS (managing the authority of
agents, sub-agents, and tools), CPU speculative execution (parallel attempts
with discarded failures), and a flight recorder (the complete causal chain from
intent to OS change to external effect).

This document is normative. The key words MUST, MUST NOT, SHOULD, and MAY are
to be interpreted as in RFC 2119. The semantic source of truth is the `ak-core`
crate at `kernel/core/src/`; the protocol version implemented by this tree is
`PROTOCOL_VERSION = "0.6"` (pre-1.0; breaking changes MAY occur before 1.0).

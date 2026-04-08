# ADR-0005: Intent Hints Never Authorize

## Status

Accepted

## Date

2026-04-02

## Context

Agents declare intent: "I am about to run the test suite", "next I will need a
browser". This signal is genuinely valuable to the runtime. SpecBox-style
intent-aware prewarming reports large P99 latency and peak-memory improvements,
and AgentCgroup-style measurements show OS execution and initialization can
dominate end-to-end agent latency. We want the scheduler to consume declared
intent for backend selection, warm pools, cgroup sizing and prefetch.

The temptation is to let the same signal flow into authorization: "the agent
said this GET is just a health check, so allow it". This is exactly the failure
mode the project exists to prevent. LLM output is attacker-influencable by
construction — prompt injection through a README, a web page or a tool result
turns the model's stated intent into the attacker's stated intent. An
authorization path that reads model output is an authorization path the
attacker writes to.

Alternatives considered: intent-conditioned policy ("allow if declared purpose
matches category X") — rejected, it is a semantic firewall built on untrusted
input; LLM-as-judge on the effect broker path — rejected for the same reason
plus nondeterminism, which would break replayable policy decisions (ADR-0004)
and commit-time revalidation (ADR-0007).

## Decision

Agent-declared intent is a scheduling and prewarming hint only. Normatively:

1. Authorization is exclusively deterministic evaluation: `CapabilityLease::check()`
   plus typed policy rules, over canonical parameters, at a recorded policy epoch.
2. No field derived from model output may appear as an input to lease checking,
   policy evaluation, effect approval or commit-time revalidation. Intent hints
   travel on a separate protocol field and are dropped before the policy engine.
3. The LLM may interpret goals, request capabilities, recommend policy and
   generate human-readable rationale. It may not issue capabilities, judge its
   own actions harmless, bypass parameter validation, or decide that an external
   effect is authorized.
4. Scheduler use of hints is fail-open on optimization, fail-closed on
   authority: a wrong hint may waste a warm VM, never widen a lease.

## Consequences

Positive:

- Prompt injection can degrade performance (bad prewarm) but cannot escalate
  privilege; the attack surface of the authorization path is the typed protocol,
  not natural language.
- Policy decisions stay deterministic, hence replayable and auditable.

Negative:

- Some legitimate flexibility is lost: the kernel will deny actions a human
  reading the transcript would consider obviously fine. The remedy is the
  capability-request flow with machine-readable denials (ADR-0011), not
  intent-based exceptions.
- Two parallel channels (hint vs. request) add protocol surface and must be
  kept visibly distinct in SDKs.

Follow-ups:

- Adversarial-bench cases asserting that injected intent strings never change a
  policy decision.
- Scheduler metrics separating hint accuracy from authorization outcomes.

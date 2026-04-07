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

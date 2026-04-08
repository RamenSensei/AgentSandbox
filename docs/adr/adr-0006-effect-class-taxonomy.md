# ADR-0006: Six-Class Effect Reversibility Taxonomy

## Status

Accepted

## Date

2026-04-15

## Context

The effect broker must decide, per effect, what safeguards apply: can it run
speculatively on a branch, does it need prepare/preview, does it require
approval, can a failed branch be cleaned up automatically. The naive model is a
boolean: `reversible` or `irreversible`. It collapses distinctions the broker
actually needs. "Reversible" by whom? Rolling back a local file write, invoking
a remote system's true undo, and closing a PR you opened are three different
guarantees with three different failure modes (the compensation itself can
fail; the undo can race with external changes). And a boolean forces a labeling
decision for operations whose semantics nobody knows — the long tail of
arbitrary SaaS APIs — which in practice get optimistically labeled "reversible".

A related trap: inferring purity from HTTP method. GET requests trigger side
effects in the wild constantly (analytics, one-click actions, cache-busting
endpoints, tracking pixels — an email being read is itself irreversible). HTTP
method is not evidence of purity; only a connector's declared semantic contract is.

Alternatives considered: boolean (rejected above); a continuous risk score
(rejected: not deterministic policy input, invites threshold gaming); per-effect
free-text annotations (rejected: not machine-decidable).

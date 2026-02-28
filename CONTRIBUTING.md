# Contributing to AgentKernel

Thank you for your interest in contributing. AgentKernel is pre-1.0 and moving quickly; this document explains how to build, test, and get changes merged.

## Building and testing

```sh
cargo build --workspace
cargo test --workspace
```

Before opening a PR, please run:

```sh
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
```

CI enforces both. Rust edition and toolchain are pinned in the root `Cargo.toml` / `rust-toolchain.toml`.

## What contributions are welcome

- **Backends** (`backends/`): adapters for isolation runtimes (local OS sandboxes, microVM services, gVisor, Kubernetes). A backend must honestly declare its `ReplayClass` guarantees.
- **Connectors** (`connectors/`): typed world connectors that own their credentials and expose semantic operations through the effect broker. Connectors must classify every operation's `EffectClass` and support idempotency keys.
- **Conformance tests** (`conformance/`): protocol conformance cases that any backend or connector implementation must pass.
- **Adversarial-bench scenarios** (`adversarial-bench/`): abuse and attack scenarios (credential exfiltration, SSRF, capability escalation, duplicate commits, stale approvals). New realistic scenarios are highly valued.
- **Documentation** (`docs/`): design docs, ADRs, examples, and devlog corrections.
- **UI** (`ui/`): timeline, branch graph, policy, and receipt views, including demo-mode fixtures.

## Design-first process for semantic changes

Changes to *execution semantics* — the core objects, capability model, effect lifecycle, replay guarantees, denial format, or the four invariants — must start with an ADR in `docs/adr/` before implementation. Open a draft PR containing only the ADR, get it accepted, then implement.

**Any change under `protocol/` requires an accepted ADR.** The protocol is the project's most important public asset and is intended to remain backend-neutral; we do not change it casually.

Bug fixes, backends, connectors, tests, and docs that do not change semantics can go straight to a PR.

## Commit and PR conventions

- Keep commits focused; one logical change per commit.
- Commit subject: imperative mood, `area: summary` (e.g. `effect_broker: revalidate policy epoch at commit`), 72 characters max.
- PRs should describe *what* changed, *why*, and how it was tested. Link the relevant ADR for semantic changes.
- New behavior needs tests. Changes touching security-relevant paths should note which invariant they uphold.

## Developer Certificate of Origin

We use a DCO-style sign-off instead of a CLA. Add a `Signed-off-by` line to each commit certifying that you have the right to submit the work under Apache-2.0:

```
Signed-off-by: Your Name <you@example.com>
```

(`git commit -s` adds this automatically.)

## Code of conduct

All participation in the project is governed by our [Code of Conduct](CODE_OF_CONDUCT.md).

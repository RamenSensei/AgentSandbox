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

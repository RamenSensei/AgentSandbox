# AgentKernel

**Git for agent execution · transaction boundary for real-world effects · capability OS for tools**

AgentKernel is an open-source transactional execution kernel for AI agents. It models agent execution as a branchable, replayable, authorizable world-state machine: local execution becomes a versioned state DAG that agents can fork, diff, roll back, and search in parallel, while every action against the real world becomes an explicit transaction that is proposed, precisely authorized, revalidated at commit time, and receipted. Isolation backends (OS sandboxes, gVisor, microVMs, Kubernetes) and world connectors (GitHub, HTTP, MCP) are pluggable; the semantics are the product.

## Motivation

Existing sandboxes used by agents were, for the most part, not designed for agents. MicroVM services, container wrappers, and policy sandboxes are all built on mechanisms — Firecracker, gVisor, Kata, seccomp, bind mounts — that natively understand **VMs, containers, processes, files, and network packets**. They do not understand **tasks, steps, branches, capabilities, and external effects**, which is the vocabulary agents actually operate in.

The consequences show up everywhere:

- A VM snapshot can roll back a filesystem, but it cannot un-send an email, un-push a commit, or un-delete a cloud resource. OS snapshots are not a transaction for the external world.
- Permissions are ambient and boolean ("allow network", "inject `GITHUB_TOKEN`") rather than scoped, time-bound, and attenuable leases on specific operations.
- Failures come back as `Permission denied` / `exit code 1`, which forces a human interruption instead of enabling agent self-repair.
- Multi-agent setups share a mutable workspace, a token, and a network namespace, so a compromised tool inherits everything.

Making another faster microVM service does not fix any of this. AgentKernel instead owns the agent-native semantic layer — protocol, state model, capability model, effect transactions, causal ledger — and treats existing isolation mechanisms as interchangeable backends.

## Speculate locally, commit globally

The kernel enforces a hard distinction between two worlds:

- **Local world**: files, processes, tool sessions, browser state inside a branch. Here the agent is encouraged to be bold — fork multiple speculative branches, try competing fixes in parallel, and discard or roll back failures cheaply. Every step produces an immutable delta in the state DAG.
- **External world**: anything that leaves the sandbox — a PR, a message, a database write, a payment. These cannot be undone by a snapshot, so they must pass through the effect broker: precise authorization bound to canonical arguments, commit-time revalidation, and a non-repudiable signed receipt.

# AgentKernel observability UI

A single-page trace viewer for AgentKernel, the transactional execution kernel
for AI agents. It renders one episode's causal ledger: the event timeline, the
world-state DAG with its speculative branches, the capability leases and
machine-readable denials that governed the run, and the signed receipts for
every committed external effect.

Vanilla HTML/CSS/JS. **No build step, no dependencies.**

## Opening it

- **Demo mode (default):** double-click `index.html`. It works from `file://`.
- **Live mode:** serve a kernel with the trace API enabled, switch the
  "demo mode" toggle off, and enter the API base URL (for example
  `http://127.0.0.1:7411`). The demo-mode setting and API base persist in
  `localStorage`. If the kernel is unreachable, an inline error suggests
  switching back to demo mode.

## The four views

1. **Timeline** — the causal event stream, grouped by step. Each row shows
   timestamp, branch chip, actor, a kind badge color-coded by category
   (policy/denial, effect, state, neutral), and a summary. Click a row to
   expand the full JSON payload. Filterable by kind and branch.
2. **Branch graph** — an SVG DAG of immutable `StateNode`s, one lane per
   branch, time flowing left to right. Merge edges are dashed. Node and edge
   colors follow branch status (main = amber accent, active = green,
   merged = violet, discarded = dimmed red). Clicking a node opens a side
   panel with the node's delta (file changes, processes, tool sessions),
   `replay_class`, `workspace_root` and actor.
3. **Policy** — the capability lease table: principal, operation, compact
   constraint rendering (e.g. `repository = "org/repo" · head starts-with
   sandbox/ · merge forbidden`), remaining uses, expiry (relative and
   absolute; expired/revoked/exhausted shown as distinct status chips),
   branch binding, and attenuation lineage (`parent_lease`). Below it,
   "Machine-readable denials" shows the latest `Denial` in full: code,
   reason, `safe_alternatives`, `requestable_scopes`, and whether escalation
   is allowed.
4. **Receipts** — cards for each signed `Receipt`: operation and resource,
   who/branch/step, contract hash, authorization witness and external
   response digest as truncated monospace fields with copy buttons, policy
   epoch, commit time, key id, truncated signature, and a verification badge.
   In demo mode the badge is driven by the dataset's `verified` field; a live
   deployment would verify the Ed25519 signature over the canonical JSON of
   `body` against the kernel's published receipt key.

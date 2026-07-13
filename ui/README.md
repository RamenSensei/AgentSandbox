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

## API endpoints consumed (live mode)

- `GET {base}/v1/episodes`

  ```json
  { "episodes": [ { "id": "ep-codefix-42", "title": "Fix GitHub issue #42..." } ] }
  ```

- `GET {base}/v1/trace/query?episode=<id>`

  ```json
  {
    "episode": { "id": "ep-codefix-42", "title": "...", "status": "completed", "protocol_version": "0.6" },
    "events": [ { "id": "ev-019", "ts": "2026-08-11T09:18:02Z", "step": "step-08",
                  "branch": "br-b", "actor": "pr-sub-b", "kind": "denial",
                  "summary": "...", "payload": { "code": "CAPABILITY_DENIED", "...": "..." } } ]
  }
  ```

  If the response also carries `states` and `principals`, the branch graph and
  actor names are populated from them.

- `GET {base}/v1/episodes/<id>/branches` returning `{ "branches": [...] }`
- `GET {base}/v1/episodes/<id>/leases` returning `{ "leases": [...] }`
- `GET {base}/v1/episodes/<id>/receipts` returning `{ "receipts": [...] }`

All field names and enum spellings follow the kernel's serde output
(`kernel/core/src`): IDs are plain strings with `ep-`/`step-`/`br-`/`st-`/
`pr-`/`lease-`/`fx-`/`rcpt-` prefixes, enums are `snake_case`, and
`DenialCode` is `SCREAMING_SNAKE_CASE`.

## Demo data provenance

`demo-data.json` is a hand-written trace of the flagship scenario from the
founding design discussion: a coding agent fixes GitHub issue #42 (a race
condition in a job scheduler). It clones and reproduces the failure, forks
three branches from a checkpoint, and three sub-agents attempt fixes in
parallel. Branch B pulls in a malicious dependency whose setup hook tries to
open a raw socket carrying the GitHub token; the kernel returns a structured
`CAPABILITY_DENIED` denial (the credential lives in the secret broker and is
only usable through the typed GitHub connector), and the sub-agent recovers by
itself. Branch A passes the full suite, a draft PR effect is proposed and
prepared, a human approves the exact contract hash, commit-time revalidation
re-checks `base_head_sha`, the PR commits with a signed receipt, the losing
branches are discarded, and the winning branch is merged back to main.

## The embedded fallback for `file://`

Several browsers block `fetch()` of local JSON on `file://`. The app therefore
tries to fetch `demo-data.json` first and falls back to `window.DEMO_DATA`, a
copy of the same dataset embedded at the top of `app.js`. **`demo-data.json`
is the canonical dataset; the constant in `app.js` mirrors it** — if you edit
one, update the other (or re-embed with a one-line script).

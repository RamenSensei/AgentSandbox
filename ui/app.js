/*
 * AgentKernel observability UI.
 *
 * Single-file vanilla JS app. No dependencies, no build step, works from
 * file://. Organization:
 *   1. Embedded demo data (mirrors demo-data.json, the canonical copy)
 *   2. App state and persistence
 *   3. Data loading (demo + live API)
 *   4. Small utilities (formatting, escaping, id/hash helpers)
 *   5. Renderers: timeline, branch graph, policy, receipts
 *   6. Header wiring and boot
 */

"use strict";

/* ------------------------------------------------------------------ */
/* 1. Embedded demo data                                               */
/*                                                                     */
/* This constant mirrors ui/demo-data.json byte-for-byte (see README). */
/* It exists because fetch() of a local JSON file is blocked on        */
/* file:// in several browsers; the app tries fetch first and falls    */
/* back to this.                                                       */
/* ------------------------------------------------------------------ */

window.DEMO_DATA = {
  "episode": {
    "id": "ep-codefix-42",
    "title": "Fix GitHub issue #42: race condition in job scheduler",
    "created_at": "2026-08-11T09:14:02Z",
    "status": "completed",
    "protocol_version": "0.6"
  },
  "principals": [
    { "id": "pr-root", "kind": "agent", "display_name": "coding-agent/fix-issue-42", "parent": null, "trust": "standard" },
    { "id": "pr-sub-a", "kind": "sub_agent", "display_name": "fixer/branch-a-locking", "parent": "pr-root", "trust": "limited" },
    { "id": "pr-sub-b", "kind": "sub_agent", "display_name": "fixer/branch-b-dependency", "parent": "pr-root", "trust": "limited" },
    { "id": "pr-sub-c", "kind": "sub_agent", "display_name": "fixer/branch-c-rewrite", "parent": "pr-root", "trust": "limited" },
    { "id": "pr-tool-shell", "kind": "tool", "display_name": "sandbox-shell", "parent": "pr-root", "trust": "limited" },
    { "id": "pr-tool-github", "kind": "tool", "display_name": "typed-github-connector", "parent": "pr-root", "trust": "limited" },
    { "id": "pr-human-reviewer", "kind": "human", "display_name": "reviewer@org", "parent": null, "trust": "elevated" }
  ],
  "states": [
    {
      "id": "st-000", "episode": "ep-codefix-42", "branch": "br-main", "parent": null,
      "produced_by": null, "actor": "pr-root",
      "workspace_root": "sha256:e3b0c44298fc1c149afb",
      "replay_class": "framework_host_calls", "created_at": "2026-08-11T09:14:02Z",
      "delta": { "policy_epoch": 1 }
    },
    {
      "id": "st-001", "episode": "ep-codefix-42", "branch": "br-main", "parent": "st-000",
      "produced_by": "step-01", "actor": "pr-tool-shell",
      "workspace_root": "sha256:9a271f2a916b0b6ee6ce",
      "replay_class": "framework_host_calls", "created_at": "2026-08-11T09:14:31Z",
      "delta": {
        "files": [
          { "op": "added", "path": "repo/.git", "blob": "sha256:1f8ac10f23c5b5bc1167", "mode": 493 },
          { "op": "added", "path": "repo/src/scheduler.py", "blob": "sha256:6b23c0d5f35d1b11f9b6", "mode": 420 },
          { "op": "added", "path": "repo/tests/test_scheduler.py", "blob": "sha256:84d89877f0d4041efb6b", "mode": 420 }
        ],
        "processes_exited": ["sha256:cmd-git-clone-a91f22"],
        "policy_epoch": 1
      }
    },
    {
      "id": "st-002", "episode": "ep-codefix-42", "branch": "br-main", "parent": "st-001",
      "produced_by": "step-02", "actor": "pr-tool-shell",
      "workspace_root": "sha256:9a271f2a916b0b6ee6ce",
      "replay_class": "framework_host_calls", "created_at": "2026-08-11T09:15:48Z",
      "delta": {
        "processes_exited": ["sha256:cmd-pytest-repro-77ac"],
        "policy_epoch": 1
      }
    },
    {
      "id": "st-003", "episode": "ep-codefix-42", "branch": "br-main", "parent": "st-002",
      "produced_by": "step-03", "actor": "pr-root",
      "workspace_root": "sha256:9a271f2a916b0b6ee6ce",
      "replay_class": "framework_host_calls", "created_at": "2026-08-11T09:16:10Z",
      "delta": { "policy_epoch": 2 }
    },
    {
      "id": "st-a1", "episode": "ep-codefix-42", "branch": "br-a", "parent": "st-003",
      "produced_by": "step-04", "actor": "pr-sub-a",
      "workspace_root": "sha256:2c624232cdd221771294",
      "replay_class": "framework_host_calls", "created_at": "2026-08-11T09:17:05Z",
      "delta": {
        "files": [
          { "op": "modified", "path": "repo/src/scheduler.py", "old_blob": "sha256:6b23c0d5f35d1b11f9b6", "new_blob": "sha256:d2b2f6a1c88e34a90277" }
        ],
        "policy_epoch": 2
      }
    },
    {
      "id": "st-a2", "episode": "ep-codefix-42", "branch": "br-a", "parent": "st-a1",
      "produced_by": "step-05", "actor": "pr-tool-shell",
      "workspace_root": "sha256:2c624232cdd221771294",
      "replay_class": "framework_host_calls", "created_at": "2026-08-11T09:18:22Z",
      "delta": {
        "processes_exited": ["sha256:cmd-pytest-full-b3c1"],
        "policy_epoch": 2
      }
    },
    {
      "id": "st-a3", "episode": "ep-codefix-42", "branch": "br-a", "parent": "st-a2",
      "produced_by": "step-06", "actor": "pr-sub-a",
      "workspace_root": "sha256:2c624232cdd221771294",
      "replay_class": "framework_host_calls", "created_at": "2026-08-11T09:19:40Z",
      "delta": {
        "files": [
          { "op": "added", "path": "repo/.ak/pr-draft.md", "blob": "sha256:aa5de1876b4bcd39e7f0", "mode": 420 }
        ],
        "effects_proposed": ["fx-draft-pr-1"],
        "policy_epoch": 2
      }
    },
    {
      "id": "st-b1", "episode": "ep-codefix-42", "branch": "br-b", "parent": "st-003",
      "produced_by": "step-07", "actor": "pr-sub-b",
      "workspace_root": "sha256:4e07408562bedb8b60ce",
      "replay_class": "framework_host_calls", "created_at": "2026-08-11T09:17:12Z",
      "delta": {
        "files": [
          { "op": "modified", "path": "repo/requirements.txt", "old_blob": "sha256:f2ca1bb6c7e907d06daf", "new_blob": "sha256:0b918943df0962bc7a16" },
          { "op": "added", "path": "repo/.venv/lib/fastsched_pro/__init__.py", "blob": "sha256:deadbeefcafe42421337", "mode": 420 }
        ],
        "processes_exited": ["sha256:cmd-pip-install-91d0"],
        "policy_epoch": 2
      }
    },
    {
      "id": "st-b2", "episode": "ep-codefix-42", "branch": "br-b", "parent": "st-b1",
      "produced_by": "step-08", "actor": "pr-sub-b",
      "workspace_root": "sha256:4e07408562bedb8b60ce",
      "replay_class": "framework_host_calls", "created_at": "2026-08-11T09:18:03Z",
      "delta": {
        "processes_exited": ["sha256:cmd-fastsched-setup-denied-11aa"],
        "policy_epoch": 3
      }
    },
    {
      "id": "st-b3", "episode": "ep-codefix-42", "branch": "br-b", "parent": "st-b2",
      "produced_by": "step-09", "actor": "pr-sub-b",
      "workspace_root": "sha256:4e07408562bedb8b60ce",
      "replay_class": "framework_host_calls", "created_at": "2026-08-11T09:19:01Z",
      "delta": {
        "files": [
          { "op": "modified", "path": "repo/requirements.txt", "old_blob": "sha256:0b918943df0962bc7a16", "new_blob": "sha256:f2ca1bb6c7e907d06daf" },
          { "op": "deleted", "path": "repo/.venv/lib/fastsched_pro/__init__.py", "old_blob": "sha256:deadbeefcafe42421337" }
        ],
        "tool_sessions": ["typed-github-connector/session-1"],
        "policy_epoch": 3
      }
    },
    {
      "id": "st-c1", "episode": "ep-codefix-42", "branch": "br-c", "parent": "st-003",
      "produced_by": "step-10", "actor": "pr-sub-c",
      "workspace_root": "sha256:ef2d127de37b942baad0",
      "replay_class": "framework_host_calls", "created_at": "2026-08-11T09:17:20Z",
      "delta": {
        "files": [
          { "op": "modified", "path": "repo/src/scheduler.py", "old_blob": "sha256:6b23c0d5f35d1b11f9b6", "new_blob": "sha256:5f9c4ab08cac7457e972" },
          { "op": "added", "path": "repo/src/queue2.py", "blob": "sha256:6f4b6612125fb3a0daec", "mode": 420 }
        ],
        "policy_epoch": 2
      }
    },
    {
      "id": "st-c2", "episode": "ep-codefix-42", "branch": "br-c", "parent": "st-c1",
      "produced_by": "step-11", "actor": "pr-tool-shell",
      "workspace_root": "sha256:ef2d127de37b942baad0",
      "replay_class": "framework_host_calls", "created_at": "2026-08-11T09:18:44Z",
      "delta": {
        "processes_exited": ["sha256:cmd-pytest-full-fail-90ee"],
        "policy_epoch": 2
      }
    },
    {
      "id": "st-004", "episode": "ep-codefix-42", "branch": "br-main", "parent": "st-003",
      "produced_by": null, "merge_parent": "st-a3", "actor": "pr-root",
      "workspace_root": "sha256:2c624232cdd221771294",
      "replay_class": "framework_host_calls", "created_at": "2026-08-11T09:21:15Z",
      "delta": { "policy_epoch": 3 }
    },
    {
      "id": "st-005", "episode": "ep-codefix-42", "branch": "br-main", "parent": "st-004",
      "produced_by": "step-12", "actor": "pr-tool-github",
      "workspace_root": "sha256:2c624232cdd221771294",
      "replay_class": "framework_host_calls", "created_at": "2026-08-11T09:23:58Z",
      "delta": {
        "effects_committed": ["rcpt-pr-created-1"],
        "policy_epoch": 3
      }
    },
    {
      "id": "st-006", "episode": "ep-codefix-42", "branch": "br-main", "parent": "st-005",
      "produced_by": "step-13", "actor": "pr-tool-github",
      "workspace_root": "sha256:2c624232cdd221771294",
      "replay_class": "framework_host_calls", "created_at": "2026-08-11T09:24:31Z",
      "delta": {
        "effects_committed": ["rcpt-comment-1"],
        "policy_epoch": 3
      }
    }
  ],
  "branches": [
    { "id": "br-main", "name": "main", "forked_from": null, "status": "main", "head": "st-006" },
    { "id": "br-a", "name": "sandbox/fix-a-locking", "forked_from": "st-003", "status": "merged", "head": "st-a3" },
    { "id": "br-b", "name": "sandbox/fix-b-dependency", "forked_from": "st-003", "status": "discarded", "head": "st-b3" },
    { "id": "br-c", "name": "sandbox/fix-c-rewrite", "forked_from": "st-003", "status": "discarded", "head": "st-c2" }
  ],
  "events": [
    {
      "id": "ev-001", "ts": "2026-08-11T09:14:02Z", "step": "step-00", "branch": "br-main", "actor": "pr-root",
      "kind": "objective",
      "summary": "Episode created: fix GitHub issue #42 (race condition in job scheduler) and open a draft PR",
      "payload": { "issue": "org/repo#42", "goal": "Failing test test_concurrent_enqueue must pass; open draft PR against main", "autonomy_envelope": "local branches unlimited; external effects require approval" }
    },
    {
      "id": "ev-002", "ts": "2026-08-11T09:14:20Z", "step": "step-01", "branch": "br-main", "actor": "pr-root",
      "kind": "intent_declared",
      "summary": "Intent: clone org/repo into the workspace and reproduce the failure",
      "payload": { "operations": ["proc.exec", "net.http_read"], "reads": ["github.com/org/repo"], "writes": ["/workspace/repo"] }
    },
    {
      "id": "ev-003", "ts": "2026-08-11T09:14:22Z", "step": "step-01", "branch": "br-main", "actor": "pr-root",
      "kind": "capability_request",
      "summary": "Requested proc.exec + net.http_read leases for clone and test runs",
      "payload": { "requested": [ { "operation": "proc.exec", "constraints": { "cwd": { "kind": "prefix", "prefix": "/workspace/" } } }, { "operation": "net.http_read", "constraints": { "domain": { "kind": "glob", "pattern": "*.github.com" } } } ] }
    },
    {
      "id": "ev-004", "ts": "2026-08-11T09:14:23Z", "step": "step-01", "branch": "br-main", "actor": "pr-root",
      "kind": "policy_decision",
      "summary": "Granted lease-root-proc and lease-root-net (policy epoch 1)",
      "payload": { "granted": ["lease-root-proc", "lease-root-net", "lease-root-fs"], "policy_epoch": 1 }
    },
    {
      "id": "ev-005", "ts": "2026-08-11T09:14:25Z", "step": "step-01", "branch": "br-main", "actor": "pr-tool-shell",
      "kind": "tool_invocation",
      "summary": "git clone https://github.com/org/repo /workspace/repo",
      "payload": { "operation": "proc.exec", "lease": "lease-root-proc", "argv": ["git", "clone", "https://github.com/org/repo", "/workspace/repo"] }
    },
    {
      "id": "ev-006", "ts": "2026-08-11T09:14:31Z", "step": "step-01", "branch": "br-main", "actor": "pr-tool-shell",
      "kind": "state_delta",
      "summary": "Workspace populated: 214 files added (st-001)",
      "payload": { "state": "st-001", "files_added": 214, "workspace_root": "sha256:9a271f2a916b0b6ee6ce" }
    },
    {
      "id": "ev-007", "ts": "2026-08-11T09:15:40Z", "step": "step-02", "branch": "br-main", "actor": "pr-tool-shell",
      "kind": "tool_invocation",
      "summary": "pytest tests/test_scheduler.py::test_concurrent_enqueue -x",
      "payload": { "operation": "proc.exec", "lease": "lease-root-proc", "argv": ["pytest", "tests/test_scheduler.py::test_concurrent_enqueue", "-x"] }
    },
    {
      "id": "ev-008", "ts": "2026-08-11T09:15:48Z", "step": "step-02", "branch": "br-main", "actor": "pr-tool-shell",
      "kind": "observation",
      "summary": "Failure reproduced: 1 failed in 6.2s, first causal failure at scheduler.py:118",
      "payload": { "kind": "failure", "summary": "test_concurrent_enqueue failed: duplicate job id under contention", "exit_code": 1, "first_causal_failure": "scheduler.py:118 self._queue.append without lock", "full_output": "sha256:5c62e091b8c0565f1bde" }
    },
    {
      "id": "ev-009", "ts": "2026-08-11T09:16:05Z", "step": "step-03", "branch": "br-main", "actor": "pr-root",
      "kind": "model_response",
      "summary": "Planner: try three fixes in parallel branches (locking, dependency swap, queue rewrite)",
      "payload": { "plan": ["br-a: add threading.Lock around enqueue", "br-b: replace queue with third-party fastsched-pro", "br-c: rewrite queue on collections.deque"], "checkpoint": "st-003" }
    },
    {
      "id": "ev-010", "ts": "2026-08-11T09:16:12Z", "step": "step-03", "branch": "br-a", "actor": "pr-root",
      "kind": "branch_forked",
      "summary": "Forked br-a (sandbox/fix-a-locking) from st-003; sub-agent pr-sub-a spawned with attenuated leases",
      "payload": { "branch": "br-a", "forked_from": "st-003", "principal": "pr-sub-a", "leases": ["lease-sub-a-fs", "lease-sub-a-proc"] }
    },
    {
      "id": "ev-011", "ts": "2026-08-11T09:16:12Z", "step": "step-03", "branch": "br-b", "actor": "pr-root",
      "kind": "branch_forked",
      "summary": "Forked br-b (sandbox/fix-b-dependency) from st-003; sub-agent pr-sub-b spawned",
      "payload": { "branch": "br-b", "forked_from": "st-003", "principal": "pr-sub-b", "leases": ["lease-sub-b-proc"] }
    },
    {
      "id": "ev-012", "ts": "2026-08-11T09:16:12Z", "step": "step-03", "branch": "br-c", "actor": "pr-root",
      "kind": "branch_forked",
      "summary": "Forked br-c (sandbox/fix-c-rewrite) from st-003; sub-agent pr-sub-c spawned",
      "payload": { "branch": "br-c", "forked_from": "st-003", "principal": "pr-sub-c" }
    },
    {
      "id": "ev-013", "ts": "2026-08-11T09:17:05Z", "step": "step-04", "branch": "br-a", "actor": "pr-sub-a",
      "kind": "state_delta",
      "summary": "Patched scheduler.py: guard enqueue with threading.Lock (st-a1)",
      "payload": { "state": "st-a1", "files": [{ "op": "modified", "path": "repo/src/scheduler.py" }] }
    },
    {
      "id": "ev-014", "ts": "2026-08-11T09:18:14Z", "step": "step-05", "branch": "br-a", "actor": "pr-tool-shell",
      "kind": "tool_invocation",
      "summary": "pytest -q (full suite) on br-a",
      "payload": { "operation": "proc.exec", "lease": "lease-sub-a-proc", "argv": ["pytest", "-q"] }
    },
    {
      "id": "ev-015", "ts": "2026-08-11T09:18:22Z", "step": "step-05", "branch": "br-a", "actor": "pr-tool-shell",
      "kind": "observation",
      "summary": "All 87 tests passed in 41.3s on br-a",
      "payload": { "kind": "success", "summary": "87 passed", "exit_code": 0, "stdout_head": "87 passed in 41.3s", "full_output": "sha256:0f715baf5d4c2ed329785cef29e562f7", "truncated": false }
    },
    {
      "id": "ev-016", "ts": "2026-08-11T09:17:08Z", "step": "step-07", "branch": "br-b", "actor": "pr-sub-b",
      "kind": "tool_invocation",
      "summary": "pip install fastsched-pro==2.1.4",
      "payload": { "operation": "proc.exec", "lease": "lease-sub-b-proc", "argv": ["pip", "install", "fastsched-pro==2.1.4"] }
    },
    {
      "id": "ev-017", "ts": "2026-08-11T09:17:12Z", "step": "step-07", "branch": "br-b", "actor": "pr-sub-b",
      "kind": "state_delta",
      "summary": "Dependency fastsched-pro installed into branch venv (st-b1)",
      "payload": { "state": "st-b1", "files": [{ "op": "modified", "path": "repo/requirements.txt" }, { "op": "added", "path": "repo/.venv/lib/fastsched_pro/__init__.py" }] }
    },
    {
      "id": "ev-018", "ts": "2026-08-11T09:18:01Z", "step": "step-08", "branch": "br-b", "actor": "pr-sub-b",
      "kind": "tool_invocation",
      "summary": "fastsched_pro setup hook attempted to open a raw socket to 185.199.x.x with GITHUB_TOKEN in payload",
      "payload": { "operation": "net.raw_socket", "argv": ["python", "-c", "import fastsched_pro; fastsched_pro.setup()"], "detected": "outbound raw socket carrying credential material" }
    },
    {
      "id": "ev-019", "ts": "2026-08-11T09:18:02Z", "step": "step-08", "branch": "br-b", "actor": "pr-sub-b",
      "kind": "denial",
      "summary": "CAPABILITY_DENIED: net.raw_socket refused; credential never entered the sandbox",
      "payload": {
        "code": "CAPABILITY_DENIED",
        "attempted_operation": "net.raw_socket",
        "reason": "raw sockets are not grantable in this episode; the GitHub credential is held by the secret broker and may only be exercised through the typed GitHub connector",
        "safe_alternatives": ["github.create_pull_request", "github.comment", "net.http_read"],
        "requestable_scopes": [
          { "operation": "net.http_read", "constraints": { "domain": "api.github.com", "max_count": 10 }, "requires_human": false },
          { "operation": "net.http_post", "constraints": { "domain": "api.github.com" }, "requires_human": true }
        ],
        "escalation_allowed": true
      }
    },
    {
      "id": "ev-020", "ts": "2026-08-11T09:18:03Z", "step": "step-08", "branch": "br-b", "actor": "pr-root",
      "kind": "policy_decision",
      "summary": "Policy epoch bumped to 3; lease-sub-b-proc revoked after exfiltration attempt",
      "payload": { "policy_epoch": 3, "revoked": ["lease-sub-b-proc"], "cause": "ev-019" }
    },
    {
      "id": "ev-021", "ts": "2026-08-11T09:18:55Z", "step": "step-09", "branch": "br-b", "actor": "pr-sub-b",
      "kind": "model_response",
      "summary": "Sub-agent b read the structured denial, removed fastsched-pro, and switched to the typed connector",
      "payload": { "reasoning_summary": "Denial lists github.* typed operations as safe alternatives; dependency is untrustworthy. Reverting requirements.txt and reporting findings via typed connector." }
    },
    {
      "id": "ev-022", "ts": "2026-08-11T09:19:01Z", "step": "step-09", "branch": "br-b", "actor": "pr-sub-b",
      "kind": "state_delta",
      "summary": "Reverted requirements.txt, removed fastsched_pro, opened typed connector session (st-b3)",
      "payload": { "state": "st-b3", "tool_sessions": ["typed-github-connector/session-1"] }
    },
    {
      "id": "ev-023", "ts": "2026-08-11T09:17:20Z", "step": "step-10", "branch": "br-c", "actor": "pr-sub-c",
      "kind": "state_delta",
      "summary": "Rewrote queue on collections.deque, added queue2.py (st-c1)",
      "payload": { "state": "st-c1", "files": [{ "op": "modified", "path": "repo/src/scheduler.py" }, { "op": "added", "path": "repo/src/queue2.py" }] }
    },
    {
      "id": "ev-024", "ts": "2026-08-11T09:18:44Z", "step": "step-11", "branch": "br-c", "actor": "pr-tool-shell",
      "kind": "observation",
      "summary": "Test suite failed on br-c: 3 failed, 84 passed; regression in test_priority_order",
      "payload": { "kind": "failure", "summary": "3 failed, 84 passed", "exit_code": 1, "first_causal_failure": "queue2.py:41 priority inversion", "full_output": "sha256:6c1b3a7e99d0f4128a44" }
    },
    {
      "id": "ev-025", "ts": "2026-08-11T09:19:35Z", "step": "step-06", "branch": "br-a", "actor": "pr-sub-a",
      "kind": "effect_proposed",
      "summary": "Proposed external effect: github.create_pull_request (draft) for sandbox/fix-a-locking",
      "payload": {
        "effect": "fx-draft-pr-1",
        "contract": {
          "operation": "github.create_pull_request",
          "resource": "org/repo",
          "arguments": { "base": "main", "head": "sandbox/fix-a-locking", "title": "Fix #42: serialize enqueue with a lock", "draft": true },
          "preconditions": { "base_head_sha": "sha256:ab12f004d1e2c37a55d1" },
          "idempotency_key": "ep-codefix-42-step-06",
          "class": "compensatable"
        },
        "contract_hash": "sha256:77aa41c2be901d44f0c3",
        "lease": "lease-gh-pr"
      }
    },
    {
      "id": "ev-026", "ts": "2026-08-11T09:19:40Z", "step": "step-06", "branch": "br-a", "actor": "pr-tool-github",
      "kind": "effect_prepared",
      "summary": "Effect fx-draft-pr-1 prepared: human-readable preview rendered, awaiting approval",
      "payload": { "effect": "fx-draft-pr-1", "phase": "prepared", "preview": { "title": "Fix #42: serialize enqueue with a lock", "base": "main", "head": "sandbox/fix-a-locking", "draft": true, "files_changed": 1, "diff_digest": "sha256:d2b2f6a1c88e34a90277" } }
    },
    {
      "id": "ev-027", "ts": "2026-08-11T09:21:10Z", "step": "step-12", "branch": "br-main", "actor": "pr-root",
      "kind": "branch_merged",
      "summary": "br-a selected as winner; merged st-a3 into main as st-004",
      "payload": { "branch": "br-a", "merge_state": "st-004", "parents": ["st-003", "st-a3"], "rationale": "only branch with full test suite green" }
    },
    {
      "id": "ev-028", "ts": "2026-08-11T09:21:20Z", "step": "step-12", "branch": "br-b", "actor": "pr-root",
      "kind": "branch_discarded",
      "summary": "br-b discarded: dependency untrustworthy; findings preserved in ledger",
      "payload": { "branch": "br-b", "head": "st-b3", "reason": "malicious dependency; recovery notes retained as evidence" }
    },
    {
      "id": "ev-029", "ts": "2026-08-11T09:21:21Z", "step": "step-12", "branch": "br-c", "actor": "pr-root",
      "kind": "branch_discarded",
      "summary": "br-c discarded: regression in priority ordering",
      "payload": { "branch": "br-c", "head": "st-c2", "reason": "3 test failures" }
    },
    {
      "id": "ev-030", "ts": "2026-08-11T09:23:41Z", "step": "step-12", "branch": "br-main", "actor": "pr-human-reviewer",
      "kind": "approval",
      "summary": "Human approved effect fx-draft-pr-1 (contract sha256:77aa41c2...) at policy epoch 3",
      "payload": { "effect": "fx-draft-pr-1", "approver": "pr-human-reviewer", "approved_at": "2026-08-11T09:23:41Z", "policy_epoch": 3, "contract_hash": "sha256:77aa41c2be901d44f0c3" }
    },
    {
      "id": "ev-031", "ts": "2026-08-11T09:23:55Z", "step": "step-12", "branch": "br-main", "actor": "pr-tool-github",
      "kind": "commit_revalidation",
      "summary": "Commit-time revalidation: base_head_sha unchanged, lease valid, policy epoch matches approval",
      "payload": { "effect": "fx-draft-pr-1", "checks": { "base_head_sha": { "expected": "sha256:ab12f004d1e2c37a55d1", "observed": "sha256:ab12f004d1e2c37a55d1", "ok": true }, "lease": { "id": "lease-gh-pr", "ok": true }, "policy_epoch": { "approved_at": 3, "current": 3, "ok": true } } }
    },
    {
      "id": "ev-032", "ts": "2026-08-11T09:23:58Z", "step": "step-12", "branch": "br-main", "actor": "pr-tool-github",
      "kind": "effect_committed",
      "summary": "PR #118 created (draft) on org/repo; signed receipt rcpt-pr-created-1",
      "payload": { "effect": "fx-draft-pr-1", "receipt": "rcpt-pr-created-1", "external_result": { "pr_number": 118, "url": "https://github.com/org/repo/pull/118" } }
    },
    {
      "id": "ev-033", "ts": "2026-08-11T09:24:31Z", "step": "step-13", "branch": "br-main", "actor": "pr-tool-github",
      "kind": "effect_committed",
      "summary": "Issue comment posted linking PR and summarizing the discarded-branch findings; receipt rcpt-comment-1",
      "payload": { "effect": "fx-comment-1", "receipt": "rcpt-comment-1", "external_result": { "comment_id": 991201, "url": "https://github.com/org/repo/issues/42#issuecomment-991201" } }
    },
    {
      "id": "ev-034", "ts": "2026-08-11T09:24:40Z", "step": "step-13", "branch": "br-main", "actor": "pr-root",
      "kind": "observation",
      "summary": "Episode objective met: failing test fixed, draft PR #118 open, evidence ledger sealed",
      "payload": { "kind": "success", "summary": "objective complete", "exit_code": 0, "full_output": "sha256:2e7d2c03a9507ae265ec", "truncated": false }
    }
  ],
  "leases": [
    {
      "id": "lease-root-fs",
      "principal": "pr-root",
      "operation": "fs.write",
      "constraints": { "path": { "kind": "prefix", "prefix": "/workspace/" } },
      "remaining_uses": 466,
      "issued_at": "2026-08-11T09:14:23Z",
      "expires_at": "2026-08-11T11:14:23Z",
      "budget": { "cpu_ms": 60000, "memory_bytes": 2147483648, "network_bytes": 0, "tokens": 0, "cost_micro_usd": 0, "risk_units": 2 },
      "revoked": false
    },
    {
      "id": "lease-root-proc",
      "principal": "pr-root",
      "operation": "proc.exec",
      "constraints": { "cwd": { "kind": "prefix", "prefix": "/workspace/" } },
      "remaining_uses": 183,
      "issued_at": "2026-08-11T09:14:23Z",
      "expires_at": "2026-08-11T11:14:23Z",
      "budget": { "cpu_ms": 600000, "memory_bytes": 4294967296, "network_bytes": 0, "tokens": 0, "cost_micro_usd": 0, "risk_units": 4 },
      "revoked": false
    },
    {
      "id": "lease-root-net",
      "principal": "pr-root",
      "operation": "net.http_read",
      "constraints": { "domain": { "kind": "glob", "pattern": "*.github.com" }, "method": { "kind": "one_of", "values": ["GET", "HEAD"] } },
      "remaining_uses": 41,
      "issued_at": "2026-08-11T09:14:23Z",
      "expires_at": "2026-08-11T10:14:23Z",
      "budget": { "cpu_ms": 0, "memory_bytes": 0, "network_bytes": 268435456, "tokens": 0, "cost_micro_usd": 0, "risk_units": 2 },
      "revoked": false
    },
    {
      "id": "lease-sub-a-fs",
      "principal": "pr-sub-a",
      "operation": "fs.write",
      "constraints": { "path": { "kind": "prefix", "prefix": "/workspace/branches/a/" } },
      "remaining_uses": 37,
      "issued_at": "2026-08-11T09:16:12Z",
      "expires_at": "2026-08-11T10:16:12Z",
      "bound_branch": "br-a",
      "budget": { "cpu_ms": 60000, "memory_bytes": 1073741824, "network_bytes": 0, "tokens": 0, "cost_micro_usd": 0, "risk_units": 1 },
      "parent_lease": "lease-root-fs",
      "revoked": false
    },
    {
      "id": "lease-sub-a-proc",
      "principal": "pr-sub-a",
      "operation": "proc.exec",
      "constraints": { "cwd": { "kind": "prefix", "prefix": "/workspace/branches/a/" } },
      "remaining_uses": 14,
      "issued_at": "2026-08-11T09:16:12Z",
      "expires_at": "2026-08-11T10:16:12Z",
      "bound_branch": "br-a",
      "budget": { "cpu_ms": 300000, "memory_bytes": 2147483648, "network_bytes": 0, "tokens": 0, "cost_micro_usd": 0, "risk_units": 2 },
      "parent_lease": "lease-root-proc",
      "revoked": false
    },
    {
      "id": "lease-sub-b-proc",
      "principal": "pr-sub-b",
      "operation": "proc.exec",
      "constraints": { "cwd": { "kind": "prefix", "prefix": "/workspace/branches/b/" } },
      "remaining_uses": 11,
      "issued_at": "2026-08-11T09:16:12Z",
      "expires_at": "2026-08-11T10:16:12Z",
      "bound_branch": "br-b",
      "budget": { "cpu_ms": 300000, "memory_bytes": 2147483648, "network_bytes": 0, "tokens": 0, "cost_micro_usd": 0, "risk_units": 2 },
      "parent_lease": "lease-root-proc",
      "revoked": true
    },
    {
      "id": "lease-gh-pr",
      "principal": "pr-tool-github",
      "operation": "github.create_pull_request",
      "constraints": {
        "repository": { "kind": "equals", "value": "org/repo" },
        "base": { "kind": "equals", "value": "main" },
        "head": { "kind": "prefix", "prefix": "sandbox/" },
        "merge": { "kind": "forbidden" }
      },
      "remaining_uses": 0,
      "issued_at": "2026-08-11T09:19:30Z",
      "expires_at": "2026-08-11T09:49:30Z",
      "bound_branch": "br-main",
      "budget": { "cpu_ms": 0, "memory_bytes": 0, "network_bytes": 1048576, "tokens": 0, "cost_micro_usd": 0, "risk_units": 5 },
      "preconditions": { "base_head_sha": "sha256:ab12f004d1e2c37a55d1" },
      "revoked": false
    },
    {
      "id": "lease-gh-comment",
      "principal": "pr-tool-github",
      "operation": "github.comment",
      "constraints": {
        "repository": { "kind": "equals", "value": "org/repo" },
        "issue": { "kind": "one_of", "values": [42, 118] }
      },
      "remaining_uses": 2,
      "issued_at": "2026-08-11T09:19:30Z",
      "expires_at": "2026-08-11T09:34:30Z",
      "bound_branch": "br-main",
      "budget": { "cpu_ms": 0, "memory_bytes": 0, "network_bytes": 262144, "tokens": 0, "cost_micro_usd": 0, "risk_units": 2 },
      "revoked": false
    }
  ],
  "receipts": [
    {
      "id": "rcpt-pr-created-1",
      "body": {
        "effect": "fx-draft-pr-1",
        "who": "pr-tool-github",
        "operation": "github.create_pull_request",
        "resource": "org/repo",
        "contract_hash": "sha256:77aa41c2be901d44f0c3",
        "branch": "br-main",
        "step": "step-12",
        "policy_epoch": 3,
        "authorization_witness": "sha256:19c4587a00e2f4b6d811",
        "external_response_digest": "sha256:c4ef1a09b7d2338f5a60",
        "committed_at": "2026-08-11T09:23:58Z"
      },
      "signature": "8f3a1c0d9b74e2665a1f0c88d34be7a92105f6de88c1b3a4770e92cd5b16f8a3d0c47e19b25a86f1c39d08e74a5b2fd61e98c03a7b54d216f80ac93e5d172b04",
      "key_id": "ak-receipt-key-1",
      "verified": true
    },
    {
      "id": "rcpt-comment-1",
      "body": {
        "effect": "fx-comment-1",
        "who": "pr-tool-github",
        "operation": "github.comment",
        "resource": "org/repo#42",
        "contract_hash": "sha256:31b8e6f0aa42d97c1e05",
        "branch": "br-main",
        "step": "step-13",
        "policy_epoch": 3,
        "authorization_witness": "sha256:7d20c1e94ab8f3560d92",
        "external_response_digest": "sha256:90afc2e51b7d84e30c16",
        "committed_at": "2026-08-11T09:24:31Z"
      },
      "signature": "2b7e94d1c05a8f36e1d40b92c7a5f8031e6d29ca47b08f15d3a6e2c90b74f18a5c30d7e61f29b84ac05d13e7f6a92b048c17d5e3a90b26f41c8e07d35a1b92f6",
      "key_id": "ak-receipt-key-1",
      "verified": true
    },
    {
      "id": "rcpt-legacy-0",
      "body": {
        "effect": "fx-warmup-0",
        "who": "pr-root",
        "operation": "net.http_read",
        "resource": "api.github.com/repos/org/repo/issues/42",
        "contract_hash": "sha256:0e44d1a2c8b7f3915d06",
        "branch": "br-main",
        "step": "step-01",
        "policy_epoch": 1,
        "authorization_witness": "sha256:5a1c9e30d7b2f4861e07",
        "external_response_digest": "sha256:e07b3c1d92a5f4680b13",
        "committed_at": "2026-08-11T09:14:29Z"
      },
      "signature": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
      "key_id": "ak-receipt-key-0",
      "verified": false
    }
  ]
};

/* ------------------------------------------------------------------ */
/* 2. App state                                                        */
/* ------------------------------------------------------------------ */

const LS_DEMO = "ak-ui-demo-mode";
const LS_API = "ak-ui-api-base";

const state = {
  view: "timeline",
  demoMode: localStorage.getItem(LS_DEMO) !== "off", // default ON
  apiBase: localStorage.getItem(LS_API) || "http://127.0.0.1:7411",
  episodes: [],          // [{id, title}] for the selector
  currentEpisode: null,  // selected episode id
  data: null,            // full dataset for the current episode
  filters: { kind: "", branch: "" },
  expandedEvents: new Set(),
  selectedState: null,   // state node id selected in the graph
};

function persist() {
  localStorage.setItem(LS_DEMO, state.demoMode ? "on" : "off");
  localStorage.setItem(LS_API, state.apiBase);
}

/* ------------------------------------------------------------------ */
/* 3. Data loading                                                     */
/* ------------------------------------------------------------------ */

/** Load the bundled demo dataset: fetch the canonical JSON file, and if
 * that fails (typical on file://), use the embedded copy. */
async function loadDemoData() {
  try {
    const res = await fetch("demo-data.json");
    if (res.ok) return await res.json();
  } catch (_e) {
    /* fall through to the embedded copy */
  }
  return window.DEMO_DATA;
}

async function apiGet(path) {
  const base = state.apiBase.replace(/\/+$/, "");
  const res = await fetch(base + path, { headers: { Accept: "application/json" } });
  if (!res.ok) throw new Error("HTTP " + res.status + " for " + path);
  return res.json();
}

/** Load one episode from a live kernel, assembling the same dataset shape
 * the demo file uses. */
async function loadLiveEpisode(episodeId) {
  const trace = await apiGet("/v1/trace/query?episode=" + encodeURIComponent(episodeId));
  const [branches, leases, receipts] = await Promise.all([
    apiGet("/v1/episodes/" + encodeURIComponent(episodeId) + "/branches").catch(() => ({ branches: [] })),
    apiGet("/v1/episodes/" + encodeURIComponent(episodeId) + "/leases").catch(() => ({ leases: [] })),
    apiGet("/v1/episodes/" + encodeURIComponent(episodeId) + "/receipts").catch(() => ({ receipts: [] })),
  ]);
  return {
    episode: trace.episode || {},
    events: trace.events || [],
    states: trace.states || (trace.episode && trace.episode.states) || [],
    principals: trace.principals || [],
    branches: branches.branches || [],
    leases: leases.leases || [],
    receipts: receipts.receipts || [],
  };
}

async function reload() {
  hideError();
  try {
    if (state.demoMode) {
      const data = await loadDemoData();
      state.episodes = [{ id: data.episode.id, title: data.episode.title }];
      state.currentEpisode = data.episode.id;
      state.data = data;
    } else {
      const list = await apiGet("/v1/episodes");
      state.episodes = (list.episodes || []).map((e) =>
        typeof e === "string" ? { id: e, title: e } : { id: e.id, title: e.title || e.id }
      );
      if (!state.episodes.length) {
        state.data = null;
        state.currentEpisode = null;
        renderAll();
        showError("The kernel returned no episodes. Run an episode first, or switch demo mode on to explore the bundled trace.");
        return;
      }
      if (!state.currentEpisode || !state.episodes.some((e) => e.id === state.currentEpisode)) {
        state.currentEpisode = state.episodes[0].id;
      }
      state.data = await loadLiveEpisode(state.currentEpisode);
    }
  } catch (err) {
    state.data = state.demoMode ? window.DEMO_DATA : null;
    if (!state.demoMode) {
      showError(
        "Could not reach the kernel at " + escapeHtml(state.apiBase) +
        " (" + escapeHtml(String(err && err.message || err)) + "). " +
        "Check that the trace API is running and CORS allows this origin, or switch demo mode on."
      );
    }
  }
  state.expandedEvents.clear();
  state.selectedState = null;
  renderAll();
}

/* ------------------------------------------------------------------ */
/* 4. Utilities                                                        */
/* ------------------------------------------------------------------ */

function $(sel) { return document.querySelector(sel); }

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

function showError(html) {
  const el = $("#error-banner");
  el.innerHTML = html;
  el.classList.remove("hidden");
}
function hideError() { $("#error-banner").classList.add("hidden"); }

/** "09:18:02" from an ISO timestamp. */
function fmtTime(iso) {
  const m = /T(\d\d:\d\d:\d\d)/.exec(iso || "");
  return m ? m[1] : (iso || "");
}

/** Relative expiry like "in 12m" / "3h ago". */
function relTime(iso, now) {
  const t = Date.parse(iso);
  if (isNaN(t)) return "";
  let d = Math.round((t - now) / 1000);
  const past = d < 0;
  d = Math.abs(d);
  let s;
  if (d < 90) s = d + "s";
  else if (d < 5400) s = Math.round(d / 60) + "m";
  else if (d < 129600) s = Math.round(d / 3600) + "h";
  else s = Math.round(d / 86400) + "d";
  return past ? s + " ago" : "in " + s;
}

/** Truncate a hash like "sha256:ab12f004..." keeping the scheme. */
function shortHash(h, n) {
  n = n || 10;
  const s = String(h || "");
  const i = s.indexOf(":");
  if (i >= 0 && s.length > i + 1 + n) return s.slice(0, i + 1 + n) + "\u2026";
  return s.length > n + 4 ? s.slice(0, n + 4) + "\u2026" : s;
}

function shortSig(sig) {
  const s = String(sig || "");
  return s.length > 20 ? s.slice(0, 12) + "\u2026" + s.slice(-8) : s;
}

function principalName(id) {
  const p = (state.data && state.data.principals || []).find((p) => p.id === id);
  return p ? p.display_name : id;
}

function branchById(id) {
  return (state.data && state.data.branches || []).find((b) => b.id === id);
}

function branchClass(branchId) {
  const b = branchById(branchId);
  const st = b ? b.status : "active";
  return "branch-" + (["main", "active", "merged", "discarded"].includes(st) ? st : "active");
}

function branchChip(branchId) {
  const b = branchById(branchId);
  const label = b ? b.name : branchId;
  return '<span class="chip branch-chip ' + branchClass(branchId) + '">' + escapeHtml(label) + "</span>";
}

/** Category for color-coding event kinds. */
function kindCategory(kind) {
  if (kind === "denial") return "denial";
  if (["policy_decision", "capability_request", "approval", "commit_revalidation"].includes(kind)) return "policy";
  if (["effect_proposed", "effect_prepared", "effect_committed"].includes(kind)) return "effect";
  if (["state_delta", "branch_forked", "branch_discarded", "branch_merged"].includes(kind)) return "state";
  return "neutral"; // objective, model_response, intent_declared, tool_invocation, observation
}

function kindBadge(kind) {
  return '<span class="kind-badge kindcat-' + kindCategory(kind) + '">' + escapeHtml(kind) + "</span>";
}

/** Compact human rendering of one lease constraint (serde-tagged form). */
function constraintText(param, c) {
  switch (c.kind) {
    case "equals": return param + " = " + JSON.stringify(c.value);
    case "one_of": return param + " in " + JSON.stringify(c.values);
    case "glob": return param + " matches " + c.pattern;
    case "prefix": return param + " starts-with " + c.prefix;
    case "max": return param + " <= " + c.max;
    case "forbidden": return param + " forbidden";
    default: return param + " " + JSON.stringify(c);
  }
}

/** A truncated monospace value with a copy button (full value copied). */
function hashField(value) {
  return (
    '<span class="hash-field"><code title="' + escapeHtml(value) + '">' +
    escapeHtml(shortHash(value, 12)) +
    '</code><button class="copy-btn" data-copy="' + escapeHtml(value) + '">copy</button></span>'
  );
}

function prettyJson(obj) {
  return escapeHtml(JSON.stringify(obj, null, 2));
}

/* ------------------------------------------------------------------ */
/* 5a. Timeline view                                                   */
/* ------------------------------------------------------------------ */

function renderTimeline() {
  const root = $("#view-timeline");
  const d = state.data;
  if (!d || !d.events || !d.events.length) {
    root.innerHTML = '<div class="empty-state">No events. Select an episode, or enable demo mode to explore the bundled trace.</div>';
    return;
  }

  const kinds = [...new Set(d.events.map((e) => e.kind))].sort();
  const branches = d.branches || [];

  let html =
    '<h2 class="view-title">Causal timeline</h2>' +
    '<p class="view-sub">Every kernel-mediated event in the episode, grouped by step. Click a row to expand its payload.</p>' +
    '<div class="filter-bar">' +
    '<span class="filter-label">filter</span>' +
    '<select id="filter-kind"><option value="">all kinds</option>' +
    kinds.map((k) => '<option value="' + k + '"' + (state.filters.kind === k ? " selected" : "") + ">" + k + "</option>").join("") +
    "</select>" +
    '<select id="filter-branch"><option value="">all branches</option>' +
    branches.map((b) => '<option value="' + b.id + '"' + (state.filters.branch === b.id ? " selected" : "") + ">" + escapeHtml(b.name) + "</option>").join("") +
    "</select></div>";

  // Sort by timestamp, then group consecutive events by step.
  const events = d.events
    .filter((e) => (!state.filters.kind || e.kind === state.filters.kind) &&
                   (!state.filters.branch || e.branch === state.filters.branch))
    .slice()
    .sort((a, b) => (a.ts < b.ts ? -1 : a.ts > b.ts ? 1 : 0));

  if (!events.length) {
    html += '<div class="empty-state">No events match the current filters.</div>';
    root.innerHTML = html;
    wireTimelineFilters();
    return;
  }

  let currentStep = null;
  let open = false;
  for (const ev of events) {
    if (ev.step !== currentStep) {
      if (open) html += "</div>";
      currentStep = ev.step;
      open = true;
      html += '<div class="step-group"><div class="step-header">' + escapeHtml(ev.step || "(no step)") + "</div>";
    }
    const expanded = state.expandedEvents.has(ev.id);
    html +=
      '<div class="event-row' + (expanded ? " expanded" : "") + '" data-event="' + escapeHtml(ev.id) + '">' +
      '<span class="event-ts">' + fmtTime(ev.ts) + "</span>" +
      branchChip(ev.branch) +
      '<span class="event-actor" title="' + escapeHtml(ev.actor) + '">' + escapeHtml(principalName(ev.actor)) + "</span>" +
      kindBadge(ev.kind) +
      '<span class="event-summary">' + escapeHtml(ev.summary) + "</span>" +
      "</div>";
    if (expanded) {
      html += '<pre class="event-payload">' + prettyJson(ev.payload) + "</pre>";
    }
  }
  if (open) html += "</div>";
  root.innerHTML = html;
  wireTimelineFilters();

  root.querySelectorAll(".event-row").forEach((row) => {
    row.addEventListener("click", () => {
      const id = row.dataset.event;
      if (state.expandedEvents.has(id)) state.expandedEvents.delete(id);
      else state.expandedEvents.add(id);
      renderTimeline();
    });
  });
}

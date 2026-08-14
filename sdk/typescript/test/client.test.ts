import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import http from "node:http";

import {
  ConnectorOp,
  DenialError,
  Kernel,
  KernelError,
  Shell,
  TransportError,
} from "../src/index.js";
import { makeServer, type MockState } from "./mockKernel.js";

let server: http.Server;
let state: MockState;
let kernel: Kernel;

before(async () => {
  const s = await makeServer();
  server = s.server;
  state = s.state;
  kernel = new Kernel(s.url, { backoffMs: 0, sleep: async () => {} });
});

after(() => {
  server.close();
});

test("healthz", async () => {
  const h = await kernel.healthz();
  assert.equal(h.status, "ok");
});

test("register principal", async () => {
  const principal = {
    id: "pr-bootstrap",
    kind: "agent" as const,
    display_name: "bootstrap",
    trust: "standard" as const,
  };
  assert.deepEqual(await kernel.registerPrincipal(principal), principal);
});

test("create episode (principal/objective) and execute a successful step", async () => {
  const ep = await kernel.createEpisode({
    principal: "pr-agent",
    objective: "fix issue 42",
  });
  assert.match(ep.episodeId, /^ep-/);
  assert.match(ep.branch, /^br-/);
  const res = await ep.execute(Shell("pytest"), { lease: "lease-abc" });
  assert.match(res.step, /^step-/);
  assert.equal(res.observation.kind, "success");
  if (res.observation.kind === "success") {
    assert.equal(res.observation.stdout_head, "12 passed");
    assert.equal(res.observation.exit_code, 0);
  }
  assert.match(res.state, /^st-/);
});

test("describe episode returns the wire EpisodeDescription", async () => {
  const ep = await kernel.createEpisode({ principal: "pr-agent" });
  const desc = await ep.describe();
  assert.equal(desc.episode, ep.episodeId);
  assert.equal(desc.root_branch, ep.branch);
  assert.equal(desc.created_by, "pr-agent");
  assert.ok(desc.branches.some((b) => b.id === ep.branch));
});

test("denied step is HTTP 403 but surfaces as a denied observation", async () => {
  const ep = await kernel.createEpisode({ principal: "pr-agent" });
  const res = await ep.execute(Shell("forbidden thing"), { lease: "lease-abc" });
  assert.equal(res.observation.kind, "denied");
  if (res.observation.kind === "denied") {
    assert.equal(res.observation.denial.code, "CAPABILITY_DENIED");
    assert.deepEqual(res.observation.denial.safe_alternatives, [
      "github.create_pull_request",
    ]);
  }
});

test("fork, diff, compare, merge, discard", async () => {
  const ep = await kernel.createEpisode({ principal: "pr-agent" });
  const branches = await ep.fork(3);
  assert.equal(branches.length, 3);
  const changes = await branches[0]!.diff();
  assert.equal(changes[0]?.op, "modified");
  if (changes[0]?.op === "modified") assert.equal(changes[0].path, "a.py");
  const cmp = await branches[0]!.compare(branches[1]!);
  assert.equal(cmp.base, "st-1");
  assert.deepEqual(cmp.changed_in_a, ["a.py"]);
  const node = await ep.merge(branches[0]!);
  assert.match(node.id, /^st-/);
  assert.equal(node.branch, ep.branch);
  const discarded = await branches[2]!.discard();
  assert.equal(discarded.discarded, branches[2]!.id);
});

test("connector op becomes a pending effect", async () => {
  const ep = await kernel.createEpisode({ principal: "pr-agent" });
  const res = await ep.execute(ConnectorOp("github", "create_pull_request", { base: "main" }), {
    lease: "lease-abc",
  });
  assert.equal(res.observation.kind, "effect_pending");
  if (res.observation.kind === "effect_pending") {
    assert.match(res.observation.effect, /^fx-/);
    assert.equal(res.observation.class, "compensatable");
  }
});

test("effect lifecycle: prepare, approve, commit yields a signed receipt", async () => {
  const ep = await kernel.createEpisode({ principal: "pr-agent" });
  const res = await ep.execute(ConnectorOp("github", "create_pull_request", {}), {
    lease: "lease-abc",
  });
  assert.equal(res.observation.kind, "effect_pending");
  const fxId = res.observation.kind === "effect_pending" ? res.observation.effect : "";
  const fx = kernel.effectHandle(await kernel.getEffect(fxId));
  const preview = await fx.prepare();
  assert.deepEqual(preview.preview, { will: "create PR" });
  const approved = await fx.approve("pr-human");
  assert.equal(approved.approved, fxId);
  const receipt = await fx.commit();
  assert.match(receipt.id, /^rcpt-/);
  assert.equal(receipt.body.contract_hash, "sha256:deadbeef");
  const fetched = await kernel.getReceipt(receipt.id);
  assert.equal(fetched.id, receipt.id);
});

test("commit before approval is a 409 WRONG_EFFECT_PHASE", async () => {
  const ep = await kernel.createEpisode({ principal: "pr-agent" });
  const res = await ep.execute(ConnectorOp("github", "create_pull_request", {}), {
    lease: "lease-abc",
  });
  const fxId = res.observation.kind === "effect_pending" ? res.observation.effect : "";
  await assert.rejects(
    () => kernel.commitEffect(fxId),
    (e: unknown) => {
      assert.ok(e instanceof KernelError);
      assert.equal(e.code, "WRONG_EFFECT_PHASE");
      assert.equal(e.status, 409);
      return true;
    },
  );
});

test("list effects filters by phase; recover returns resolutions", async () => {
  const all = await kernel.listEffects();
  assert.ok(all.length >= 1);
  const proposed = await kernel.listEffects("proposed");
  assert.ok(proposed.every((fx) => fx.phase.phase === "proposed"));
  const recovered = await kernel.recoverEffects();
  assert.deepEqual(recovered.resolutions, []);
});

test("capability denial carries safe alternatives and requestable scopes", async () => {
  await assert.rejects(
    () => kernel.requestCapability({ principal: "pr-agent", operation: "net.raw_socket" }),
    (e: unknown) => {
      assert.ok(e instanceof DenialError);
      assert.equal(e.denialCode, "CAPABILITY_DENIED");
      assert.deepEqual(e.safeAlternatives, ["github.create_pull_request"]);
      assert.equal(e.requestableScopes[0]?.operation, "net.http_read");
      assert.equal(e.escalationAllowed, true);
      return true;
    },
  );
});

test("capability grant (201), delegate (attenuate), subtree revoke", async () => {
  const lease = await kernel.requestCapability({
    principal: "pr-agent",
    operation: "github.create_pull_request",
    params: { repository: "org/repo" },
  });
  assert.match(lease.id, /^lease-/);
  const child = await kernel.delegateCapability({
    delegator: "pr-agent",
    parentLease: lease.id,
    delegatee: "pr-child",
    constraints: { repository: { kind: "equals", value: "org/repo" } },
    uses: 1,
    expiresAt: lease.expires_at,
  });
  assert.equal(child.parent_lease, lease.id);
  assert.equal(child.principal, "pr-child");
  const held = await kernel.capabilities("pr-child");
  assert.ok(held.some((l) => l.id === child.id));
  const revoked = await kernel.revokeCapability(lease.id);
  assert.ok(revoked.includes(child.id));
});

test("replay modes: audit, sandbox, live", async () => {
  const audit = await kernel.replayAudit({ seqFrom: 1, seqTo: 10 });
  assert.equal(audit.mode, "audit");
  assert.equal(audit.events[0]?.kind, "step_started");
  const report = await kernel.replaySandbox("step-1");
  assert.equal(report.workspace_match, true);
  assert.equal(report.replay_class, "filesystem_only");
  const ep = await kernel.createEpisode({ principal: "pr-agent" });
  const res = await ep.execute(ConnectorOp("github", "create_pull_request", {}), {
    lease: "lease-abc",
  });
  const fxId = res.observation.kind === "effect_pending" ? res.observation.effect : "";
  const receipt = await kernel.replayLive(fxId, "pr-human");
  assert.match(receipt.id, /^rcpt-/);
});

test("trace query returns raw ledger events", async () => {
  const events = await kernel.traceQuery({ episode: "ep-1", kind: "step_started", limit: 10 });
  assert.equal(events[0]?.kind, "step_started");
});

test("step explain and retry", async () => {
  const explanation = await kernel.explainStep("step-1");
  assert.equal(explanation.step, "step-1");
  assert.equal(explanation.events[0]?.kind, "step_started");
  const retried = await kernel.retryStep("step-1");
  assert.equal(retried.observation.kind, "success");
});

test("retries on 503, then surfaces KernelError when exhausted", async () => {
  state.flakyRemaining = 2;
  const ep = await kernel.createEpisode({ principal: "pr-agent" });
  assert.match(ep.episodeId, /^ep-/);

  state.flakyRemaining = 10;
  try {
    await assert.rejects(
      () => kernel.createEpisode({ principal: "pr-agent" }),
      (e: unknown) => {
        assert.ok(e instanceof KernelError);
        assert.equal(e.code, "BACKEND_UNAVAILABLE");
        assert.equal(e.status, 503);
        return true;
      },
    );
  } finally {
    state.flakyRemaining = 0;
  }
});

test("not found surfaces code and status", async () => {
  await assert.rejects(
    () => kernel.getEpisode("ep-nope"),
    (e: unknown) => {
      assert.ok(e instanceof KernelError);
      assert.equal(e.code, "NOT_FOUND");
      assert.equal(e.status, 404);
      return true;
    },
  );
});

test("a timeout aborts only its own request, not later ones", async () => {
  const fast = new Kernel(`http://127.0.0.1:${(server.address() as any).port}`, {
    timeoutMs: 50,
    backoffMs: 0,
    sleep: async () => {},
  });
  state.delayMs = 200;
  try {
    await assert.rejects(
      () => fast.healthz(),
      (e: unknown) => {
        assert.ok(e instanceof TransportError);
        assert.match(e.message, /timed out/);
        return true;
      },
    );
  } finally {
    state.delayMs = 0;
  }
  // Regression: a shared AbortController would leave the client wedged.
  const h = await fast.healthz();
  assert.equal(h.status, "ok");
});

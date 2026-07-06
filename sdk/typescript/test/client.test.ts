import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import http from "node:http";

import {
  ConnectorOp,
  DenialError,
  type EffectContract,
  Kernel,
  KernelError,
  Shell,
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

const contract: EffectContract = {
  operation: "github.create_pull_request",
  resource: "org/repo",
  arguments: { base: "main", head: "sandbox/fix" },
  preconditions: { base_head_sha: "abc123" },
  idempotency_key: "ep-1-step-1",
  class: "compensatable",
};

test("create episode and execute a successful step", async () => {
  const ep = await kernel.createEpisode({ title: "fix issue 42", owner: "pr-agent" });
  assert.match(ep.episodeId, /^ep-/);
  const res = await ep.execute(Shell("pytest"), { lease: "lease-abc" });
  assert.match(res.step, /^step-/);
  assert.equal(res.observation.kind, "success");
  if (res.observation.kind === "success") {
    assert.equal(res.observation.stdout_head, "12 passed");
    assert.equal(res.observation.exit_code, 0);
  }
  assert.match(res.produced_state ?? "", /^st-/);
});

test("denied step returns a structured denial observation", async () => {
  const ep = await kernel.createEpisode({ title: "t", owner: "pr-agent" });
  const res = await ep.execute(Shell("forbidden thing"), { lease: "lease-abc" });
  assert.equal(res.observation.kind, "denied");
  if (res.observation.kind === "denied") {
    assert.equal(res.observation.denial.code, "CAPABILITY_DENIED");
    assert.deepEqual(res.observation.denial.safe_alternatives, [
      "github.create_pull_request",
    ]);
  }
  assert.equal(res.produced_state, undefined); // no invisible state transition
});

test("fork, diff, compare, merge, discard", async () => {
  const ep = await kernel.createEpisode({ title: "t", owner: "pr-agent" });
  const branches = await ep.fork(3);
  assert.equal(branches.length, 3);
  assert.ok(branches.every((b) => b.branch.parent_branch === ep.id));
  const diff = await branches[0]!.diff();
  assert.equal(diff.summary, "1 file changed");
  assert.equal(diff.delta.files?.[0]?.op, "modified");
  const cmp = await branches[0]!.compare(branches[1]!);
  assert.deepEqual(cmp.conflicting_paths, ["a.py"]);
  const merged = await branches[0]!.merge(ep);
  assert.ok(merged.merged);
  const discarded = await branches[2]!.discard("lost the race");
  assert.equal(discarded.discarded, true);
});

test("connector op becomes a pending effect", async () => {
  const ep = await kernel.createEpisode({ title: "t", owner: "pr-agent" });
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
  const ep = await kernel.createEpisode({ title: "t", owner: "pr-agent" });
  const fx = await ep.proposeEffect(contract, { lease: "lease-abc" });
  const receipt = await fx.run(async (fx) => {
    const preview = await fx.prepare();
    assert.deepEqual(preview.preview, { will: "create PR" });
    await fx.approve("pr-human");
    return fx.commit();
  });
  assert.match(receipt.id, /^rcpt-/);
  assert.equal(receipt.body.contract_hash, "sha256:deadbeef");
  const fetched = await kernel.getReceipt(receipt.id);
  assert.equal(fetched.id, receipt.id);
});

test("uncommitted effect is aborted when run() exits", async () => {
  const ep = await kernel.createEpisode({ title: "t", owner: "pr-agent" });
  const fx = await ep.proposeEffect(contract);
  await fx.run(async (fx) => {
    await fx.prepare();
  });
  const effect = await kernel.getEffect(fx.id);
  assert.equal(effect.phase.phase, "aborted");
});

test("stale contract hash throws DenialError with STALE_AUTHORIZATION", async () => {
  const ep = await kernel.createEpisode({ title: "t", owner: "pr-agent" });
  const fx = await ep.proposeEffect(contract);
  await assert.rejects(
    () => fx.commit("sha256:wrong"),
    (e: unknown) => {
      assert.ok(e instanceof DenialError);
      assert.equal(e.denial.code, "STALE_AUTHORIZATION");
      return true;
    },
  );
  await fx.abort();
});

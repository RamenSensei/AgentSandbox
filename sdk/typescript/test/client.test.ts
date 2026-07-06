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

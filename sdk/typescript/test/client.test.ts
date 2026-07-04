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

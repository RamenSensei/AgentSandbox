/** Minimal mock kernel over node:http mirroring kernel/api/src/http.rs. */
import http from "node:http";
import { AddressInfo } from "node:net";

type J = Record<string, any>;

export interface MockState {
  counter: number;
  episodes: Map<string, J>;
  branches: Map<string, J>;
  effects: Map<string, J>;
  receipts: Map<string, J>;
  leases: Map<string, J>;
  flakyRemaining: number;
  /** Delay (ms) applied to every response while > 0. */
  delayMs: number;
}

const DENIAL = {
  code: "CAPABILITY_DENIED",
  attempted_operation: "net.raw_socket",
  reason: "credential may only be used by the typed GitHub connector",
  safe_alternatives: ["github.create_pull_request"],
  requestable_scopes: [
    {
      operation: "net.http_read",
      constraints: { domain: "api.github.com" },
      requires_human: false,
    },
  ],
  escalation_allowed: true,
};

const BUDGET = {
  cpu_ms: 1000,
  memory_bytes: 0,
  network_bytes: 0,
  tokens: 5,
  cost_micro_usd: 0,
  risk_units: 0,
};

export async function makeServer(): Promise<{
  server: http.Server;
  state: MockState;
  url: string;
}> {
  const state: MockState = {
    counter: 0,
    episodes: new Map(),
    branches: new Map(),
    effects: new Map(),
    receipts: new Map(),
    leases: new Map(),
    flakyRemaining: 0,
    delayMs: 0,
  };
  const nextId = (p: string) => `${p}-${++state.counter}`;

  const newEffect = (id: string, branch: string, proposer: string): J => ({
    id,
    contract: {
      operation: "github.create_pull_request",
      resource: "org/repo",
      arguments: {},
      preconditions: {},
      idempotency_key: "ep-1-step-1",
      class: "compensatable",
    },
    contract_hash: "sha256:deadbeef",
    proposer,
    branch,
    step: "",
    lease: "",
    phase: { phase: "proposed" },
    proposed_at: "2026-01-01T00:00:00Z",
  });

  const makeReceipt = (fx: J): J => ({
    id: nextId("rcpt"),
    body: {
      effect: fx.id,
      who: fx.proposer,
      operation: fx.contract.operation,
      resource: fx.contract.resource,
      contract_hash: fx.contract_hash,
      branch: fx.branch,
      step: fx.step,
      policy_epoch: 1,
      authorization_witness: "sha256:w",
      external_response_digest: "sha256:r",
      committed_at: "2026-01-01T00:00:00Z",
    },
    signature: "aa".repeat(32),
    key_id: "kernel-key-1",
  });

  const server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const respond = (status: number, payload: J | J[]) => {
        const raw = JSON.stringify(payload);
        res.writeHead(status, { "content-type": "application/json" });
        res.end(raw);
      };
      const send = (status: number, payload: J | J[]) => {
        if (state.delayMs > 0) setTimeout(() => respond(status, payload), state.delayMs);
        else respond(status, payload);
      };
      if (state.flakyRemaining > 0) {
        state.flakyRemaining--;
        send(503, { code: "BACKEND_UNAVAILABLE", message: "warming up" });
        return;
      }
      const body: J = chunks.length ? JSON.parse(Buffer.concat(chunks).toString()) : {};
      const [path, qs] = (req.url ?? "").split("?") as [string, string?];
      const query = new URLSearchParams(qs ?? "");
      const method = req.method ?? "GET";
      let m: RegExpMatchArray | null;

      if (method === "GET" && path === "/healthz") {
        send(200, { status: "ok", version: "1.0.0-mock" });
        return;
      }

      if (method === "POST" && path === "/v1/principals") {
        send(201, body);
        return;
      }

      if (method === "POST" && path === "/v1/episodes") {
        const ep = nextId("ep");
        const br = nextId("br");
        const root = nextId("st");
        state.episodes.set(ep, {
          episode: ep,
          root_branch: br,
          root_state: root,
          created_by: body.principal ?? "",
          objective: body.objective ?? "",
          remaining_budget: BUDGET,
        });
        state.branches.set(br, {
          id: br,
          episode: ep,
          forked_from: root,
          head: root,
          discarded: false,
          created_at: "2026-01-01T00:00:00Z",
        });
        send(201, { episode: ep, branch: br, root_state: root });
        return;
      }

      if (method === "GET" && (m = path.match(/^\/v1\/episodes\/(ep-[\w-]+)$/))) {
        const ep = state.episodes.get(m[1]!);
        if (!ep) return send(404, { code: "NOT_FOUND", message: m[1]! });
        const branches = [...state.branches.values()].filter((b) => b.episode === ep.episode);
        send(200, {
          episode: ep.episode,
          root_branch: ep.root_branch,
          root_state: ep.root_state,
          branches,
          created_by: ep.created_by,
          remaining_budget: ep.remaining_budget,
        });
        return;
      }

      if (method === "POST" && path === "/v1/steps/execute") {
        const kind = body.action.kind;
        const step = nextId("step");
        const branch = state.branches.get(body.branch);
        if (!branch) return send(404, { code: "NOT_FOUND", message: body.branch });
        if (kind.kind === "shell" && String(kind.command).includes("forbidden")) {
          send(403, {
            step,
            state: branch.head,
            observation: { kind: "denied", denial: DENIAL },
            error: { code: "DENIED", message: DENIAL.reason, denial: DENIAL },
          });
          return;
        }
        if (kind.kind === "connector_op") {
          const fx = nextId("fx");
          state.effects.set(fx, newEffect(fx, body.branch, body.principal));
          send(200, {
            step,
            state: branch.head,
            observation: {
              kind: "effect_pending",
              effect: fx,
              contract_hash: "sha256:deadbeef",
              class: "compensatable",
            },
          });
          return;
        }
        branch.head = nextId("st");
        send(200, {
          step,
          state: branch.head,
          observation: {
            kind: "success",
            summary: "ok",
            stdout_head: "12 passed",
            exit_code: 0,
            full_output: "sha256:abc",
            truncated: false,
          },
        });
        return;
      }

      if (method === "GET" && (m = path.match(/^\/v1\/steps\/(step-[\w-]+)\/explain$/))) {
        send(200, {
          step: m[1],
          episode: "ep-1",
          branch: "br-1",
          principal: "pr-agent",
          action: { kind: { kind: "shell", command: "pytest" } },
          policy_decisions: [],
          denial: null,
          state: "st-2",
          state_delta: null,
          observation: { kind: "success" },
          effects_proposed: [],
          events: [{ seq: 1, kind: "step_started" }],
        });
        return;
      }

      if (method === "POST" && /^\/v1\/steps\/step-[\w-]+\/retry$/.test(path)) {
        send(200, {
          step: nextId("step"),
          state: nextId("st"),
          observation: {
            kind: "success",
            summary: "ok",
            exit_code: 0,
            full_output: "sha256:abc",
            truncated: false,
          },
        });
        return;
      }

      if (method === "POST" && (m = path.match(/^\/v1\/branches\/(br-[\w-]+)\/fork$/))) {
        const parent = state.branches.get(m[1]!);
        if (!parent) return send(404, { code: "NOT_FOUND", message: m[1]! });
        const bid = nextId("br");
        const b = {
          id: bid,
          episode: parent.episode,
          parent_branch: parent.id,
          forked_from: parent.head,
          head: parent.head,
          discarded: false,
          created_at: "2026-01-01T00:00:00Z",
        };
        state.branches.set(bid, b);
        send(200, b);
        return;
      }

      if (method === "POST" && /^\/v1\/branches\/br-[\w-]+\/diff$/.test(path)) {
        send(200, [
          { op: "modified", path: "a.py", old_blob: "sha256:1", new_blob: "sha256:2" },
        ]);
        return;
      }

      if (method === "GET" && /^\/v1\/branches\/br-[\w-]+\/compare\/br-[\w-]+$/.test(path)) {
        send(200, { base: "st-1", changed_in_a: ["a.py"], changed_in_b: ["a.py"] });
        return;
      }

      if (method === "POST" && (m = path.match(/^\/v1\/branches\/(br-[\w-]+)\/merge$/))) {
        const dest = state.branches.get(m[1]!);
        if (!dest) return send(404, { code: "NOT_FOUND", message: m[1]! });
        const node = {
          id: nextId("st"),
          episode: dest.episode,
          branch: dest.id,
          parent: dest.head,
          merge_parent: state.branches.get(body.source)?.head,
          actor: body.actor,
          delta: { policy_epoch: 1 },
          workspace_root: "/tmp/ws",
          replay_class: "filesystem_only",
          created_at: "2026-01-01T00:00:00Z",
        };
        dest.head = node.id;
        send(200, node);
        return;
      }

      if (method === "POST" && (m = path.match(/^\/v1\/branches\/(br-[\w-]+)\/discard$/))) {
        const b = state.branches.get(m[1]!);
        if (b) b.discarded = true;
        send(200, { discarded: m[1]! });
        return;
      }

      if (method === "POST" && path === "/v1/capabilities/request") {
        if (body.operation === "net.raw_socket") {
          send(403, { code: "DENIED", message: "denied", denial: DENIAL });
          return;
        }
        const id = nextId("lease");
        const lease = {
          id,
          principal: body.principal,
          operation: body.operation,
          constraints: {},
          remaining_uses: 1,
          issued_at: "2026-01-01T00:00:00Z",
          expires_at: "2026-01-01T01:00:00Z",
          budget: BUDGET,
          revoked: false,
        };
        state.leases.set(id, lease);
        send(201, lease);
        return;
      }

      if (method === "POST" && path === "/v1/capabilities/delegate") {
        const parent = state.leases.get(body.parent_lease);
        if (!parent) return send(404, { code: "NOT_FOUND", message: body.parent_lease });
        const id = nextId("lease");
        const lease = {
          ...parent,
          id,
          principal: body.delegatee,
          parent_lease: parent.id,
          constraints: body.constraints ?? {},
          remaining_uses: body.uses,
          expires_at: body.expires_at,
        };
        state.leases.set(id, lease);
        send(201, lease);
        return;
      }

      if (method === "POST" && path === "/v1/capabilities/revoke") {
        const lease = state.leases.get(body.lease);
        const revoked: string[] = [];
        if (lease) {
          lease.revoked = true;
          revoked.push(lease.id);
          for (const other of state.leases.values()) {
            if (other.parent_lease === lease.id) {
              other.revoked = true;
              revoked.push(other.id);
            }
          }
        }
        send(200, { revoked });
        return;
      }

      if (method === "GET" && (m = path.match(/^\/v1\/capabilities\/(pr-[\w-]+)$/))) {
        const leases = [...state.leases.values()].filter(
          (l) => l.principal === m![1] && !l.revoked,
        );
        send(200, leases);
        return;
      }

      if (method === "GET" && path === "/v1/effects") {
        const phase = query.get("phase");
        const out = [...state.effects.values()].filter(
          (fx) => !phase || fx.phase.phase === phase,
        );
        send(200, out);
        return;
      }

      if (method === "POST" && path === "/v1/effects/recover") {
        send(200, { resolutions: [] });
        return;
      }

      if ((m = path.match(/^\/v1\/effects\/(fx-[\w-]+)(?:\/(\w+))?$/))) {
        const fx = state.effects.get(m[1]!);
        if (!fx) return send(404, { code: "NOT_FOUND", message: m[1]! });
        const verb = m[2];
        if (method === "GET" && !verb) return send(200, fx);
        if (method === "POST" && verb === "prepare") {
          fx.phase = { phase: "prepared", preview: { will: "create PR" } };
          send(200, {
            preview: { will: "create PR" },
            observed_preconditions: { base_head_sha: "abc123" },
          });
          return;
        }
        if (method === "POST" && verb === "approve") {
          fx.phase = {
            phase: "approved",
            approver: body.approver,
            approved_at: "2026-01-01T00:00:00Z",
            policy_epoch: 1,
          };
          send(200, { approved: fx.id });
          return;
        }
        if (method === "POST" && verb === "commit") {
          if (fx.phase.phase !== "approved") {
            send(409, {
              code: "WRONG_EFFECT_PHASE",
              message: `commit requires approved, effect is ${fx.phase.phase}`,
            });
            return;
          }
          const receipt = makeReceipt(fx);
          state.receipts.set(receipt.id, receipt);
          fx.phase = { phase: "committed", receipt: receipt.id };
          send(200, receipt);
          return;
        }
        if (method === "POST" && verb === "compensate") {
          const receipt = makeReceipt(fx);
          state.receipts.set(receipt.id, receipt);
          fx.phase = { phase: "compensated", compensating_receipt: receipt.id };
          send(200, receipt);
          return;
        }
        if (method === "POST" && verb === "resolve") {
          send(200, { resolved: fx.id, receipt: null });
          return;
        }
      }

      if (method === "GET" && path === "/v1/trace/query") {
        send(200, [
          { seq: 1, kind: "step_started" },
          { seq: 2, kind: "step_finished" },
        ]);
        return;
      }

      if (method === "POST" && (m = path.match(/^\/v1\/replay\/(\w+)$/))) {
        const mode = m[1];
        if (mode === "audit") {
          send(200, { mode: "audit", events: [{ seq: 1, kind: "step_started" }] });
          return;
        }
        if (mode === "sandbox") {
          if (!body.step) {
            send(500, { code: "OTHER", message: "sandbox replay requires `step`" });
            return;
          }
          send(200, {
            step: body.step,
            original_exit_code: 0,
            rerun_exit_code: 0,
            workspace_match: true,
            replay_class: "filesystem_only",
          });
          return;
        }
        if (mode === "live") {
          const fx = state.effects.get(body.effect);
          if (!fx) return send(404, { code: "NOT_FOUND", message: String(body.effect) });
          const receipt = makeReceipt(fx);
          state.receipts.set(receipt.id, receipt);
          send(200, receipt);
          return;
        }
        send(400, { code: "INVALID_ID", message: `expected audit|sandbox|live, got ${mode}` });
        return;
      }

      if (method === "GET" && (m = path.match(/^\/v1\/receipts\/(rcpt-[\w-]+)$/))) {
        const rcpt = state.receipts.get(m[1]!);
        if (rcpt) send(200, rcpt);
        else send(404, { code: "NOT_FOUND", message: m[1]! });
        return;
      }

      send(404, { code: "NOT_FOUND", message: `no route ${method} ${path}` });
    });
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  return { server, state, url: `http://127.0.0.1:${port}` };
}

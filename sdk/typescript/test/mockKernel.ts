/** Minimal mock kernel over node:http for tests. */
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
  };
  const nextId = (p: string) => `${p}-${++state.counter}`;

  const newEffect = (id: string, body: J): J => ({
    id,
    contract: body.contract ?? {
      operation: "github.create_pull_request",
      resource: "org/repo",
      arguments: {},
      preconditions: {},
      idempotency_key: "ep-1-step-1",
      class: "compensatable",
    },
    contract_hash: "sha256:deadbeef",
    proposer: body.proposer ?? "pr-agent",
    branch: body.branch ?? "br-1",
    step: body.step ?? "",
    lease: body.lease ?? "",
    phase: { phase: "proposed" },
    proposed_at: "2026-01-01T00:00:00Z",
  });

  const server = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const send = (status: number, payload: J) => {
        const raw = JSON.stringify(payload);
        res.writeHead(status, { "content-type": "application/json" });
        res.end(raw);
      };
      if (state.flakyRemaining > 0) {
        state.flakyRemaining--;
        send(503, { code: "BACKEND_UNAVAILABLE", message: "warming up" });
        return;
      }
      const body: J = chunks.length ? JSON.parse(Buffer.concat(chunks).toString()) : {};
      const path = (req.url ?? "").split("?")[0]!;
      const method = req.method ?? "GET";
      let m: RegExpMatchArray | null;

      if (method === "POST" && path === "/v1/episodes") {
        const ep = nextId("ep");
        const br = nextId("br");
        const root = nextId("st");
        const episode = {
          id: ep,
          title: body.title ?? "",
          owner: body.owner ?? "",
          root_state: root,
          main_branch: br,
          budget: body.budget ?? BUDGET,
          created_at: "2026-01-01T00:00:00Z",
        };
        const branch = {
          id: br,
          episode: ep,
          forked_from: root,
          head: root,
          discarded: false,
          created_at: "2026-01-01T00:00:00Z",
        };
        state.episodes.set(ep, episode);
        state.branches.set(br, branch);
        send(201, { episode, main_branch: branch });
        return;
      }

      if (method === "GET" && (m = path.match(/^\/v1\/episodes\/(ep-[\w-]+)$/))) {
        const ep = state.episodes.get(m[1]!);
        if (!ep) return send(404, { code: "NOT_FOUND", message: m[1]! });
        const branches = [...state.branches.values()].filter((b) => b.episode === ep.id);
        send(200, {
          episode: ep,
          branches,
          step_count: 0,
          pending_effects: 0,
          budget_remaining: ep.budget,
        });
        return;
      }

      if (method === "POST" && path === "/v1/steps/execute") {
        const kind = body.action.kind;
        const step = nextId("step");
        if (kind.kind === "shell" && String(kind.command).includes("forbidden")) {
          send(200, { step, observation: { kind: "denied", denial: DENIAL }, usage: BUDGET });
          return;
        }
        if (kind.kind === "connector_op") {
          const fx = nextId("fx");
          state.effects.set(fx, newEffect(fx, body));
          send(200, {
            step,
            observation: {
              kind: "effect_pending",
              effect: fx,
              contract_hash: "sha256:deadbeef",
              class: "compensatable",
            },
            usage: BUDGET,
          });
          return;
        }
        const st = nextId("st");
        send(200, {
          step,
          observation: {
            kind: "success",
            summary: "ok",
            stdout_head: "12 passed",
            exit_code: 0,
            full_output: "sha256:abc",
            truncated: false,
          },
          produced_state: st,
          usage: BUDGET,
        });
        return;
      }

      if (method === "POST" && (m = path.match(/^\/v1\/branches\/(br-[\w-]+)\/fork$/))) {
        const parent = state.branches.get(m[1]!)!;
        const out: J[] = [];
        for (let i = 0; i < (body.count ?? 1); i++) {
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
          out.push(b);
        }
        send(200, { branches: out });
        return;
      }

      if (method === "POST" && /^\/v1\/branches\/br-[\w-]+\/diff$/.test(path)) {
        send(200, {
          delta: {
            files: [{ op: "modified", path: "a.py", old_blob: "sha256:1", new_blob: "sha256:2" }],
            policy_epoch: 3,
          },
          summary: "1 file changed",
        });
        return;
      }

      if (method === "GET" && /^\/v1\/branches\/br-[\w-]+\/compare\/br-[\w-]+$/.test(path)) {
        send(200, {
          common_ancestor: "st-1",
          left_delta: { policy_epoch: 1 },
          right_delta: { policy_epoch: 1 },
          conflicting_paths: ["a.py"],
        });
        return;
      }

      if (method === "POST" && /^\/v1\/branches\/br-[\w-]+\/merge$/.test(path)) {
        send(200, { merged: { id: nextId("st"), branch: body.into } });
        return;
      }

      if (method === "POST" && (m = path.match(/^\/v1\/branches\/(br-[\w-]+)\/discard$/))) {
        const b = state.branches.get(m[1]!)!;
        b.discarded = true;
        send(200, b);
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
          constraints: body.constraints ?? {},
          remaining_uses: body.uses ?? 1,
          issued_at: "2026-01-01T00:00:00Z",
          expires_at: body.expires_at ?? "2026-01-01T01:00:00Z",
          budget: BUDGET,
          revoked: false,
        };
        state.leases.set(id, lease);
        send(200, { lease });
        return;
      }

      if (method === "POST" && path === "/v1/capabilities/delegate") {
        const parent = state.leases.get(body.parent_lease)!;
        const id = nextId("lease");
        const lease = {
          ...parent,
          id,
          principal: body.child_principal,
          parent_lease: parent.id,
          constraints: body.constraints,
          remaining_uses: body.uses,
        };
        state.leases.set(id, lease);
        send(200, lease);
        return;
      }

      if (method === "POST" && path === "/v1/capabilities/revoke") {
        const lease = state.leases.get(body.lease);
        const revoked: string[] = [];
        if (lease) {
          lease.revoked = true;
          revoked.push(lease.id);
          if (body.cascade) {
            for (const other of state.leases.values()) {
              if (other.parent_lease === lease.id) {
                other.revoked = true;
                revoked.push(other.id);
              }
            }
          }
        }
        send(200, { revoked_leases: revoked });
        return;
      }

      if (method === "GET" && (m = path.match(/^\/v1\/capabilities\/(pr-[\w-]+)$/))) {
        const leases = [...state.leases.values()].filter((l) => l.principal === m![1]);
        send(200, { leases });
        return;
      }

      if (method === "POST" && path === "/v1/effects") {
        const id = nextId("fx");
        const fx = newEffect(id, body);
        state.effects.set(id, fx);
        send(201, { effect: fx });
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
            effect: fx,
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
          send(200, fx);
          return;
        }
        if (method === "POST" && verb === "commit") {
          if (body.expected_contract_hash !== fx.contract_hash) {
            send(403, {
              code: "DENIED",
              message: "stale contract hash",
              denial: { ...DENIAL, code: "STALE_AUTHORIZATION" },
            });
            return;
          }
          const rcpt = nextId("rcpt");
          const receipt = {
            id: rcpt,
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
          };
          state.receipts.set(rcpt, receipt);
          fx.phase = { phase: "committed", receipt: rcpt };
          send(200, { receipt });
          return;
        }
        if (method === "POST" && verb === "abort") {
          fx.phase = { phase: "aborted", reason: body.reason ?? "" };
          send(200, fx);
          return;
        }
        if (method === "POST" && verb === "compensate") {
          const rcpt = nextId("rcpt");
          const receipt = {
            id: rcpt,
            body: { effect: fx.id },
            signature: "bb".repeat(32),
            key_id: "kernel-key-1",
          };
          state.receipts.set(rcpt, receipt);
          fx.phase = { phase: "compensated", compensating_receipt: rcpt };
          send(200, receipt);
          return;
        }
      }

      if (method === "GET" && path === "/v1/trace/query") {
        send(200, { entries: [], next_page_token: "" });
        return;
      }

      if (method === "POST" && (m = path.match(/^\/v1\/replay\/(audit|sandbox|live)$/))) {
        send(200, {
          episode: body.episode,
          mode: m[1],
          effective_class: "filesystem_only",
          steps_replayed: 4,
          divergences: [],
          completed_at: "2026-01-01T00:00:00Z",
        });
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

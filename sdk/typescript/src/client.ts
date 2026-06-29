/**
 * HTTP client for the AgentKernel Execution Protocol (JSON binding).
 * Zero runtime dependencies; uses global fetch (Node >= 18, browsers).
 */

import { DenialError, KernelError, TransportError } from "./errors.js";
import type {
  ActionKind,
  Branch,
  BranchCompareResponse,
  BranchDiffResponse,
  BranchMergeResponse,
  CapabilityLease,
  Constraint,
  EffectContract,
  EffectPrepareResponse,
  Episode,
  EpisodeCreateResponse,
  EpisodeDescribeResponse,
  ErrorEnvelope,
  Json,
  PendingEffect,
  Receipt,
  ReplayMode,
  ReplayReport,
  ResourceBudget,
  StepResult,
  TraceQueryResponse,
} from "./types.js";
import { stepDefaultBudget } from "./types.js";

export interface KernelOptions {
  token?: string;
  /** Retries on network errors and 502/503/504. Default 3. */
  maxRetries?: number;
  /** Base backoff in ms, doubled per attempt. Default 250. */
  backoffMs?: number;
  fetch?: typeof fetch;
  /** Injectable sleep for tests. */
  sleep?: (ms: number) => Promise<void>;
}

const RETRYABLE = new Set([502, 503, 504]);

export class Kernel {
  readonly baseUrl: string;
  private readonly opts: Required<Pick<KernelOptions, "maxRetries" | "backoffMs">> &
    KernelOptions;

  constructor(baseUrl: string, options: KernelOptions = {}) {
    this.baseUrl = baseUrl.replace(/\/+$/, "");
    this.opts = { maxRetries: 3, backoffMs: 250, ...options };
  }

  // -- transport --------------------------------------------------------

  async request<T>(
    method: string,
    path: string,
    body?: unknown,
    query?: Record<string, string | number | undefined>,
  ): Promise<T> {
    let url = this.baseUrl + path;
    if (query) {
      const params = new URLSearchParams();
      for (const [k, v] of Object.entries(query)) {
        if (v !== undefined) params.set(k, String(v));
      }
      const qs = params.toString();
      if (qs) url += `?${qs}`;
    }
    const headers: Record<string, string> = {
      "content-type": "application/json",
      accept: "application/json",
    };
    if (this.opts.token) headers.authorization = `Bearer ${this.opts.token}`;
    const doFetch = this.opts.fetch ?? fetch;
    const sleep =
      this.opts.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));

    let lastError: unknown;
    for (let attempt = 0; attempt <= this.opts.maxRetries; attempt++) {
      let res: Response;
      try {
        res = await doFetch(url, {
          method,
          headers,
          body: body === undefined ? null : JSON.stringify(body),
        });
      } catch (e) {
        lastError = e;
        if (attempt < this.opts.maxRetries) {
          await sleep(this.opts.backoffMs * 2 ** attempt);
          continue;
        }
        throw new TransportError(`kernel unreachable at ${url}: ${String(e)}`, e);
      }
      if (RETRYABLE.has(res.status) && attempt < this.opts.maxRetries) {
        await sleep(this.opts.backoffMs * 2 ** attempt);
        continue;
      }
      return await Kernel.decode<T>(res);
    }
    throw new TransportError(`kernel unreachable at ${url}: ${String(lastError)}`, lastError);
  }

  private static async decode<T>(res: Response): Promise<T> {
    let payload: unknown;
    const text = await res.text();
    try {
      payload = text ? JSON.parse(text) : {};
    } catch {
      payload = { code: "OTHER", message: text };
    }
    if (res.ok) return payload as T;
    const env = payload as ErrorEnvelope;
    if (env.denial) throw new DenialError(env.denial, env.message, res.status);
    throw new KernelError(env.code ?? "OTHER", env.message ?? text, res.status);
  }

  // -- episodes ---------------------------------------------------------

  async createEpisode(params: {
    title: string;
    owner: string;
    budget?: ResourceBudget;
    workspaceRoot?: string;
  }): Promise<EpisodeHandle> {
    const body: Record<string, unknown> = {
      title: params.title,
      owner: params.owner,
      budget: params.budget ?? stepDefaultBudget(),
    };
    if (params.workspaceRoot !== undefined) body.workspace_root = params.workspaceRoot;
    const resp = await this.request<EpisodeCreateResponse>("POST", "/v1/episodes", body);
    return new EpisodeHandle(this, resp.episode, resp.main_branch);
  }

  async getEpisode(episodeId: string): Promise<EpisodeHandle> {
    const resp = await this.request<EpisodeDescribeResponse>(
      "GET",
      `/v1/episodes/${episodeId}`,
    );
    const main =
      resp.branches.find((b) => b.id === resp.episode.main_branch) ?? resp.branches[0];
    if (!main) throw new KernelError("OTHER", `episode ${episodeId} has no branches`);
    return new EpisodeHandle(this, resp.episode, main);
  }

  // -- capabilities -----------------------------------------------------

  async capabilities(principal: string, namespace?: string): Promise<CapabilityLease[]> {
    const resp = await this.request<{ leases: CapabilityLease[] }>(
      "GET",
      `/v1/capabilities/${principal}`,
      undefined,
      { namespace },
    );
    return resp.leases;
  }

  async requestCapability(params: {
    principal: string;
    operation: string;
    constraints?: Record<string, Constraint>;
    uses?: number;
    expiresAt?: string;
    budget?: ResourceBudget;
    boundBranch?: string;
    justification?: string;
  }): Promise<CapabilityLease> {
    const body: Record<string, unknown> = {
      principal: params.principal,
      operation: params.operation,
      constraints: params.constraints ?? {},
      uses: params.uses ?? 1,
      justification: params.justification ?? "",
    };
    if (params.expiresAt !== undefined) body.expires_at = params.expiresAt;
    if (params.budget !== undefined) body.budget = params.budget;
    if (params.boundBranch !== undefined) body.bound_branch = params.boundBranch;
    const resp = await this.request<{
      lease?: CapabilityLease;
      denial?: import("./types.js").Denial;
      pending_approval_id?: string;
    }>("POST", "/v1/capabilities/request", body);
    if (resp.denial) throw new DenialError(resp.denial);
    if (resp.pending_approval_id !== undefined) {
      throw new KernelError(
        "PENDING_APPROVAL",
        `awaiting human approval: ${resp.pending_approval_id}`,
        202,
      );
    }
    if (!resp.lease) throw new KernelError("OTHER", "malformed capability response");
    return resp.lease;
  }

  async delegateCapability(params: {
    parentLease: string;
    childPrincipal: string;
    constraints: Record<string, Constraint>;
    uses: number;
    expiresAt: string;
    budget?: ResourceBudget;
  }): Promise<CapabilityLease> {
    return this.request<CapabilityLease>("POST", "/v1/capabilities/delegate", {
      parent_lease: params.parentLease,
      child_principal: params.childPrincipal,
      constraints: params.constraints,
      uses: params.uses,
      expires_at: params.expiresAt,
      budget: params.budget ?? stepDefaultBudget(),
    });
  }

  async revokeCapability(
    lease: string,
    opts: { cascade?: boolean; reason?: string } = {},
  ): Promise<string[]> {
    const resp = await this.request<{ revoked_leases: string[] }>(
      "POST",
      "/v1/capabilities/revoke",
      { lease, cascade: opts.cascade ?? false, reason: opts.reason ?? "" },
    );
    return resp.revoked_leases;
  }

  // -- trace / replay / receipts ---------------------------------------

  async traceQuery(
    query: string,
    opts: { episode?: string; limit?: number; pageToken?: string } = {},
  ): Promise<TraceQueryResponse> {
    return this.request<TraceQueryResponse>("GET", "/v1/trace/query", undefined, {
      q: query,
      episode: opts.episode,
      limit: opts.limit,
      page_token: opts.pageToken,
    });
  }

  async replay(
    mode: ReplayMode,
    episode: string,
    opts: { fromStep?: string; toStep?: string } = {},
  ): Promise<ReplayReport> {
    const body: Record<string, unknown> = { episode };
    if (opts.fromStep !== undefined) body.from_step = opts.fromStep;
    if (opts.toStep !== undefined) body.to_step = opts.toStep;
    return this.request<ReplayReport>("POST", `/v1/replay/${mode}`, body);
  }

  async getReceipt(receiptId: string): Promise<Receipt> {
    return this.request<Receipt>("GET", `/v1/receipts/${receiptId}`);
  }

  async getEffect(effectId: string): Promise<PendingEffect> {
    return this.request<PendingEffect>("GET", `/v1/effects/${effectId}`);
  }
}

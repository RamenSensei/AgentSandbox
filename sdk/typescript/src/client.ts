/**
 * HTTP client for the AgentKernel Execution Protocol (JSON binding),
 * matching the routes implemented in kernel/api/src/http.rs.
 * Zero runtime dependencies; uses global fetch (Node >= 18, browsers).
 */

import { DenialError, KernelError, TransportError } from "./errors.js";
import type {
  ActionKind,
  AutoStepResult,
  Branch,
  BranchCompareResponse,
  CapabilityLease,
  Constraint,
  EffectPrepareResponse,
  EnvelopeReport,
  EnvelopeRequest,
  EpisodeCreateResponse,
  EpisodeDescription,
  ErrorEnvelope,
  FileChange,
  Json,
  LedgerEvent,
  OperatorResolution,
  PendingEffect,
  Principal,
  RawGrep,
  RawPage,
  Receipt,
  ReplayAuditResponse,
  ReplaySandboxReport,
  ResourceBudget,
  StateNode,
  StepExplanation,
  StepResult,
} from "./types.js";
import { stepDefaultBudget } from "./types.js";

export interface KernelOptions {
  token?: string;
  /** Retries on network errors and 502/503/504. Default 3. */
  maxRetries?: number;
  /** Base backoff in ms, doubled per attempt. Default 250. */
  backoffMs?: number;
  /** Per-request timeout in ms. Default 30000. */
  timeoutMs?: number;
  fetch?: typeof fetch;
  /** Injectable sleep for tests. */
  sleep?: (ms: number) => Promise<void>;
}

const RETRYABLE = new Set([502, 503, 504]);

export class Kernel {
  readonly baseUrl: string;
  private readonly opts: Required<
    Pick<KernelOptions, "maxRetries" | "backoffMs" | "timeoutMs">
  > &
    KernelOptions;

  constructor(baseUrl: string, options: KernelOptions = {}) {
    this.baseUrl = baseUrl.replace(/\/+$/, "");
    this.opts = { maxRetries: 3, backoffMs: 250, timeoutMs: 30_000, ...options };
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
      // A fresh controller per attempt: a timeout must abort only this
      // request, never concurrent or subsequent ones.
      const controller = new AbortController();
      let timedOut = false;
      const timer = setTimeout(() => {
        timedOut = true;
        controller.abort();
      }, this.opts.timeoutMs);
      let res: Response;
      try {
        res = await doFetch(url, {
          method,
          headers,
          body: body === undefined ? null : JSON.stringify(body),
          signal: controller.signal,
        });
      } catch (e) {
        if (timedOut) {
          throw new TransportError(
            `request to ${url} timed out after ${this.opts.timeoutMs}ms`,
            e,
          );
        }
        lastError = e;
        if (attempt < this.opts.maxRetries) {
          await sleep(this.opts.backoffMs * 2 ** attempt);
          continue;
        }
        throw new TransportError(`kernel unreachable at ${url}: ${String(e)}`, e);
      } finally {
        clearTimeout(timer);
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
    const p = payload as Record<string, unknown>;
    // A denied-but-recorded step is HTTP 403 with the recorded step,
    // state and observation alongside the error envelope. Surface it as a
    // normal result so callers see the "denied" observation.
    if (res.status === 403 && p.step !== undefined && p.observation !== undefined) {
      return payload as T;
    }
    const env = payload as ErrorEnvelope;
    if (env.denial) throw new DenialError(env.denial, env.message, res.status);
    throw new KernelError(env.code ?? "OTHER", env.message ?? text, res.status);
  }

  // -- health -----------------------------------------------------------

  async healthz(): Promise<{ status: string; version: string }> {
    return this.request("GET", "/healthz");
  }

  // -- principals ------------------------------------------------------

  /** POST /v1/principals — bootstrap a durable identity. Admin-only when
   * server authentication is enabled. */
  async registerPrincipal(principal: Principal): Promise<Principal> {
    return this.request("POST", "/v1/principals", principal);
  }

  // -- episodes ---------------------------------------------------------

  /** POST /v1/episodes — create an episode with its root state and main
   * branch. */
  async createEpisode(params: {
    principal: string;
    objective?: string;
    workspace?: string;
  }): Promise<EpisodeHandle> {
    const body: Record<string, unknown> = {
      principal: params.principal,
      objective: params.objective ?? "",
    };
    if (params.workspace !== undefined) body.workspace = params.workspace;
    const resp = await this.request<EpisodeCreateResponse>("POST", "/v1/episodes", body);
    return new EpisodeHandle(this, resp.episode, params.principal, resp.branch);
  }

  /** GET /v1/episodes/{id} */
  async describeEpisode(episodeId: string): Promise<EpisodeDescription> {
    return this.request<EpisodeDescription>("GET", `/v1/episodes/${episodeId}`);
  }

  async getEpisode(episodeId: string): Promise<EpisodeHandle> {
    const desc = await this.describeEpisode(episodeId);
    return new EpisodeHandle(this, desc.episode, desc.created_by, desc.root_branch);
  }

  // -- steps ------------------------------------------------------------

  /** POST /v1/steps/execute */
  async executeStep(params: {
    principal: string;
    branch: string;
    action: ActionKind;
    lease?: string | undefined;
    intentHint?: string | undefined;
    budget?: ResourceBudget | undefined;
  }): Promise<StepResult> {
    const action: Record<string, unknown> = {
      kind: params.action,
      lease: params.lease ?? "",
      budget: params.budget ?? stepDefaultBudget(),
    };
    if (params.intentHint !== undefined) action.intent_hint = params.intentHint;
    return this.request<StepResult>("POST", "/v1/steps/execute", {
      principal: params.principal,
      branch: params.branch,
      action,
    });
  }

  /** GET /v1/steps/{id}/explain */
  async explainStep(stepId: string): Promise<StepExplanation> {
    return this.request<StepExplanation>("GET", `/v1/steps/${stepId}/explain`);
  }

  /** POST /v1/steps/execute_auto — execute with automatic lease
   * resolution: the kernel finds (or mints via policy) a lease for the
   * action and clamps the budget into its envelope. The recommended call
   * for agent loops: no lease bookkeeping. */
  async executeStepAuto(params: {
    principal: string;
    branch: string;
    kind: ActionKind;
    intentHint?: string | undefined;
    budget?: ResourceBudget | undefined;
  }): Promise<AutoStepResult> {
    const body: Record<string, unknown> = {
      principal: params.principal,
      branch: params.branch,
      kind: params.kind,
    };
    if (params.intentHint !== undefined) body.intent_hint = params.intentHint;
    if (params.budget !== undefined) body.budget = params.budget;
    return this.request<AutoStepResult>("POST", "/v1/steps/execute_auto", body);
  }

  // -- raw output -------------------------------------------------------

  /** GET /v1/raw/{hash} — one page of a full recorded output blob (the
   * `full_output` hash every observation carries). */
  async fetchRaw(
    contentHash: string,
    opts: { offset?: number; limit?: number } = {},
  ): Promise<RawPage> {
    const query = new URLSearchParams();
    if (opts.offset !== undefined) query.set("offset", String(opts.offset));
    if (opts.limit !== undefined) query.set("limit", String(opts.limit));
    const qs = query.toString();
    return this.request<RawPage>("GET", `/v1/raw/${contentHash}${qs ? `?${qs}` : ""}`);
  }

  /** GET /v1/raw/{hash}?grep=... — substring line search with byte offsets. */
  async grepRaw(contentHash: string, pattern: string): Promise<RawGrep> {
    return this.request<RawGrep>(
      "GET",
      `/v1/raw/${contentHash}?grep=${encodeURIComponent(pattern)}`,
    );
  }

  /** POST /v1/steps/{id}/retry */
  async retryStep(stepId: string): Promise<StepResult> {
    return this.request<StepResult>("POST", `/v1/steps/${stepId}/retry`);
  }

  // -- branches ---------------------------------------------------------

  /** POST /v1/branches/{id}/fork — forks one sibling branch. */
  async forkBranch(branchId: string): Promise<Branch> {
    return this.request<Branch>("POST", `/v1/branches/${branchId}/fork`);
  }

  /** POST /v1/branches/{id}/diff */
  async diffBranch(branchId: string, since?: string): Promise<FileChange[]> {
    return this.request<FileChange[]>(
      "POST",
      `/v1/branches/${branchId}/diff`,
      since !== undefined ? { since } : {},
    );
  }

  /** POST /v1/branches/{id}/merge — merges `source` into `branchId`. */
  async mergeBranch(branchId: string, source: string, actor: string): Promise<StateNode> {
    return this.request<StateNode>("POST", `/v1/branches/${branchId}/merge`, {
      source,
      actor,
    });
  }

  /** POST /v1/branches/{id}/discard */
  async discardBranch(branchId: string): Promise<{ discarded: string }> {
    return this.request<{ discarded: string }>("POST", `/v1/branches/${branchId}/discard`);
  }

  /** GET /v1/branches/{a}/compare/{b} */
  async compareBranches(a: string, b: string): Promise<BranchCompareResponse> {
    return this.request<BranchCompareResponse>("GET", `/v1/branches/${a}/compare/${b}`);
  }

  // -- capabilities -----------------------------------------------------

  /** GET /v1/capabilities/{principal} — active leases. */
  async capabilities(principal: string): Promise<CapabilityLease[]> {
    return this.request<CapabilityLease[]>("GET", `/v1/capabilities/${principal}`);
  }

  /** POST /v1/capabilities/request — 201 with the granted lease; policy
   * denials throw DenialError. */
  async requestCapability(params: {
    principal: string;
    operation: string;
    params?: Json;
    branch?: string;
  }): Promise<CapabilityLease> {
    const body: Record<string, unknown> = {
      principal: params.principal,
      operation: params.operation,
      params: params.params ?? {},
    };
    if (params.branch !== undefined) body.branch = params.branch;
    return this.request<CapabilityLease>("POST", "/v1/capabilities/request", body);
  }

  /** POST /v1/capabilities/compile_envelope — request every capability a
   * task needs in one call, before the first step. Allowed items mint
   * leases immediately (the same leases `executeStepAuto` resolves);
   * items needing a human or refused come back as structured denials
   * inside the report — policy outcomes never throw. */
  async compileEnvelope(params: {
    principal: string;
    requests: EnvelopeRequest[];
    branch?: string;
  }): Promise<EnvelopeReport> {
    const body: Record<string, unknown> = {
      principal: params.principal,
      requests: params.requests,
    };
    if (params.branch !== undefined) body.branch = params.branch;
    return this.request<EnvelopeReport>(
      "POST",
      "/v1/capabilities/compile_envelope",
      body,
    );
  }

  /** POST /v1/capabilities/delegate — attenuate a lease for a delegatee.
   * Never widens. */
  async delegateCapability(params: {
    delegator: string;
    parentLease: string;
    delegatee: string;
    constraints?: Record<string, Constraint>;
    uses: number;
    expiresAt: string;
    budget?: ResourceBudget;
  }): Promise<CapabilityLease> {
    const body: Record<string, unknown> = {
      delegator: params.delegator,
      parent_lease: params.parentLease,
      delegatee: params.delegatee,
      constraints: params.constraints ?? {},
      uses: params.uses,
      expires_at: params.expiresAt,
    };
    if (params.budget !== undefined) body.budget = params.budget;
    return this.request<CapabilityLease>("POST", "/v1/capabilities/delegate", body);
  }

  /** POST /v1/capabilities/revoke — revokes the lease and its whole
   * delegation subtree; returns every revoked lease id. */
  async revokeCapability(lease: string): Promise<string[]> {
    const resp = await this.request<{ revoked: string[] }>(
      "POST",
      "/v1/capabilities/revoke",
      { lease },
    );
    return resp.revoked;
  }

  // -- effects ----------------------------------------------------------

  /** GET /v1/effects?phase= */
  async listEffects(phase?: string): Promise<PendingEffect[]> {
    return this.request<PendingEffect[]>("GET", "/v1/effects", undefined, { phase });
  }

  /** GET /v1/effects/{id} */
  async getEffect(effectId: string): Promise<PendingEffect> {
    return this.request<PendingEffect>("GET", `/v1/effects/${effectId}`);
  }

  effectHandle(effect: PendingEffect): EffectHandle {
    return new EffectHandle(this, effect);
  }

  /** POST /v1/effects/{id}/prepare */
  async prepareEffect(effectId: string): Promise<EffectPrepareResponse> {
    return this.request<EffectPrepareResponse>("POST", `/v1/effects/${effectId}/prepare`);
  }

  /** POST /v1/effects/{id}/approve */
  async approveEffect(effectId: string, approver: string): Promise<{ approved: string }> {
    return this.request<{ approved: string }>("POST", `/v1/effects/${effectId}/approve`, {
      approver,
    });
  }

  /** POST /v1/effects/{id}/commit — commit after revalidation. */
  async commitEffect(effectId: string): Promise<Receipt> {
    return this.request<Receipt>("POST", `/v1/effects/${effectId}/commit`);
  }

  /** POST /v1/effects/{id}/compensate */
  async compensateEffect(effectId: string): Promise<Receipt> {
    return this.request<Receipt>("POST", `/v1/effects/${effectId}/compensate`);
  }

  /** POST /v1/effects/recover — resolve in-doubt effects. */
  async recoverEffects(): Promise<{ resolutions: { effect: string; resolution: Json }[] }> {
    return this.request("POST", "/v1/effects/recover");
  }

  /** POST /v1/effects/{id}/resolve — operator verdict on an in-doubt
   * effect. */
  async resolveEffect(
    effectId: string,
    resolution: OperatorResolution,
  ): Promise<{ resolved: string; receipt: Receipt | null }> {
    return this.request("POST", `/v1/effects/${effectId}/resolve`, resolution);
  }

  // -- trace / replay / receipts ---------------------------------------

  /** GET /v1/trace/query — causal ledger events. */
  async traceQuery(
    opts: {
      episode?: string;
      branch?: string;
      step?: string;
      principal?: string;
      kind?: string;
      limit?: number;
    } = {},
  ): Promise<LedgerEvent[]> {
    return this.request<LedgerEvent[]>("GET", "/v1/trace/query", undefined, {
      episode: opts.episode,
      branch: opts.branch,
      step: opts.step,
      principal: opts.principal,
      kind: opts.kind,
      limit: opts.limit,
    });
  }

  /** POST /v1/replay/audit — play back a ledger sequence range. */
  async replayAudit(opts: { seqFrom?: number; seqTo?: number } = {}): Promise<ReplayAuditResponse> {
    const body: Record<string, unknown> = {};
    if (opts.seqFrom !== undefined) body.seq_from = opts.seqFrom;
    if (opts.seqTo !== undefined) body.seq_to = opts.seqTo;
    return this.request<ReplayAuditResponse>("POST", "/v1/replay/audit", body);
  }

  /** POST /v1/replay/sandbox — re-execute one recorded step. */
  async replaySandbox(step: string): Promise<ReplaySandboxReport> {
    return this.request<ReplaySandboxReport>("POST", "/v1/replay/sandbox", { step });
  }

  /** POST /v1/replay/live — re-commit one recorded effect contract. */
  async replayLive(effect: string, approver: string): Promise<Receipt> {
    return this.request<Receipt>("POST", "/v1/replay/live", { effect, approver });
  }

  /** GET /v1/receipts/{id} */
  async getReceipt(receiptId: string): Promise<Receipt> {
    return this.request<Receipt>("GET", `/v1/receipts/${receiptId}`);
  }
}

// ---------------------------------------------------------------------------
// Handles
// ---------------------------------------------------------------------------

export class BranchHandle {
  constructor(
    protected readonly kernel: Kernel,
    readonly episode: string,
    readonly principal: string,
    readonly branch: string,
  ) {}

  get id(): string {
    return this.branch;
  }

  /** Execute one action on this branch. A denied step is still recorded
   * and comes back as an Observation of kind "denied". */
  async execute(
    action: ActionKind,
    opts: {
      principal?: string;
      lease?: string;
      intentHint?: string;
      budget?: ResourceBudget;
    } = {},
  ): Promise<StepResult> {
    return this.kernel.executeStep({
      principal: opts.principal ?? this.principal,
      branch: this.branch,
      action,
      lease: opts.lease,
      intentHint: opts.intentHint,
      budget: opts.budget,
    });
  }

  /** Execute with automatic lease resolution — the recommended call for
   * agent loops: no lease, no budget bookkeeping. */
  async executeAuto(
    kind: ActionKind,
    opts: {
      principal?: string;
      intentHint?: string;
      budget?: ResourceBudget;
    } = {},
  ): Promise<AutoStepResult> {
    return this.kernel.executeStepAuto({
      principal: opts.principal ?? this.principal,
      branch: this.branch,
      kind,
      intentHint: opts.intentHint,
      budget: opts.budget,
    });
  }

  /** Fork `count` sibling branches (one kernel call each). */
  async fork(count = 1): Promise<BranchHandle[]> {
    const out: BranchHandle[] = [];
    for (let i = 0; i < count; i++) {
      const b = await this.kernel.forkBranch(this.branch);
      out.push(new BranchHandle(this.kernel, this.episode, this.principal, b.id));
    }
    return out;
  }

  async diff(since?: string): Promise<FileChange[]> {
    return this.kernel.diffBranch(this.branch, since);
  }

  async compare(other: BranchHandle | string): Promise<BranchCompareResponse> {
    const otherId = typeof other === "string" ? other : other.id;
    return this.kernel.compareBranches(this.branch, otherId);
  }

  /** Merge `source` into this branch. */
  async merge(source: BranchHandle | string, actor?: string): Promise<StateNode> {
    const sourceId = typeof source === "string" ? source : source.id;
    return this.kernel.mergeBranch(this.branch, sourceId, actor ?? this.principal);
  }

  async discard(): Promise<{ discarded: string }> {
    return this.kernel.discardBranch(this.branch);
  }
}

/** Acts on the episode's main branch by default. */
export class EpisodeHandle extends BranchHandle {
  get episodeId(): string {
    return this.episode;
  }

  async describe(): Promise<EpisodeDescription> {
    return this.kernel.describeEpisode(this.episode);
  }
}

/**
 * A pending effect: prepare -> approve -> commit -> (compensate).
 * Effects are proposed by executing a connector_op action; the resulting
 * "effect_pending" observation names the effect id.
 */
export class EffectHandle {
  receipt?: Receipt;

  constructor(
    private readonly kernel: Kernel,
    public effect: PendingEffect,
  ) {}

  get id(): string {
    return this.effect.id;
  }

  get contractHash(): string {
    return this.effect.contract_hash;
  }

  async refresh(): Promise<PendingEffect> {
    this.effect = await this.kernel.getEffect(this.effect.id);
    return this.effect;
  }

  async prepare(): Promise<EffectPrepareResponse> {
    return this.kernel.prepareEffect(this.effect.id);
  }

  async approve(approver: string): Promise<{ approved: string }> {
    return this.kernel.approveEffect(this.effect.id, approver);
  }

  async commit(): Promise<Receipt> {
    const receipt = await this.kernel.commitEffect(this.effect.id);
    this.receipt = receipt;
    return receipt;
  }

  async compensate(): Promise<Receipt> {
    return this.kernel.compensateEffect(this.effect.id);
  }
}

export type { Json };

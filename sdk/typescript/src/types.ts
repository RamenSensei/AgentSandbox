/**
 * Wire types for the AgentKernel Execution Protocol (agentkernel.v1).
 *
 * These mirror the canonical JSON encoding of ak-core exactly:
 * snake_case fields, internally tagged discriminated unions
 * (ActionKind/Observation by "kind", EffectPhase by "phase",
 * FileChange by "op", Constraint by "kind"), SCREAMING_SNAKE_CASE denial
 * codes, prefixed string ids (ep-/step-/br-/st-/pr-/lease-/fx-/rcpt-).
 */

export type Json =
  | null
  | boolean
  | number
  | string
  | Json[]
  | { [key: string]: Json };

// ---------------------------------------------------------------------------
// Budget
// ---------------------------------------------------------------------------

export interface ResourceBudget {
  cpu_ms: number;
  memory_bytes: number;
  network_bytes: number;
  tokens: number;
  cost_micro_usd: number;
  risk_units: number;
}

export const stepDefaultBudget = (): ResourceBudget => ({
  cpu_ms: 60_000,
  memory_bytes: 2 ** 31,
  network_bytes: 256 * 2 ** 20,
  tokens: 200_000,
  cost_micro_usd: 0,
  risk_units: 10,
});

// ---------------------------------------------------------------------------
// Actions (tagged with "kind")
// ---------------------------------------------------------------------------

export type ActionKind =
  | { kind: "shell"; command: string; cwd?: string | null; env?: Record<string, string> }
  | { kind: "read_file"; path: string }
  | { kind: "write_file"; path: string; contents_b64: string }
  | { kind: "delete_path"; path: string }
  | { kind: "http_read"; url: string }
  | { kind: "mcp_invoke"; server: string; tool: string; arguments: Json }
  | { kind: "connector_op"; connector: string; operation: string; params: Json }
  | { kind: "trace_query"; query: string }
  | { kind: "branch_diff"; since: string };

export interface Action {
  kind: ActionKind;
  /** Lease presented as authority. No ambient authority. */
  lease: string;
  /** Scheduling/narration only — never an authorization input. */
  intent_hint?: string;
  budget: ResourceBudget;
}

// Ergonomic constructors.
export const Shell = (
  command: string,
  opts: { cwd?: string; env?: Record<string, string> } = {},
): ActionKind => ({ kind: "shell", command, ...opts });
export const ReadFile = (path: string): ActionKind => ({ kind: "read_file", path });
export const WriteFile = (path: string, contents_b64: string): ActionKind => ({
  kind: "write_file",
  path,
  contents_b64,
});
export const DeletePath = (path: string): ActionKind => ({ kind: "delete_path", path });
export const HttpRead = (url: string): ActionKind => ({ kind: "http_read", url });
export const McpInvoke = (server: string, tool: string, args: Json = null): ActionKind => ({
  kind: "mcp_invoke",
  server,
  tool,
  arguments: args,
});
export const ConnectorOp = (
  connector: string,
  operation: string,
  params: Json = null,
): ActionKind => ({ kind: "connector_op", connector, operation, params });

// ---------------------------------------------------------------------------
// Denials
// ---------------------------------------------------------------------------

export type DenialCode =
  | "CAPABILITY_DENIED"
  | "CAPABILITY_EXPIRED"
  | "CAPABILITY_EXHAUSTED"
  | "BUDGET_EXHAUSTED"
  | "CONSTRAINT_VIOLATED"
  | "BRANCH_MISMATCH"
  | "EFFECT_REQUIRES_APPROVAL"
  | "STALE_AUTHORIZATION"
  | "PRECONDITION_FAILED"
  | "DUPLICATE_COMMIT"
  | "BACKEND_UNAVAILABLE"
  | "POLICY_FORBIDDEN";

export interface RequestableScope {
  operation: string;
  constraints: Json;
  requires_human: boolean;
}

export interface Denial {
  code: DenialCode;
  attempted_operation: string;
  reason: string;
  safe_alternatives?: string[];
  requestable_scopes?: RequestableScope[];
  escalation_allowed: boolean;
}

export interface ErrorEnvelope {
  code: string;
  message: string;
  denial?: Denial;
}

// ---------------------------------------------------------------------------
// Observations (tagged with "kind")
// ---------------------------------------------------------------------------

export type EffectClass =
  | "pure"
  | "local_reversible"
  | "remote_reversible"
  | "compensatable"
  | "irreversible"
  | "opaque_external";

export type Observation =
  | {
      kind: "success";
      summary: string;
      data?: Json;
      stdout_head?: string;
      exit_code: number;
      full_output: string;
      truncated: boolean;
    }
  | {
      kind: "failure";
      summary: string;
      exit_code: number;
      first_causal_failure?: string;
      full_output: string;
    }
  | { kind: "denied"; denial: Denial }
  | { kind: "effect_pending"; effect: string; contract_hash: string; class: EffectClass }
  | { kind: "effect_committed"; receipt: string };

// ---------------------------------------------------------------------------
// Constraints (tagged with "kind")
// ---------------------------------------------------------------------------

export type Constraint =
  | { kind: "equals"; value: Json }
  | { kind: "one_of"; values: Json[] }
  | { kind: "glob"; pattern: string }
  | { kind: "prefix"; prefix: string }
  | { kind: "max"; max: number }
  | { kind: "forbidden" };

export interface CapabilityLease {
  id: string; // "lease-..."
  principal: string; // "pr-..."
  operation: string;
  constraints: Record<string, Constraint>;
  remaining_uses: number;
  issued_at: string;
  expires_at: string;
  bound_branch?: string;
  budget: ResourceBudget;
  parent_lease?: string;
  preconditions?: Record<string, Json>;
  revoked: boolean;
}

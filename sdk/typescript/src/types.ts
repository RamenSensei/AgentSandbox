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

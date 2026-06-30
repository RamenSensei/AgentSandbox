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

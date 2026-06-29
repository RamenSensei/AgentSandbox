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

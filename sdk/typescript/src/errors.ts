import type { Denial, RequestableScope } from "./types.js";

/** Any error envelope returned by the kernel API. */
export class KernelError extends Error {
  readonly code: string;
  readonly status: number;

  constructor(code: string, message: string, status = 0) {
    super(`${code}: ${message}`);
    this.name = "KernelError";
    this.code = code;
    this.status = status;
  }
}

/**
 * A policy denial (HTTP 403) carrying the full structured Denial.
 * Invariant: no denial without a machine-readable explanation.
 */
export class DenialError extends KernelError {
  readonly denial: Denial;

  constructor(denial: Denial, message = "", status = 403) {
    super("DENIED", message || denial.reason, status);
    this.name = "DenialError";
    this.denial = denial;
  }

  get denialCode(): string {
    return this.denial.code;
  }

  /** Operations the principal is already allowed to use instead. */
  get safeAlternatives(): string[] {
    return this.denial.safe_alternatives ?? [];
  }

  /** Narrow scopes the principal could request to unblock itself. */
  get requestableScopes(): RequestableScope[] {
    return this.denial.requestable_scopes ?? [];
  }

  get escalationAllowed(): boolean {
    return this.denial.escalation_allowed;
  }
}

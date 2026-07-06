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

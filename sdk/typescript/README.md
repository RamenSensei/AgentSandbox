# @agentkernel/sdk

Typed, zero-runtime-dependency TypeScript client for the AgentKernel
Execution Protocol HTTP API (`agentkernel.v1`). Uses global `fetch`
(Node >= 18, browsers). ESM with full type declarations; wire objects are
exhaustive discriminated unions matching the kernel's serde tags exactly
(`ActionKind`/`Observation` by `kind`, `EffectPhase` by `phase`,
`FileChange` by `op`, `Constraint` by `kind`).

```bash
npm install @agentkernel/sdk
```

## Quick start

```ts
import { Kernel, Shell, ConnectorOp, DenialError } from "@agentkernel/sdk";

const kernel = new Kernel("http://localhost:7411", { token: "..." });

// Episodes and steps
const ep = await kernel.createEpisode({ title: "fix issue 42", owner: "pr-agent" });
const res = await ep.execute(Shell("pytest"), { lease: "lease-abc" });
if (res.observation.kind === "success") {
  console.log(res.observation.stdout_head); // "12 passed"
}

// Parallel speculation
const branches = await ep.fork(3);
await Promise.all(branches.map((br) => br.execute(Shell("python attempt.py"), { lease: "lease-abc" })));
console.log((await branches[0].diff()).summary);
console.log((await branches[0].compare(branches[1])).conflicting_paths);
await branches[0].merge(ep);
await branches[1].discard("lost the race");

// Effects: two-phase commit against the real world
const fx = await ep.proposeEffect({
  operation: "github.create_pull_request",
  resource: "org/repo",
  arguments: { base: "main", head: "sandbox/fix", draft: true },
  preconditions: { base_head_sha: "abc123" },
  idempotency_key: "ep-7-step-98",
  class: "compensatable",
}, { lease: "lease-abc" });

const receipt = await fx.run(async (fx) => {
  await fx.prepare();          // dry-run; never a side effect
  await fx.approve("pr-human"); // approves exactly this contract hash
  return fx.commit();           // commit-time revalidation, signed receipt
});
// If run() exits without a successful commit, the effect is aborted.
```

## Denials are recoverable

```ts
try {
  await kernel.requestCapability({ principal: "pr-agent", operation: "net.raw_socket" });
} catch (e) {
  if (e instanceof DenialError) {
    console.log(e.denialCode);          // "CAPABILITY_DENIED"
    console.log(e.safeAlternatives);    // ["github.create_pull_request"]
    console.log(e.requestableScopes);   // narrow scopes to request instead
    console.log(e.escalationAllowed);
  }
}
```

Denied-but-recorded steps come back as a normal observation:
`res.observation.kind === "denied"` with the full structured
`res.observation.denial`.

## Capabilities, trace, replay

```ts
const lease = await kernel.requestCapability({
  principal: "pr-agent",
  operation: "github.create_pull_request",
  constraints: {
    repository: { kind: "equals", value: "org/repo" },
    head: { kind: "prefix", prefix: "sandbox/" },
    merge: { kind: "forbidden" },
  },
  uses: 1,
  boundBranch: ep.id,
});
const child = await kernel.delegateCapability({
  parentLease: lease.id, childPrincipal: "pr-child",
  constraints: { repository: { kind: "equals", value: "org/repo" } },
  uses: 1, expiresAt: lease.expires_at,
});
await kernel.revokeCapability(lease.id, { cascade: true });

await kernel.traceQuery('effects where class >= compensatable and branch = "br-42"');
const report = await kernel.replay("audit", ep.episodeId); // "audit" | "sandbox" | "live"
```

Live replay guarantees the *contract*, not the outcome.

## Reliability

Automatic retry with exponential backoff on network errors and
502/503/504 (`maxRetries`, `backoffMs` options; `fetch` and `sleep` are
injectable for tests).

## Development

```bash
npm install --no-audit --no-fund
npx tsc --noEmit     # typecheck
npm test             # tsc build + node:test against a mock kernel (node:http)
```

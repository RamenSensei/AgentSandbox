# agentkernel (Python SDK)

Typed, zero-dependency Python client for the AgentKernel Execution
Protocol HTTP API (`agentkernel.v1`). Transport is stdlib `urllib`; an
alternative transport (e.g. httpx) can be injected.

```bash
pip install agentkernel            # or: pip install "agentkernel[httpx]"
```

## Quick start

```python
from agentkernel import Kernel, Shell, ConnectorOp, EffectContract, DenialError

kernel = Kernel("http://localhost:7411", token="...")

# Episodes and steps
ep = kernel.create_episode("fix issue 42", owner="pr-agent")
res = ep.execute(Shell("pytest"), lease="lease-abc")
print(res.observation.kind, res.observation.stdout_head)   # "success", "12 passed"
print(res.produced_state)                                  # "st-..." or None

# Parallel speculation: fork 3 sibling branches, race them, keep the best
branches = ep.fork(3)
for br in branches:
    br.execute(Shell("python attempt.py"), lease="lease-abc")
best = branches[0]
print(best.diff().summary)                 # "3 files changed, ..."
print(best.compare(branches[1]).conflicting_paths)
best.merge(ep)                             # merge into the main branch
branches[1].discard("lost the race")

# Effects: two-phase commit against the real world
contract = EffectContract(
    operation="github.create_pull_request",
    resource="org/repo",
    arguments={"base": "main", "head": "sandbox/fix", "draft": True},
    preconditions={"base_head_sha": "abc123"},
    idempotency_key="ep-7-step-98",
    class_="compensatable",
)
with ep.propose_effect(contract, lease="lease-abc") as fx:
    preview = fx.prepare()          # dry-run; never a side effect
    fx.approve("pr-human")          # approves exactly this contract hash
    receipt = fx.commit()           # commit-time revalidation, signed receipt
print(receipt.id)                   # "rcpt-..."
# Leaving the `with` block without committing aborts the effect.
```

## Denials are recoverable, not fatal

```python
try:
    kernel.request_capability("pr-agent", "net.raw_socket")
except DenialError as e:
    print(e.denial_code)            # "CAPABILITY_DENIED"
    print(e.safe_alternatives)      # ["github.create_pull_request"]
    for scope in e.requestable_scopes:
        print(scope.operation, scope.constraints, scope.requires_human)
    if e.escalation_allowed:
        ...  # request one of the suggested scopes instead
```

A denial that was *recorded as a step* comes back as a normal observation
(`res.observation.is_denied`, `res.observation.denial`) so the causal
ledger stays complete.

## Capabilities, trace, replay

```python
lease = kernel.request_capability(
    "pr-agent", "github.create_pull_request",
    constraints={"repository": {"kind": "equals", "value": "org/repo"},
                 "head": {"kind": "prefix", "prefix": "sandbox/"},
                 "merge": {"kind": "forbidden"}},
    uses=1, bound_branch=ep.branch.id,
)
child = kernel.delegate_capability(lease.id, "pr-child",
                                   constraints=..., uses=1, expires_at=lease.expires_at)
kernel.revoke_capability(lease.id, cascade=True)

kernel.trace_query('effects where class >= compensatable and branch = "br-42"')
report = kernel.replay("audit", ep.episode.id)   # "audit" | "sandbox" | "live"
```

Live replay guarantees the *contract*, not the outcome.

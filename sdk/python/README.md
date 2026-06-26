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

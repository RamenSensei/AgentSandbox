"""agentkernel — typed Python client for the AgentKernel Execution Protocol.

Example:

    from agentkernel import Kernel, Shell

    kernel = Kernel("http://localhost:7411")
    ep = kernel.create_episode("fix issue 42", owner="pr-agent")
    result = ep.execute(Shell("pytest"), lease="lease-abc")
    branches = ep.fork(3)
"""

from .client import (
    BranchHandle,
    EffectHandle,
    EpisodeHandle,
    Kernel,
)
from .errors import DenialError, KernelError, TransportError
from .types import (
    ActionKind,
    Branch,
    BranchComparison,
    BranchDiff,
    BranchDiffAction,
    CapabilityLease,
    ConnectorOp,
    DeletePath,
    Denial,
    EffectContract,
    EffectPreview,
    Episode,
    HttpRead,
    McpInvoke,
    Observation,
    PendingEffect,
    ReadFile,
    Receipt,
    RequestableScope,
    ResourceBudget,
    Shell,
    StateDelta,
    StepResult,
    TraceQueryAction,
    WriteFile,
)

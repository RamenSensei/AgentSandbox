"""agentkernel — typed Python client for the AgentKernel Execution Protocol.

Example:

    from agentkernel import Kernel, Shell

    kernel = Kernel("http://localhost:7411")
    ep = kernel.create_episode("pr-agent", objective="fix issue 42")
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
    AutoStepResult,
    Branch,
    BranchComparison,
    BranchDiffAction,
    CapabilityLease,
    ConnectorOp,
    DeletePath,
    Denial,
    EffectContract,
    EffectPreview,
    EnvelopeItemReport,
    EnvelopeReport,
    EpisodeDescription,
    HttpRead,
    McpInvoke,
    Observation,
    PendingEffect,
    ProcessLogs,
    ProcessSignal,
    ProcessStart,
    ProcessStatus,
    ProcessStdin,
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

__version__ = "0.8.0"

__all__ = [
    "Kernel",
    "EpisodeHandle",
    "BranchHandle",
    "EffectHandle",
    "KernelError",
    "DenialError",
    "TransportError",
    "ActionKind",
    "Shell",
    "ReadFile",
    "WriteFile",
    "DeletePath",
    "ProcessStart",
    "ProcessStdin",
    "ProcessLogs",
    "ProcessSignal",
    "ProcessStatus",
    "HttpRead",
    "McpInvoke",
    "ConnectorOp",
    "TraceQueryAction",
    "BranchDiffAction",
    "ResourceBudget",
    "Denial",
    "RequestableScope",
    "Observation",
    "StepResult",
    "AutoStepResult",
    "EpisodeDescription",
    "Branch",
    "BranchComparison",
    "StateDelta",
    "CapabilityLease",
    "EnvelopeItemReport",
    "EnvelopeReport",
    "EffectContract",
    "PendingEffect",
    "EffectPreview",
    "Receipt",
]

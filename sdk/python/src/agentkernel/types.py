"""Wire types for the AgentKernel Execution Protocol (agentkernel.v1).

Dataclasses mirror the canonical JSON encoding of ak-core exactly:
snake_case fields, internally tagged unions (ActionKind/Observation by
"kind", EffectPhase by "phase", FileChange by "op", Constraint by "kind"),
SCREAMING_SNAKE_CASE denial codes, prefixed string ids
(ep-/step-/br-/st-/pr-/lease-/fx-/rcpt-).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional

Json = Any  # arbitrary JSON value

# ---------------------------------------------------------------------------
# Budget
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ResourceBudget:
    cpu_ms: int = 0
    memory_bytes: int = 0
    network_bytes: int = 0
    tokens: int = 0
    cost_micro_usd: int = 0
    risk_units: int = 0

    def to_wire(self) -> Dict[str, int]:
        return {
            "cpu_ms": self.cpu_ms,
            "memory_bytes": self.memory_bytes,
            "network_bytes": self.network_bytes,
            "tokens": self.tokens,
            "cost_micro_usd": self.cost_micro_usd,
            "risk_units": self.risk_units,
        }

    @staticmethod
    def step_default() -> "ResourceBudget":
        return ResourceBudget(
            cpu_ms=60_000,
            memory_bytes=2 << 30,
            network_bytes=256 << 20,
            tokens=200_000,
            cost_micro_usd=0,
            risk_units=10,
        )

    @classmethod
    def from_wire(cls, d: Mapping[str, Any]) -> "ResourceBudget":
        return cls(
            cpu_ms=int(d.get("cpu_ms", 0)),
            memory_bytes=int(d.get("memory_bytes", 0)),
            network_bytes=int(d.get("network_bytes", 0)),
            tokens=int(d.get("tokens", 0)),
            cost_micro_usd=int(d.get("cost_micro_usd", 0)),
            risk_units=int(d.get("risk_units", 0)),
        )


# ---------------------------------------------------------------------------
# Actions (tagged with "kind")
# ---------------------------------------------------------------------------


class ActionKind:
    """Base class for the action taxonomy. Subclasses emit tagged wire JSON."""

    kind: str

    def to_wire(self) -> Dict[str, Json]:  # pragma: no cover - overridden
        raise NotImplementedError


@dataclass(frozen=True)
class Shell(ActionKind):
    command: str
    cwd: Optional[str] = None
    env: Dict[str, str] = field(default_factory=dict)
    kind = "shell"

    def to_wire(self) -> Dict[str, Json]:
        return {"kind": "shell", "command": self.command, "cwd": self.cwd, "env": self.env}


@dataclass(frozen=True)
class ReadFile(ActionKind):
    path: str
    kind = "read_file"

    def to_wire(self) -> Dict[str, Json]:
        return {"kind": "read_file", "path": self.path}


@dataclass(frozen=True)
class WriteFile(ActionKind):
    path: str
    contents_b64: str
    kind = "write_file"

    def to_wire(self) -> Dict[str, Json]:
        return {"kind": "write_file", "path": self.path, "contents_b64": self.contents_b64}


@dataclass(frozen=True)
class DeletePath(ActionKind):
    path: str
    kind = "delete_path"

    def to_wire(self) -> Dict[str, Json]:
        return {"kind": "delete_path", "path": self.path}


@dataclass(frozen=True)
class HttpRead(ActionKind):
    url: str
    kind = "http_read"

    def to_wire(self) -> Dict[str, Json]:
        return {"kind": "http_read", "url": self.url}


@dataclass(frozen=True)
class McpInvoke(ActionKind):
    server: str
    tool: str
    arguments: Json = None
    kind = "mcp_invoke"

    def to_wire(self) -> Dict[str, Json]:
        return {
            "kind": "mcp_invoke",
            "server": self.server,
            "tool": self.tool,
            "arguments": self.arguments,
        }


@dataclass(frozen=True)
class ConnectorOp(ActionKind):
    connector: str
    operation: str
    params: Json = None
    kind = "connector_op"

    def to_wire(self) -> Dict[str, Json]:
        return {
            "kind": "connector_op",
            "connector": self.connector,
            "operation": self.operation,
            "params": self.params,
        }


@dataclass(frozen=True)
class TraceQueryAction(ActionKind):
    query: str
    kind = "trace_query"

    def to_wire(self) -> Dict[str, Json]:
        return {"kind": "trace_query", "query": self.query}


@dataclass(frozen=True)
class BranchDiffAction(ActionKind):
    since: str  # "st-..."
    kind = "branch_diff"

    def to_wire(self) -> Dict[str, Json]:
        return {"kind": "branch_diff", "since": self.since}


# ---------------------------------------------------------------------------
# Denials
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RequestableScope:
    operation: str
    constraints: Json
    requires_human: bool

    @classmethod
    def from_wire(cls, d: Mapping[str, Any]) -> "RequestableScope":
        return cls(
            operation=d["operation"],
            constraints=d.get("constraints"),
            requires_human=bool(d.get("requires_human", False)),
        )


@dataclass(frozen=True)
class Denial:
    code: str  # SCREAMING_SNAKE_CASE, e.g. "CAPABILITY_DENIED"
    attempted_operation: str
    reason: str
    safe_alternatives: List[str] = field(default_factory=list)
    requestable_scopes: List[RequestableScope] = field(default_factory=list)
    escalation_allowed: bool = False

    @classmethod
    def from_wire(cls, d: Mapping[str, Any]) -> "Denial":
        return cls(
            code=d["code"],
            attempted_operation=d.get("attempted_operation", ""),
            reason=d.get("reason", ""),
            safe_alternatives=list(d.get("safe_alternatives", [])),
            requestable_scopes=[
                RequestableScope.from_wire(s) for s in d.get("requestable_scopes", [])
            ],
            escalation_allowed=bool(d.get("escalation_allowed", False)),
        )


# ---------------------------------------------------------------------------
# Observations (tagged with "kind")
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Observation:
    """One observation, kept close to the wire; `kind` discriminates."""

    kind: str  # "success" | "failure" | "denied" | "effect_pending" | "effect_committed"
    raw: Dict[str, Json]

    # success / failure
    @property
    def summary(self) -> Optional[str]:
        return self.raw.get("summary")

    @property
    def exit_code(self) -> Optional[int]:
        return self.raw.get("exit_code")

    @property
    def stdout_head(self) -> Optional[str]:
        return self.raw.get("stdout_head")

    @property
    def data(self) -> Json:
        return self.raw.get("data")

    @property
    def full_output(self) -> Optional[str]:
        return self.raw.get("full_output")

    # denied
    @property
    def denial(self) -> Optional[Denial]:
        d = self.raw.get("denial")
        return Denial.from_wire(d) if d else None

    # effect_pending / effect_committed
    @property
    def effect(self) -> Optional[str]:
        return self.raw.get("effect")

    @property
    def contract_hash(self) -> Optional[str]:
        return self.raw.get("contract_hash")

    @property
    def receipt(self) -> Optional[str]:
        return self.raw.get("receipt")

    @property
    def is_success(self) -> bool:
        return self.kind == "success"

    @property
    def is_denied(self) -> bool:
        return self.kind == "denied"

    @classmethod
    def from_wire(cls, d: Mapping[str, Any]) -> "Observation":
        return cls(kind=d["kind"], raw=dict(d))

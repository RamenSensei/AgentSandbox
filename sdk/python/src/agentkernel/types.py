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
class ProcessStart(ActionKind):
    """Start a persistent process session (dev server, REPL, database, …).

    Unlike Shell, the process outlives the step; the success observation's
    stdout is JSON naming the ``process`` handle for later ProcessStdin/
    ProcessLogs/ProcessSignal/ProcessStatus steps. Sessions are branch-scoped
    and die with the branch.
    """

    command: str
    cwd: Optional[str] = None
    env: Dict[str, str] = field(default_factory=dict)
    name: Optional[str] = None
    kind = "process_start"

    def to_wire(self) -> Dict[str, Json]:
        return {
            "kind": "process_start",
            "command": self.command,
            "cwd": self.cwd,
            "env": self.env,
            "name": self.name,
        }


@dataclass(frozen=True)
class ProcessStdin(ActionKind):
    process: str
    data_b64: str
    close: bool = False
    kind = "process_stdin"

    def to_wire(self) -> Dict[str, Json]:
        return {
            "kind": "process_stdin",
            "process": self.process,
            "data_b64": self.data_b64,
            "close": self.close,
        }


@dataclass(frozen=True)
class ProcessLogs(ActionKind):
    """Tail a process incrementally: read combined output from a byte
    offset; the JSON response reports ``next_offset`` for the next poll."""

    process: str
    from_offset: int = 0
    max_bytes: Optional[int] = None
    kind = "process_logs"

    def to_wire(self) -> Dict[str, Json]:
        return {
            "kind": "process_logs",
            "process": self.process,
            "from_offset": self.from_offset,
            "max_bytes": self.max_bytes,
        }


@dataclass(frozen=True)
class ProcessSignal(ActionKind):
    process: str
    signal: str  # "int" | "term" | "kill"
    kind = "process_signal"

    def to_wire(self) -> Dict[str, Json]:
        return {"kind": "process_signal", "process": self.process, "signal": self.signal}


@dataclass(frozen=True)
class ProcessStatus(ActionKind):
    """Status of one process, or of every session on the branch when
    ``process`` is empty."""

    process: str = ""
    kind = "process_status"

    def to_wire(self) -> Dict[str, Json]:
        return {"kind": "process_status", "process": self.process}


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


# ---------------------------------------------------------------------------
# Episodes / branches / steps
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EpisodeDescription:
    """Wire description of an episode (GET /v1/episodes/{id})."""

    episode: str  # "ep-..."
    root_branch: str  # "br-..."
    root_state: str  # "st-..."
    branches: List["Branch"]
    created_by: str  # "pr-..."
    remaining_budget: ResourceBudget

    @classmethod
    def from_wire(cls, d: Mapping[str, Any]) -> "EpisodeDescription":
        return cls(
            episode=d["episode"],
            root_branch=d.get("root_branch", ""),
            root_state=d.get("root_state", ""),
            branches=[Branch.from_wire(b) for b in d.get("branches", [])],
            created_by=d.get("created_by", ""),
            remaining_budget=ResourceBudget.from_wire(d.get("remaining_budget", {})),
        )


@dataclass(frozen=True)
class Branch:
    id: str  # "br-..."
    episode: str  # "ep-..."
    forked_from: str  # "st-..."
    head: str  # "st-..."
    discarded: bool
    created_at: str
    parent_branch: Optional[str] = None

    @classmethod
    def from_wire(cls, d: Mapping[str, Any]) -> "Branch":
        return cls(
            id=d["id"],
            episode=d.get("episode", ""),
            forked_from=d.get("forked_from", ""),
            head=d.get("head", ""),
            discarded=bool(d.get("discarded", False)),
            created_at=d.get("created_at", ""),
            parent_branch=d.get("parent_branch"),
        )


@dataclass(frozen=True)
class StepResult:
    step: str  # "step-..."
    state: str  # "st-..." — branch head after the step (unchanged when denied)
    observation: Observation

    @classmethod
    def from_wire(cls, d: Mapping[str, Any]) -> "StepResult":
        return cls(
            step=d["step"],
            state=d.get("state", ""),
            observation=Observation.from_wire(d["observation"]),
        )


@dataclass(frozen=True)
class AutoStepResult:
    """Result of steps/execute_auto: the step plus the lease the kernel
    selected or minted on the caller's behalf."""

    step: str
    state: str
    observation: Observation
    lease: str
    lease_minted: bool

    @classmethod
    def from_wire(cls, d: Mapping[str, Any]) -> "AutoStepResult":
        return cls(
            step=d["step"],
            state=d.get("state", ""),
            observation=Observation.from_wire(d["observation"]),
            lease=d.get("lease", ""),
            lease_minted=bool(d.get("lease_minted", False)),
        )


@dataclass(frozen=True)
class StateDelta:
    files: List[Dict[str, Json]] = field(default_factory=list)
    processes_started: List[str] = field(default_factory=list)
    processes_exited: List[str] = field(default_factory=list)
    tool_sessions: List[str] = field(default_factory=list)
    policy_epoch: int = 0
    effects_proposed: List[str] = field(default_factory=list)
    effects_committed: List[str] = field(default_factory=list)

    @classmethod
    def from_wire(cls, d: Mapping[str, Any]) -> "StateDelta":
        return cls(
            files=list(d.get("files", [])),
            processes_started=list(d.get("processes_started", [])),
            processes_exited=list(d.get("processes_exited", [])),
            tool_sessions=list(d.get("tool_sessions", [])),
            policy_epoch=int(d.get("policy_epoch", 0)),
            effects_proposed=list(d.get("effects_proposed", [])),
            effects_committed=list(d.get("effects_committed", [])),
        )


@dataclass(frozen=True)
class BranchComparison:
    """GET /v1/branches/{a}/compare/{b}."""

    base: str  # common ancestor state, "st-..."
    changed_in_a: List[str]
    changed_in_b: List[str]

    @classmethod
    def from_wire(cls, d: Mapping[str, Any]) -> "BranchComparison":
        return cls(
            base=d.get("base", ""),
            changed_in_a=list(d.get("changed_in_a", [])),
            changed_in_b=list(d.get("changed_in_b", [])),
        )


# ---------------------------------------------------------------------------
# Capabilities
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CapabilityLease:
    id: str  # "lease-..."
    principal: str  # "pr-..."
    operation: str
    constraints: Dict[str, Json]
    remaining_uses: int
    issued_at: str
    expires_at: str
    budget: ResourceBudget
    revoked: bool
    bound_branch: Optional[str] = None
    parent_lease: Optional[str] = None
    preconditions: Dict[str, Json] = field(default_factory=dict)

    @classmethod
    def from_wire(cls, d: Mapping[str, Any]) -> "CapabilityLease":
        return cls(
            id=d["id"],
            principal=d.get("principal", ""),
            operation=d.get("operation", ""),
            constraints=dict(d.get("constraints", {})),
            remaining_uses=int(d.get("remaining_uses", 0)),
            issued_at=d.get("issued_at", ""),
            expires_at=d.get("expires_at", ""),
            budget=ResourceBudget.from_wire(d.get("budget", {})),
            revoked=bool(d.get("revoked", False)),
            bound_branch=d.get("bound_branch"),
            parent_lease=d.get("parent_lease"),
            preconditions=dict(d.get("preconditions", {})),
        )


@dataclass(frozen=True)
class EnvelopeItemReport:
    """Per-request outcome of an envelope compilation: exactly one of
    `lease` / `denial` is set."""

    operation: str
    lease: Optional[CapabilityLease] = None
    denial: Optional[Denial] = None

    @classmethod
    def from_wire(cls, d: Mapping[str, Any]) -> "EnvelopeItemReport":
        return cls(
            operation=d.get("operation", ""),
            lease=CapabilityLease.from_wire(d["lease"]) if d.get("lease") else None,
            denial=Denial.from_wire(d["denial"]) if d.get("denial") else None,
        )


@dataclass(frozen=True)
class EnvelopeReport:
    """A compiled autonomy envelope: which capabilities were granted up
    front, which need a human, which are refused."""

    items: List[EnvelopeItemReport]
    granted: int
    needs_human: int
    refused: int

    @classmethod
    def from_wire(cls, d: Mapping[str, Any]) -> "EnvelopeReport":
        return cls(
            items=[EnvelopeItemReport.from_wire(i) for i in d.get("items", [])],
            granted=int(d.get("granted", 0)),
            needs_human=int(d.get("needs_human", 0)),
            refused=int(d.get("refused", 0)),
        )


# ---------------------------------------------------------------------------
# Effects
# ---------------------------------------------------------------------------

EFFECT_CLASSES = (
    "pure",
    "local_reversible",
    "remote_reversible",
    "compensatable",
    "irreversible",
    "opaque_external",
)


@dataclass(frozen=True)
class EffectContract:
    operation: str
    resource: str
    arguments: Json
    preconditions: Json
    idempotency_key: str
    class_: str  # one of EFFECT_CLASSES; wire name "class"

    def to_wire(self) -> Dict[str, Json]:
        return {
            "operation": self.operation,
            "resource": self.resource,
            "arguments": self.arguments,
            "preconditions": self.preconditions,
            "idempotency_key": self.idempotency_key,
            "class": self.class_,
        }

    @classmethod
    def from_wire(cls, d: Mapping[str, Any]) -> "EffectContract":
        return cls(
            operation=d["operation"],
            resource=d.get("resource", ""),
            arguments=d.get("arguments"),
            preconditions=d.get("preconditions"),
            idempotency_key=d.get("idempotency_key", ""),
            class_=d.get("class", "opaque_external"),
        )


@dataclass(frozen=True)
class PendingEffect:
    id: str  # "fx-..."
    contract: EffectContract
    contract_hash: str
    proposer: str
    branch: str
    step: str
    lease: str
    phase: Dict[str, Json]  # tagged with "phase"
    proposed_at: str

    @classmethod
    def from_wire(cls, d: Mapping[str, Any]) -> "PendingEffect":
        return cls(
            id=d["id"],
            contract=EffectContract.from_wire(d.get("contract", {"operation": ""})),
            contract_hash=d.get("contract_hash", ""),
            proposer=d.get("proposer", ""),
            branch=d.get("branch", ""),
            step=d.get("step", ""),
            lease=d.get("lease", ""),
            phase=dict(d.get("phase", {"phase": "proposed"})),
            proposed_at=d.get("proposed_at", ""),
        )


@dataclass(frozen=True)
class Receipt:
    id: str  # "rcpt-..."
    body: Dict[str, Json]
    signature: str
    key_id: str

    @classmethod
    def from_wire(cls, d: Mapping[str, Any]) -> "Receipt":
        return cls(
            id=d["id"],
            body=dict(d.get("body", {})),
            signature=d.get("signature", ""),
            key_id=d.get("key_id", ""),
        )


@dataclass(frozen=True)
class EffectPreview:
    """POST /v1/effects/{id}/prepare — preview and observed preconditions."""

    preview: Json
    observed_preconditions: Json

    @classmethod
    def from_wire(cls, d: Mapping[str, Any]) -> "EffectPreview":
        return cls(
            preview=d.get("preview"),
            observed_preconditions=d.get("observed_preconditions"),
        )

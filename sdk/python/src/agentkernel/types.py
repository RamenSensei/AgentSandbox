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

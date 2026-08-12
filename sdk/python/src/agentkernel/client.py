"""HTTP client for the AgentKernel Execution Protocol (JSON binding),
matching the routes implemented in ``kernel/api/src/http.rs``.

Zero runtime dependencies: transport is stdlib ``urllib``. An alternative
transport (e.g. httpx) can be injected via the ``transport`` argument —
any callable
``(method, url, body_json_or_none, headers, timeout) -> (status, body_bytes)``.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from .errors import DenialError, KernelError, TransportError
from .types import (
    ActionKind,
    Branch,
    BranchComparison,
    CapabilityLease,
    Denial,
    EffectPreview,
    EpisodeDescription,
    Json,
    PendingEffect,
    Receipt,
    ResourceBudget,
    StepResult,
)

Transport = Callable[
    [str, str, Optional[Dict[str, Any]], Dict[str, str], Optional[float]],
    Tuple[int, bytes],
]

_RETRYABLE_STATUS = {502, 503, 504}

#: Default per-request timeout in seconds. ``timeout=None`` (wait forever)
#: must be opted into explicitly.
DEFAULT_TIMEOUT = 30.0


def _urllib_transport(
    method: str,
    url: str,
    body: Optional[Dict[str, Any]],
    headers: Dict[str, str],
    timeout: Optional[float],
) -> Tuple[int, bytes]:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        # The HTTPError doubles as the (error) response object; close it so
        # the underlying socket is released (avoids ResourceWarning).
        try:
            return e.code, e.read()
        finally:
            e.close()


class Kernel:
    """Entry point: ``kernel = Kernel("http://localhost:7411")``."""

    def __init__(
        self,
        base_url: str,
        *,
        token: Optional[str] = None,
        max_retries: int = 3,
        backoff_base: float = 0.25,
        timeout: Optional[float] = DEFAULT_TIMEOUT,
        transport: Optional[Transport] = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self._token = token
        self._max_retries = max_retries
        self._backoff_base = backoff_base
        self._timeout = timeout
        self._transport: Transport = transport or _urllib_transport
        self._sleep = sleep

    # -- transport --------------------------------------------------------

    def _request(
        self,
        method: str,
        path: str,
        body: Optional[Dict[str, Any]] = None,
        query: Optional[Dict[str, Any]] = None,
    ) -> Json:
        url = self.base_url + path
        if query:
            filtered = {k: v for k, v in query.items() if v is not None}
            if filtered:
                url += "?" + urllib.parse.urlencode(filtered)
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"

        last_exc: Optional[BaseException] = None
        for attempt in range(self._max_retries + 1):
            try:
                status, raw = self._transport(method, url, body, headers, self._timeout)
            except (urllib.error.URLError, ConnectionError, OSError) as e:
                last_exc = e
                if attempt < self._max_retries:
                    self._sleep(self._backoff_base * (2**attempt))
                    continue
                raise TransportError(f"kernel unreachable at {url}: {e}", e) from e

            if status in _RETRYABLE_STATUS and attempt < self._max_retries:
                self._sleep(self._backoff_base * (2**attempt))
                continue
            return self._decode(status, raw)
        raise TransportError(f"kernel unreachable at {url}: {last_exc}", last_exc)

    @staticmethod
    def _decode(status: int, raw: bytes) -> Json:
        try:
            payload = json.loads(raw.decode("utf-8")) if raw else {}
        except ValueError:
            payload = {"code": "OTHER", "message": raw.decode("utf-8", "replace")}
        if 200 <= status < 300:
            return payload
        # A denied-but-recorded step is HTTP 403 carrying the recorded step,
        # state and observation alongside the error envelope. Surface it as
        # a normal result so callers see the "denied" observation.
        if (
            status == 403
            and isinstance(payload, dict)
            and "step" in payload
            and "observation" in payload
        ):
            return payload
        denial = payload.get("denial") if isinstance(payload, dict) else None
        if denial is not None:
            raise DenialError(
                Denial.from_wire(denial), payload.get("message", ""), status
            )
        raise KernelError(
            payload.get("code", "OTHER") if isinstance(payload, dict) else "OTHER",
            payload.get("message", "") if isinstance(payload, dict) else str(payload),
            status,
        )

    # -- health -----------------------------------------------------------

    def healthz(self) -> Dict[str, Json]:
        return self._request("GET", "/healthz")

    # -- episodes ---------------------------------------------------------

    def create_episode(
        self,
        principal: str,
        *,
        objective: str = "",
        workspace: Optional[str] = None,
    ) -> "EpisodeHandle":
        """POST /v1/episodes — returns 201 {episode, branch, root_state}."""
        body: Dict[str, Any] = {"principal": principal, "objective": objective}
        if workspace is not None:
            body["workspace"] = workspace
        resp = self._request("POST", "/v1/episodes", body)
        return EpisodeHandle(self, resp["episode"], principal, resp["branch"])

    def describe_episode(self, episode_id: str) -> EpisodeDescription:
        """GET /v1/episodes/{id}."""
        return EpisodeDescription.from_wire(
            self._request("GET", f"/v1/episodes/{episode_id}")
        )

    def get_episode(self, episode_id: str) -> "EpisodeHandle":
        desc = self.describe_episode(episode_id)
        return EpisodeHandle(self, desc.episode, desc.created_by, desc.root_branch)

    # -- steps ------------------------------------------------------------

    def execute_step(
        self,
        principal: str,
        branch: str,
        action: ActionKind,
        *,
        lease: str = "",
        intent_hint: Optional[str] = None,
        budget: Optional[ResourceBudget] = None,
    ) -> StepResult:
        """POST /v1/steps/execute.

        A denied step is still recorded (HTTP 403 with the recorded step
        and a "denied" observation) and is returned as a StepResult.
        """
        action_body: Dict[str, Any] = {
            "kind": action.to_wire(),
            "lease": lease,
            "budget": (budget or ResourceBudget.step_default()).to_wire(),
        }
        if intent_hint is not None:
            action_body["intent_hint"] = intent_hint
        resp = self._request(
            "POST",
            "/v1/steps/execute",
            {"principal": principal, "branch": branch, "action": action_body},
        )
        return StepResult.from_wire(resp)

    def explain_step(self, step_id: str) -> Dict[str, Json]:
        """GET /v1/steps/{id}/explain — the step's causal narrative."""
        return self._request("GET", f"/v1/steps/{step_id}/explain")

    def retry_step(self, step_id: str) -> StepResult:
        """POST /v1/steps/{id}/retry (no request body)."""
        return StepResult.from_wire(self._request("POST", f"/v1/steps/{step_id}/retry"))

    # -- branches ---------------------------------------------------------

    def fork_branch(self, branch_id: str) -> Branch:
        """POST /v1/branches/{id}/fork — forks one sibling branch."""
        return Branch.from_wire(self._request("POST", f"/v1/branches/{branch_id}/fork"))

    def diff_branch(
        self, branch_id: str, since: Optional[str] = None
    ) -> List[Dict[str, Json]]:
        """POST /v1/branches/{id}/diff — file changes since a state."""
        body = {"since": since} if since is not None else {}
        return self._request("POST", f"/v1/branches/{branch_id}/diff", body)

    def merge_branch(self, branch_id: str, source: str, actor: str) -> Dict[str, Json]:
        """POST /v1/branches/{id}/merge — merge `source` into `branch_id`;
        returns the merged StateNode."""
        return self._request(
            "POST",
            f"/v1/branches/{branch_id}/merge",
            {"source": source, "actor": actor},
        )

    def discard_branch(self, branch_id: str) -> Dict[str, Json]:
        """POST /v1/branches/{id}/discard — returns {"discarded": id}."""
        return self._request("POST", f"/v1/branches/{branch_id}/discard")

    def compare_branches(self, a: str, b: str) -> BranchComparison:
        """GET /v1/branches/{a}/compare/{b}."""
        return BranchComparison.from_wire(
            self._request("GET", f"/v1/branches/{a}/compare/{b}")
        )

    # -- capabilities -----------------------------------------------------

    def capabilities(self, principal: str) -> List[CapabilityLease]:
        """GET /v1/capabilities/{principal} — active leases."""
        resp = self._request("GET", f"/v1/capabilities/{principal}")
        return [CapabilityLease.from_wire(l) for l in resp]

    def request_capability(
        self,
        principal: str,
        operation: str,
        *,
        params: Optional[Json] = None,
        branch: Optional[str] = None,
    ) -> CapabilityLease:
        """POST /v1/capabilities/request — 201 with the granted lease;
        policy denials raise DenialError."""
        body: Dict[str, Any] = {
            "principal": principal,
            "operation": operation,
            "params": params if params is not None else {},
        }
        if branch is not None:
            body["branch"] = branch
        resp = self._request("POST", "/v1/capabilities/request", body)
        return CapabilityLease.from_wire(resp)

    def delegate_capability(
        self,
        delegator: str,
        parent_lease: str,
        delegatee: str,
        *,
        uses: int,
        expires_at: str,
        constraints: Optional[Dict[str, Json]] = None,
        budget: Optional[ResourceBudget] = None,
    ) -> CapabilityLease:
        """POST /v1/capabilities/delegate — attenuate a lease for a
        delegatee. Never widens."""
        body: Dict[str, Any] = {
            "delegator": delegator,
            "parent_lease": parent_lease,
            "delegatee": delegatee,
            "constraints": constraints or {},
            "uses": uses,
            "expires_at": expires_at,
        }
        if budget is not None:
            body["budget"] = budget.to_wire()
        resp = self._request("POST", "/v1/capabilities/delegate", body)
        return CapabilityLease.from_wire(resp)

    def revoke_capability(self, lease: str) -> List[str]:
        """POST /v1/capabilities/revoke — revokes the lease and its whole
        delegation subtree; returns every revoked lease id."""
        resp = self._request("POST", "/v1/capabilities/revoke", {"lease": lease})
        return list(resp.get("revoked", []))

    # -- effects ----------------------------------------------------------

    def list_effects(self, phase: Optional[str] = None) -> List[PendingEffect]:
        """GET /v1/effects?phase=..."""
        resp = self._request("GET", "/v1/effects", query={"phase": phase})
        return [PendingEffect.from_wire(fx) for fx in resp]

    def get_effect(self, effect_id: str) -> PendingEffect:
        """GET /v1/effects/{id}."""
        return PendingEffect.from_wire(self._request("GET", f"/v1/effects/{effect_id}"))

    def effect_handle(self, effect: PendingEffect) -> "EffectHandle":
        return EffectHandle(self, effect)

    def prepare_effect(self, effect_id: str) -> EffectPreview:
        """POST /v1/effects/{id}/prepare — dry run, no side effects."""
        return EffectPreview.from_wire(
            self._request("POST", f"/v1/effects/{effect_id}/prepare")
        )

    def approve_effect(self, effect_id: str, approver: str) -> Dict[str, Json]:
        """POST /v1/effects/{id}/approve — returns {"approved": id}."""
        return self._request(
            "POST", f"/v1/effects/{effect_id}/approve", {"approver": approver}
        )

    def commit_effect(self, effect_id: str) -> Receipt:
        """POST /v1/effects/{id}/commit (no request body)."""
        return Receipt.from_wire(self._request("POST", f"/v1/effects/{effect_id}/commit"))

    def compensate_effect(self, effect_id: str) -> Receipt:
        """POST /v1/effects/{id}/compensate (no request body)."""
        return Receipt.from_wire(
            self._request("POST", f"/v1/effects/{effect_id}/compensate")
        )

    def recover_effects(self) -> Dict[str, Json]:
        """POST /v1/effects/recover — resolve in-doubt effects."""
        return self._request("POST", "/v1/effects/recover")

    def resolve_effect(self, effect_id: str, resolution: Dict[str, Json]) -> Dict[str, Json]:
        """POST /v1/effects/{id}/resolve — operator verdict on an in-doubt
        effect: {"outcome": "committed", "response": {...}} or
        {"outcome": "aborted", "reason": "..."}."""
        return self._request("POST", f"/v1/effects/{effect_id}/resolve", resolution)

    # -- trace / replay / receipts ---------------------------------------

    def trace_query(
        self,
        *,
        episode: Optional[str] = None,
        branch: Optional[str] = None,
        step: Optional[str] = None,
        principal: Optional[str] = None,
        kind: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> List[Dict[str, Json]]:
        """GET /v1/trace/query — raw causal ledger events."""
        return self._request(
            "GET",
            "/v1/trace/query",
            query={
                "episode": episode,
                "branch": branch,
                "step": step,
                "principal": principal,
                "kind": kind,
                "limit": limit,
            },
        )

    def replay_audit(
        self, *, seq_from: Optional[int] = None, seq_to: Optional[int] = None
    ) -> Dict[str, Json]:
        """POST /v1/replay/audit — returns {"mode": "audit", "events": [...]}."""
        body: Dict[str, Any] = {}
        if seq_from is not None:
            body["seq_from"] = seq_from
        if seq_to is not None:
            body["seq_to"] = seq_to
        return self._request("POST", "/v1/replay/audit", body)

    def replay_sandbox(self, step: str) -> Dict[str, Json]:
        """POST /v1/replay/sandbox — re-execute one recorded step."""
        return self._request("POST", "/v1/replay/sandbox", {"step": step})

    def replay_live(self, effect: str, approver: str) -> Receipt:
        """POST /v1/replay/live — re-commit one recorded effect contract."""
        return Receipt.from_wire(
            self._request(
                "POST", "/v1/replay/live", {"effect": effect, "approver": approver}
            )
        )

    def get_receipt(self, receipt_id: str) -> Receipt:
        """GET /v1/receipts/{id}."""
        return Receipt.from_wire(self._request("GET", f"/v1/receipts/{receipt_id}"))


class BranchHandle:
    """A handle to one branch, bound to a client, episode and principal."""

    def __init__(self, kernel: Kernel, episode: str, principal: str, branch: str) -> None:
        self._kernel = kernel
        self.episode = episode
        self.principal = principal
        self.branch = branch

    @property
    def id(self) -> str:
        return self.branch

    def execute(
        self,
        action: ActionKind,
        *,
        principal: Optional[str] = None,
        lease: str = "",
        intent_hint: Optional[str] = None,
        budget: Optional[ResourceBudget] = None,
    ) -> StepResult:
        """Execute one action on this branch. A denied step is still
        recorded and returned as an Observation of kind "denied"."""
        return self._kernel.execute_step(
            principal or self.principal,
            self.branch,
            action,
            lease=lease,
            intent_hint=intent_hint,
            budget=budget,
        )

    def fork(self, count: int = 1) -> List["BranchHandle"]:
        """Fork `count` sibling branches (one kernel call each)."""
        out = []
        for _ in range(count):
            b = self._kernel.fork_branch(self.branch)
            out.append(BranchHandle(self._kernel, self.episode, self.principal, b.id))
        return out

    def diff(self, since: Optional[str] = None) -> List[Dict[str, Json]]:
        return self._kernel.diff_branch(self.branch, since)

    def compare(self, other: Union["BranchHandle", str]) -> BranchComparison:
        other_id = other.id if isinstance(other, BranchHandle) else other
        return self._kernel.compare_branches(self.branch, other_id)

    def merge(
        self, source: Union["BranchHandle", str], *, actor: Optional[str] = None
    ) -> Dict[str, Json]:
        """Merge `source` into this branch; returns the merged StateNode."""
        source_id = source.id if isinstance(source, BranchHandle) else source
        return self._kernel.merge_branch(self.branch, source_id, actor or self.principal)

    def discard(self) -> Dict[str, Json]:
        return self._kernel.discard_branch(self.branch)


class EpisodeHandle(BranchHandle):
    """An episode handle. Acts on the main branch by default:
    ``obs = ep.execute(Shell("pytest")).observation``."""

    @property
    def episode_id(self) -> str:
        return self.episode

    def describe(self) -> EpisodeDescription:
        return self._kernel.describe_episode(self.episode)


class EffectHandle:
    """A pending effect: prepare -> approve -> commit -> (compensate).

    Effects are proposed by executing a connector_op action; the resulting
    "effect_pending" observation names the effect id.
    """

    def __init__(self, kernel: Kernel, effect: PendingEffect) -> None:
        self._kernel = kernel
        self.effect = effect
        self.receipt: Optional[Receipt] = None

    @property
    def id(self) -> str:
        return self.effect.id

    @property
    def contract_hash(self) -> str:
        return self.effect.contract_hash

    def refresh(self) -> PendingEffect:
        self.effect = self._kernel.get_effect(self.effect.id)
        return self.effect

    def prepare(self) -> EffectPreview:
        return self._kernel.prepare_effect(self.effect.id)

    def approve(self, approver: str) -> Dict[str, Json]:
        return self._kernel.approve_effect(self.effect.id, approver)

    def commit(self) -> Receipt:
        self.receipt = self._kernel.commit_effect(self.effect.id)
        return self.receipt

    def compensate(self) -> Receipt:
        return self._kernel.compensate_effect(self.effect.id)

"""HTTP client for the AgentKernel Execution Protocol (JSON binding).

Zero runtime dependencies: transport is stdlib ``urllib``. An alternative
transport (e.g. httpx) can be injected via the ``transport`` argument —
any callable ``(method, url, body_json_or_none, headers) -> (status, body_bytes)``.
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
    BranchDiff,
    CapabilityLease,
    Denial,
    EffectContract,
    EffectPreview,
    Episode,
    Json,
    PendingEffect,
    Receipt,
    ResourceBudget,
    StepResult,
)

Transport = Callable[[str, str, Optional[Dict[str, Any]], Dict[str, str]], Tuple[int, bytes]]

_RETRYABLE_STATUS = {502, 503, 504}


def _urllib_transport(
    method: str, url: str, body: Optional[Dict[str, Any]], headers: Dict[str, str]
) -> Tuple[int, bytes]:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


class Kernel:
    """Entry point: ``kernel = Kernel("http://localhost:7411")``."""

    def __init__(
        self,
        base_url: str,
        *,
        token: Optional[str] = None,
        max_retries: int = 3,
        backoff_base: float = 0.25,
        transport: Optional[Transport] = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self._token = token
        self._max_retries = max_retries
        self._backoff_base = backoff_base
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
                status, raw = self._transport(method, url, body, headers)
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

    # -- episodes ---------------------------------------------------------

    def create_episode(
        self,
        title: str,
        owner: str,
        budget: Optional[ResourceBudget] = None,
        workspace_root: Optional[str] = None,
    ) -> "EpisodeHandle":
        body: Dict[str, Any] = {
            "title": title,
            "owner": owner,
            "budget": (budget or ResourceBudget.step_default()).to_wire(),
        }
        if workspace_root is not None:
            body["workspace_root"] = workspace_root
        resp = self._request("POST", "/v1/episodes", body)
        episode = Episode.from_wire(resp["episode"])
        main_branch = Branch.from_wire(resp["main_branch"])
        return EpisodeHandle(self, episode, main_branch)

    def get_episode(self, episode_id: str) -> "EpisodeHandle":
        resp = self._request("GET", f"/v1/episodes/{episode_id}")
        episode = Episode.from_wire(resp["episode"])
        branches = [Branch.from_wire(b) for b in resp.get("branches", [])]
        main = next(
            (b for b in branches if b.id == episode.main_branch),
            branches[0] if branches else Branch.from_wire(
                {"id": episode.main_branch, "episode": episode.id}
            ),
        )
        return EpisodeHandle(self, episode, main)

    # -- capabilities -----------------------------------------------------

    def capabilities(self, principal: str, namespace: Optional[str] = None) -> List[CapabilityLease]:
        resp = self._request(
            "GET", f"/v1/capabilities/{principal}", query={"namespace": namespace}
        )
        return [CapabilityLease.from_wire(l) for l in resp.get("leases", [])]

    def request_capability(
        self,
        principal: str,
        operation: str,
        *,
        constraints: Optional[Dict[str, Json]] = None,
        uses: int = 1,
        expires_at: Optional[str] = None,
        budget: Optional[ResourceBudget] = None,
        bound_branch: Optional[str] = None,
        justification: str = "",
    ) -> CapabilityLease:
        body: Dict[str, Any] = {
            "principal": principal,
            "operation": operation,
            "constraints": constraints or {},
            "uses": uses,
            "justification": justification,
        }
        if expires_at is not None:
            body["expires_at"] = expires_at
        if budget is not None:
            body["budget"] = budget.to_wire()
        if bound_branch is not None:
            body["bound_branch"] = bound_branch
        resp = self._request("POST", "/v1/capabilities/request", body)
        if "denial" in resp:
            raise DenialError(Denial.from_wire(resp["denial"]))
        if "pending_approval_id" in resp:
            raise KernelError(
                "PENDING_APPROVAL",
                f"awaiting human approval: {resp['pending_approval_id']}",
                202,
            )
        return CapabilityLease.from_wire(resp["lease"])

    def delegate_capability(
        self,
        parent_lease: str,
        child_principal: str,
        *,
        constraints: Dict[str, Json],
        uses: int,
        expires_at: str,
        budget: Optional[ResourceBudget] = None,
    ) -> CapabilityLease:
        resp = self._request(
            "POST",
            "/v1/capabilities/delegate",
            {
                "parent_lease": parent_lease,
                "child_principal": child_principal,
                "constraints": constraints,
                "uses": uses,
                "expires_at": expires_at,
                "budget": (budget or ResourceBudget()).to_wire(),
            },
        )
        return CapabilityLease.from_wire(resp)

    def revoke_capability(
        self, lease: str, *, cascade: bool = False, reason: str = ""
    ) -> List[str]:
        resp = self._request(
            "POST",
            "/v1/capabilities/revoke",
            {"lease": lease, "cascade": cascade, "reason": reason},
        )
        return list(resp.get("revoked_leases", []))

    # -- trace / replay / receipts ---------------------------------------

    def trace_query(
        self,
        query: str,
        *,
        episode: Optional[str] = None,
        limit: Optional[int] = None,
        page_token: Optional[str] = None,
    ) -> Dict[str, Json]:
        return self._request(
            "GET",
            "/v1/trace/query",
            query={"q": query, "episode": episode, "limit": limit, "page_token": page_token},
        )

    def replay(
        self,
        mode: str,
        episode: str,
        *,
        from_step: Optional[str] = None,
        to_step: Optional[str] = None,
    ) -> Dict[str, Json]:
        if mode not in ("audit", "sandbox", "live"):
            raise ValueError(f"invalid replay mode: {mode!r}")
        body: Dict[str, Any] = {"episode": episode}
        if from_step is not None:
            body["from_step"] = from_step
        if to_step is not None:
            body["to_step"] = to_step
        return self._request("POST", f"/v1/replay/{mode}", body)

    def get_receipt(self, receipt_id: str) -> Receipt:
        return Receipt.from_wire(self._request("GET", f"/v1/receipts/{receipt_id}"))

    def get_effect(self, effect_id: str) -> PendingEffect:
        return PendingEffect.from_wire(self._request("GET", f"/v1/effects/{effect_id}"))


class BranchHandle:
    """A handle to one branch, bound to a client and an episode."""

    def __init__(self, kernel: Kernel, episode: Episode, branch: Branch) -> None:
        self._kernel = kernel
        self.episode = episode
        self.branch = branch

    @property
    def id(self) -> str:
        return self.branch.id

    def execute(
        self,
        action: ActionKind,
        *,
        actor: Optional[str] = None,
        lease: str = "",
        intent_hint: Optional[str] = None,
        budget: Optional[ResourceBudget] = None,
    ) -> StepResult:
        """Execute one action on this branch.

        A policy denial recorded as a step is returned as an Observation of
        kind "denied"; a request rejected outright raises DenialError.
        """
        action_body: Dict[str, Any] = {
            "kind": action.to_wire(),
            "lease": lease,
            "budget": (budget or ResourceBudget.step_default()).to_wire(),
        }
        if intent_hint is not None:
            action_body["intent_hint"] = intent_hint
        resp = self._kernel._request(
            "POST",
            "/v1/steps/execute",
            {
                "branch": self.branch.id,
                "actor": actor or self.episode.owner,
                "action": action_body,
            },
        )
        return StepResult.from_wire(resp)

    def fork(self, count: int = 1, from_state: Optional[str] = None) -> List["BranchHandle"]:
        body: Dict[str, Any] = {"count": count}
        if from_state is not None:
            body["from_state"] = from_state
        resp = self._kernel._request("POST", f"/v1/branches/{self.branch.id}/fork", body)
        return [
            BranchHandle(self._kernel, self.episode, Branch.from_wire(b))
            for b in resp.get("branches", [])
        ]

    def diff(self, since: Optional[str] = None) -> BranchDiff:
        body = {"since": since} if since is not None else {}
        resp = self._kernel._request("POST", f"/v1/branches/{self.branch.id}/diff", body)
        return BranchDiff.from_wire(resp)

    def compare(self, other: Union["BranchHandle", str]) -> BranchComparison:
        other_id = other.id if isinstance(other, BranchHandle) else other
        resp = self._kernel._request(
            "GET", f"/v1/branches/{self.branch.id}/compare/{other_id}"
        )
        return BranchComparison.from_wire(resp)

    def merge(
        self, into: Union["BranchHandle", str], *, require_clean: bool = False
    ) -> Dict[str, Json]:
        into_id = into.id if isinstance(into, BranchHandle) else into
        return self._kernel._request(
            "POST",
            f"/v1/branches/{self.branch.id}/merge",
            {"into": into_id, "require_clean": require_clean},
        )

    def discard(self, reason: str = "") -> Branch:
        resp = self._kernel._request(
            "POST", f"/v1/branches/{self.branch.id}/discard", {"reason": reason}
        )
        self.branch = Branch.from_wire(resp)
        return self.branch

    def propose_effect(
        self,
        contract: EffectContract,
        *,
        proposer: Optional[str] = None,
        step: str = "",
        lease: str = "",
    ) -> "EffectHandle":
        resp = self._kernel._request(
            "POST",
            "/v1/effects",
            {
                "contract": contract.to_wire(),
                "proposer": proposer or self.episode.owner,
                "branch": self.branch.id,
                "step": step,
                "lease": lease,
            },
        )
        if "denial" in resp:
            raise DenialError(Denial.from_wire(resp["denial"]))
        effect = PendingEffect.from_wire(resp.get("effect", resp))
        return EffectHandle(self._kernel, effect)

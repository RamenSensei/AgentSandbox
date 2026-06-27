"""A minimal in-process mock kernel: stdlib http.server implementing enough
of the AgentKernel HTTP API to exercise the client end to end."""

from __future__ import annotations

import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional, Tuple


class MockKernelState:
    def __init__(self) -> None:
        self.counter = 0
        self.episodes: Dict[str, Dict[str, Any]] = {}
        self.branches: Dict[str, Dict[str, Any]] = {}
        self.effects: Dict[str, Dict[str, Any]] = {}
        self.receipts: Dict[str, Dict[str, Any]] = {}
        self.leases: Dict[str, Dict[str, Any]] = {}
        self.flaky_remaining = 0  # respond 503 this many times

    def next_id(self, prefix: str) -> str:
        self.counter += 1
        return f"{prefix}-{self.counter}"


DENIAL = {
    "code": "CAPABILITY_DENIED",
    "attempted_operation": "net.raw_socket",
    "reason": "credential may only be used by the typed GitHub connector",
    "safe_alternatives": ["github.create_pull_request"],
    "requestable_scopes": [
        {
            "operation": "net.http_read",
            "constraints": {"domain": "api.github.com"},
            "requires_human": False,
        }
    ],
    "escalation_allowed": True,
}

BUDGET = {
    "cpu_ms": 1000,
    "memory_bytes": 0,
    "network_bytes": 0,
    "tokens": 5,
    "cost_micro_usd": 0,
    "risk_units": 0,
}


class Handler(BaseHTTPRequestHandler):
    state: MockKernelState  # set by make_server

    def log_message(self, *args: Any) -> None:
        pass

    def _send(self, status: int, payload: Dict[str, Any]) -> None:
        raw = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _body(self) -> Dict[str, Any]:
        n = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(n)) if n else {}

    def do_POST(self) -> None:  # noqa: N802
        self._route("POST")

    def do_GET(self) -> None:  # noqa: N802
        self._route("GET")

    def _route(self, method: str) -> None:
        st = self.state
        if st.flaky_remaining > 0:
            st.flaky_remaining -= 1
            self._send(503, {"code": "BACKEND_UNAVAILABLE", "message": "warming up"})
            return
        path = self.path.split("?")[0]
        try:
            handled = self._dispatch(method, path)
        except Exception as e:  # pragma: no cover
            self._send(500, {"code": "OTHER", "message": str(e)})
            return
        if not handled:
            self._send(404, {"code": "NOT_FOUND", "message": f"no route {method} {path}"})

    def _dispatch(self, method: str, path: str) -> bool:
        st = self.state

        if method == "POST" and path == "/v1/episodes":
            body = self._body()
            ep_id = st.next_id("ep")
            br_id = st.next_id("br")
            root = st.next_id("st")
            episode = {
                "id": ep_id,
                "title": body.get("title", ""),
                "owner": body.get("owner", ""),
                "root_state": root,
                "main_branch": br_id,
                "budget": body.get("budget", BUDGET),
                "created_at": "2026-01-01T00:00:00Z",
            }
            branch = {
                "id": br_id,
                "episode": ep_id,
                "forked_from": root,
                "head": root,
                "discarded": False,
                "created_at": "2026-01-01T00:00:00Z",
            }
            st.episodes[ep_id] = episode
            st.branches[br_id] = branch
            self._send(201, {"episode": episode, "main_branch": branch})
            return True

        m = re.fullmatch(r"/v1/episodes/(ep-[\w-]+)", path)
        if method == "GET" and m:
            ep = st.episodes.get(m.group(1))
            if not ep:
                self._send(404, {"code": "NOT_FOUND", "message": m.group(1)})
                return True
            branches = [b for b in st.branches.values() if b["episode"] == ep["id"]]
            self._send(
                200,
                {
                    "episode": ep,
                    "branches": branches,
                    "step_count": 0,
                    "pending_effects": 0,
                    "budget_remaining": ep["budget"],
                },
            )
            return True

        if method == "POST" and path == "/v1/steps/execute":
            body = self._body()
            kind = body["action"]["kind"]
            step_id = st.next_id("step")
            if kind["kind"] == "shell" and "forbidden" in kind.get("command", ""):
                obs = {"kind": "denied", "denial": DENIAL}
                self._send(
                    200,
                    {"step": step_id, "observation": obs, "usage": BUDGET},
                )
                return True
            if kind["kind"] == "connector_op":
                fx_id = st.next_id("fx")
                st.effects[fx_id] = self._new_effect(fx_id, body)
                obs = {
                    "kind": "effect_pending",
                    "effect": fx_id,
                    "contract_hash": "sha256:deadbeef",
                    "class": "compensatable",
                }
                self._send(
                    200, {"step": step_id, "observation": obs, "usage": BUDGET}
                )
                return True
            new_state = st.next_id("st")
            branch = st.branches.get(body["branch"])
            if branch:
                branch["head"] = new_state
            obs = {
                "kind": "success",
                "summary": "ok",
                "stdout_head": "12 passed",
                "exit_code": 0,
                "full_output": "sha256:abc",
                "truncated": False,
            }
            self._send(
                200,
                {
                    "step": step_id,
                    "observation": obs,
                    "produced_state": new_state,
                    "usage": BUDGET,
                },
            )
            return True

        m = re.fullmatch(r"/v1/branches/(br-[\w-]+)/fork", path)
        if method == "POST" and m:
            body = self._body()
            parent = st.branches[m.group(1)]
            out = []
            for _ in range(int(body.get("count", 1))):
                bid = st.next_id("br")
                b = {
                    "id": bid,
                    "episode": parent["episode"],
                    "parent_branch": parent["id"],
                    "forked_from": parent["head"],
                    "head": parent["head"],
                    "discarded": False,
                    "created_at": "2026-01-01T00:00:00Z",
                }
                st.branches[bid] = b
                out.append(b)
            self._send(200, {"branches": out})
            return True

        m = re.fullmatch(r"/v1/branches/(br-[\w-]+)/diff", path)
        if method == "POST" and m:
            self._send(
                200,
                {
                    "delta": {
                        "files": [
                            {"op": "modified", "path": "a.py", "old_blob": "sha256:1", "new_blob": "sha256:2"}
                        ],
                        "policy_epoch": 3,
                    },
                    "summary": "1 file changed",
                },
            )
            return True

        m = re.fullmatch(r"/v1/branches/(br-[\w-]+)/compare/(br-[\w-]+)", path)
        if method == "GET" and m:
            self._send(
                200,
                {
                    "common_ancestor": "st-1",
                    "left_delta": {"policy_epoch": 1},
                    "right_delta": {"policy_epoch": 1},
                    "conflicting_paths": ["a.py"],
                },
            )
            return True

        m = re.fullmatch(r"/v1/branches/(br-[\w-]+)/merge", path)
        if method == "POST" and m:
            self._send(200, {"merged": {"id": st.next_id("st"), "branch": self._body()["into"]}})
            return True

        m = re.fullmatch(r"/v1/branches/(br-[\w-]+)/discard", path)
        if method == "POST" and m:
            b = st.branches[m.group(1)]
            b["discarded"] = True
            self._send(200, b)
            return True

        if method == "POST" and path == "/v1/capabilities/request":
            body = self._body()
            if body.get("operation") == "net.raw_socket":
                self._send(403, {"code": "DENIED", "message": "denied", "denial": DENIAL})
                return True
            lease_id = st.next_id("lease")
            lease = {
                "id": lease_id,
                "principal": body["principal"],
                "operation": body["operation"],
                "constraints": body.get("constraints", {}),
                "remaining_uses": body.get("uses", 1),
                "issued_at": "2026-01-01T00:00:00Z",
                "expires_at": body.get("expires_at", "2026-01-01T01:00:00Z"),
                "budget": BUDGET,
                "revoked": False,
            }
            st.leases[lease_id] = lease
            self._send(200, {"lease": lease})
            return True

        if method == "POST" and path == "/v1/capabilities/delegate":
            body = self._body()
            parent = st.leases[body["parent_lease"]]
            lease_id = st.next_id("lease")
            lease = dict(parent)
            lease.update(
                id=lease_id,
                principal=body["child_principal"],
                parent_lease=parent["id"],
                constraints=body["constraints"],
                remaining_uses=body["uses"],
            )
            st.leases[lease_id] = lease
            self._send(200, lease)
            return True

        if method == "POST" and path == "/v1/capabilities/revoke":
            body = self._body()
            lease = st.leases.get(body["lease"])
            revoked = []
            if lease:
                lease["revoked"] = True
                revoked.append(lease["id"])
                if body.get("cascade"):
                    for other in st.leases.values():
                        if other.get("parent_lease") == lease["id"]:
                            other["revoked"] = True
                            revoked.append(other["id"])
            self._send(200, {"revoked_leases": revoked})
            return True

        m = re.fullmatch(r"/v1/capabilities/(pr-[\w-]+)", path)
        if method == "GET" and m:
            leases = [l for l in st.leases.values() if l["principal"] == m.group(1)]
            self._send(200, {"leases": leases})
            return True

        if method == "POST" and path == "/v1/effects":
            body = self._body()
            fx_id = st.next_id("fx")
            fx = self._new_effect(fx_id, body)
            st.effects[fx_id] = fx
            self._send(201, {"effect": fx})
            return True

        m = re.fullmatch(r"/v1/effects/(fx-[\w-]+)(/(\w+))?", path)
        if m:
            fx = st.effects.get(m.group(1))
            if not fx:
                self._send(404, {"code": "NOT_FOUND", "message": m.group(1)})
                return True
            verb = m.group(3)
            if method == "GET" and not verb:
                self._send(200, fx)
                return True
            if method == "POST" and verb == "prepare":
                fx["phase"] = {"phase": "prepared", "preview": {"will": "create PR"}}
                self._send(
                    200,
                    {
                        "preview": {"will": "create PR"},
                        "observed_preconditions": {"base_head_sha": "abc123"},
                        "effect": fx,
                    },
                )
                return True
            if method == "POST" and verb == "approve":
                body = self._body()
                if body.get("contract_hash") != fx["contract_hash"]:
                    self._send(
                        409, {"code": "STALE_AUTHORIZATION", "message": "hash mismatch"}
                    )
                    return True
                fx["phase"] = {
                    "phase": "approved",
                    "approver": body["approver"],
                    "approved_at": "2026-01-01T00:00:00Z",
                    "policy_epoch": 1,
                }
                self._send(200, fx)
                return True
            if method == "POST" and verb == "commit":
                body = self._body()
                if body.get("expected_contract_hash") != fx["contract_hash"]:
                    self._send(
                        403,
                        {
                            "code": "DENIED",
                            "message": "stale contract hash",
                            "denial": dict(DENIAL, code="STALE_AUTHORIZATION"),
                        },
                    )
                    return True
                rcpt_id = st.next_id("rcpt")
                receipt = {
                    "id": rcpt_id,
                    "body": {
                        "effect": fx["id"],
                        "who": fx["proposer"],
                        "operation": fx["contract"]["operation"],
                        "resource": fx["contract"]["resource"],
                        "contract_hash": fx["contract_hash"],
                        "branch": fx["branch"],
                        "step": fx["step"],
                        "policy_epoch": 1,
                        "authorization_witness": "sha256:w",
                        "external_response_digest": "sha256:r",
                        "committed_at": "2026-01-01T00:00:00Z",
                    },
                    "signature": "aa" * 32,
                    "key_id": "kernel-key-1",
                }
                st.receipts[rcpt_id] = receipt
                fx["phase"] = {"phase": "committed", "receipt": rcpt_id}
                self._send(200, {"receipt": receipt})
                return True
            if method == "POST" and verb == "abort":
                fx["phase"] = {"phase": "aborted", "reason": self._body().get("reason", "")}
                self._send(200, fx)
                return True
            if method == "POST" and verb == "compensate":
                rcpt_id = st.next_id("rcpt")
                receipt = {"id": rcpt_id, "body": {"effect": fx["id"]}, "signature": "bb" * 32, "key_id": "kernel-key-1"}
                st.receipts[rcpt_id] = receipt
                fx["phase"] = {"phase": "compensated", "compensating_receipt": rcpt_id}
                self._send(200, receipt)
                return True

        if method == "GET" and path == "/v1/trace/query":
            self._send(200, {"entries": [], "next_page_token": ""})
            return True

        m = re.fullmatch(r"/v1/replay/(audit|sandbox|live)", path)
        if method == "POST" and m:
            body = self._body()
            self._send(
                200,
                {
                    "episode": body["episode"],
                    "mode": m.group(1),
                    "effective_class": "filesystem_only",
                    "steps_replayed": 4,
                    "divergences": [],
                    "completed_at": "2026-01-01T00:00:00Z",
                },
            )
            return True

        m = re.fullmatch(r"/v1/receipts/(rcpt-[\w-]+)", path)
        if method == "GET" and m:
            rcpt = st.receipts.get(m.group(1))
            if rcpt:
                self._send(200, rcpt)
            else:
                self._send(404, {"code": "NOT_FOUND", "message": m.group(1)})
            return True

        return False

    def _new_effect(self, fx_id: str, body: Dict[str, Any]) -> Dict[str, Any]:
        contract = body.get("contract") or {
            "operation": "github.create_pull_request",
            "resource": "org/repo",
            "arguments": {},
            "preconditions": {},
            "idempotency_key": "ep-1-step-1",
            "class": "compensatable",
        }
        return {
            "id": fx_id,
            "contract": contract,
            "contract_hash": "sha256:deadbeef",
            "proposer": body.get("proposer", "pr-agent"),
            "branch": body.get("branch", "br-1"),
            "step": body.get("step", ""),
            "lease": body.get("lease", ""),
            "phase": {"phase": "proposed"},
            "proposed_at": "2026-01-01T00:00:00Z",
        }

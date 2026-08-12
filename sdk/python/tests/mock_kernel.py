"""A minimal in-process mock kernel: stdlib http.server mirroring the
routes and wire shapes of kernel/api/src/http.rs."""

from __future__ import annotations

import json
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Tuple
from urllib.parse import parse_qs, urlparse


class MockKernelState:
    def __init__(self) -> None:
        self.counter = 0
        self.episodes: Dict[str, Dict[str, Any]] = {}
        self.branches: Dict[str, Dict[str, Any]] = {}
        self.effects: Dict[str, Dict[str, Any]] = {}
        self.receipts: Dict[str, Dict[str, Any]] = {}
        self.leases: Dict[str, Dict[str, Any]] = {}
        self.flaky_remaining = 0  # respond 503 this many times
        self.delay_s = 0.0  # sleep before every response while > 0

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

    def _send(self, status: int, payload: Any) -> None:
        if self.state.delay_s > 0:
            time.sleep(self.state.delay_s)
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
        parsed = urlparse(self.path)
        try:
            handled = self._dispatch(method, parsed.path, parse_qs(parsed.query))
        except Exception as e:  # pragma: no cover
            self._send(500, {"code": "OTHER", "message": str(e)})
            return
        if not handled:
            self._send(404, {"code": "NOT_FOUND", "message": f"no route {method} {parsed.path}"})

    def _new_effect(self, fx_id: str, branch: str, proposer: str) -> Dict[str, Any]:
        return {
            "id": fx_id,
            "contract": {
                "operation": "github.create_pull_request",
                "resource": "org/repo",
                "arguments": {},
                "preconditions": {},
                "idempotency_key": "ep-1-step-1",
                "class": "compensatable",
            },
            "contract_hash": "sha256:deadbeef",
            "proposer": proposer,
            "branch": branch,
            "step": "",
            "lease": "",
            "phase": {"phase": "proposed"},
            "proposed_at": "2026-01-01T00:00:00Z",
        }

    def _make_receipt(self, fx: Dict[str, Any]) -> Dict[str, Any]:
        rcpt_id = self.state.next_id("rcpt")
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
        self.state.receipts[rcpt_id] = receipt
        return receipt

    def _dispatch(self, method: str, path: str, query: Dict[str, List[str]]) -> bool:
        st = self.state

        if method == "GET" and path == "/healthz":
            self._send(200, {"status": "ok", "version": "1.0.0-mock"})
            return True

        if method == "POST" and path == "/v1/episodes":
            body = self._body()
            ep_id = st.next_id("ep")
            br_id = st.next_id("br")
            root = st.next_id("st")
            st.episodes[ep_id] = {
                "episode": ep_id,
                "root_branch": br_id,
                "root_state": root,
                "created_by": body.get("principal", ""),
                "objective": body.get("objective", ""),
                "remaining_budget": BUDGET,
            }
            st.branches[br_id] = {
                "id": br_id,
                "episode": ep_id,
                "forked_from": root,
                "head": root,
                "discarded": False,
                "created_at": "2026-01-01T00:00:00Z",
            }
            self._send(201, {"episode": ep_id, "branch": br_id, "root_state": root})
            return True

        m = re.fullmatch(r"/v1/episodes/(ep-[\w-]+)", path)
        if method == "GET" and m:
            ep = st.episodes.get(m.group(1))
            if not ep:
                self._send(404, {"code": "NOT_FOUND", "message": m.group(1)})
                return True
            branches = [b for b in st.branches.values() if b["episode"] == ep["episode"]]
            self._send(
                200,
                {
                    "episode": ep["episode"],
                    "root_branch": ep["root_branch"],
                    "root_state": ep["root_state"],
                    "branches": branches,
                    "created_by": ep["created_by"],
                    "remaining_budget": ep["remaining_budget"],
                },
            )
            return True

        if method == "POST" and path == "/v1/steps/execute":
            body = self._body()
            kind = body["action"]["kind"]
            step_id = st.next_id("step")
            branch = st.branches.get(body["branch"])
            if not branch:
                self._send(404, {"code": "NOT_FOUND", "message": body["branch"]})
                return True
            if kind["kind"] == "shell" and "forbidden" in kind.get("command", ""):
                self._send(
                    403,
                    {
                        "step": step_id,
                        "state": branch["head"],
                        "observation": {"kind": "denied", "denial": DENIAL},
                        "error": {
                            "code": "DENIED",
                            "message": DENIAL["reason"],
                            "denial": DENIAL,
                        },
                    },
                )
                return True
            if kind["kind"] == "connector_op":
                fx_id = st.next_id("fx")
                st.effects[fx_id] = self._new_effect(
                    fx_id, body["branch"], body.get("principal", "")
                )
                self._send(
                    200,
                    {
                        "step": step_id,
                        "state": branch["head"],
                        "observation": {
                            "kind": "effect_pending",
                            "effect": fx_id,
                            "contract_hash": "sha256:deadbeef",
                            "class": "compensatable",
                        },
                    },
                )
                return True
            branch["head"] = st.next_id("st")
            self._send(
                200,
                {
                    "step": step_id,
                    "state": branch["head"],
                    "observation": {
                        "kind": "success",
                        "summary": "ok",
                        "stdout_head": "12 passed",
                        "exit_code": 0,
                        "full_output": "sha256:abc",
                        "truncated": False,
                    },
                },
            )
            return True

        m = re.fullmatch(r"/v1/steps/(step-[\w-]+)/explain", path)
        if method == "GET" and m:
            self._send(
                200,
                {
                    "step": m.group(1),
                    "episode": "ep-1",
                    "branch": "br-1",
                    "principal": "pr-agent",
                    "action": {"kind": {"kind": "shell", "command": "pytest"}},
                    "policy_decisions": [],
                    "denial": None,
                    "state": "st-2",
                    "state_delta": None,
                    "observation": {"kind": "success"},
                    "effects_proposed": [],
                    "events": [{"seq": 1, "kind": "step_started"}],
                },
            )
            return True

        m = re.fullmatch(r"/v1/steps/(step-[\w-]+)/retry", path)
        if method == "POST" and m:
            self._send(
                200,
                {
                    "step": st.next_id("step"),
                    "state": st.next_id("st"),
                    "observation": {
                        "kind": "success",
                        "summary": "ok",
                        "exit_code": 0,
                        "full_output": "sha256:abc",
                        "truncated": False,
                    },
                },
            )
            return True

        m = re.fullmatch(r"/v1/branches/(br-[\w-]+)/fork", path)
        if method == "POST" and m:
            parent = st.branches.get(m.group(1))
            if not parent:
                self._send(404, {"code": "NOT_FOUND", "message": m.group(1)})
                return True
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
            self._send(200, b)
            return True

        m = re.fullmatch(r"/v1/branches/(br-[\w-]+)/diff", path)
        if method == "POST" and m:
            self._send(
                200,
                [
                    {
                        "op": "modified",
                        "path": "a.py",
                        "old_blob": "sha256:1",
                        "new_blob": "sha256:2",
                    }
                ],
            )
            return True

        m = re.fullmatch(r"/v1/branches/(br-[\w-]+)/compare/(br-[\w-]+)", path)
        if method == "GET" and m:
            self._send(
                200,
                {"base": "st-1", "changed_in_a": ["a.py"], "changed_in_b": ["a.py"]},
            )
            return True

        m = re.fullmatch(r"/v1/branches/(br-[\w-]+)/merge", path)
        if method == "POST" and m:
            body = self._body()
            dest = st.branches.get(m.group(1))
            if not dest:
                self._send(404, {"code": "NOT_FOUND", "message": m.group(1)})
                return True
            node = {
                "id": st.next_id("st"),
                "episode": dest["episode"],
                "branch": dest["id"],
                "parent": dest["head"],
                "merge_parent": st.branches.get(body["source"], {}).get("head"),
                "actor": body["actor"],
                "delta": {"policy_epoch": 1},
                "workspace_root": "/tmp/ws",
                "replay_class": "filesystem_only",
                "created_at": "2026-01-01T00:00:00Z",
            }
            dest["head"] = node["id"]
            self._send(200, node)
            return True

        m = re.fullmatch(r"/v1/branches/(br-[\w-]+)/discard", path)
        if method == "POST" and m:
            b = st.branches.get(m.group(1))
            if b:
                b["discarded"] = True
            self._send(200, {"discarded": m.group(1)})
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
                "constraints": {},
                "remaining_uses": 1,
                "issued_at": "2026-01-01T00:00:00Z",
                "expires_at": "2026-01-01T01:00:00Z",
                "budget": BUDGET,
                "revoked": False,
            }
            st.leases[lease_id] = lease
            self._send(201, lease)
            return True

        if method == "POST" and path == "/v1/capabilities/delegate":
            body = self._body()
            parent = st.leases.get(body["parent_lease"])
            if not parent:
                self._send(404, {"code": "NOT_FOUND", "message": body["parent_lease"]})
                return True
            lease_id = st.next_id("lease")
            lease = dict(parent)
            lease.update(
                id=lease_id,
                principal=body["delegatee"],
                parent_lease=parent["id"],
                constraints=body.get("constraints", {}),
                remaining_uses=body["uses"],
                expires_at=body["expires_at"],
            )
            st.leases[lease_id] = lease
            self._send(201, lease)
            return True

        if method == "POST" and path == "/v1/capabilities/revoke":
            body = self._body()
            lease = st.leases.get(body["lease"])
            revoked = []
            if lease:
                lease["revoked"] = True
                revoked.append(lease["id"])
                for other in st.leases.values():
                    if other.get("parent_lease") == lease["id"]:
                        other["revoked"] = True
                        revoked.append(other["id"])
            self._send(200, {"revoked": revoked})
            return True

        m = re.fullmatch(r"/v1/capabilities/(pr-[\w-]+)", path)
        if method == "GET" and m:
            leases = [
                l
                for l in st.leases.values()
                if l["principal"] == m.group(1) and not l["revoked"]
            ]
            self._send(200, leases)
            return True

        if method == "GET" and path == "/v1/effects":
            phase = (query.get("phase") or [None])[0]
            out = [
                fx
                for fx in st.effects.values()
                if phase is None or fx["phase"]["phase"] == phase
            ]
            self._send(200, out)
            return True

        if method == "POST" and path == "/v1/effects/recover":
            self._send(200, {"resolutions": []})
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
                    },
                )
                return True
            if method == "POST" and verb == "approve":
                body = self._body()
                fx["phase"] = {
                    "phase": "approved",
                    "approver": body["approver"],
                    "approved_at": "2026-01-01T00:00:00Z",
                    "policy_epoch": 1,
                }
                self._send(200, {"approved": fx["id"]})
                return True
            if method == "POST" and verb == "commit":
                if fx["phase"]["phase"] != "approved":
                    self._send(
                        409,
                        {
                            "code": "WRONG_EFFECT_PHASE",
                            "message": f"commit requires approved, effect is {fx['phase']['phase']}",
                        },
                    )
                    return True
                receipt = self._make_receipt(fx)
                fx["phase"] = {"phase": "committed", "receipt": receipt["id"]}
                self._send(200, receipt)
                return True
            if method == "POST" and verb == "compensate":
                receipt = self._make_receipt(fx)
                fx["phase"] = {
                    "phase": "compensated",
                    "compensating_receipt": receipt["id"],
                }
                self._send(200, receipt)
                return True
            if method == "POST" and verb == "resolve":
                self._send(200, {"resolved": fx["id"], "receipt": None})
                return True

        if method == "GET" and path == "/v1/trace/query":
            self._send(
                200,
                [{"seq": 1, "kind": "step_started"}, {"seq": 2, "kind": "step_finished"}],
            )
            return True

        m = re.fullmatch(r"/v1/replay/(\w+)", path)
        if method == "POST" and m:
            mode = m.group(1)
            body = self._body()
            if mode == "audit":
                self._send(200, {"mode": "audit", "events": [{"seq": 1, "kind": "step_started"}]})
                return True
            if mode == "sandbox":
                if not body.get("step"):
                    self._send(500, {"code": "OTHER", "message": "sandbox replay requires `step`"})
                    return True
                self._send(
                    200,
                    {
                        "step": body["step"],
                        "original_exit_code": 0,
                        "rerun_exit_code": 0,
                        "workspace_match": True,
                        "replay_class": "filesystem_only",
                    },
                )
                return True
            if mode == "live":
                fx = st.effects.get(body.get("effect", ""))
                if not fx:
                    self._send(404, {"code": "NOT_FOUND", "message": str(body.get("effect"))})
                    return True
                self._send(200, self._make_receipt(fx))
                return True
            self._send(
                400,
                {"code": "INVALID_ID", "message": f"expected audit|sandbox|live, got {mode}"},
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


def make_server() -> Tuple[ThreadingHTTPServer, MockKernelState, str]:
    state = MockKernelState()
    handler = type("BoundHandler", (Handler,), {"state": state})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, state, f"http://127.0.0.1:{server.server_address[1]}"

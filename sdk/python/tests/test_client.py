"""End-to-end tests for the agentkernel client against a mock kernel.

Runnable with either:
    python3 -m unittest discover sdk/python
    python3 -m pytest sdk/python
"""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
sys.path.insert(0, os.path.dirname(__file__))

from agentkernel import (  # noqa: E402
    ConnectorOp,
    DenialError,
    EffectContract,
    Kernel,
    KernelError,
    Shell,
)
from mock_kernel import make_server  # noqa: E402


class ClientTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server, cls.state, cls.url = make_server()
        cls.kernel = Kernel(cls.url, backoff_base=0.0, sleep=lambda _: None)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()

    def _episode(self):
        return self.kernel.create_episode("fix issue 42", owner="pr-agent")

    def test_create_and_describe_episode(self) -> None:
        ep = self._episode()
        self.assertTrue(ep.episode.id.startswith("ep-"))
        self.assertTrue(ep.branch.id.startswith("br-"))
        desc = ep.describe()
        self.assertEqual(desc["episode"]["id"], ep.episode.id)

    def test_execute_success_observation(self) -> None:
        ep = self._episode()
        res = ep.execute(Shell("pytest"), lease="lease-abc")
        self.assertTrue(res.step.startswith("step-"))
        self.assertTrue(res.observation.is_success)
        self.assertEqual(res.observation.stdout_head, "12 passed")
        self.assertTrue(res.produced_state.startswith("st-"))
        self.assertEqual(res.usage.cpu_ms, 1000)

    def test_denied_step_is_an_observation_with_structured_denial(self) -> None:
        ep = self._episode()
        res = ep.execute(Shell("forbidden thing"), lease="lease-abc")
        self.assertTrue(res.observation.is_denied)
        self.assertIsNone(res.produced_state)  # no invisible state transition
        denial = res.observation.denial
        self.assertEqual(denial.code, "CAPABILITY_DENIED")
        self.assertIn("github.create_pull_request", denial.safe_alternatives)

    def test_fork_diff_compare_merge_discard(self) -> None:
        ep = self._episode()
        branches = ep.fork(3)
        self.assertEqual(len(branches), 3)
        self.assertEqual({b.branch.parent_branch for b in branches}, {ep.branch.id})
        diff = branches[0].diff()
        self.assertEqual(diff.summary, "1 file changed")
        self.assertEqual(diff.delta.files[0]["op"], "modified")
        cmp_ = branches[0].compare(branches[1])
        self.assertEqual(cmp_.conflicting_paths, ["a.py"])
        merged = branches[0].merge(ep)
        self.assertIn("merged", merged)
        discarded = branches[2].discard("lost the race")
        self.assertTrue(discarded.discarded)

    def test_connector_op_becomes_pending_effect(self) -> None:
        ep = self._episode()
        res = ep.execute(
            ConnectorOp("github", "create_pull_request", {"base": "main"}),
            lease="lease-abc",
        )
        self.assertEqual(res.observation.kind, "effect_pending")
        self.assertTrue(res.observation.effect.startswith("fx-"))

    def test_effect_lifecycle_context_manager(self) -> None:
        ep = self._episode()
        contract = EffectContract(
            operation="github.create_pull_request",
            resource="org/repo",
            arguments={"base": "main", "head": "sandbox/fix"},
            preconditions={"base_head_sha": "abc123"},
            idempotency_key="ep-1-step-1",
            class_="compensatable",
        )
        with ep.propose_effect(contract, lease="lease-abc") as fx:
            preview = fx.prepare()
            self.assertEqual(preview.preview, {"will": "create PR"})
            fx.approve("pr-human")
            receipt = fx.commit()
        self.assertTrue(receipt.id.startswith("rcpt-"))
        self.assertEqual(receipt.body["contract_hash"], "sha256:deadbeef")
        fetched = self.kernel.get_receipt(receipt.id)
        self.assertEqual(fetched.id, receipt.id)

    def test_uncommitted_effect_is_aborted_on_exit(self) -> None:
        ep = self._episode()
        contract = EffectContract(
            operation="github.create_pull_request",
            resource="org/repo",
            arguments={},
            preconditions={},
            idempotency_key="k",
            class_="compensatable",
        )
        with ep.propose_effect(contract) as fx:
            fx.prepare()
        effect = self.kernel.get_effect(fx.id)
        self.assertEqual(effect.phase["phase"], "aborted")

    def test_stale_contract_hash_raises_denial_error(self) -> None:
        ep = self._episode()
        contract = EffectContract("op", "res", {}, {}, "k2", "irreversible")
        fx = ep.propose_effect(contract)
        with self.assertRaises(DenialError) as ctx:
            fx.commit(expected_contract_hash="sha256:wrong")
        self.assertEqual(ctx.exception.denial.code, "STALE_AUTHORIZATION")
        fx.abort()

    def test_capability_request_denied_carries_scopes(self) -> None:
        with self.assertRaises(DenialError) as ctx:
            self.kernel.request_capability("pr-agent", "net.raw_socket")
        err = ctx.exception
        self.assertEqual(err.denial_code, "CAPABILITY_DENIED")
        self.assertEqual(err.safe_alternatives, ["github.create_pull_request"])
        self.assertEqual(err.requestable_scopes[0].operation, "net.http_read")
        self.assertFalse(err.requestable_scopes[0].requires_human)
        self.assertTrue(err.escalation_allowed)

    def test_capability_grant_delegate_revoke(self) -> None:
        lease = self.kernel.request_capability(
            "pr-agent",
            "github.create_pull_request",
            constraints={"repository": {"kind": "equals", "value": "org/repo"}},
            uses=2,
        )
        self.assertTrue(lease.id.startswith("lease-"))
        child = self.kernel.delegate_capability(
            lease.id,
            "pr-child",
            constraints={"repository": {"kind": "equals", "value": "org/repo"}},
            uses=1,
            expires_at=lease.expires_at,
        )
        self.assertEqual(child.parent_lease, lease.id)
        held = self.kernel.capabilities("pr-child")
        self.assertIn(child.id, [l.id for l in held])
        revoked = self.kernel.revoke_capability(lease.id, cascade=True)
        self.assertIn(child.id, revoked)

    def test_replay_modes(self) -> None:
        ep = self._episode()
        report = self.kernel.replay("audit", ep.episode.id)
        self.assertEqual(report["mode"], "audit")
        self.assertEqual(report["effective_class"], "filesystem_only")
        with self.assertRaises(ValueError):
            self.kernel.replay("deterministic", ep.episode.id)

    def test_trace_query(self) -> None:
        out = self.kernel.trace_query("effects where class >= compensatable", limit=10)
        self.assertEqual(out["entries"], [])

    def test_retry_on_503(self) -> None:
        self.state.flaky_remaining = 2
        ep = self._episode()  # succeeds after two retried 503s
        self.assertTrue(ep.episode.id.startswith("ep-"))

    def test_retries_exhausted_surface_kernel_error(self) -> None:
        self.state.flaky_remaining = 10
        try:
            with self.assertRaises(KernelError) as ctx:
                self._episode()
            self.assertEqual(ctx.exception.code, "BACKEND_UNAVAILABLE")
            self.assertEqual(ctx.exception.status, 503)
        finally:
            self.state.flaky_remaining = 0

    def test_not_found(self) -> None:
        with self.assertRaises(KernelError) as ctx:
            self.kernel.get_episode("ep-nope")
        self.assertEqual(ctx.exception.code, "NOT_FOUND")
        self.assertEqual(ctx.exception.status, 404)

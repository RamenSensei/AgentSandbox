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
    Kernel,
    KernelError,
    Shell,
    TransportError,
)
from agentkernel.client import DEFAULT_TIMEOUT  # noqa: E402
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
        return self.kernel.create_episode("pr-agent", objective="fix issue 42")

    def test_default_timeout_is_30s_not_none(self) -> None:
        self.assertEqual(DEFAULT_TIMEOUT, 30.0)
        self.assertEqual(Kernel("http://x")._timeout, 30.0)

    def test_healthz(self) -> None:
        self.assertEqual(self.kernel.healthz()["status"], "ok")

    def test_create_and_describe_episode(self) -> None:
        ep = self._episode()
        self.assertTrue(ep.episode.startswith("ep-"))
        self.assertTrue(ep.branch.startswith("br-"))
        desc = ep.describe()
        self.assertEqual(desc.episode, ep.episode)
        self.assertEqual(desc.root_branch, ep.branch)
        self.assertEqual(desc.created_by, "pr-agent")
        self.assertIn(ep.branch, [b.id for b in desc.branches])

    def test_execute_success_observation(self) -> None:
        ep = self._episode()
        res = ep.execute(Shell("pytest"), lease="lease-abc")
        self.assertTrue(res.step.startswith("step-"))
        self.assertTrue(res.observation.is_success)
        self.assertEqual(res.observation.stdout_head, "12 passed")
        self.assertTrue(res.state.startswith("st-"))

    def test_denied_step_is_an_observation_with_structured_denial(self) -> None:
        ep = self._episode()
        res = ep.execute(Shell("forbidden thing"), lease="lease-abc")
        self.assertTrue(res.observation.is_denied)
        denial = res.observation.denial
        self.assertEqual(denial.code, "CAPABILITY_DENIED")
        self.assertIn("github.create_pull_request", denial.safe_alternatives)

    def test_fork_diff_compare_merge_discard(self) -> None:
        ep = self._episode()
        branches = ep.fork(3)
        self.assertEqual(len(branches), 3)
        changes = branches[0].diff()
        self.assertEqual(changes[0]["op"], "modified")
        self.assertEqual(changes[0]["path"], "a.py")
        cmp_ = branches[0].compare(branches[1])
        self.assertEqual(cmp_.base, "st-1")
        self.assertEqual(cmp_.changed_in_a, ["a.py"])
        node = ep.merge(branches[0])
        self.assertTrue(node["id"].startswith("st-"))
        self.assertEqual(node["branch"], ep.branch)
        discarded = branches[2].discard()
        self.assertEqual(discarded["discarded"], branches[2].id)

    def test_connector_op_becomes_pending_effect(self) -> None:
        ep = self._episode()
        res = ep.execute(
            ConnectorOp("github", "create_pull_request", {"base": "main"}),
            lease="lease-abc",
        )
        self.assertEqual(res.observation.kind, "effect_pending")
        self.assertTrue(res.observation.effect.startswith("fx-"))

    def test_effect_lifecycle(self) -> None:
        ep = self._episode()
        res = ep.execute(ConnectorOp("github", "create_pull_request", {}), lease="lease-abc")
        fx = self.kernel.effect_handle(self.kernel.get_effect(res.observation.effect))
        preview = fx.prepare()
        self.assertEqual(preview.preview, {"will": "create PR"})
        approved = fx.approve("pr-human")
        self.assertEqual(approved["approved"], fx.id)
        receipt = fx.commit()
        self.assertTrue(receipt.id.startswith("rcpt-"))
        self.assertEqual(receipt.body["contract_hash"], "sha256:deadbeef")
        fetched = self.kernel.get_receipt(receipt.id)
        self.assertEqual(fetched.id, receipt.id)

    def test_commit_before_approval_is_wrong_phase_conflict(self) -> None:
        ep = self._episode()
        res = ep.execute(ConnectorOp("github", "create_pull_request", {}), lease="lease-abc")
        with self.assertRaises(KernelError) as ctx:
            self.kernel.commit_effect(res.observation.effect)
        self.assertEqual(ctx.exception.code, "WRONG_EFFECT_PHASE")
        self.assertEqual(ctx.exception.status, 409)

    def test_list_and_recover_effects(self) -> None:
        ep = self._episode()
        ep.execute(ConnectorOp("github", "create_pull_request", {}), lease="lease-abc")
        proposed = self.kernel.list_effects("proposed")
        self.assertTrue(all(fx.phase["phase"] == "proposed" for fx in proposed))
        self.assertGreaterEqual(len(proposed), 1)
        recovered = self.kernel.recover_effects()
        self.assertEqual(recovered["resolutions"], [])

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
            params={"repository": "org/repo"},
        )
        self.assertTrue(lease.id.startswith("lease-"))
        child = self.kernel.delegate_capability(
            "pr-agent",
            lease.id,
            "pr-child",
            constraints={"repository": {"kind": "equals", "value": "org/repo"}},
            uses=1,
            expires_at=lease.expires_at,
        )
        self.assertEqual(child.parent_lease, lease.id)
        self.assertEqual(child.principal, "pr-child")
        held = self.kernel.capabilities("pr-child")
        self.assertIn(child.id, [l.id for l in held])
        revoked = self.kernel.revoke_capability(lease.id)
        self.assertIn(child.id, revoked)

    def test_replay_modes(self) -> None:
        audit = self.kernel.replay_audit(seq_from=1, seq_to=10)
        self.assertEqual(audit["mode"], "audit")
        self.assertEqual(audit["events"][0]["kind"], "step_started")
        report = self.kernel.replay_sandbox("step-1")
        self.assertTrue(report["workspace_match"])
        self.assertEqual(report["replay_class"], "filesystem_only")
        ep = self._episode()
        res = ep.execute(ConnectorOp("github", "create_pull_request", {}), lease="lease-abc")
        receipt = self.kernel.replay_live(res.observation.effect, "pr-human")
        self.assertTrue(receipt.id.startswith("rcpt-"))

    def test_trace_query_returns_ledger_events(self) -> None:
        events = self.kernel.trace_query(episode="ep-1", kind="step_started", limit=10)
        self.assertEqual(events[0]["kind"], "step_started")

    def test_step_explain_and_retry(self) -> None:
        explanation = self.kernel.explain_step("step-1")
        self.assertEqual(explanation["step"], "step-1")
        self.assertEqual(explanation["events"][0]["kind"], "step_started")
        retried = self.kernel.retry_step("step-1")
        self.assertTrue(retried.observation.is_success)

    def test_retry_on_503(self) -> None:
        self.state.flaky_remaining = 2
        ep = self._episode()  # succeeds after two retried 503s
        self.assertTrue(ep.episode.startswith("ep-"))

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

    def test_error_bodies_do_not_leak_sockets(self) -> None:
        """HTTPError responses must be closed (no ResourceWarning)."""
        import warnings

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("error", ResourceWarning)
            for _ in range(5):
                with self.assertRaises(KernelError):
                    self.kernel.get_episode("ep-nope")
            import gc

            gc.collect()
        self.assertEqual([w for w in caught if w.category is ResourceWarning], [])

    def test_timeout_fails_this_request_only(self) -> None:
        fast = Kernel(self.url, timeout=0.05, max_retries=0, sleep=lambda _: None)
        self.state.delay_s = 0.3
        try:
            with self.assertRaises(TransportError):
                fast.healthz()
        finally:
            self.state.delay_s = 0.0
        # Subsequent requests on the same client still work.
        self.assertEqual(fast.healthz()["status"], "ok")


if __name__ == "__main__":
    unittest.main()

"""Offline campaign gates and a fake-provider relay run; no Stripe or Docker calls."""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


campaign = load("stripe_credit_note_campaign_test",
                ROOT / "src/velvet/stripe_credit_note_campaign.py")
fixture = load("stripe_credit_note_fixture_for_campaign",
               ROOT / "tests/test_stripe_credit_note_probe.py")
fixture.probe = campaign._probe
ENV = {"GITHUB_SHA": "a" * 40, "GITHUB_RUN_ID": "123456789", "GITHUB_RUN_ATTEMPT": "1",
       "VELVET_STRIPE_SETUP_KEY": "sk_test_setup", "VELVET_STRIPE_AGENT_KEY": "rk_test_actor",
       "VELVET_STRIPE_OBSERVER_KEY": "rk_test_observer"}
IMAGE = "sha256:" + "a" * 64


def baseline(path: Path, *, direct_count: int = 1,
             fingerprint: str | None = None) -> None:
    path.write_text(json.dumps({
        "schema_version": campaign._probe.SCHEMA, "source_commit": ENV["GITHUB_SHA"],
        "summary": {"measurement_complete": True, "direct_refund_effect_count": direct_count,
                    "credit_note_effect_confirmed": True,
                    "non_refunding_credit_control_passed": True},
        "settings": {"observe_seconds": 60},
        "credentials": {"actor_fingerprint_scope": "github_run_id",
                        "actor_fingerprint_sha256": fingerprint or campaign.actor_fingerprint(ENV)},
    }))


class FakeWorker:
    """Exercise the real Unix relay and fake provider, replacing only Docker."""

    def __init__(self, mount: Path, image: str) -> None:
        assert image == IMAGE
        self.socket = mount / "stripe.sock"
        self.evidence = {"verified": True, "source": "offline_fake_docker"}
        self.witnesses: list[dict[str, Any]] = []

    def start(self) -> None:
        assert self.socket.exists()

    def check_inspection(self) -> None:
        assert self.socket.exists()

    def recheck_runtime(self) -> None:
        assert self.socket.exists()

    def request(self, role: str, method: str, path: str,
                params: dict[str, object], idempotency: str | None = None) -> Any:
        client = campaign._relay_module().RelayClient(self.socket)
        try:
            return client.request(role, method, path, params, idempotency)
        finally:
            if client.last_witness is not None:
                self.witnesses.append(client.last_witness)

    def close(self) -> None:
        pass


class CampaignFakeStripeApi:
    def __init__(self) -> None:
        self.inner = fixture.FakeStripeApi()
        self.calls: list[tuple[str, str, str, dict[str, Any]]] = self.inner.calls

    def request(self, role: str, method: str, path: str,
                params: dict[str, object], idempotency: str | None) -> Any:
        response = self.inner.request(role, method, path, params, idempotency)
        return campaign._probe.ApiResponse(
            response.value, response.status, f"req_{len(self.calls)}", "2026-08-26.dahlia")


class CapabilityGateTests(unittest.TestCase):
    def test_baseline_requires_positive_direct_control_and_same_actor_key(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "baseline.json"
            baseline(path, direct_count=0)
            with self.assertRaises(campaign._probe.ProbeError):
                campaign.verify_baseline(path, ENV)
            baseline(path, fingerprint="0" * 64)
            with self.assertRaises(campaign._probe.ProbeError):
                campaign.verify_baseline(path, ENV)
            baseline(path)
            self.assertTrue(campaign.verify_baseline(path, ENV)["summary"][
                "measurement_complete"])

    def test_invalid_baseline_stops_before_docker_or_provider(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(campaign.platform, "system", return_value="Linux"), \
                    patch.object(campaign, "_image_verified", side_effect=AssertionError(
                        "Docker must not be reached")):
                result = campaign.run_campaign("A", IMAGE, root / "stripe-A",
                                               root / "missing.json", None, True, ENV)
            self.assertFalse(result["measurement_complete"])
            self.assertFalse(result["audit_verified"])
            saved = json.loads((root / "stripe-A/result.json").read_text())
            self.assertEqual(saved["probe_summary"]["overall_verdict"], "INDETERMINATE")

    def test_policy_c_requires_verified_policy_a_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base = root / "baseline.json"
            baseline(base)
            with patch.object(campaign.platform, "system", return_value="Linux"), \
                    patch.object(campaign, "_image_verified", side_effect=AssertionError(
                        "Docker must not be reached")):
                result = campaign.run_campaign("C", IMAGE, root / "stripe-C", base,
                                               None, True, ENV)
            self.assertFalse(result["measurement_complete"])
            self.assertNotIn("candidate_prerequisite_verified", result)


class WorkerHandshakeTests(unittest.TestCase):
    def test_facts_payload_is_checked_before_worker_becomes_usable(self) -> None:
        class FakeIso:
            @staticmethod
            def docker(*args: str) -> str:
                if args[0] == "create":
                    return "b" * 64
                return "[{}]"

            @staticmethod
            def inspect_boundary(raw: Any, image: str, mount: Path) -> dict[str, Any]:
                return {"verified": True}

            @staticmethod
            def docker_env() -> dict[str, str]:
                return {}

            @staticmethod
            def runtime_verified(facts: dict[str, object]) -> bool:
                return facts.get("uid") == 65532

        class FakeProcess:
            stdin = object()
            stdout = object()

        with tempfile.TemporaryDirectory() as directory, \
                patch.object(campaign, "_image_verified", return_value=True), \
                patch.object(campaign, "_iso", FakeIso), \
                patch.object(campaign.shutil, "which", return_value="/usr/bin/docker"), \
                patch.object(campaign.subprocess, "Popen", return_value=FakeProcess()):
            worker = campaign.Worker(Path(directory), IMAGE)
            source = campaign._sha256((campaign.SOURCE / "stripe_rest_relay.py").read_bytes())
            with patch.object(worker, "command", return_value={"ok": True, "facts": {
                "uid": 65532, "source_sha256": source,
            }}):
                worker.start()
            self.assertTrue(worker.evidence["verified"])
            rejected = campaign.Worker(Path(directory), IMAGE)
            with patch.object(rejected, "command", return_value={"ok": True, "result": {
                "uid": 65532, "source_sha256": source,
            }}), self.assertRaises(campaign._probe.ProbeError):
                rejected.start()


class ScriptedCampaignTests(unittest.TestCase):
    def run_policy(self, policy: str, directory: Path, base: Path,
                   candidate: Path | None = None) -> tuple[dict[str, Any], Any]:
        provider = CampaignFakeStripeApi()
        with patch.object(campaign.platform, "system", return_value="Linux"), \
                patch.object(campaign, "_image_verified", return_value=True), \
                patch.object(campaign, "Worker", FakeWorker), \
                patch.object(campaign, "MIN_OBSERVE_SECONDS", 0.01), \
                patch.object(campaign._probe, "StripeApi", side_effect=lambda keys: provider):
            result = campaign.run_campaign(policy, IMAGE, directory, base, candidate, True,
                                           ENV, observe_seconds=0.01, poll_seconds=0.005)
        return result, provider

    def test_same_key_provider_control_then_a_candidate_then_c_closure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base = root / "baseline.json"
            baseline(base)
            a, provider_a = self.run_policy("A", root / "stripe-A", base)
            self.assertTrue(a["measurement_complete"], a)
            self.assertTrue(a["candidate_confirmed"])
            self.assertEqual(a["relay_audit"]["decision_count"], 3)
            self.assertEqual(a["relay_audit"]["provider_dispatch_count"], 2)
            self.assertEqual(a["probe_summary"]["credit_note_refund_effect_count"], 1)
            self.assertEqual(len([call for call in provider_a.calls if call[0] == "actor"]), 2)
            saved_a = json.loads((root / "stripe-A/result.json").read_text())
            self.assertEqual(saved_a["relay_audit"]["rows"], a["relay_audit"]["rows"])
            self.assertEqual(saved_a["probe_report"]["summary"], a["probe_summary"])
            self.assertNotIn("rk_test_actor", json.dumps(saved_a))

            c, provider_c = self.run_policy("C", root / "stripe-C", base,
                                            root / "stripe-A/result.json")
            self.assertTrue(c["measurement_complete"], c)
            self.assertTrue(c["closure_confirmed"])
            self.assertEqual(c["relay_audit"]["provider_dispatch_count"], 1)
            self.assertEqual(len([call for call in provider_c.calls if call[0] == "actor"]), 1)

    def test_audit_tamper_voids_completion(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base = root / "baseline.json"
            baseline(base)
            result, _ = self.run_policy("A", root / "stripe-A", base)
            self.assertTrue(result["measurement_complete"])
            audit = root / "stripe-A/relay_audit.jsonl"
            rows = [json.loads(row) for row in audit.read_text().splitlines()]
            rows[0]["params"]["amount"] = 500
            audit.write_text("\n".join(json.dumps(row) for row in rows) + "\n")
            with self.assertRaises(campaign._probe.ProbeError):
                campaign.verify_audit(audit, "A", result["probe_report"],
                                      type("Witnesses", (), {"witnesses": [
                                          {key: row[key] for key in (
                                              "decision_id", "policy_sha256", "source_sha256",
                                              "resource_scope_sha256",
                                              "decision", "dispatch_count_before",
                                              "dispatch_count_after")}
                                          for row in result["relay_audit"]["rows"]
                                          if row["event"] == "decision"]})(),
                                      type("Relay", (), {"policy_sha256":
                                          result["relay_audit"]["policy_sha256"],
                                          "resource_scope_sha256":
                                          result["relay_audit"]["resource_scope_sha256"],
                                          "dispatch_count": 2})())


if __name__ == "__main__":
    unittest.main()

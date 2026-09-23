"""Offline safety and evidence tests; these do not make Stripe requests."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

SOURCE = Path(__file__).resolve().parents[1] / "src" / "velvet" / "stripe_credit_note_probe.py"
SPEC = importlib.util.spec_from_file_location("stripe_credit_note_probe_under_test", SOURCE)
assert SPEC is not None and SPEC.loader is not None
probe = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = probe
SPEC.loader.exec_module(probe)


class ConfigurationTests(unittest.TestCase):
    def test_refuses_live_and_nonrestricted_observer_keys(self) -> None:
        with self.assertRaises(probe.ProbeError):
            probe.test_key("sk_live_example", "setup", restricted=False)
        with self.assertRaises(probe.ProbeError):
            probe.test_key("sk_test_example", "observer", restricted=True)
        self.assertEqual(
            probe.test_key("rk_test_observer", "observer", restricted=True),
            "rk_test_observer",
        )

    def test_refuses_mutations_without_explicit_test_opt_in(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            settings = probe.Settings(output=Path(directory), allow_test_writes=False)
            with self.assertRaisesRegex(probe.ProbeError, "allow-test-writes"):
                settings.validate()

    def test_bounds_refund_and_invoice_amounts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            valid = probe.Settings(output=Path(directory), allow_test_writes=True)
            valid.validate()
            self.assertEqual(valid.invoice_cents, 200)
            for amount, invoice in ((0, 200), (100, 100), (501, 1000), (100, 5001)):
                invalid = probe.Settings(
                    output=Path(directory), amount_cents=amount, invoice_cents=invoice,
                    allow_test_writes=True,
                )
                with self.subTest(amount=amount, invoice=invoice):
                    with self.assertRaises(probe.ProbeError):
                        invalid.validate()


class TransportGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.api = probe.StripeApi({"setup": "sk_test_setup", "actor": "rk_test_actor",
                                    "observer": "rk_test_observer"})

    def test_rejects_non_stripe_paths_before_network(self) -> None:
        for path in ("/v1/balance", "/v1/../../secrets", "https://evil.example/v1/refunds"):
            with self.subTest(path=path):
                with self.assertRaises(probe.ProbeError):
                    self.api.request("actor", "GET", path, {})

    def test_requires_idempotency_key_for_every_write(self) -> None:
        with self.assertRaisesRegex(probe.ProbeError, "idempotency"):
            self.api.request("actor", "POST", "/v1/refunds", {"amount": 100})

    def test_observer_role_cannot_write(self) -> None:
        with self.assertRaises(probe.ProbeError):
            self.api.request("observer", "POST", "/v1/refunds", {"amount": 100}, "test-key")


class EvidenceTests(unittest.TestCase):
    def test_write_intent_is_on_disk_before_dispatch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "run"
            output.mkdir()
            settings = probe.Settings(output=output, allow_test_writes=True)
            run = probe.Probe(settings, {"GITHUB_SHA": "source-commit"})

            class InspectingApi:
                def request(self, role: str, method: str, path: str,
                            params: dict[str, Any], idempotency: str | None) -> Any:
                    saved = json.loads((output / "result.json").read_text())
                    event = saved["requests"][0]
                    self_outer.assertEqual(event["classification"], "outcome_unknown")
                    self_outer.assertEqual(event["path"], "/v1/refunds")
                    self_outer.assertEqual(event["action"]["amount"], 100)
                    self_outer.assertTrue(idempotency)
                    raise probe.ProbeError("simulated transport uncertainty")

            self_outer = self
            run.api = InspectingApi()
            with self.assertRaises(probe.ProbeError):
                run.call("actor", "direct_refund", "POST", "/v1/refunds", {"amount": 100})
            saved = json.loads((output / "result.json").read_text())
            self.assertEqual(saved["requests"][0]["classification"], "outcome_unknown")
            self.assertFalse(saved["summary"]["measurement_complete"])
            self.assertNotIn("sk_test_", json.dumps(saved))

    def test_approval_is_not_treated_as_a_completed_effect(self) -> None:
        error = probe.RemoteFailure(402, "req_123", "approval_required", "apreq_123")
        self.assertEqual(probe.classify_failure(error), "approval_required")
        self.assertEqual(error.approval_request_id, "apreq_123")


class AssessmentTests(unittest.TestCase):
    def complete_report(self, *, linked_refund: str = "re_credit") -> Any:
        settings = probe.Settings(output=Path("/unused"), allow_test_writes=True)
        run = probe.Probe(settings, {})
        run.report["account_consistency"] = "verified_same_test_account"
        run.report["phases"] = [
            {"name": "direct_refund", "dispatch": "approval_required",
             "observation_complete": True, "observed_refunds": []},
            {"name": "credit_note_refund", "dispatch": "accepted",
             "observation_complete": True, "credit_note_id": "cn_credit",
             "observed_refunds": [{"id": "re_credit", "charge": "ch_credit", "amount": 100,
                                   "currency": "usd", "status": "succeeded"}],
             "observed_credit_note": {
                 "id": "cn_credit", "status": "issued", "type": "post_payment",
                 "post_payment_amount": 100, "pre_payment_amount": 0,
                 "linked_refund_ids": [linked_refund],
             }},
            {"name": "balance_credit", "dispatch": "accepted",
             "observation_complete": True, "observed_refunds": [],
             "observed_credit_note": {
                 "id": "cn_balance", "status": "issued", "type": "post_payment",
                 "post_payment_amount": 100, "pre_payment_amount": 0,
                 "customer_balance_transaction_id": "cbtxn_balance",
                 "linked_refund_ids": [],
             }},
        ]
        return run

    def test_nested_effect_remains_visible_when_direct_refund_requires_approval(self) -> None:
        run = self.complete_report()
        run.assess()
        summary = run.report["summary"]
        self.assertTrue(summary["measurement_complete"])
        self.assertTrue(summary["credit_note_effect_confirmed"])
        self.assertEqual(summary["credit_note_refund_effect_count"], 1)
        self.assertNotEqual(summary["overall_verdict"], "DIRECT_REFUND_APPROVAL_REQUIRED")

    def test_unlinked_refund_cannot_prove_credit_note_effect(self) -> None:
        run = self.complete_report(linked_refund="re_other")
        run.assess()
        summary = run.report["summary"]
        self.assertTrue(summary["measurement_complete"])
        self.assertFalse(summary["credit_note_effect_confirmed"])
        self.assertNotEqual(summary["overall_verdict"], "ALTERNATE_REFUND_EFFECT_OBSERVED")

    def test_incomplete_observation_cannot_be_measured_as_success(self) -> None:
        run = self.complete_report()
        run.report["phases"][1]["observation_complete"] = False
        run.assess()
        self.assertFalse(run.report["summary"]["measurement_complete"])
        self.assertEqual(run.report["summary"]["overall_verdict"], "INDETERMINATE")

    def test_credit_note_effect_survives_failed_nonrefunding_control(self) -> None:
        run = self.complete_report()
        run.report["phases"][2]["dispatch"] = "approval_required"
        run.report["phases"][2]["observed_credit_note"] = {}
        run.assess()
        summary = run.report["summary"]
        self.assertFalse(summary["measurement_complete"])
        self.assertEqual(summary["overall_verdict"], "INDETERMINATE")
        self.assertTrue(summary["credit_note_effect_confirmed"])
        self.assertEqual(summary["credit_note_refund_effect_count"], 1)
        self.assertFalse(summary["non_refunding_credit_control_passed"])


class FakeStripeApi:
    """Small stateful provider stand-in for the complete three-lane probe."""

    lanes = ("direct_refund", "credit_note_refund", "balance_credit")
    tags = {"direct_refund": "Dr1", "credit_note_refund": "Cr1",
            "balance_credit": "Ba1"}

    def __init__(self, *, partial_refund_page: bool = False) -> None:
        self.partial_refund_page = partial_refund_page
        self.calls: list[tuple[str, str, str, dict[str, Any]]] = []
        self.invoices: dict[str, dict[str, Any]] = {}
        self.refunds: dict[str, list[dict[str, Any]]] = {}
        self.notes: dict[str, dict[str, Any]] = {}

    def resource_id(self, prefix: str, lane: str) -> str:
        return f"{prefix}_{self.tags[lane]}"

    def lane_for_id(self, value: str) -> str:
        tag = value.split("_", 1)[1]
        return next(lane for lane, candidate in self.tags.items() if candidate == tag)

    def response(self, value: dict[str, Any], status: int = 200) -> Any:
        return probe.ApiResponse(value, status, f"req_probe_{len(self.calls)}", "2026-08-26.dahlia")

    def request(self, role: str, method: str, path: str,
                params: dict[str, Any], idempotency: str | None) -> Any:
        self.calls.append((role, method, path, dict(params)))
        if method == "POST":
            assert role != "observer" and idempotency, "every write is bound to a role and key"
        else:
            assert idempotency is None
        if path == "/v1/account":
            if role != "setup":
                raise probe.RemoteFailure(403, "req_account_denied", "permission_denied")
            return self.response({"id": "acct_probe"})

        if method == "POST" and path == "/v1/customers":
            lane = self.lanes[len(self.invoices)]
            customer = self.resource_id("cus", lane)
            self.invoices[lane] = {"customer": customer}
            return self.response({"id": customer, "object": "customer", "livemode": False}, 201)
        if method == "POST" and path == "/v1/payment_methods":
            assert params == {"type": "card", "card[token]": "tok_visa"}
            lane = self.lanes[len(self.invoices) - 1]
            return self.response({"id": self.resource_id("pm", lane), "object": "payment_method",
                                  "livemode": False}, 201)
        if method == "POST" and path.endswith("/attach"):
            payment_method = path.split("/")[3]
            return self.response({"id": payment_method, "customer": params["customer"]})
        if method == "POST" and path == "/v1/invoiceitems":
            assert params["amount"] == 200 and params["currency"] == "usd"
            return self.response({"id": f"ii_{len(self.invoices)}", "object": "invoiceitem",
                                  "livemode": False}, 201)
        if method == "POST" and path == "/v1/invoices":
            lane = self.lanes[len(self.invoices) - 1]
            assert params["customer"] == self.invoices[lane]["customer"]
            invoice_id = self.resource_id("in", lane)
            self.invoices[lane]["id"] = invoice_id
            self.invoices[lane]["intent"] = self.resource_id("pi", lane)
            self.invoices[lane]["charge"] = self.resource_id("ch", lane)
            self.refunds[self.resource_id("ch", lane)] = []
            return self.response({"id": invoice_id, "object": "invoice", "livemode": False},
                                 201)
        if method == "POST" and path.endswith("/finalize"):
            invoice_id = path.split("/")[3]
            return self.response({"id": invoice_id, "livemode": False, "status": "open"})
        if method == "POST" and path.endswith("/pay"):
            invoice_id = path.split("/")[3]
            return self.response({"id": invoice_id, "livemode": False, "status": "paid",
                                  "amount_paid": 200, "amount_remaining": 0})
        if method == "GET" and path == "/v1/invoice_payments":
            invoice_id = params["invoice"]
            lane = next(name for name, row in self.invoices.items()
                        if row["id"] == invoice_id)
            return self.response({"data": [{"id": self.resource_id("inpay", lane),
                                           "object": "invoice_payment", "livemode": False,
                                           "invoice": invoice_id, "status": "paid",
                                           "amount_paid": 200,
                                           "payment": {"type": "payment_intent",
                                                       "payment_intent":
                                                           self.resource_id("pi", lane)}}],
                                  "has_more": False})
        if method == "GET" and path.startswith("/v1/payment_intents/"):
            intent_id = path.split("/")[3]
            lane = self.lane_for_id(intent_id)
            return self.response({"id": intent_id, "object": "payment_intent",
                                  "livemode": False, "status": "succeeded",
                                  "amount_received": 200,
                                  "latest_charge": self.resource_id("ch", lane)})
        if method == "GET" and path.startswith("/v1/charges/"):
            assert role == "observer"
            charge_id = path.split("/")[3]
            lane = self.lane_for_id(charge_id)
            return self.response({"id": charge_id, "object": "charge", "livemode": False,
                                  "paid": True, "captured": True, "status": "succeeded",
                                  "customer": self.resource_id("cus", lane),
                                  "payment_intent": self.resource_id("pi", lane),
                                  "amount": 200, "currency": "usd"})
        if method == "GET" and path == "/v1/refunds":
            assert role == "observer" and params["limit"] == 100
            rows = self.refunds[params["charge"]]
            if self.partial_refund_page and rows:
                if params.get("starting_after"):
                    return self.response({"data": None, "has_more": False})
                return self.response({"data": rows, "has_more": True})
            return self.response({"data": rows, "has_more": False})
        if role == "actor" and method == "POST" and path == "/v1/refunds":
            assert params["charge"] == self.resource_id("ch", "direct_refund")
            assert params["amount"] == 100
            raise probe.RemoteFailure(403, "req_direct_denied", "permission_denied")
        if role == "actor" and method == "POST" and path == "/v1/credit_notes":
            invoice_id = params["invoice"]
            lane = self.lane_for_id(invoice_id)
            assert lane in {"credit_note_refund", "balance_credit"}
            assert params["amount"] == 100 and params["email_type"] == "none"
            note_id = self.resource_id("cn", lane)
            note = {"id": note_id, "object": "credit_note", "livemode": False,
                    "invoice": invoice_id, "currency": "usd", "status": "issued",
                    "type": "post_payment", "amount": 100, "post_payment_amount": 100,
                    "pre_payment_amount": 0, "refunds": [],
                    "customer_balance_transaction": None}
            if lane == "credit_note_refund":
                assert params["refund_amount"] == 100 and "credit_amount" not in params
                refund_id = self.resource_id("re", lane)
                note["refunds"] = [{"refund": refund_id, "amount": 100}]
                # Stripe's published Refund shape omits livemode. The tested charge and
                # three test credentials establish the mode without that optional field.
                self.refunds[self.resource_id("ch", lane)].append({
                    "id": refund_id, "object": "refund",
                    "charge": self.resource_id("ch", lane),
                    "amount": 100, "currency": "usd", "status": "succeeded",
                })
            else:
                assert params["credit_amount"] == 100 and "refund_amount" not in params
                note["customer_balance_transaction"] = self.resource_id("cbtxn", lane)
            self.notes[note_id] = note
            return self.response({"id": note_id, "object": "credit_note",
                                  "livemode": False, "invoice": invoice_id,
                                  "amount": 100, "status": "issued"}, 201)
        if method == "GET" and path.startswith("/v1/credit_notes/"):
            assert role == "observer"
            return self.response(self.notes[path.split("/")[3]])
        raise AssertionError(f"unexpected provider call: {role} {method} {path}")


class EndToEndTests(unittest.TestCase):
    KEYS = {"VELVET_STRIPE_SETUP_KEY": "sk_test_setup",
            "VELVET_STRIPE_AGENT_KEY": "rk_test_actor",
            "VELVET_STRIPE_OBSERVER_KEY": "rk_test_observer"}

    def settings(self, directory: str) -> Any:
        return probe.Settings(output=Path(directory) / "run", allow_test_writes=True,
                              observe_seconds=0.001, poll_seconds=0.001)

    def test_complete_provider_effect_and_nonrefunding_control(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            provider = FakeStripeApi()
            run = probe.Probe(self.settings(directory), self.KEYS, provider)
            report = run.run()
            saved = json.loads((run.settings.output / "result.json").read_text())
            self.assertEqual(report, saved)
            self.assertEqual(report["summary"]["overall_verdict"],
                             "CREDIT_NOTE_REFUND_AFTER_DIRECT_PERMISSION_DENIAL")
            self.assertTrue(report["summary"]["measurement_complete"])
            self.assertTrue(report["summary"]["credit_note_effect_confirmed"])
            self.assertTrue(report["summary"]["non_refunding_credit_control_passed"])
            self.assertEqual(report["summary"]["credit_note_refund_effect_count"], 1)
            self.assertEqual(report["summary"]["direct_refund_effect_count"], 0)
            self.assertEqual(report["summary"]["balance_credit_refund_count"], 0)
            self.assertEqual(report["account_consistency"],
                             "verified_by_fresh_credit_note_resource")
            self.assertEqual(report["account_checks"], {
                "setup_account_read": True, "actor_account_read": False,
                "observer_account_read": False, "observer_fresh_charge_read": True,
            })
            self.assertEqual({row["charge_id"] for row in report["invoices"].values()},
                             {"ch_Dr1", "ch_Cr1", "ch_Ba1"})
            self.assertTrue(all(row["invoice_payment_id"].startswith("inpay_")
                                for row in report["invoices"].values()))
            self.assertEqual(report["phases"][1]["observed_credit_note"]["linked_refund_ids"],
                             ["re_Cr1"])
            self.assertEqual(report["phases"][1]["observed_refunds"][0]["status"],
                             "succeeded")
            self.assertEqual(report["phases"][2]["observed_refunds"], [])
            self.assertEqual(len([call for call in provider.calls
                                  if call[:3] == ("observer", "GET", "/v1/account")]), 1)
            self.assertNotIn("sk_test_setup", json.dumps(report))
            self.assertNotIn("rk_test_actor", json.dumps(report))

    def test_partial_refund_pagination_preserves_effect_but_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            provider = FakeStripeApi(partial_refund_page=True)
            run = probe.Probe(self.settings(directory), self.KEYS, provider)
            report = run.run()
            saved = json.loads((run.settings.output / "result.json").read_text())
            self.assertEqual(report, saved)
            self.assertFalse(report["summary"]["measurement_complete"])
            self.assertEqual(report["summary"]["overall_verdict"], "INDETERMINATE")
            self.assertEqual(len(report["phases"]), 2)
            credit = report["phases"][1]
            self.assertEqual(credit["observed_refunds"][0]["id"], "re_Cr1")
            self.assertFalse(credit["observation_complete"])
            self.assertIn("pagination", credit["observation_error"])
            self.assertFalse(any(call[:3] == ("actor", "POST", "/v1/credit_notes")
                                 and call[3]["invoice"] == "in_Ba1"
                                 for call in provider.calls))

    def test_invalid_credentials_leave_indeterminate_evidence_without_network(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            provider = FakeStripeApi()
            run = probe.Probe(self.settings(directory), {}, provider)
            report = run.run()
            self.assertFalse(report["summary"]["measurement_complete"])
            self.assertEqual(report["summary"]["overall_verdict"], "INDETERMINATE")
            self.assertEqual(provider.calls, [])
            self.assertEqual(json.loads((run.settings.output / "result.json").read_text()),
                             report)


if __name__ == "__main__":
    unittest.main()

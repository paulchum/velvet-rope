"""Bounded Stripe test-mode experiment: direct refund versus credit-note refund.

Source-only usage: ``python -I src/velvet/stripe_credit_note_probe.py run --help``.
All writes require ``--allow-test-writes`` and test keys. This is a provider
effect measurement, not an autonomous discovery or a Stripe vulnerability claim.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request  # nosec B310 - fixed HTTPS Stripe API origin.
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

Json = dict[str, Any]
STRIPE_API = "https://api.stripe.com"
STRIPE_VERSION = "2026-08-26.dahlia"
MAX_BYTES = 2 * 1024 * 1024
SCHEMA = "velvet.stripe.credit_note_probe.v1"
ID = re.compile(r"[A-Za-z][A-Za-z0-9_]{1,128}\Z")
SAFE_CODE = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
PATH = re.compile(
    r"/v1/(?:account|customers|payment_methods|payment_methods/pm_[A-Za-z0-9]+/attach|"
    r"invoiceitems|invoices|invoices/in_[A-Za-z0-9]+/(?:finalize|pay)|"
    r"invoice_payments|payment_intents/pi_[A-Za-z0-9]+|charges/ch_[A-Za-z0-9]+|"
    r"refunds|credit_notes|credit_notes/cn_[A-Za-z0-9]+)\Z"
)


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


def valid_id(value: object, prefix: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(prefix + r"_[A-Za-z0-9]{1,128}", value):
        raise ProbeError(f"invalid {prefix} identifier in provider response")
    return value


def obj(value: object, label: str) -> Json:
    if not isinstance(value, dict):
        raise ProbeError(f"{label} must be a JSON object")
    return value


def test_key(value: str, label: str, *, restricted: bool) -> str:
    prefixes = ("rk_test_",) if restricted else ("rk_test_", "sk_test_")
    if not value.startswith(prefixes) or not re.fullmatch(r"[A-Za-z0-9_]+", value):
        raise ProbeError(f"{label} requires a {'restricted ' if restricted else ''}test key")
    return value


class ProbeError(RuntimeError):
    """Safe local configuration, transport, or measurement error."""


class RemoteFailure(ProbeError):
    def __init__(self, status: int, request_id: str | None, code: str | None,
                 approval_request_id: str | None = None,
                 approval_status: str | None = None) -> None:
        self.status = status
        self.request_id = request_id
        self.code = code
        self.approval_request_id = approval_request_id
        self.approval_status = approval_status
        super().__init__(f"Stripe HTTP {status}")


def classify_failure(error: RemoteFailure) -> str:
    if error.code in {"approval_required", "confirmation_required", "human_approval_required"}:
        return "approval_required"
    if error.status == 403 or error.code == "permission_denied":
        return "permission_denied"
    if error.status == 401:
        return "authentication_failed"
    if error.status == 429:
        return "rate_limited"
    if error.status >= 500:
        return "provider_error"
    return "request_rejected"


@dataclass(frozen=True)
class ApiResponse:
    value: Json
    status: int
    request_id: str | None = None
    stripe_version: str | None = None


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str,
                         headers: Any, newurl: str) -> None:
        raise ProbeError("redirect refused")


class StripeApi:
    """Small fixed-origin transport; credentials and response bodies never enter evidence."""

    def __init__(self, keys: Mapping[str, str], timeout_seconds: float = 20) -> None:
        self.keys = keys
        self.timeout_seconds = timeout_seconds
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def request(self, role: str, method: str, path: str, params: Mapping[str, object],
                idempotency: str | None = None) -> ApiResponse:
        if (role not in self.keys or method not in {"GET", "POST"}
                or (role == "observer" and method != "GET") or not PATH.fullmatch(path)):
            raise ProbeError("request outside fixed Stripe probe surface")
        if method == "POST" and not idempotency:
            raise ProbeError("write requires an idempotency key")
        encoded = urllib.parse.urlencode(params).encode()
        url = STRIPE_API + path
        if method == "GET" and encoded:
            url += "?" + encoded.decode()
        headers = {"Authorization": "Bearer " + self.keys[role],
                   "Stripe-Version": STRIPE_VERSION,
                   "Content-Type": "application/x-www-form-urlencoded"}
        if idempotency:
            headers["Idempotency-Key"] = idempotency
        request = urllib.request.Request(  # noqa: S310 - fixed allowlisted HTTPS origin.
            url, data=encoded if method == "POST" else None, headers=headers, method=method)
        try:
            with self.opener.open(request, timeout=self.timeout_seconds) as response:  # noqa: S310
                raw = response.read(MAX_BYTES + 1)
                if len(raw) > MAX_BYTES:
                    raise ProbeError("provider response too large")
                value = obj(json.loads(raw), "provider response")
                request_id = response.headers.get("Request-Id")
                return ApiResponse(value, response.status,
                                   request_id if request_id and ID.fullmatch(request_id) else None,
                                   response.headers.get("Stripe-Version"))
        except urllib.error.HTTPError as error:
            request_id = error.headers.get("Request-Id")
            code: str | None = None
            approval_request_id: str | None = None
            approval_status: str | None = None
            try:
                raw = error.read(MAX_BYTES + 1)
                if len(raw) <= MAX_BYTES:
                    details = obj(obj(json.loads(raw), "error").get("error"), "Stripe error")
                    candidate = details.get("code")
                    if isinstance(candidate, str) and SAFE_CODE.fullmatch(candidate):
                        code = candidate
                    approval = details.get("approval_request")
                    if isinstance(approval, dict):
                        candidate_status = approval.get("status")
                        if (isinstance(candidate_status, str)
                                and SAFE_CODE.fullmatch(candidate_status)):
                            approval_status = candidate_status
                        approval = approval.get("id")
                    if isinstance(approval, str) and re.fullmatch(
                        r"apreq_[A-Za-z0-9]{1,128}", approval
                    ):
                        approval_request_id = approval
            except (OSError, ValueError, ProbeError):
                pass
            finally:
                error.close()
            raise RemoteFailure(error.code,
                                request_id if request_id and ID.fullmatch(request_id) else None,
                                code, approval_request_id, approval_status) from None
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as error:
            raise ProbeError(f"transport/protocol failure: {type(error).__name__}") from None


@dataclass(frozen=True)
class Settings:
    output: Path
    amount_cents: int = 100
    invoice_cents: int = 200
    observe_seconds: float = 60
    poll_seconds: float = 2
    allow_test_writes: bool = False

    def validate(self) -> None:
        if not self.allow_test_writes:
            raise ProbeError("--allow-test-writes is required")
        if not 100 <= self.amount_cents <= 500:
            raise ProbeError("amount must be 100 to 500 cents")
        if not self.amount_cents < self.invoice_cents <= 5000:
            raise ProbeError("invoice amount must exceed refund amount and be at most 5000 cents")
        if not 0 < self.observe_seconds <= 120 or not 0 < self.poll_seconds <= 30:
            raise ProbeError("invalid bounded observation settings")


class Probe:
    def __init__(self, settings: Settings, env: Mapping[str, str], api: Any = None) -> None:
        self.settings = settings
        self.env = env
        self.api = api
        self.run_id = uuid4().hex
        self.report: Json = {
            "schema_version": SCHEMA, "run_id": self.run_id, "mode": "stripe_test",
            "started_at": utc_now(), "source_commit": env.get("GITHUB_SHA", "unrecorded"),
            "claim_boundary": "Designed for three fresh paid test invoices and fixed REST routes, "
            "separate observer key, bounded readback. No autonomous route discovery, "
            "live funds, provider-wide policy claim, "
            "or Stripe vulnerability claim.",
            "settings": {"amount_cents": settings.amount_cents,
                         "invoice_cents": settings.invoice_cents,
                         "stripe_version": STRIPE_VERSION,
                         "observe_seconds": settings.observe_seconds,
                         "poll_seconds": settings.poll_seconds},
            "account_consistency": "unverified", "requests": [], "refund_pages": [],
            "invoices": {}, "phases": [],
            "account_checks": {"setup_account_read": False, "actor_account_read": False,
                               "observer_account_read": False,
                               "observer_refund_list_read": False,
                               "observer_credit_note_list_read": False,
                               "observer_fresh_charge_read": False},
            "application_boundary": "none; direct Stripe REST test",
            "summary": {"overall_verdict": "INDETERMINATE", "measurement_complete": False},
        }

    def save(self) -> None:
        self.report["updated_at"] = utc_now()
        target = self.settings.output / "result.json"
        temporary = target.with_suffix(".tmp")
        temporary.write_text(json.dumps(self.report, indent=2, sort_keys=True) + "\n")
        temporary.replace(target)

    def call(self, role: str, phase: str, method: str, path: str,
             params: Mapping[str, object] | None = None) -> Json:
        params = params or {}
        safe_names = {"customer", "invoice", "amount", "amount_paid", "currency",
                      "refund_amount", "credit_amount", "charge", "payment_method",
                      "paid_out_of_band", "email_type", "auto_advance",
                      "collection_method", "default_payment_method",
                      "pending_invoice_items_behavior", "limit", "starting_after"}
        action = {name: value for name, value in params.items() if name in safe_names}
        if "card[token]" in params:
            action["uses_standard_stripe_test_token"] = True
        event: Json = {"role": role, "phase": phase, "method": method, "path": path,
                       "action": action, "attempted_at": utc_now(),
                       "classification": "outcome_unknown"}
        self.report["requests"].append(event)
        idempotency = (f"stripe-cn-probe:{self.run_id}:{phase}:{len(self.report['requests'])}"
                       if method == "POST" else None)
        if idempotency:
            event["idempotency_key"] = idempotency
        self.save()  # Persist intent before any possibly ambiguous write.
        try:
            response: ApiResponse = self.api.request(
                role, method, path, params, idempotency)
            event.update({"http_status": response.status, "request_id": response.request_id,
                          "stripe_version": response.stripe_version,
                          "classification": "http_success", "responded_at": utc_now()})
            return response.value
        except RemoteFailure as error:
            event.update({"http_status": error.status, "request_id": error.request_id,
                          "error_code": error.code,
                          "approval_request_id": error.approval_request_id,
                          "approval_status": error.approval_status,
                          "classification": classify_failure(error), "responded_at": utc_now()})
            raise
        except ProbeError as error:
            event.update({"classification": "outcome_unknown", "error_type": type(error).__name__,
                          "responded_at": utc_now()})
            raise
        finally:
            self.save()

    def verify_accounts(self) -> None:
        setup = self.call("setup", "account_preflight", "GET", "/v1/account")
        setup_id = valid_id(setup.get("id"), "acct")
        self.report["account_id"] = setup_id
        self.report["account_checks"]["setup_account_read"] = True
        self.save()
        for role in ("actor", "observer"):
            try:
                value = self.call(role, "account_preflight", "GET", "/v1/account")
            except RemoteFailure as error:
                if error.status != 403:
                    raise
                # Exact account-read denial semantics are not used to claim a finding.
                # A fresh observed resource must bind this role to setup later.
                continue
            if valid_id(value.get("id"), "acct") != setup_id:
                raise ProbeError(f"{role} key targets a different Stripe account")
            self.report["account_checks"][role + "_account_read"] = True
            self.save()
        self.report["account_consistency"] = (
            "verified_same_test_account"
            if (self.report["account_checks"]["actor_account_read"]
                and self.report["account_checks"]["observer_account_read"])
            else "partially_verified_pending_fresh_resource")
        self.save()
        for path, check in (("/v1/refunds", "observer_refund_list_read"),
                            ("/v1/credit_notes", "observer_credit_note_list_read")):
            listing = self.call("observer", "read_scope_preflight", "GET", path, {"limit": 1})
            if (not isinstance(listing.get("data"), list)
                    or type(listing.get("has_more")) is not bool):
                raise ProbeError(f"observer {path} read preflight was malformed")
            self.report["account_checks"][check] = True
            self.save()

    def setup_invoice(self, name: str) -> Json:
        """Create a fresh charged invoice and prove its invoice-payment to charge chain."""
        label = "setup_" + name
        invoice_evidence: Json = {}
        self.report["invoices"][name] = invoice_evidence
        self.save()
        customer = self.call("setup", label, "POST", "/v1/customers", {
            "name": "Stripe outcome probe " + self.run_id[:10] + " " + name,
            "metadata[probe_run]": self.run_id,
            "metadata[probe_lane]": name,
        })
        customer_id = valid_id(customer.get("id"), "cus")
        if customer.get("object") != "customer" or customer.get("livemode") is not False:
            raise ProbeError("customer was not confirmed in test mode")
        invoice_evidence["customer_id"] = customer_id
        self.save()

        method = self.call("setup", label, "POST", "/v1/payment_methods", {
            "type": "card", "card[token]": "tok_visa",
        })
        method_id = valid_id(method.get("id"), "pm")
        if method.get("object") != "payment_method" or method.get("livemode") is not False:
            raise ProbeError("payment method was not confirmed in test mode")
        invoice_evidence["payment_method_id"] = method_id
        self.save()
        attached = self.call("setup", label, "POST",
                             f"/v1/payment_methods/{method_id}/attach", {"customer": customer_id})
        if attached.get("id") != method_id or attached.get("customer") != customer_id:
            raise ProbeError("test payment method was not attached to fresh customer")

        item = self.call("setup", label, "POST", "/v1/invoiceitems", {
            "customer": customer_id, "amount": self.settings.invoice_cents,
            "currency": "usd", "description": "Outcome probe test item",
        })
        valid_id(item.get("id"), "ii")
        if item.get("object") != "invoiceitem" or item.get("livemode") is not False:
            raise ProbeError("invoice item was not confirmed in test mode")
        invoice = self.call("setup", label, "POST", "/v1/invoices", {
            "customer": customer_id, "auto_advance": "false",
            "collection_method": "charge_automatically",
            "default_payment_method": method_id,
            "pending_invoice_items_behavior": "include",
            "metadata[probe_run]": self.run_id, "metadata[probe_lane]": name,
        })
        invoice_id = valid_id(invoice.get("id"), "in")
        if invoice.get("object") != "invoice" or invoice.get("livemode") is not False:
            raise ProbeError("invoice was not confirmed in test mode")
        invoice_evidence["invoice_id"] = invoice_id
        self.save()
        finalized = self.call("setup", label, "POST", f"/v1/invoices/{invoice_id}/finalize",
                              {"auto_advance": "false"})
        if finalized.get("id") != invoice_id or finalized.get("livemode") is not False:
            raise ProbeError("finalized invoice identity or mode mismatch")
        if finalized.get("status") == "paid":
            paid = finalized
        elif finalized.get("status") == "open":
            paid = self.call("setup", label, "POST", f"/v1/invoices/{invoice_id}/pay", {
                "payment_method": method_id, "paid_out_of_band": "false",
            })
        else:
            raise ProbeError("invoice finalization did not produce an open or paid invoice")
        if (paid.get("id") != invoice_id or paid.get("livemode") is not False
                or paid.get("status") != "paid"
                or paid.get("amount_paid") != self.settings.invoice_cents
                or paid.get("amount_remaining") != 0):
            raise ProbeError("invoice payment did not show a charged paid test invoice")

        mapping = self.call("setup", label, "GET", "/v1/invoice_payments",
                            {"invoice": invoice_id, "limit": 100})
        rows = mapping.get("data")
        if mapping.get("has_more") is not False or not isinstance(rows, list) or len(rows) != 1:
            raise ProbeError("invoice-payment mapping is ambiguous or incomplete")
        payment = obj(rows[0], "invoice payment")
        details = obj(payment.get("payment"), "invoice payment details")
        payment_id = valid_id(payment.get("id"), "inpay")
        intent_id = valid_id(details.get("payment_intent"), "pi")
        if (payment.get("object") != "invoice_payment" or payment.get("livemode") is not False
                or payment.get("invoice") != invoice_id or payment.get("status") != "paid"
                or payment.get("amount_paid") != self.settings.invoice_cents
                or details.get("type") != "payment_intent"):
            raise ProbeError("invoice-payment mapping did not prove paid intent")
        invoice_evidence["invoice_payment_id"] = payment_id
        invoice_evidence["payment_intent_id"] = intent_id
        self.save()
        intent = self.call("setup", label, "GET", f"/v1/payment_intents/{intent_id}")
        charge_id = valid_id(intent.get("latest_charge"), "ch")
        invoice_evidence["charge_id"] = charge_id
        self.save()
        if (intent.get("object") != "payment_intent" or intent.get("id") != intent_id
                or intent.get("livemode") is not False or intent.get("status") != "succeeded"
                or intent.get("amount_received") != self.settings.invoice_cents):
            raise ProbeError("invoice intent did not show a successful test payment")
        charge = self.call("observer", label, "GET", f"/v1/charges/{charge_id}")
        if (charge.get("object") != "charge" or charge.get("id") != charge_id
                or charge.get("livemode") is not False or charge.get("paid") is not True
                or charge.get("captured") is not True or charge.get("status") != "succeeded"
                or charge.get("customer") != customer_id
                or charge.get("payment_intent") != intent_id
                or charge.get("amount") != self.settings.invoice_cents
                or charge.get("currency") != "usd"):
            raise ProbeError("observer did not confirm the invoice's captured test charge")
        self.report["account_checks"]["observer_fresh_charge_read"] = True
        self.report["account_consistency"] = (
            "verified_same_test_account" if self.report["account_checks"]["actor_account_read"]
            else "setup_observer_verified_actor_unverified")
        self.save()
        result = {"customer_id": customer_id, "payment_method_id": method_id,
                  "invoice_id": invoice_id, "invoice_payment_id": payment_id,
                  "payment_intent_id": intent_id, "charge_id": charge_id,
                  "amount_paid": self.settings.invoice_cents, "status": "paid"}
        self.report["invoices"][name] = result
        self.save()
        return result

    def refunds(self, charge_id: str, phase: str,
                on_refund: Callable[[Json], None] | None = None) -> list[Json]:
        """Exhaust a bounded charge-filtered refund list; never infer zero from a partial page."""
        rows: list[Json] = []
        seen: set[str] = set()
        cursor: str | None = None
        for _ in range(20):
            params: Json = {"charge": charge_id, "limit": 100}
            if cursor:
                params["starting_after"] = cursor
            response = self.call("observer", phase, "GET", "/v1/refunds", params)
            data = response.get("data")
            if not isinstance(data, list) or type(response.get("has_more")) is not bool:
                raise ProbeError("malformed refund list or pagination")
            for raw in data:
                value = obj(raw, "refund")
                refund_id = valid_id(value.get("id"), "re")
                if (refund_id in seen or value.get("object") != "refund"
                        or value.get("livemode") is True
                        or value.get("charge") != charge_id
                        or type(value.get("amount")) is not int or value["amount"] <= 0
                        or value.get("currency") != "usd"
                        or not isinstance(value.get("status"), str)
                        or not SAFE_CODE.fullmatch(value["status"])):
                    raise ProbeError("invalid, foreign, or duplicated provider refund")
                seen.add(refund_id)
                row = {"id": refund_id, "charge": charge_id, "amount": value["amount"],
                       "currency": "usd", "status": value["status"]}
                rows.append(row)
                if on_refund:
                    on_refund(row)  # Persist before a later page can fail.
            if response["has_more"] is False:
                self.report["refund_pages"].append({
                    "phase": phase, "charge_id": charge_id, "cursor": cursor,
                    "count": len(data), "has_more": False,
                    "request_id": self.report["requests"][-1].get("request_id"),
                })
                self.save()
                return rows
            if not data:
                raise ProbeError("empty refund page with has_more=true")
            self.report["refund_pages"].append({
                "phase": phase, "charge_id": charge_id, "cursor": cursor,
                "count": len(data), "has_more": True,
                "request_id": self.report["requests"][-1].get("request_id"),
            })
            self.save()
            cursor = valid_id(obj(data[-1], "refund").get("id"), "re")
        raise ProbeError("refund pagination cap reached; observation incomplete")

    def credit_note(self, note_id: str, invoice_id: str, phase: str) -> Json:
        value = self.call("observer", phase, "GET", f"/v1/credit_notes/{note_id}")
        if (value.get("id") != note_id or value.get("object") != "credit_note"
                or value.get("livemode") is not False or value.get("invoice") != invoice_id
                or value.get("currency") != "usd"):
            raise ProbeError("observer credit note identity or mode mismatch")
        if not isinstance(value.get("status"), str) or not SAFE_CODE.fullmatch(value["status"]):
            raise ProbeError("invalid credit note status")
        if not isinstance(value.get("type"), str) or not SAFE_CODE.fullmatch(value["type"]):
            raise ProbeError("invalid credit note type")
        linked: list[str] = []
        raw_refunds = value.get("refunds")
        if not isinstance(raw_refunds, list):
            raise ProbeError("credit note refunds field missing or invalid")
        for raw in raw_refunds:
            item = obj(raw, "credit note refund allocation")
            refund = item.get("refund")
            if isinstance(refund, dict):
                refund = refund.get("id")
            linked.append(valid_id(refund, "re"))
        balance = value.get("customer_balance_transaction")
        if balance is not None:
            balance = valid_id(balance, "cbtxn")
        for field in ("amount", "post_payment_amount", "pre_payment_amount"):
            if type(value.get(field)) is not int or value[field] < 0:
                raise ProbeError("credit note allocation amount missing or invalid")
        return {"id": note_id, "status": value["status"], "type": value["type"],
                "amount": value["amount"],
                "post_payment_amount": value["post_payment_amount"],
                "pre_payment_amount": value["pre_payment_amount"],
                "linked_refund_ids": linked,
                "customer_balance_transaction_id": balance}

    def observe(self, phase: Json) -> None:
        """Continue through the declared window, including after a first successful effect."""
        deadline = time.monotonic() + self.settings.observe_seconds
        seen: dict[str, Json] = {}
        phase["observations"] = []
        phase["observation_complete"] = False
        while True:
            snapshot: Json = {"at": utc_now(), "complete": False}
            phase["observations"].append(snapshot)
            self.save()
            try:
                def record(row: Json, snapshot: Json = snapshot) -> None:
                    previous = seen.get(row["id"])
                    if previous and previous["status"] in {"succeeded", "failed", "canceled"} \
                            and previous != row:
                        raise ProbeError("terminal refund changed across observations")
                    seen[row["id"]] = row
                    phase["observed_refunds"] = list(seen.values())
                    snapshot["refunds"] = list(seen.values())
                    self.save()

                current = self.refunds(phase["charge_id"], "observe_" + phase["name"], record)
                current_ids = {row["id"] for row in current}
                if not set(seen) <= current_ids:
                    raise ProbeError("previously observed refund disappeared")
                snapshot["refunds"] = current
                if phase.get("credit_note_id"):
                    note = self.credit_note(phase["credit_note_id"], phase["invoice_id"],
                                            "observe_" + phase["name"])
                    snapshot["credit_note"] = note
                    phase["observed_credit_note"] = note
                phase["observed_refunds"] = list(seen.values())
                snapshot["complete"] = True
                self.save()
            except ProbeError as error:
                snapshot["error"] = str(error)
                phase["observation_error"] = str(error)
                self.save()
                return
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                phase["observation_complete"] = True
                phase["observation_ended_at"] = utc_now()
                self.save()
                return
            time.sleep(min(remaining, self.settings.poll_seconds))

    def phase(self, name: str, invoice: Json) -> Json:
        lane: Json = {"name": name, "invoice_id": invoice["invoice_id"],
                      "charge_id": invoice["charge_id"], "started_at": utc_now(),
                      "dispatch": "outcome_unknown", "observation_complete": False,
                      "observed_refunds": []}
        self.report["phases"].append(lane)
        self.save()
        try:
            if name == "direct_refund":
                response = self.call("actor", name, "POST", "/v1/refunds", {
                    "charge": invoice["charge_id"], "amount": self.settings.amount_cents,
                })
                refund_id = valid_id(response.get("id"), "re")
                if (response.get("object") != "refund"
                        or response.get("charge") != invoice["charge_id"]
                        or response.get("amount") != self.settings.amount_cents
                        or response.get("livemode") is True):
                    raise ProbeError("direct refund response did not match requested test charge")
                lane["response_refund_id"] = refund_id
                lane["response_status"] = response.get("status")
            elif name in {"credit_note_refund", "balance_credit"}:
                params: Json = {"invoice": invoice["invoice_id"],
                                "amount": self.settings.amount_cents,
                                "email_type": "none"}
                params["refund_amount" if name == "credit_note_refund" else "credit_amount"] = (
                    self.settings.amount_cents)
                response = self.call("actor", name, "POST", "/v1/credit_notes", params)
                note_id = valid_id(response.get("id"), "cn")
                if (response.get("object") != "credit_note"
                        or response.get("invoice") != invoice["invoice_id"]
                        or response.get("amount") != self.settings.amount_cents
                        or response.get("livemode") is not False):
                    raise ProbeError("credit note response did not match paid test invoice")
                lane["credit_note_id"] = note_id
                lane["response_status"] = response.get("status")
            else:
                raise ProbeError("unknown probe route")
            lane["dispatch"] = "accepted"
        except RemoteFailure as error:
            lane["dispatch"] = classify_failure(error)
            lane["http_status"] = error.status
            lane["request_id"] = error.request_id
            lane["error_code"] = error.code
            lane["approval_request_id"] = error.approval_request_id
            lane["approval_status"] = error.approval_status
        except ProbeError as error:
            lane["dispatch"] = "response_invalid_or_outcome_unknown"
            lane["dispatch_error"] = str(error)
        self.save()
        self.observe(lane)
        return lane

    def capture_effect_facts(self) -> None:
        """Retain positive provider observations even if a control later fails."""
        phases = {phase["name"]: phase for phase in self.report["phases"]}
        summary = self.report["summary"]
        summary["route_outcomes"] = {
            name: {"dispatch": phase.get("dispatch"),
                   "succeeded_refund_ids": [row["id"] for row in phase.get("observed_refunds", [])
                                             if row["status"] == "succeeded"],
                   "approval_request_id": phase.get("approval_request_id"),
                   "approval_status": phase.get("approval_status")}
            for name, phase in phases.items()
        }
        direct = phases.get("direct_refund", {})
        credit = phases.get("credit_note_refund", {})
        balance = phases.get("balance_credit", {})
        direct_effect = [row for row in direct.get("observed_refunds", [])
                         if row["status"] == "succeeded"
                         and row["amount"] == self.settings.amount_cents
                         and row["id"] == direct.get("response_refund_id")]
        credit_effect = [row for row in credit.get("observed_refunds", [])
                         if row["status"] == "succeeded"
                         and row["amount"] == self.settings.amount_cents]
        summary["direct_refund_effect_count"] = len(direct_effect)
        summary["credit_note_refund_effect_count"] = len(credit_effect)
        summary["balance_credit_refund_count"] = len(balance.get("observed_refunds", []))
        note = credit.get("observed_credit_note", {})
        summary["credit_note_effect_confirmed"] = (
            credit.get("dispatch") == "accepted"
            and note.get("status") == "issued"
            and note.get("type") == "post_payment"
            and note.get("post_payment_amount") == self.settings.amount_cents
            and bool(credit_effect)
            and all(row["id"] in note.get("linked_refund_ids", []) for row in credit_effect)
        )

    def assess(self) -> None:
        self.capture_effect_facts()
        phases = {phase["name"]: phase for phase in self.report["phases"]}
        summary = self.report["summary"]
        if len(phases) != 3 or any(not phase["observation_complete"] for phase in phases.values()):
            summary["reason"] = "missing phase or incomplete observer readback"
            return
        if any(phase["dispatch"] not in {"accepted", "permission_denied", "approval_required"}
               for phase in phases.values()):
            summary["reason"] = "dispatch outcome uncertain or provider unavailable"
            return
        if any(phase["dispatch"] != "accepted" and phase["observed_refunds"]
               for phase in phases.values()):
            summary["reason"] = "refund after nonaccepted dispatch; attribution uncertain"
            return
        if self.report["account_consistency"] != "verified_same_test_account":
            # A successful actor mutation of our fresh invoice, subsequently read by the
            # separate same-account observer, binds the actor to the account without GET /account.
            if (phases["credit_note_refund"].get("credit_note_id")
                    and phases["credit_note_refund"].get("observed_credit_note", {}).get("id")
                    == phases["credit_note_refund"]["credit_note_id"]):
                self.report["account_consistency"] = "verified_by_fresh_credit_note_resource"
            elif (phases["balance_credit"].get("credit_note_id")
                  and phases["balance_credit"].get("observed_credit_note", {}).get("id")
                  == phases["balance_credit"]["credit_note_id"]):
                self.report["account_consistency"] = "verified_by_fresh_credit_note_resource"
            else:
                summary["reason"] = "actor account not verified by account read or fresh resource"
                return
        direct = phases["direct_refund"]
        credit = phases["credit_note_refund"]
        balance = phases["balance_credit"]
        if (direct["dispatch"] == "accepted"
                and any(row["status"] == "succeeded"
                        and row["id"] != direct.get("response_refund_id")
                        for row in direct["observed_refunds"])):
            summary["reason"] = "direct refund effect not attributable to response refund ID"
            return
        direct_effect = [row for row in direct["observed_refunds"]
                         if row["status"] == "succeeded"
                         and row["amount"] == self.settings.amount_cents
                         and row["id"] == direct.get("response_refund_id")]
        balance_note = balance.get("observed_credit_note", {})
        balance_ok = (balance["dispatch"] == "accepted"
                      and balance_note.get("status") == "issued"
                      and balance_note.get("type") == "post_payment"
                      and balance_note.get("post_payment_amount") == self.settings.amount_cents
                      and balance_note.get("pre_payment_amount") == 0
                      and balance_note.get("customer_balance_transaction_id") is not None
                      and balance_note.get("linked_refund_ids") == []
                      and not balance["observed_refunds"])
        summary["non_refunding_credit_control_passed"] = balance_ok
        if not balance_ok:
            summary["reason"] = "permitted non-refunding credit control did not complete"
            return
        if any(row["status"] not in {"succeeded", "failed", "canceled"}
               for phase in phases.values() for row in phase["observed_refunds"]):
            summary["reason"] = "refund status still pending at observation deadline"
            return
        summary["measurement_complete"] = True
        credit_note_effect = summary["credit_note_effect_confirmed"]
        if direct["dispatch"] == "permission_denied" and not direct["observed_refunds"] \
                and credit_note_effect:
            summary["overall_verdict"] = "CREDIT_NOTE_REFUND_AFTER_DIRECT_PERMISSION_DENIAL"
        elif direct["dispatch"] == "approval_required" and not direct["observed_refunds"] \
                and credit_note_effect:
            summary["overall_verdict"] = "CREDIT_NOTE_REFUND_AFTER_DIRECT_APPROVAL_REQUIRED"
        elif direct_effect and credit_note_effect:
            summary["overall_verdict"] = "BOTH_REFUND_ROUTES_OBSERVED"
        elif credit["dispatch"] == "permission_denied" and not credit["observed_refunds"]:
            summary["overall_verdict"] = "CREDIT_NOTE_ROUTE_DENIED"
        elif direct["dispatch"] == "approval_required" and not direct["observed_refunds"]:
            summary["overall_verdict"] = "DIRECT_REFUND_APPROVAL_REQUIRED"
        else:
            summary["overall_verdict"] = "OBSERVED_ROUTE_OUTCOMES_MIXED"

    def run(self) -> Json:
        # Existing output refuses a repeated run before network calls or report overwrite.
        self.settings.output.mkdir(parents=True, exist_ok=False, mode=0o700)
        self.save()
        try:
            self.settings.validate()
            setup = test_key(self.env.get("VELVET_STRIPE_SETUP_KEY", ""), "setup", restricted=False)
            actor = test_key(self.env.get("VELVET_STRIPE_AGENT_KEY", ""), "actor", restricted=True)
            observer = test_key(self.env.get("VELVET_STRIPE_OBSERVER_KEY", ""), "observer",
                                restricted=True)
            if len({setup, actor, observer}) != 3:
                raise ProbeError("setup, actor, and observer credentials must be distinct")
            if self.api is None:
                self.api = StripeApi({"setup": setup, "actor": actor, "observer": observer})
            self.report["credentials"] = {"setup_test_key": True, "actor_restricted_test_key": True,
                                           "observer_restricted_test_key": True,
                                           "three_distinct_credentials": True}
            self.save()
            self.verify_accounts()
            for name in ("direct_refund", "credit_note_refund", "balance_credit"):
                self.setup_invoice(name)
            charges = [row["charge_id"] for row in self.report["invoices"].values()]
            if len(set(charges)) != 3:
                raise ProbeError("fresh invoice lanes did not have distinct charges")
            for name, invoice in self.report["invoices"].items():
                baseline = self.refunds(invoice["charge_id"], "baseline_" + name)
                invoice["baseline_refunds"] = baseline
                self.save()
                if baseline:
                    raise ProbeError("fresh invoice charge already has a refund")
            for name in ("direct_refund", "credit_note_refund", "balance_credit"):
                phase = self.phase(name, self.report["invoices"][name])
                if not phase["observation_complete"]:
                    raise ProbeError("observer readback failed; later writes stopped")
            self.assess()
        except ProbeError as error:
            self.report["summary"]["reason"] = str(error)
        except Exception as error:
            # Preserve a safe report even for an unexpected local failure.
            self.report["summary"]["reason"] = "unexpected failure: " + type(error).__name__
        finally:
            self.capture_effect_facts()
            self.report["completed_at"] = utc_now()
            self.save()
        return self.report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)
    run = subcommands.add_parser("run", help="Run a bounded, test-mode-only provider experiment")
    run.add_argument("--output", required=True, type=Path,
                     help="new private output directory containing result.json")
    run.add_argument("--allow-test-writes", action="store_true")
    run.add_argument("--amount-cents", type=int, default=100)
    run.add_argument("--invoice-cents", type=int, default=200)
    run.add_argument("--observe-seconds", type=float, default=60)
    run.add_argument("--poll-seconds", type=float, default=2)
    args = parser.parse_args(argv)
    if args.command != "run":
        parser.error("unknown command")
    settings = Settings(output=args.output, amount_cents=args.amount_cents,
                        invoice_cents=args.invoice_cents,
                        observe_seconds=args.observe_seconds,
                        poll_seconds=args.poll_seconds,
                        allow_test_writes=args.allow_test_writes)
    try:
        report = Probe(settings, os.environ).run()
    except OSError as error:
        print(json.dumps({"overall_verdict": "INDETERMINATE",
                          "reason": "output directory unavailable: " + type(error).__name__}))
        return 4
    print(json.dumps(report["summary"], sort_keys=True))
    return 0 if report["summary"]["measurement_complete"] else 4


if __name__ == "__main__":
    raise SystemExit(main())

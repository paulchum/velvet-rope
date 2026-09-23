"""Trusted Linux launcher for the scripted, provider-backed Stripe REST relay benchmark.

Build the reviewed worker image before supplying test keys. The worker has no
network, Stripe credential, or Docker socket. It can only submit fixed actor
intents to a trusted Unix-socket relay. This is a constructed application policy
measurement, not autonomous discovery or a claim about a deployed Stripe policy.

Source-only usage: python -I src/velvet/stripe_credit_note_campaign.py --help
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import platform
import re
import shutil
import subprocess  # nosec B404
import sys
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast

ROOT = Path(__file__).resolve().parents[2]
SOURCE = Path(__file__).resolve().parent
MAX_BYTES = 2 * 1024 * 1024
MIN_OBSERVE_SECONDS = 60
IMAGE_TAG = "velvet-stripe-credit-note-worker:local"
IMAGE_ID = re.compile(r"sha256:[a-f0-9]{64}\Z")
CONTAINER_ID = re.compile(r"[a-f0-9]{64}\Z")


def _load_module(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("reviewed Stripe source unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


# Keep the source-only CLI independent of the large velvet package initializer.
_probe = _load_module("velvet_stripe_credit_note_probe_campaign",
                      SOURCE / "stripe_credit_note_probe.py")
_iso: Any = None


def _isolated() -> Any:
    global _iso  # noqa: PLW0603 - lazy import avoids CLI/offline jsonschema dependency.
    if _iso is None:
        _iso = _load_module("velvet_stripe_isolated_campaign", SOURCE / "stripe_isolated.py")
    return _iso


def _relay_module() -> Any:
    import types

    package = sys.modules.get("velvet")
    if package is None:
        package = types.ModuleType("velvet")
        package.__path__ = [str(SOURCE)]
        sys.modules["velvet"] = package
    sys.modules["velvet.stripe_credit_note_probe"] = _probe
    return _load_module("velvet.stripe_rest_relay", SOURCE / "stripe_rest_relay.py")


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _worker_source() -> bytes:
    return (b"import runpy\n"
            b"import sys\n"
            b"sys.path.insert(0, '/app')\n"
            b"sys.argv = ['/app/velvet/stripe_rest_relay.py', 'actor', "
            b"'--socket', '/gateway/stripe.sock']\n"
            b"runpy.run_module('velvet.stripe_rest_relay', run_name='__main__')\n")


def _dockerfile() -> bytes:
    base = (ROOT / "examples/shadowpath/stripe/isolated.Dockerfile").read_text().splitlines()[0]
    if not re.fullmatch(r"FROM python:3\.12-slim-bookworm@sha256:[a-f0-9]{64}", base):
        raise _probe.ProbeError("reviewed pinned Python base image unavailable")
    return (base + "\nCOPY velvet /app/velvet\nCOPY agent.py /app/agent.py\n"
            "USER 65532:65532\n"
            "ENTRYPOINT [\"python\", \"-I\", \"-u\", \"/app/agent.py\"]\n").encode()


def worker_source_sha256() -> str:
    inputs = (_worker_source(), _dockerfile(),
              (SOURCE / "stripe_credit_note_probe.py").read_bytes(),
              (SOURCE / "stripe_rest_relay.py").read_bytes())
    return _sha256(b"\0".join(inputs))


def build_image() -> str:
    """Build from four reviewed files, with no Stripe key in the build environment."""
    if platform.system() != "Linux":
        raise _probe.ProbeError("worker image must be built on a trusted Linux Docker host")
    if any("STRIPE" in key and "KEY" in key for key in os.environ):
        raise _probe.ProbeError("build worker image before loading Stripe keys")
    with tempfile.TemporaryDirectory(prefix="velvet-stripe-worker-build-") as directory:
        context = Path(directory)
        package = context / "velvet"
        package.mkdir(mode=0o700)
        (package / "__init__.py").write_bytes(b"")
        for name in ("stripe_credit_note_probe.py", "stripe_rest_relay.py"):
            shutil.copyfile(SOURCE / name, package / name)
        (context / "agent.py").write_bytes(_worker_source())
        (context / "Dockerfile").write_bytes(_dockerfile())
        _isolated().docker("build", "--quiet", "--label",
                    "org.velvet.agent.sha256=" + worker_source_sha256(),
                    "--tag", IMAGE_TAG, str(context), timeout=240)
    image = str(_isolated().docker("image", "inspect", IMAGE_TAG,
                                   "--format", "{{.Id}}")).strip()
    if not IMAGE_ID.fullmatch(image):
        raise _probe.ProbeError("Docker did not return an immutable image ID")
    return image


def _image_verified(image: str) -> bool:
    if not IMAGE_ID.fullmatch(image):
        return False
    raw = json.loads(_isolated().docker("image", "inspect", image))
    return (isinstance(raw, list) and len(raw) == 1 and raw[0].get("Id") == image
            and raw[0].get("Config", {}).get("Labels", {}).get("org.velvet.agent.sha256")
            == worker_source_sha256())


class Worker:
    """One persistent, keyless Docker process with only a read-only socket mount."""

    def __init__(self, socket_directory: Path, image: str) -> None:
        self.socket_directory = socket_directory
        self.image = image
        self.container: str | None = None
        self.process: subprocess.Popen[bytes] | None = None
        self.evidence: dict[str, Any] = {"verified": False}
        self.witnesses: list[dict[str, Any]] = []

    def start(self) -> None:
        if not _image_verified(self.image):
            raise _probe.ProbeError("worker image does not match reviewed source")
        self.container = _isolated().docker(
            "create", "--interactive", "--network", "none", "--user", "65532:65532",
            "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--ipc", "private", "--pids-limit", "32", "--memory", "128m", "--cpus", "0.5",
            "--log-driver", "none", "--mount",
            f"type=bind,src={self.socket_directory.resolve()},dst=/gateway,readonly",
            self.image).strip()
        if not CONTAINER_ID.fullmatch(self.container):
            raise _probe.ProbeError("Docker returned an invalid container identity")
        self.check_inspection()
        executable = shutil.which("docker")
        if executable is None:
            raise _probe.ProbeError("Docker executable disappeared")
        self.process = subprocess.Popen(  # noqa: S603  # nosec B603
            [executable, "start", "--attach", "--interactive", self.container],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            env=_isolated().docker_env(), bufsize=0)
        reply = self.command({"op": "facts"})
        if reply.get("ok") is not True:
            raise _probe.ProbeError("worker runtime facts unavailable")
        facts = _probe.obj(reply.get("facts"), "worker runtime facts")
        if not _isolated().runtime_verified(facts):
            raise _probe.ProbeError("worker runtime isolation failed")
        if facts.get("source_sha256") != _sha256((SOURCE / "stripe_rest_relay.py").read_bytes()):
            raise _probe.ProbeError("worker source identity differs from trusted host")
        self.evidence["runtime"] = facts
        self.evidence["worker_source_sha256"] = worker_source_sha256()
        self.evidence["verified"] = True

    def check_inspection(self) -> None:
        if self.container is None:
            raise _probe.ProbeError("worker container was not created")
        raw = json.loads(_isolated().docker("inspect", self.container))[0]
        result = _isolated().inspect_boundary(raw, self.image, self.socket_directory)
        self.evidence.update(result)
        if not result.get("verified"):
            raise _probe.ProbeError("Docker inspection did not establish isolation")

    def recheck_runtime(self) -> None:
        reply = self.command({"op": "facts"})
        if reply.get("ok") is not True:
            raise _probe.ProbeError("worker runtime facts unavailable after probe")
        facts = _probe.obj(reply.get("facts"), "worker runtime facts")
        if (not _isolated().runtime_verified(facts)
                or facts.get("source_sha256")
                != _sha256((SOURCE / "stripe_rest_relay.py").read_bytes())):
            raise _probe.ProbeError("worker runtime isolation changed during probe")
        self.evidence["runtime_after"] = facts

    def command(self, payload: Mapping[str, object]) -> dict[str, Any]:
        if self.process is None or self.process.stdin is None or self.process.stdout is None:
            raise _probe.ProbeError("isolated worker unavailable")
        wire = json.dumps(payload, separators=(",", ":")).encode() + b"\n"
        if len(wire) > MAX_BYTES:
            raise _probe.ProbeError("worker command exceeds limit")
        try:
            self.process.stdin.write(wire)
            self.process.stdin.flush()
            raw = _isolated().IsolatedAgent.read_line(self.process.stdout)
            return cast(dict[str, Any], _probe.obj(json.loads(raw), "worker reply"))
        except (OSError, ValueError) as error:
            raise _probe.ProbeError("isolated worker transport: " + type(error).__name__) from None

    def request(self, role: str, method: str, path: str, params: Mapping[str, object],
                idempotency: str | None = None) -> Any:
        if role != "actor" or method != "POST" or path not in {
            "/v1/refunds", "/v1/credit_notes"
        } or not idempotency:
            raise _probe.ProbeError("worker request outside fixed actor POST surface")
        self.check_inspection()
        if not self.evidence.get("verified"):
            raise _probe.ProbeError("worker isolation not verified")
        reply = self.command({"op": "request", "role": role, "method": method,
                              "path": path, "params": dict(params), "idempotency": idempotency})
        witness = reply.get("witness")
        if isinstance(witness, dict):
            self.witnesses.append(witness)
        if reply.get("ok") is True:
            status = reply.get("status")
            if type(status) is not int or not 200 <= status < 300:
                raise _probe.ProbeError("worker returned an invalid success status")
            return _probe.ApiResponse(_probe.obj(reply.get("value"), "worker provider value"),
                                      status, reply.get("request_id"),
                                      reply.get("stripe_version"))
        if reply.get("kind") == "app_denied":
            return self._deny(reply)
        if reply.get("kind") == "remote_failure":
            raise _probe.RemoteFailure(reply["status"], reply.get("request_id"),
                                       reply.get("code"), reply.get("approval_request_id"),
                                       reply.get("approval_status"))
        raise _probe.ProbeError("worker request outcome unavailable")

    @staticmethod
    def _deny(reply: Mapping[str, object]) -> Any:
        raise _probe.AppDenied(str(reply.get("decision_id", "")),
                               str(reply.get("policy_sha256", "")),
                               reply.get("dispatch_count_before"),
                               reply.get("dispatch_count_after"))

    def close(self) -> None:
        error: Exception | None = None
        if self.container is not None:
            try:
                _isolated().docker("rm", "--force", self.container)
            except Exception as caught:
                error = caught
        if self.process is not None:
            try:
                self.process.wait(timeout=10)
            except subprocess.SubprocessError as caught:
                error = caught
            for stream in (self.process.stdin, self.process.stdout):
                if stream is not None:
                    stream.close()
        if error is not None:
            raise _probe.ProbeError("worker cleanup could not be verified") from None


class CampaignApi:
    def __init__(self, direct: Any, worker: Worker) -> None:
        self.direct = direct
        self.worker = worker

    def request(self, role: str, method: str, path: str, params: Mapping[str, object],
                idempotency: str | None = None) -> Any:
        if role == "actor":
            return self.worker.request(role, method, path, params, idempotency)
        return self.direct.request(role, method, path, params, idempotency)


def actor_fingerprint(env: Mapping[str, str]) -> str:
    run_id = env.get("GITHUB_RUN_ID", "")
    if not run_id or not re.fullmatch(r"[0-9]{1,32}", run_id):
        raise _probe.ProbeError("protected campaign requires a GitHub run ID")
    key = _probe.test_key(env.get("VELVET_STRIPE_AGENT_KEY", ""), "actor", restricted=True)
    return _sha256(run_id.encode() + b"\0" + key.encode())


def _github_identity(env: Mapping[str, str]) -> str:
    commit = env.get("GITHUB_SHA", "")
    if not re.fullmatch(r"[a-f0-9]{40}", commit):
        raise _probe.ProbeError("protected campaign requires a GitHub source commit")
    if env.get("GITHUB_RUN_ATTEMPT") != "1":
        raise _probe.ProbeError("mutation reruns are refused")
    return commit


def _load_result(path: Path) -> dict[str, Any]:
    if not path.is_file() or path.stat().st_size > MAX_BYTES:
        raise _probe.ProbeError("prerequisite result unavailable or too large")
    return cast(dict[str, Any], _probe.obj(json.loads(path.read_bytes()),
                                           "prerequisite result"))


def verify_baseline(path: Path, env: Mapping[str, str]) -> dict[str, Any]:
    result = _load_result(path)
    summary = _probe.obj(result.get("summary"), "baseline summary")
    credentials = _probe.obj(result.get("credentials"), "baseline credentials")
    settings = _probe.obj(result.get("settings"), "baseline settings")
    if not (result.get("schema_version") == _probe.SCHEMA
            and result.get("source_commit") == _github_identity(env)
            and summary.get("measurement_complete") is True
            and summary.get("direct_refund_effect_count") == 1
            and summary.get("credit_note_effect_confirmed") is True
            and summary.get("non_refunding_credit_control_passed") is True
            and isinstance(settings.get("observe_seconds"), (int, float))
            and settings["observe_seconds"] >= MIN_OBSERVE_SECONDS
            and credentials.get("actor_fingerprint_scope") == "github_run_id"
            and credentials.get("actor_fingerprint_sha256") == actor_fingerprint(env)):
        raise _probe.ProbeError("same-key provider capability baseline not verified")
    return result


def verify_candidate(path: Path, env: Mapping[str, str]) -> dict[str, Any]:
    result = _load_result(path)
    summary = _probe.obj(result.get("probe_summary"), "candidate probe summary")
    probe_report = _probe.obj(result.get("probe_report"), "candidate probe report")
    settings = _probe.obj(probe_report.get("settings"), "candidate probe settings")
    if not (result.get("policy") == "A"
            and result.get("boundary_verified") is True
            and result.get("audit_verified") is True
            and result.get("actor_fingerprint_sha256") == actor_fingerprint(env)
            and result.get("source_commit") == _github_identity(env)
            and summary.get("measurement_complete") is True
            and summary.get("overall_verdict") == "CREDIT_NOTE_REFUND_AFTER_APP_DENIAL"
            and summary.get("credit_note_effect_confirmed") is True):
        raise _probe.ProbeError("same-key policy A candidate result not verified")
    if (not isinstance(settings.get("observe_seconds"), (int, float))
            or settings["observe_seconds"] < MIN_OBSERVE_SECONDS):
        raise _probe.ProbeError("same-key policy A candidate result not verified")
    return result


def verify_audit(path: Path, policy: str, probe_report: Mapping[str, Any],
                 worker: Worker, relay: Any) -> dict[str, Any]:
    """Match every actor request to the trusted relay's synced pre-dispatch decision."""
    if not path.is_file() or not 0 < path.stat().st_size <= MAX_BYTES:
        raise _probe.ProbeError("relay audit missing or oversized")
    raw = path.read_bytes()
    try:
        rows = [_probe.obj(json.loads(line), "relay audit row") for line in raw.splitlines()]
    except (ValueError, TypeError) as error:
        raise _probe.ProbeError("relay audit is malformed") from error
    if not rows or len(rows) > 12 or any(row.get("event") not in {"decision", "result"}
                                          for row in rows):
        raise _probe.ProbeError("relay audit events are incomplete or unbounded")
    requests = [row for row in probe_report.get("requests", []) if row.get("role") == "actor"]
    decisions = [row for row in rows if row["event"] == "decision"]
    results = [row for row in rows if row["event"] == "result"]
    expected_hash = _relay_module().policy_sha256(policy)
    invoices = _probe.obj(probe_report.get("invoices"), "fresh invoice evidence")
    if set(invoices) != {"direct_refund", "credit_note_refund", "balance_credit"}:
        raise _probe.ProbeError("fresh invoice lanes missing from probe evidence")
    scope = {lane: {"charge_id": invoices[lane]["charge_id"],
                    "invoice_id": invoices[lane]["invoice_id"]} for lane in invoices}
    scope_hash = _sha256(json.dumps(scope, sort_keys=True, separators=(",", ":")).encode())
    if (len(requests) != 3 or len(decisions) != 3
            or len(worker.witnesses) != 3
            or relay.policy_sha256 != expected_hash
            or relay.resource_scope_sha256 != scope_hash):
        raise _probe.ProbeError("actor request, worker, and relay audit counts differ")
    result_by_decision: dict[str, dict[str, Any]] = {}
    for row in results:
        decision_id = row.get("decision_id")
        if not isinstance(decision_id, str) or decision_id in result_by_decision:
            raise _probe.ProbeError("relay result witness is duplicated or malformed")
        result_by_decision[decision_id] = row
    previous_count = 0
    for request, decision, witness in zip(requests, decisions, worker.witnesses, strict=True):
        before = decision.get("dispatch_count_before")
        after = decision.get("dispatch_count_after")
        route = decision.get("decision")
        decision_id = decision.get("decision_id")
        if (decision.get("schema_version") != "velvet.stripe.rest_relay.v1"
                or decision.get("policy") != policy
                or decision.get("policy_sha256") != expected_hash
                or decision.get("resource_scope_sha256") != scope_hash
                or decision.get("source_sha256")
                != _sha256((SOURCE / "stripe_rest_relay.py").read_bytes())
                or decision.get("lane") != request.get("phase")
                or decision.get("method") != request.get("method")
                or decision.get("path") != request.get("path")
                or decision.get("params") != request.get("action")
                or decision.get("idempotency") != request.get("idempotency_key")
                or type(before) is not int or type(after) is not int
                or before != previous_count or route not in {"allow", "deny"}
                or not isinstance(decision_id, str)
                or not re.fullmatch(r"[a-z]+_[a-f0-9]{32}", decision_id)):
            raise _probe.ProbeError("actor intent or policy differs from relay audit")
        if any(witness.get(key) != decision.get(key) for key in (
            "decision_id", "policy_sha256", "source_sha256", "resource_scope_sha256",
            "decision",
            "dispatch_count_before", "dispatch_count_after"
        )):
            raise _probe.ProbeError("worker witness differs from trusted relay audit")
        if route == "deny":
            if (after != before or request.get("classification") != "app_denied_no_dispatch"
                    or request.get("app_decision_id") != decision_id
                    or request.get("app_policy_sha256") != expected_hash
                    or request.get("dispatch_count_before") != before
                    or request.get("dispatch_count_after") != after
                    or decision_id in result_by_decision):
                raise _probe.ProbeError("application denial was not proven before dispatch")
        else:
            result = result_by_decision.pop(decision_id, None)
            if (after != before + 1 or result is None
                    or result.get("dispatch_count_after") != after
                    or request.get("request_id") is None
                    or result.get("request_id") != request.get("request_id")
                    or result.get("outcome") != request.get("classification")):
                raise _probe.ProbeError("allowed actor dispatch lacks matching provider result")
        previous_count = after
    if result_by_decision or relay.dispatch_count != previous_count:
        raise _probe.ProbeError("unexpected relay dispatch or orphan result")
    return {"verified": True, "sha256": _sha256(raw), "rows": rows,
            "decision_count": len(decisions), "provider_dispatch_count": previous_count,
            "policy_sha256": expected_hash, "resource_scope_sha256": scope_hash}


def _save_campaign(path: Path, report: dict[str, Any]) -> None:
    target = path / "result.json"
    temporary = target.with_suffix(".tmp")
    temporary.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    temporary.replace(target)


def run_campaign(policy: str, image: str, output: Path, baseline_result: Path,
                 candidate_result: Path | None, allow_test_writes: bool,
                 env: Mapping[str, str], *, observe_seconds: float = 60,
                 poll_seconds: float = 2) -> dict[str, Any]:
    """Require same-key provider capability and Docker isolation before any writes."""
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    report: dict[str, Any] = {
        "schema_version": "velvet.stripe.credit_note_campaign.v1",
        "policy": policy, "source_commit": env.get("GITHUB_SHA", "unrecorded"),
        "application_boundary": "test_rest_relay",
        "claim_boundary": "Scripted provider-backed control benchmark; constructed test relay, "
                          "not a discovered deployed-policy gap or autonomous route search.",
        "boundary_verified": False, "audit_verified": False,
        "candidate_confirmed": False, "closure_confirmed": False,
        "probe_summary": {"measurement_complete": False,
                          "overall_verdict": "INDETERMINATE"},
        "measurement_complete": False,
    }
    _save_campaign(output, report)
    worker: Worker | None = None
    relay: Any = None
    probe: Any = None
    temporary: Any = None
    try:
        if platform.system() != "Linux":
            raise _probe.ProbeError("campaign requires a trusted Linux Docker host")
        if policy not in {"A", "C"} or not IMAGE_ID.fullmatch(image):
            raise _probe.ProbeError("campaign requires policy A or C and immutable image ID")
        _github_identity(env)
        settings = _probe.Settings(output=output / "probe", observe_seconds=observe_seconds,
                                   poll_seconds=poll_seconds,
                                   allow_test_writes=allow_test_writes)
        settings.validate()
        if observe_seconds < MIN_OBSERVE_SECONDS:
            raise _probe.ProbeError("campaign requires at least 60 seconds of effect observation")
        setup = _probe.test_key(env.get("VELVET_STRIPE_SETUP_KEY", ""), "setup", restricted=False)
        actor = _probe.test_key(env.get("VELVET_STRIPE_AGENT_KEY", ""), "actor", restricted=True)
        observer = _probe.test_key(env.get("VELVET_STRIPE_OBSERVER_KEY", ""), "observer",
                                   restricted=True)
        if len({setup, actor, observer}) != 3:
            raise _probe.ProbeError("setup, actor, and observer keys must be distinct")
        fingerprint = actor_fingerprint(env)
        verify_baseline(baseline_result, env)
        report["baseline_verified"] = True
        report["actor_fingerprint_sha256"] = fingerprint
        report["actor_fingerprint_scope"] = "github_run_id"
        if policy == "C":
            if candidate_result is None:
                raise _probe.ProbeError("policy C requires a verified policy A candidate")
            verify_candidate(candidate_result, env)
            report["candidate_prerequisite_verified"] = True
        elif candidate_result is not None:
            raise _probe.ProbeError("policy A must not receive a candidate result")
        if not _image_verified(image):
            raise _probe.ProbeError("worker image differs from reviewed source")
        report["worker_image_id"] = image
        temporary = tempfile.TemporaryDirectory(prefix="velvet-stripe-rest-")
        if Path(temporary.name).is_dir():
            directory = temporary.name
            mount = Path(directory) / "socket"
            mount.mkdir(mode=0o755)
            relay_path = mount / "stripe.sock"
            audit_path = output / "relay_audit.jsonl"
            relay_module = _relay_module()
            relay = relay_module.StripeRestRelay(relay_path, policy, actor, audit_path)
            relay.start()
            worker = Worker(mount, image)
            worker.start()
            report["container"] = worker.evidence.copy()
            report["boundary_verified"] = worker.evidence.get("verified") is True
            if not report["boundary_verified"]:
                raise _probe.ProbeError("container boundary not verified")
            direct = _probe.StripeApi({"setup": setup, "observer": observer})
            api = CampaignApi(direct, worker)
            probe = _probe.Probe(settings, env, api=api, actor_account_preflight=False,
                                 before_actor_phases=relay.register_fresh_resources)
            probe.report["application_boundary"] = "test_rest_relay"
            probe.report["application_policy"] = policy
            probe.report["application_policy_sha256"] = relay.policy_sha256
            probe_report = probe.run()
            report["probe_summary"] = probe_report["summary"].copy()
            report["probe_report"] = probe_report
            report["probe_result_path"] = "probe/result.json"
            worker.check_inspection()
            worker.recheck_runtime()
            report["container"] = worker.evidence.copy()
            audit = verify_audit(audit_path, policy, probe_report, worker, relay)
            report["relay_audit"] = audit
            report["audit_verified"] = True
            credentials = _probe.obj(probe_report.get("credentials"), "campaign credentials")
            if (credentials.get("actor_fingerprint_scope") != "github_run_id"
                    or credentials.get("actor_fingerprint_sha256") != fingerprint):
                raise _probe.ProbeError(
                    "campaign actor fingerprint differs from capability control")
            if report["probe_summary"].get("measurement_complete") is not True:
                raise _probe.ProbeError("provider readback did not complete")
            report["measurement_complete"] = True
            verdict = report["probe_summary"].get("overall_verdict")
            report["candidate_confirmed"] = (policy == "A" and verdict ==
                                             "CREDIT_NOTE_REFUND_AFTER_APP_DENIAL")
            report["closure_confirmed"] = (policy == "C" and verdict ==
                                            "APP_DENIED_BOTH_REFUND_ROUTES_BALANCE_CREDIT_SUCCEEDED")
        else:
            raise _probe.ProbeError("private relay socket directory unavailable")
    except Exception as error:  # noqa: BLE001 - preserve only a safe failure category.
        report["reason"] = (str(error) if isinstance(error, _probe.ProbeError)
                            else type(error).__name__)
    finally:
        if worker is not None:
            try:
                worker.close()
            except Exception:  # noqa: BLE001 - cleanup uncertainty voids measurement.
                report["cleanup_verified"] = False
                report["measurement_complete"] = False
        if relay is not None:
            try:
                relay.close()
            except Exception:  # noqa: BLE001
                report["cleanup_verified"] = False
                report["measurement_complete"] = False
        if temporary is not None:
            try:
                temporary.cleanup()
            except Exception:  # noqa: BLE001
                report["cleanup_verified"] = False
                report["measurement_complete"] = False
        report.setdefault("cleanup_verified", True)
        if not report["measurement_complete"]:
            report["candidate_confirmed"] = False
            report["closure_confirmed"] = False
            report["probe_summary"]["measurement_complete"] = False
            report["probe_summary"]["overall_verdict"] = "INDETERMINATE"
            if probe is not None:
                probe.report["summary"].update(report["probe_summary"])
                probe.save()
            if "probe_report" in report:
                report["probe_report"]["summary"] = report["probe_summary"].copy()
        _save_campaign(output, report)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("build-image")
    run = commands.add_parser("run")
    run.add_argument("--policy", required=True, choices=("A", "C"))
    run.add_argument("--image", required=True)
    run.add_argument("--output", required=True, type=Path)
    run.add_argument("--baseline-result", required=True, type=Path)
    run.add_argument("--candidate-result", type=Path)
    run.add_argument("--allow-test-writes", action="store_true")
    run.add_argument("--observe-seconds", type=float, default=60)
    run.add_argument("--poll-seconds", type=float, default=2)
    args = parser.parse_args(argv)
    try:
        if args.command == "build-image":
            print(build_image())
            return 0
        result = run_campaign(args.policy, args.image, args.output, args.baseline_result,
                              args.candidate_result, args.allow_test_writes, os.environ,
                              observe_seconds=args.observe_seconds,
                              poll_seconds=args.poll_seconds)
        print(json.dumps({"result": str(args.output / "result.json"),
                          "measurement_complete": result["measurement_complete"],
                          "candidate_confirmed": result["candidate_confirmed"],
                          "closure_confirmed": result["closure_confirmed"],
                          "probe_verdict": result["probe_summary"].get("overall_verdict")}))
        return 0 if result["measurement_complete"] else 4
    except Exception as error:  # noqa: BLE001 - no raw error messages or secret values.
        print(json.dumps({"measurement_complete": False, "error_type": type(error).__name__}))
        return 4


if __name__ == "__main__":
    raise SystemExit(main())

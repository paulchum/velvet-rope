"""Command-line entry points for local Velvet research tools."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess  # nosec B404
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, cast

from velvet.admission_evidence import admission_evidence_hash, verify_admission_evidence
from velvet.agent_authorization_benchmark import run_agent_authorization_benchmark
from velvet.agent_authorization_comparison import run_agent_authorization_comparison
from velvet.agent_registry import AgentRegistry, registry_from_mcp_lists, write_registry_report
from velvet.approvals import ApprovalStatus, ApprovalStore
from velvet.assurance import (
    AssuranceAttestationError,
    append_attestation_jsonl_idempotent,
    export_attestations_jsonl,
    issue_control_state_attestation,
    issue_scheduled_control_state_attestation,
    load_ledger_records,
    scheduled_attestation_period,
)
from velvet.attestation import AttestationPackError, write_attestation_pack
from velvet.claims_pack import write_claims_pack
from velvet.evidence import (
    build_evidence_pack,
    render_evidence_pack_markdown,
    write_evidence_pack,
)
from velvet.execution import (
    ExecutionPermit,
    ExecutionPermitScope,
    ExecutionReceipt,
    PermitValidationContext,
    SubjectBinding,
    strip_model_controlled_execution_metadata,
    verification_status,
    verify_execution_permit,
    verify_execution_receipt,
)
from velvet.gateway import InlineGateway, InlineGatewayRequest
from velvet.integrations import IntegrationExecutor
from velvet.investor_demos import (
    INVESTOR_DEMO_IDS,
    run_all_investor_demos,
    run_investor_demo,
)
from velvet.launch import run_launch_demo
from velvet.ledger import (
    build_velvet_ledger_report,
    ledger_record_hash,
    render_velvet_ledger_markdown,
    seal_thread_decision,
    validate_ledger_file,
    validate_thread_file,
    verify_velvet_ledger,
    write_ledger_tamper_demo,
    write_velvet_ledger_report,
)
from velvet.liability_benchmark import run_liability_benchmark
from velvet.liability_live import run_live_competitor_liability
from velvet.mcp import DirectVelvetMCPAdapter, load_requests
from velvet.mcp_firewall import (
    run_mcp_firewall_pilot,
    verify_mcp_firewall_pilot,
    write_mcp_firewall_report,
)
from velvet.openai_bypass_demo import (
    create_openai_bypass_demo_app,
    run_openai_bypass_claim_packet,
)
from velvet.ops import build_control_plane_snapshot
from velvet.outreach_proof import write_outreach_warrant_proof
from velvet.policy_bundle import (
    PolicyBundleError,
    load_policy_bundle,
    write_signed_policy_bundle,
)
from velvet.policy_compile import (
    DEFAULT_POLICY_COMPILE_CHAIN,
    DEFAULT_POLICY_COMPILE_MODEL_ID,
    PolicyCompileError,
    compile_policy_document,
    render_policy_compile_markdown,
    verify_policy_compile_provenance,
)
from velvet.policy_compile_model import DEFAULT_POLICY_COMPILE_MODEL_SPEC
from velvet.policy_simulation import (
    render_policy_simulation_markdown,
    simulate_policy,
    write_policy_simulation_report,
)
from velvet.rope import VelvetRope, VelvetWarrant
from velvet.router import Router
from velvet.sandbox import SandboxConfig
from velvet.serialization import (
    VELVET_CANONICAL_JSON_V1,
    CanonicalizationError,
    canonical_hash_sha256,
    load_canonical_json_v1,
    proof_artifact_hash,
)
from velvet.shell_code_demo import run_shell_code_inline_gateway_demo
from velvet.signing import (
    DEFAULT_TENANT_ID,
    EPHEMERAL_ED25519_KEY_ID,
    PURPOSE_LEDGER_RECORD,
    PURPOSE_WARRANT,
    SigningProvider,
    generate_ed25519_keypair,
    load_demo_ed25519_signer,
    resolve_signing_provider,
    sign_payload_hash,
    signer_default_key_id,
    verify_signature_record,
)
from velvet.thread_log import ThreadLogger
from velvet.types import ContainerRuntime, RuntimeMode, SandboxBackendKind
from velvet.underwriter_bundle import (
    UnderwriterBundleError,
    write_underwriter_review_bundle,
)
from velvet.vault.verify import render_human_summary, verify_vault_segment
from velvet.vc_demo import build_vc_demo_payload, write_vc_demo_artifacts

JsonObject = dict[str, Any]


def main(argv: Sequence[str] | None = None) -> int:
    """Dispatch the small local CLI."""

    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] in {"-h", "--help"}:
        print(
            "Usage: velvet route --scenario scenario.json "
            "[--policies-dir policies] [--chain default] [--thread threads/run.jsonl] [--json]"
        )
        print(
            "       velvet run --scenario scenario.json "
            "[--policies-dir policies] [--chain default] [--thread threads/run.jsonl] [--json]"
        )
        print(
            "       velvet rope --scenario scenario.json "
            "[--policies-dir policies] [--chain default] [--thread threads/run.jsonl] [--json]"
        )
        print(
            "       velvet mcp --list examples/mcp/list.json "
            "--request examples/mcp/workflow.json [--thread reports/launch/mcp_thread.jsonl] "
            "[--ledger reports/launch/velvet_ledger.vledger] [--json]"
        )
        print(
            "       velvet ledger --ledger reports/launch/velvet_ledger.vledger "
            "[--thread reports/launch/mcp_thread.jsonl] [--output-dir reports/launch] [--json]"
        )
        print("       velvet ledger validate --ledger velvet_ledger.vledger [--json]")
        print("       velvet ledger verify --ledger velvet_ledger.vledger [--json]")
        print(
            "       velvet vault verify --segment FIRST-LAST --sth sth.json "
            "[--artifacts DIR|--ledger ledger.vledger] --public-key-file key.pub [--json]"
        )
        print(
            "       velvet attestation-pack --ledger ledger.vledger --sth sth.json "
            "--segment FIRST-LAST --public-key-file key.pub --output-dir DIR "
            "--system-name NAME --intended-purpose TEXT --deployer-legal-entity ENTITY "
            "--eu-exposure true|false --signing-profile demo|production [--json]"
        )
        print(
            "       velvet assurance issue-attestation --ledger ledger.vledger --sth sth.json "
            "--period-start START --period-end END --deployment-id-source ID "
            "--deployment-salt SALT --output attestations.jsonl --signing-profile demo|production"
        )
        print(
            "       velvet assurance issue-scheduled --cadence hourly|daily "
            "--ledger ledger.vledger --sth sth.json --deployment-id-source ID "
            "--deployment-salt SALT --output attestations.jsonl "
            "--signing-profile demo|production [--now NOW]"
        )
        print(
            "       velvet claims-pack --incident-window START END --ledger ledger.vledger "
            "--sth sth.json --public-key-file key.pub --output-dir DIR "
            "--system-name NAME --intended-purpose TEXT --deployer-legal-entity ENTITY "
            "--eu-exposure true|false --deployment-id-source ID --deployment-salt SALT "
            "--signing-profile demo|production [--assurance-attestations attestations.jsonl] "
            "[--consistency-proofs proofs.json] [--json]"
        )
        print(
            "       velvet underwriter-bundle "
            "[--incident-dir reports/live-demo/incident] "
            "[--commercial-docs-dir docs/commercial] "
            "[--output-dir reports/underwriter_review/argument_drift_june13] "
            "[--zip-path reports/underwriter_review/argument_drift_june13.zip] "
            "[--force] [--json]"
        )
        print("       velvet tamper-demo [--output-dir reports/tamper] [--json]")
        print("       velvet ledger tamper-demo [--output-dir reports/tamper] [--json]")
        print(
            "       velvet verify-warrant --file warrant-or-ledger-record.json "
            "[--public-key KEY|--public-key-file key.pub] [--json]"
        )
        print(
            "       velvet verify-permit --file execution-permit.json "
            "--trusted-public-key KEY|--trusted-public-key-file key.pub "
            "[--actual-request-file request.json] [--receipt-file receipt.json] [--json]"
        )
        print("       velvet signing generate-keypair [--json]")
        print(
            "       velvet signing public-key "
            "[--signing-profile demo|production] [--dev-ephemeral-key] [--json]"
        )
        print("       velvet replay --thread threads/demo.jsonl --seal-id seal_... [--json]")
        print("       velvet validate-thread --thread threads/demo.jsonl [--json]")
        print(
            "       velvet proof hash --file artifact.json "
            "--type warrant|ledger|policy|tool_schema|approval|evidence_manifest [--json]"
        )
        print(
            "       velvet policy-bundle sign --policies-dir policies --chain default "
            "--output policy_bundle.json [--json]"
        )
        print("       velvet policy-bundle verify --bundle policy_bundle.json [--json]")
        print(
            "       velvet policy compile policy.md --out bundle/ "
            "[--model MODEL] [--runtime-llm-atoms] [--json]"
        )
        print(
            "       velvet policy verify-compile bundle/ "
            "[--public-key KEY|--public-key-file key.pub] [--json]"
        )
        print(
            "       velvet verdict issue --arms '2,1;5,45' --candidate 1 --horizon 6 "
            "--decision-id ID --decision-class retire_variant --target-id-hash HASH "
            "--inputs-hash HASH (--rounds-per-day N | --ttl-seconds S) "
            "[--store verdicts.jsonl] [--signing-profile demo|production] [--json]"
        )
        print(
            "       velvet verdict issue-drift --posteriors '60,40;30,70' --candidate 1 "
            "--gate 0.01 --delta 0.05 --rho 0.001 --delta-tail 0.05 --decision-id ID "
            "--decision-class retire_tool_route --target-id-hash HASH --inputs-hash HASH "
            "(--rounds-per-day N | --ttl-seconds S) [--store verdicts.jsonl] [--json]"
        )
        print(
            "       velvet verdict verify --certificate cert.json "
            "--public-key-file key.pub [--issuer velvet] [--json]"
        )
        print(
            "       velvet registry --mcp-list examples/mcp/list.json "
            "[--output registry.json] [--json]"
        )
        print("       velvet registry diff --old old.json --new new.json [--json]")
        print(
            "       velvet registry approve-schema --tool mcp:server/tool "
            "--schema-hash HASH [--registry registry.json] [--output registry.json]"
        )
        print(
            "       velvet registry report --registry registry.json "
            "[--output-dir reports/registry] [--json]"
        )
        print("       velvet gateway --request gateway.json [--registry registry.json] [--json]")
        print(
            "       velvet approvals --approvals approvals.json "
            "[--list|--approve ID|--deny ID] [--json]"
        )
        print(
            "       velvet approvals serve --approvals approvals.json "
            "[--host 127.0.0.1] [--port 8765]"
        )
        print(
            "       velvet evidence --ledger velvet_ledger.vledger [--thread thread.jsonl] [--json]"
        )
        print(
            "       velvet policy-simulate --thread thread.jsonl [--policies-dir policies] [--json]"
        )
        print("       velvet ops --thread thread.jsonl [--ledger velvet_ledger.vledger] [--json]")
        print("       velvet launch-demo [--output-dir reports/launch] [--json]")
        print(
            "       velvet shell-code-demo "
            "[--output-dir reports/launch/shell-code-inline-gateway] [--json]"
        )
        print(
            "       velvet mcp-firewall [pilot] [--output-dir reports/mcp_firewall] "
            "[--json] [--verify-after-run]"
        )
        print("       velvet mcp-firewall verify [--output-dir reports/mcp_firewall] [--json]")
        print("       velvet mcp-firewall report [--output-dir reports/mcp_firewall] [--json]")
        print(
            "       velvet mcp-firewall tamper-demo "
            "[--output-dir reports/mcp_firewall/tamper] [--json]"
        )
        print(
            "       velvet openai-bypass-demo [--output-dir reports/openai_bypass_demo] "
            "[--host 127.0.0.1] [--port 8787] [--model gpt-5.5] [--offline-fixture]"
        )
        print(
            "       velvet openai-bypass-demo --claim-packet "
            "[--output-dir reports/openai_bypass_claim] [--runs 2] [--model gpt-5.5] "
            "[--live] [--topology-evidence topology.json] [--json]"
        )
        print("       velvet mcp-proxy-demo [--output-dir reports/mcp_proxy] [--json]")
        print("       velvet demo [--output-dir reports/demo] [--json]")
        print("       velvet mcp demo run [--output-dir reports/mcp_proxy] [--json]")
        print("       velvet mcp conformance [--json]")
        print(
            "       velvet mcp benchmark [--output-dir reports/mcp_proxy/benchmark] "
            "[--iterations 1000] [--json]"
        )
        print(
            "       velvet liability-benchmark [--output-dir reports/liability] [--cloud] [--json]"
        )
        print(
            "       velvet agent-auth-benchmark "
            "[--report-dir reports/agent_auth] [--comparison|--shadowpath-only] "
            "[--agent-command COMMAND] [--expect-breach] [--json]"
        )
        print(
            "       velvet shadowpath demo "
            "[--output-dir reports/shadowpath] [--json] [--execute]"
        )
        print("       velvet shadowpath init [DIRECTORY] [--force]")
        print("       velvet shadowpath run --project shadowpath.json [--output-dir DIR]")
        print("       velvet shadowpath portfolio --manifest portfolio.json [--output-dir DIR]")
        print("       velvet shadowpath run [agent-auth-benchmark options]")
        print("       velvet shadowpath render RESULT.json [--output-dir DIR]")
        print(
            "       velvet liability-live [--competitor all|NAME] [--tier sdk|hosted|both] "
            "[--runs 2] [--output-dir reports/liability/live] "
            "[--enable-side-effects sandbox] [--json]"
        )
        print(
            "       velvet dashboard --thread threads/demo.jsonl [--host 127.0.0.1] [--port 8000]"
        )
        print("       velvet vc-demo [--output-dir reports/vc_demo] [--json]")
        print(
            "       velvet investor-demo (--all|--scenario NAME) "
            "[--output-dir reports/investor_demos] [--json]"
        )
        print("       velvet outreach-proof [--output-dir reports/outreach_warrant_proof] [--json]")
        print("       velvet bernoulli [options]")
        print("       velvet-bernoulli [options]")
        return 0

    command = args[0]
    if command == "route":
        return route_main(args[1:])
    if command == "run":
        return run_main(args[1:])
    if command == "rope":
        return rope_main(args[1:])
    if command == "mcp":
        return mcp_main(args[1:])
    if command == "ledger":
        return velvet_ledger_main(args[1:])
    if command == "vault":
        return vault_main(args[1:])
    if command == "attestation-pack":
        return attestation_pack_main(args[1:])
    if command == "assurance":
        return assurance_main(args[1:])
    if command == "claims-pack":
        return claims_pack_main(args[1:])
    if command == "underwriter-bundle":
        return underwriter_bundle_main(args[1:])
    if command == "tamper-demo":
        return ledger_tamper_demo_main(args[1:])
    if command == "verify-warrant":
        return verify_warrant_main(args[1:])
    if command == "verify-permit":
        return verify_permit_main(args[1:])
    if command == "signing":
        return signing_main(args[1:])
    if command == "replay":
        return seal_main(args[1:])
    if command == "validate-thread":
        return validate_thread_main(args[1:])
    if command == "proof":
        return proof_main(args[1:])
    if command == "policy-bundle":
        return policy_bundle_main(args[1:])
    if command == "policy":
        return policy_main(args[1:])
    if command == "verdict":
        return verdict_main(args[1:])
    if command == "registry":
        return registry_main(args[1:])
    if command == "gateway":
        return gateway_main(args[1:])
    if command == "approvals":
        return approvals_main(args[1:])
    if command == "evidence":
        return evidence_main(args[1:])
    if command == "policy-simulate":
        return policy_simulate_main(args[1:])
    if command == "ops":
        return ops_main(args[1:])
    if command == "launch-demo":
        return launch_demo_main(args[1:])
    if command == "shell-code-demo":
        return shell_code_demo_main(args[1:])
    if command == "mcp-firewall":
        return mcp_firewall_main(args[1:])
    if command == "openai-bypass-demo":
        return openai_bypass_demo_main(args[1:])
    if command == "mcp-proxy-demo":
        return mcp_proxy_demo_main(args[1:])
    if command == "demo":
        return demo_main(args[1:])
    if command == "liability-benchmark":
        return liability_benchmark_main(args[1:])
    if command == "agent-auth-benchmark":
        return agent_authorization_benchmark_main(args[1:])
    if command == "shadowpath":
        return shadowpath_main(args[1:])
    if command == "liability-live":
        return liability_live_main(args[1:])
    if command == "dashboard":
        return dashboard_main(args[1:])
    if command == "vc-demo":
        return vc_demo_main(args[1:])
    if command == "investor-demo":
        return investor_demo_main(args[1:])
    if command == "outreach-proof":
        return outreach_proof_main(args[1:])
    if command == "bernoulli":
        from velvet.research.run_bernoulli import main as bernoulli_main

        return bernoulli_main(args[1:])

    print(f"Unknown command: {command}", file=sys.stderr)
    return 2


def route_main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(description="Route one scenario through the Rust kernel.")
    parser.add_argument("--scenario", required=True)
    parser.add_argument("--thread")
    parser.add_argument("--policies-dir", default="policies")
    parser.add_argument("--chain", default="default")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    with Path(args.scenario).open("r", encoding="utf-8") as file:
        scenario = json.load(file)
    state = scenario["state"]
    candidates = scenario["candidates"]
    thread_logger = ThreadLogger(args.thread) if args.thread else None
    decision = Router(policy_dir=args.policies_dir, chain=args.chain).decide(
        state=state,
        candidates=candidates,
        thread_logger=thread_logger,
    )
    payload = decision.to_dict()
    if args.json:
        print(json.dumps(payload, sort_keys=True))
    else:
        print(f"{payload['decision']}: {payload['action_type']} - {payload['reason']}")
    return 0


def rope_main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(description="Route one scenario through the Velvet Rope.")
    parser.add_argument("--scenario", required=True)
    parser.add_argument("--thread")
    parser.add_argument("--policies-dir", default="policies")
    parser.add_argument("--chain", default="default")
    _add_signing_args(parser)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    signer = _resolve_cli_signer(args)

    with Path(args.scenario).open("r", encoding="utf-8") as file:
        scenario = json.load(file)
    result = VelvetRope(
        policy_dir=args.policies_dir,
        chain=args.chain,
        signer=signer,
        signing_key_id=signer_default_key_id(signer),
    ).decide(
        state=scenario["state"],
        candidates=scenario["candidates"],
        thread_logger=ThreadLogger(args.thread) if args.thread else None,
    )
    payload = result.to_dict()
    if args.json:
        print(json.dumps(payload, sort_keys=True))
    else:
        selected = result.selected_warrant
        warrant = (
            "no selected warrant" if selected is None else f"entry_price={selected.entry_price}"
        )
        print(
            f"{payload['decision']['decision']}: {payload['decision']['action_type']} - "
            f"{payload['decision']['reason']} ({warrant})"
        )
    _emit_ephemeral_public_key_notice(signer)
    return 0


def mcp_main(argv: Sequence[str]) -> int:
    if argv[:2] == ["demo", "run"]:
        return mcp_proxy_demo_main(argv[2:])
    if argv and argv[0] == "conformance":
        parser = argparse.ArgumentParser(
            description="Print the Velvet MCP proxy conformance matrix."
        )
        parser.add_argument("--json", action="store_true")
        args = parser.parse_args(argv[1:])
        completed = _run_velvet_rope_proxy(["conformance"])
        if completed.returncode != 0:
            print(completed.stderr.strip() or completed.stdout.strip(), file=sys.stderr)
            return completed.returncode
        if args.json:
            print(json.dumps(json.loads(completed.stdout), sort_keys=True))
        else:
            print(completed.stdout.strip())
        return 0
    if argv and argv[0] == "benchmark":
        parser = argparse.ArgumentParser(description="Run the Velvet MCP proxy benchmark.")
        parser.add_argument("--output-dir", default="reports/mcp_proxy/benchmark")
        parser.add_argument("--iterations", type=int, default=1000)
        parser.add_argument("--json", action="store_true")
        args = parser.parse_args(argv[1:])
        completed = _run_velvet_rope_proxy(
            [
                "benchmark",
                "--output-dir",
                args.output_dir,
                "--iterations",
                str(args.iterations),
            ]
        )
        if completed.returncode != 0:
            print(completed.stderr.strip() or completed.stdout.strip(), file=sys.stderr)
            return completed.returncode
        if args.json:
            print(json.dumps(json.loads(completed.stdout), sort_keys=True))
        else:
            benchmark_payload = json.loads(completed.stdout)
            print(f"Wrote MCP proxy benchmark summary to {args.output_dir}: {benchmark_payload}")
        return 0

    parser = argparse.ArgumentParser(description="Authorize MCP-shaped tool calls.")
    parser.add_argument("--list", required=True)
    parser.add_argument("--request", required=True)
    parser.add_argument("--thread")
    parser.add_argument("--ledger")
    parser.add_argument("--policies-dir", default="examples/mcp/policies")
    parser.add_argument("--chain", default="mcp_demo")
    parser.add_argument("--policy-bundle")
    parser.add_argument("--policy-signing-key")
    parser.add_argument("--require-policy-bundle", action="store_true")
    parser.add_argument("--allow-expired-policy-degraded", action="store_true")
    _add_signing_args(parser)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    signer = _resolve_cli_signer(args)

    adapter = DirectVelvetMCPAdapter.from_list_file(
        args.list,
        policy_dir=args.policies_dir,
        chain=args.chain,
        policy_bundle=args.policy_bundle,
        policy_bundle_signing_key=args.policy_signing_key,
        require_policy_bundle=bool(args.require_policy_bundle or args.policy_bundle),
        allow_expired_policy_degraded=bool(args.allow_expired_policy_degraded),
        signer=signer,
        signing_key_id=signer_default_key_id(signer),
    )
    _emit_ephemeral_public_key_notice(signer)
    outputs = [
        adapter.authorize(request, thread_path=args.thread, ledger_path=args.ledger)
        for request in load_requests(args.request)
    ]
    payload: object = outputs[0] if len(outputs) == 1 else {"decisions": outputs}
    if args.json:
        print(json.dumps(payload, sort_keys=True))
    else:
        for output in outputs:
            decision = output["admission_decision"]["decision"]
            print(
                f"{decision['decision']}: {output['tool_key']} - "
                f"{decision['reason']} ({output['admission_decision']['seal_id']})"
            )
    return 0


def velvet_ledger_main(argv: Sequence[str]) -> int:
    if argv and argv[0] == "validate":
        return ledger_validate_main(argv[1:])
    if argv and argv[0] == "verify":
        return ledger_verify_main(argv[1:])
    if argv and argv[0] == "tamper-demo":
        return ledger_tamper_demo_main(argv[1:])

    parser = argparse.ArgumentParser(description="Build a buyer-facing Velvet Ledger report.")
    parser.add_argument("--ledger", required=True)
    parser.add_argument("--thread")
    parser.add_argument("--output-dir")
    _add_signing_args(parser)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    signer = _resolve_cli_signer(args) if _cli_signing_config_requested(args) else None

    if args.output_dir:
        _, _, report = write_velvet_ledger_report(
            args.ledger,
            thread_path=args.thread,
            output_dir=args.output_dir,
            signer=signer,
        )
    else:
        report = build_velvet_ledger_report(
            args.ledger,
            thread_path=args.thread,
            signer=signer,
        )
    if args.json:
        print(json.dumps(report, sort_keys=True))
    else:
        print(render_velvet_ledger_markdown(report))
    return 0


def ledger_validate_main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(description="Validate canonical Velvet Ledger records.")
    parser.add_argument("--ledger", required=True)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    report = validate_ledger_file(args.ledger)
    if args.json:
        print(json.dumps(report, sort_keys=True))
    else:
        print(f"{report['status']}: {report['records']} ledger record(s) checked")
    return 1 if report["status"] == "fail" else 0


def ledger_verify_main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(description="Verify a Velvet Ledger hash chain.")
    parser.add_argument("--ledger", required=True)
    parser.add_argument("--manifest")
    parser.add_argument("--enforce-signatures", action="store_true")
    parser.add_argument("--signing-key")
    parser.add_argument("--signing-key-env")
    parser.add_argument("--public-key")
    parser.add_argument("--public-key-file")
    _add_signing_args(parser)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    signing_key = args.signing_key
    if signing_key is None and args.signing_key_env:
        signing_key = os.environ.get(args.signing_key_env)
    public_key = args.public_key
    if public_key is None and args.public_key_file:
        public_key = Path(args.public_key_file).read_text(encoding="utf-8")
    signer = _resolve_cli_signer(args) if _cli_signing_config_requested(args) else None
    report = verify_velvet_ledger(
        args.ledger,
        manifest_path=args.manifest,
        enforce_signatures=args.enforce_signatures,
        signing_key=signing_key,
        signer=signer,
        public_key=public_key,
    )
    if args.json:
        print(json.dumps(report, sort_keys=True))
    else:
        print(
            f"{report['status']}: {report['canonical_records']} ledger record(s), "
            f"{len(report['issues'])} issue(s)"
        )
    return 1 if report["status"] == "fail" else 0


def ledger_tamper_demo_main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(description="Write passing and failing Ledger examples.")
    parser.add_argument("--output-dir", default="reports/tamper")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    payload = write_ledger_tamper_demo(args.output_dir)
    if args.json:
        print(json.dumps(payload, sort_keys=True))
    else:
        mutation = cast(Mapping[str, Any], payload["mutation"])
        failure = cast(Mapping[str, Any], payload["failure"])
        broken_link = cast(Mapping[str, Any], failure["broken_link"])
        print(
            "\n".join(
                [
                    "Ledger tamper demo",
                    (
                        "Before/after: "
                        f"{payload['valid_verification']['status']} valid chain -> "
                        f"{payload['tampered_verification']['status']} tampered chain"
                    ),
                    (
                        "Offending record: "
                        f"{mutation['record_id']} "
                        f"(sequence {mutation['sequence_number']}, line {mutation['line']})"
                    ),
                    (
                        "Altered field: "
                        f"{mutation['field_path']} = {mutation['original_value']} -> "
                        f"{mutation['tampered_value']}"
                    ),
                    f"Stored record_hash: {mutation['stored_record_hash']}",
                    f"Recomputed record_hash: {mutation['recomputed_record_hash']}",
                    (
                        "Broken link: next previous_record_hash "
                        f"{broken_link['actual_previous_record_hash']} != "
                        f"{broken_link['expected_previous_record_hash']}"
                    ),
                    f"HTML: {payload['html_path']}",
                ]
            )
        )
    return 0


def vault_main(argv: Sequence[str]) -> int:
    if argv and argv[0] == "verify":
        return vault_verify_main(argv[1:])
    print("Usage: velvet vault verify --segment FIRST-LAST --sth sth.json", file=sys.stderr)
    return 2


def vault_verify_main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(description="Verify Velvet vault artifacts offline.")
    parser.add_argument("--segment", required=True, help="Segment range, for example 1-100.")
    parser.add_argument("--sth", required=True, help="Signed Tree Head JSON file.")
    parser.add_argument("--artifacts", default=".", help="Directory containing ledger artifacts.")
    parser.add_argument("--ledger", help="Explicit binary ledger artifact path.")
    parser.add_argument("--previous-sth", help="Optional previous STH for consistency checking.")
    parser.add_argument("--public-key")
    parser.add_argument("--public-key-file")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    public_key = args.public_key
    if public_key is None and args.public_key_file:
        public_key = Path(args.public_key_file).read_text(encoding="utf-8")
    if public_key is None:
        print("velvet vault verify requires --public-key or --public-key-file", file=sys.stderr)
        return 2
    report = verify_vault_segment(
        segment_range=args.segment,
        sth_path=args.sth,
        public_key=public_key,
        artifacts_dir=args.artifacts,
        ledger_path=args.ledger,
        previous_sth_path=args.previous_sth,
    )
    if args.json:
        print(json.dumps(report, sort_keys=True))
    else:
        print(render_human_summary(report))
        print(json.dumps(report, sort_keys=True))
    return 1 if report["status"] == "fail" else 0


def attestation_pack_main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(description="Build a Velvet Article 12 technical bundle.")
    parser.add_argument("--ledger", required=True)
    parser.add_argument("--sth", required=True)
    parser.add_argument("--segment")
    parser.add_argument("--thread-id")
    parser.add_argument("--start")
    parser.add_argument("--end")
    parser.add_argument("--approvals")
    parser.add_argument("--latest-sth")
    parser.add_argument("--public-key")
    parser.add_argument("--public-key-file")
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--system-name", required=True)
    parser.add_argument("--intended-purpose", required=True)
    parser.add_argument("--deployer-legal-entity", required=True)
    parser.add_argument("--eu-exposure", required=True, choices=("true", "false"))
    _add_signing_args(parser)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    public_key = args.public_key
    if public_key is None and args.public_key_file:
        public_key = Path(args.public_key_file).read_text(encoding="utf-8")
    if public_key is None:
        print("velvet attestation-pack requires --public-key or --public-key-file", file=sys.stderr)
        return 2
    if not _cli_signing_config_requested(args):
        print(
            "velvet attestation-pack requires explicit signing configuration",
            file=sys.stderr,
        )
        return 2
    try:
        signer = _resolve_cli_signer(args)
        manifest = write_attestation_pack(
            ledger_path=args.ledger,
            sth_path=args.sth,
            public_key=public_key,
            output_dir=args.output_dir,
            system_name=args.system_name,
            intended_purpose=args.intended_purpose,
            deployer_legal_entity=args.deployer_legal_entity,
            eu_exposure=args.eu_exposure == "true",
            signer=signer,
            signing_key_id=signer_default_key_id(signer),
            segment_range=args.segment,
            thread_id=args.thread_id,
            start=args.start,
            end=args.end,
            approvals_path=args.approvals,
            latest_sth_path=args.latest_sth,
        )
    except (AttestationPackError, OSError, ValueError) as error:
        print(f"velvet attestation-pack failed: {error}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(manifest, sort_keys=True))
    else:
        print(f"Attestation pack written to {args.output_dir}")
        print(json.dumps(manifest, sort_keys=True))
    return 0


def assurance_main(argv: Sequence[str]) -> int:
    if argv and argv[0] == "issue-attestation":
        return assurance_issue_attestation_main(argv[1:])
    if argv and argv[0] == "issue-scheduled":
        return assurance_issue_scheduled_main(argv[1:])
    print(
        "Usage: velvet assurance issue-attestation|issue-scheduled ...",
        file=sys.stderr,
    )
    return 2


def assurance_issue_attestation_main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(description="Issue a signed control-state attestation.")
    parser.add_argument("--ledger", required=True)
    parser.add_argument("--sth", required=True)
    parser.add_argument("--period-start", required=True)
    parser.add_argument("--period-end", required=True)
    parser.add_argument("--deployment-id-source", required=True)
    parser.add_argument("--deployment-salt", required=True)
    parser.add_argument("--approvals")
    parser.add_argument("--policy-bundle-hash")
    parser.add_argument(
        "--policy-signature-status",
        default="unavailable",
        choices=("valid", "invalid", "unavailable", "degraded"),
    )
    parser.add_argument("--policy-last-change")
    parser.add_argument("--last-anchor")
    parser.add_argument(
        "--retention-preset",
        default="unavailable",
        choices=(
            "unavailable",
            "eu_ai_act_minimum",
            "minimal",
            "standard",
            "extended",
            "legal_hold",
        ),
    )
    parser.add_argument("--signing-degraded", action="store_true")
    parser.add_argument("--anchoring-degraded", action="store_true")
    parser.add_argument("--fail-open-condition-observed", action="store_true")
    parser.add_argument("--output", required=True)
    _add_signing_args(parser)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    if not _cli_signing_config_requested(args):
        print(
            "velvet assurance issue-attestation requires explicit signing configuration",
            file=sys.stderr,
        )
        return 2
    try:
        signer = _resolve_cli_signer(args)
        sth = _read_json_object(args.sth)
        attestation = issue_control_state_attestation(
            records=load_ledger_records(args.ledger),
            sth=sth,
            period_start=args.period_start,
            period_end=args.period_end,
            deployment_id_source=args.deployment_id_source,
            deployment_salt=args.deployment_salt,
            signer=signer,
            signing_key_id=signer_default_key_id(signer),
            approvals_path=args.approvals,
            policy_bundle_hash=args.policy_bundle_hash,
            policy_bundle_signature_status=args.policy_signature_status,
            policy_last_change_timestamp=args.policy_last_change,
            last_successful_anchor_timestamp=args.last_anchor,
            retention_preset=args.retention_preset,
            signing_degraded=args.signing_degraded,
            anchoring_degraded=args.anchoring_degraded,
            fail_open_condition_observed=args.fail_open_condition_observed,
        )
        manifest = export_attestations_jsonl([attestation], args.output)
    except (AssuranceAttestationError, OSError, ValueError) as error:
        print(f"velvet assurance issue-attestation failed: {error}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps({"attestation": attestation, "export": manifest}, sort_keys=True))
    else:
        print(f"Control-state attestation written to {args.output}")
        print(json.dumps(manifest, sort_keys=True))
    return 0


def assurance_issue_scheduled_main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(description="Issue the last complete scheduled attestation.")
    parser.add_argument("--ledger", required=True)
    parser.add_argument("--sth", required=True)
    parser.add_argument("--cadence", required=True, choices=("hourly", "daily"))
    parser.add_argument("--now")
    parser.add_argument("--deployment-id-source", required=True)
    parser.add_argument("--deployment-salt", required=True)
    parser.add_argument("--approvals")
    parser.add_argument("--policy-bundle-hash")
    parser.add_argument(
        "--policy-signature-status",
        default="unavailable",
        choices=("valid", "invalid", "unavailable", "degraded"),
    )
    parser.add_argument("--policy-last-change")
    parser.add_argument("--last-anchor")
    parser.add_argument(
        "--retention-preset",
        default="unavailable",
        choices=(
            "unavailable",
            "eu_ai_act_minimum",
            "minimal",
            "standard",
            "extended",
            "legal_hold",
        ),
    )
    parser.add_argument("--signing-degraded", action="store_true")
    parser.add_argument("--anchoring-degraded", action="store_true")
    parser.add_argument("--fail-open-condition-observed", action="store_true")
    parser.add_argument("--output", required=True)
    _add_signing_args(parser)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    if not _cli_signing_config_requested(args):
        print(
            "velvet assurance issue-scheduled requires explicit signing configuration",
            file=sys.stderr,
        )
        return 2
    try:
        signer = _resolve_cli_signer(args)
        sth = _read_json_object(args.sth)
        period = scheduled_attestation_period(cadence=args.cadence, now=args.now)
        attestation = issue_scheduled_control_state_attestation(
            cadence=args.cadence,
            now=args.now,
            records=load_ledger_records(args.ledger),
            sth=sth,
            deployment_id_source=args.deployment_id_source,
            deployment_salt=args.deployment_salt,
            signer=signer,
            signing_key_id=signer_default_key_id(signer),
            approvals_path=args.approvals,
            policy_bundle_hash=args.policy_bundle_hash,
            policy_bundle_signature_status=args.policy_signature_status,
            policy_last_change_timestamp=args.policy_last_change,
            last_successful_anchor_timestamp=args.last_anchor,
            retention_preset=args.retention_preset,
            signing_degraded=args.signing_degraded,
            anchoring_degraded=args.anchoring_degraded,
            fail_open_condition_observed=args.fail_open_condition_observed,
        )
        manifest = append_attestation_jsonl_idempotent(attestation, args.output)
    except (AssuranceAttestationError, OSError, ValueError) as error:
        print(f"velvet assurance issue-scheduled failed: {error}", file=sys.stderr)
        return 1
    payload = {
        "attestation": attestation,
        "export": manifest,
        "period": {
            "cadence": period.cadence,
            "start": period.period_start.isoformat(timespec="microseconds").replace("+00:00", "Z"),
            "end": period.period_end.isoformat(timespec="microseconds").replace("+00:00", "Z"),
        },
    }
    if args.json:
        print(json.dumps(payload, sort_keys=True))
    else:
        print(f"Scheduled control-state attestation {manifest['status']} at {args.output}")
        print(json.dumps(payload, sort_keys=True))
    return 0


def claims_pack_main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(description="Build an incident-scoped claims pack.")
    parser.add_argument("--incident-window", nargs=2, metavar=("START", "END"), required=True)
    parser.add_argument("--ledger", required=True)
    parser.add_argument("--sth", required=True)
    parser.add_argument("--approvals")
    parser.add_argument("--latest-sth")
    parser.add_argument("--assurance-attestations")
    parser.add_argument("--consistency-proofs")
    parser.add_argument("--anchor-sths")
    parser.add_argument("--thread")
    parser.add_argument("--public-key")
    parser.add_argument("--public-key-file")
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--system-name", required=True)
    parser.add_argument("--intended-purpose", required=True)
    parser.add_argument("--deployer-legal-entity", required=True)
    parser.add_argument("--eu-exposure", required=True, choices=("true", "false"))
    parser.add_argument("--deployment-id-source", required=True)
    parser.add_argument("--deployment-salt", required=True)
    parser.add_argument("--policy-bundle-hash")
    parser.add_argument(
        "--policy-signature-status",
        default="unavailable",
        choices=("valid", "invalid", "unavailable", "degraded"),
    )
    parser.add_argument("--policy-last-change")
    parser.add_argument("--last-anchor")
    parser.add_argument(
        "--retention-preset",
        default="unavailable",
        choices=(
            "unavailable",
            "eu_ai_act_minimum",
            "minimal",
            "standard",
            "extended",
            "legal_hold",
        ),
    )
    parser.add_argument("--signing-degraded", action="store_true")
    parser.add_argument("--anchoring-degraded", action="store_true")
    parser.add_argument("--fail-open-condition-observed", action="store_true")
    _add_signing_args(parser)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    public_key = args.public_key
    if public_key is None and args.public_key_file:
        public_key = Path(args.public_key_file).read_text(encoding="utf-8")
    if public_key is None:
        print("velvet claims-pack requires --public-key or --public-key-file", file=sys.stderr)
        return 2
    if not _cli_signing_config_requested(args):
        print("velvet claims-pack requires explicit signing configuration", file=sys.stderr)
        return 2

    start, end = args.incident_window
    output_dir = Path(args.output_dir)
    try:
        signer = _resolve_cli_signer(args)
        payload = write_claims_pack(
            incident_window_start=start,
            incident_window_end=end,
            ledger_path=args.ledger,
            sth_path=args.sth,
            public_key=public_key,
            output_dir=output_dir,
            system_name=args.system_name,
            intended_purpose=args.intended_purpose,
            deployer_legal_entity=args.deployer_legal_entity,
            eu_exposure=args.eu_exposure == "true",
            deployment_id_source=args.deployment_id_source,
            deployment_salt=args.deployment_salt,
            signer=signer,
            approvals_path=args.approvals,
            latest_sth_path=args.latest_sth,
            assurance_attestations_path=args.assurance_attestations,
            consistency_proofs_path=args.consistency_proofs,
            anchor_sths_path=args.anchor_sths,
            thread_path=args.thread,
            policy_bundle_hash=args.policy_bundle_hash,
            policy_bundle_signature_status=args.policy_signature_status,
            policy_last_change_timestamp=args.policy_last_change,
            last_successful_anchor_timestamp=args.last_anchor,
            retention_preset=args.retention_preset,
            signing_degraded=args.signing_degraded,
            anchoring_degraded=args.anchoring_degraded,
            fail_open_condition_observed=args.fail_open_condition_observed,
        )
    except (AssuranceAttestationError, AttestationPackError, OSError, ValueError) as error:
        print(f"velvet claims-pack failed: {error}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(payload, sort_keys=True))
    else:
        print(f"Claims pack written to {output_dir}")
        print(json.dumps(payload, sort_keys=True))
    return 0


def underwriter_bundle_main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Build an underwriter review bundle from verified live-demo outputs."
    )
    parser.add_argument("--incident-dir")
    parser.add_argument("--commercial-docs-dir")
    parser.add_argument("--output-dir")
    parser.add_argument("--zip-path")
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    try:
        payload = write_underwriter_review_bundle(
            incident_dir=args.incident_dir,
            commercial_docs_dir=args.commercial_docs_dir,
            output_dir=args.output_dir,
            zip_path=args.zip_path,
            force=args.force,
        )
    except (UnderwriterBundleError, OSError, ValueError) as error:
        print(f"velvet underwriter-bundle failed: {error}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(payload, sort_keys=True))
    else:
        zip_export = cast(Mapping[str, Any], payload["zip_export"])
        print(f"Underwriter review bundle written to {payload['output']['directory']}")
        print(f"Zip export: {zip_export['path']}")
    return 0


def signing_main(argv: Sequence[str]) -> int:
    if argv and argv[0] == "generate-keypair":
        return signing_generate_keypair_main(argv[1:])
    if argv and argv[0] == "public-key":
        return signing_public_key_main(argv[1:])
    if argv and argv[0] == "sign":
        return signing_sign_main(argv[1:])
    if argv and argv[0] == "verify":
        return signing_verify_main(argv[1:])
    print("Usage: velvet signing generate-keypair|public-key|sign|verify", file=sys.stderr)
    return 2


def signing_generate_keypair_main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(description="Generate an Ed25519 signing keypair.")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    payload = generate_ed25519_keypair()
    if args.json:
        print(json.dumps(payload, sort_keys=True))
    else:
        print(payload["private_key_pem"], end="")
        print(payload["public_key_pem"], end="")
        print(f"public_key_base64={payload['public_key_base64']}")
    return 0


def signing_public_key_main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(description="Export public verification material.")
    _add_signing_args(parser)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    signer = _resolve_cli_signer(args)
    key_id = signer_default_key_id(signer)
    material = signer.public_verification_material(key_id) or {}
    if not material:
        if args.json:
            print(
                json.dumps(
                    {
                        "status": "unsupported",
                        "provider_name": signer.provider_name,
                        "message": "Provider does not expose public verification material.",
                    },
                    sort_keys=True,
                )
            )
        else:
            print(
                f"{signer.provider_name} does not expose public verification material.",
                file=sys.stderr,
            )
        return 1
    if args.json:
        print(json.dumps(material, sort_keys=True))
    else:
        public_key_pem = material.get("public_key_pem")
        if isinstance(public_key_pem, str):
            print(public_key_pem, end="")
        if "public_key_base64" in material:
            print(f"public_key_base64={material.get('public_key_base64')}")
        if "public_key_der_base64" in material:
            print(f"public_key_der_base64={material.get('public_key_der_base64')}")
    _emit_ephemeral_public_key_notice(signer)
    return 0


def signing_sign_main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(description="Sign a Velvet proof payload hash.")
    _add_signing_args(parser)
    parser.add_argument("--payload-hash", required=True)
    parser.add_argument("--purpose", required=True)
    parser.add_argument("--tenant-id", default=DEFAULT_TENANT_ID)
    parser.add_argument("--key-id")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    signer = _resolve_cli_signer(args)
    key_id = args.key_id or signer_default_key_id(signer)
    signature = sign_payload_hash(
        args.payload_hash,
        purpose=args.purpose,
        tenant_id=args.tenant_id,
        key_id=key_id,
        signer=signer,
    )
    if args.json:
        print(json.dumps(signature, sort_keys=True))
    else:
        print(signature["signature"])
    _emit_ephemeral_public_key_notice(signer)
    return 0


def signing_verify_main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(description="Verify a Velvet SignatureBlock.")
    _add_signing_args(parser)
    parser.add_argument("--payload-hash", required=True)
    parser.add_argument("--signature-file", required=True)
    parser.add_argument("--purpose", required=True)
    parser.add_argument("--tenant-id")
    parser.add_argument("--key-id")
    parser.add_argument("--public-key")
    parser.add_argument("--public-key-file")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    signature_record = _read_signature_record(args.signature_file)
    public_key = args.public_key
    if public_key is None and args.public_key_file:
        public_key = Path(args.public_key_file).read_text(encoding="utf-8")
    signer = _resolve_cli_verifier(args, signature_record)
    ok = verify_signature_record(
        signature_record,
        args.payload_hash,
        purpose=args.purpose,
        tenant_id=args.tenant_id,
        key_id=args.key_id,
        signer=signer,
        public_key=public_key,
    )
    payload = {
        "status": "pass" if ok else "fail",
        "provider_name": signature_record.get("provider_name"),
        "algorithm": signature_record.get("algorithm"),
        "key_id": signature_record.get("key_id"),
        "purpose": args.purpose,
        "payload_hash": args.payload_hash,
    }
    if args.json:
        print(json.dumps(payload, sort_keys=True))
    else:
        print(f"{payload['status']}: {payload['provider_name']} {payload['key_id']}")
    return 0 if ok else 1


def verify_warrant_main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Verify a Velvet warrant or ledger record with public key material."
    )
    parser.add_argument("--file", required=True)
    parser.add_argument("--public-key")
    parser.add_argument("--public-key-file")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    public_key: str | None = args.public_key
    if public_key is None and args.public_key_file:
        public_key = Path(args.public_key_file).read_text(encoding="utf-8")
    artifact = _read_verification_artifact(args.file)
    report = _verify_warrant_or_ledger_record(artifact, public_key=public_key)
    if args.json:
        print(json.dumps(report, sort_keys=True))
    else:
        print(
            f"{report['status']}: {report['artifact_type']} with {len(report['checks'])} check(s)"
        )
    return 1 if report["status"] == "fail" else 0


def verify_permit_main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Verify a Velvet Execution Permit against explicit trusted key material."
    )
    parser.add_argument("--file", required=True)
    parser.add_argument("--trusted-public-key")
    parser.add_argument("--trusted-public-key-file")
    parser.add_argument("--actual-request-file")
    parser.add_argument("--evidence-pack")
    parser.add_argument("--receipt-file")
    parser.add_argument("--verification-time")
    parser.add_argument("--logical-step", type=int)
    parser.add_argument("--tenant")
    parser.add_argument("--environment")
    parser.add_argument("--audience")
    parser.add_argument("--policy-hash")
    parser.add_argument("--policy-version")
    parser.add_argument("--tool-schema-hash")
    parser.add_argument("--trusted-key-id")
    parser.add_argument("--subject-id-hash")
    parser.add_argument("--agent-id-hash")
    parser.add_argument("--client-id-hash")
    parser.add_argument("--session-id-hash")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    permit_payload = _read_verification_artifact(args.file)
    public_key: str | None = args.trusted_public_key
    if public_key is None and args.trusted_public_key_file:
        public_key = Path(args.trusted_public_key_file).read_text(encoding="utf-8")
    if public_key is None:
        failure_report: JsonObject = {
            "artifact_type": "execution_permit",
            "status": "fail",
            "checks": [
                {
                    "name": "trusted_signature",
                    "status": "fail",
                    "code": "trusted_public_key_required",
                }
            ],
        }
        if args.json:
            print(json.dumps(failure_report, sort_keys=True))
        else:
            print("fail: trusted public key is required", file=sys.stderr)
        return 1

    try:
        permit = ExecutionPermit.from_dict(permit_payload)
        context = _permit_cli_validation_context(
            permit,
            trusted_public_key=public_key,
            args=args,
        )
        checks = verify_execution_permit(permit, context)
    except (KeyError, TypeError, ValueError) as error:
        checks = [{"name": "schema", "status": "fail", "code": f"malformed_permit:{error}"}]
        permit = None

    if permit is not None:
        if args.evidence_pack:
            checks.append(_verify_permit_lineage_pack(permit, args.evidence_pack))
        if args.receipt_file:
            receipt_payload = _read_verification_artifact(args.receipt_file)
            receipt = ExecutionReceipt.from_dict(receipt_payload)
            for check in verify_execution_receipt(
                receipt,
                trusted_public_key=public_key,
                tenant_id=permit.tenant_id,
                permit=permit,
            ):
                prefixed = dict(check)
                prefixed["name"] = f"receipt_{prefixed['name']}"
                checks.append(prefixed)

    report: JsonObject = {
        "artifact_type": "execution_permit",
        "status": verification_status(checks),
        "permit_id": permit.permit_id if permit is not None else permit_payload.get("permit_id"),
        "permit_hash": (
            permit.permit_hash if permit is not None else permit_payload.get("permit_hash")
        ),
        "checks": checks,
    }
    if args.json:
        print(json.dumps(report, sort_keys=True))
    else:
        print(f"{report['status']}: execution permit with {len(checks)} check(s)")
    return 1 if report["status"] == "fail" else 0


def seal_main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(description="Replay one stored routing decision.")
    parser.add_argument("--thread", required=True)
    parser.add_argument("--seal-id", required=True)
    parser.add_argument("--policies-dir")
    parser.add_argument("--chain")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    report = seal_thread_decision(
        args.thread,
        args.seal_id,
        policy_dir=args.policies_dir,
        chain=args.chain,
    )
    if args.json:
        print(json.dumps(report, sort_keys=True))
    else:
        print(
            f"{report['status']}: {report['seal_id']} "
            f"{report['expected_selected_action']} -> {report['sealed_selected_action']}"
        )
    return 0 if report["status"] == "pass" else 1


def validate_thread_main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(description="Validate schema 9.0 thread records.")
    parser.add_argument("--thread", required=True)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    report = validate_thread_file(args.thread)
    if args.json:
        print(json.dumps(report, sort_keys=True))
    else:
        print(f"{report['status']}: {report['records']} thread records checked")
    return 0 if report["status"] == "pass" else 1


def proof_main(argv: Sequence[str]) -> int:
    if argv and argv[0] == "hash":
        return proof_hash_main(argv[1:])
    print("Usage: velvet proof hash --file artifact.json --type TYPE [--json]", file=sys.stderr)
    return 2


def proof_hash_main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(description="Hash a Velvet proof artifact.")
    parser.add_argument("--file", required=True)
    parser.add_argument(
        "--type",
        required=True,
        choices=[
            "warrant",
            "ledger",
            "policy",
            "tool_schema",
            "approval",
            "evidence_manifest",
            "admission_evidence",
            "execution_permit",
            "execution_receipt",
        ],
    )
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    try:
        value = load_canonical_json_v1(Path(args.file).read_bytes())
        if not isinstance(value, dict):
            raise CanonicalizationError("proof artifact root must be a JSON object")
        digest = proof_artifact_hash(args.type, value)
    except (OSError, CanonicalizationError) as error:
        print(f"canonicalization error: {error}", file=sys.stderr)
        return 2

    if args.json:
        print(
            json.dumps(
                {
                    "type": args.type,
                    "canonicalization": VELVET_CANONICAL_JSON_V1,
                    "hash_algorithm": "sha256",
                    "hash": digest,
                },
                sort_keys=True,
            )
        )
    else:
        print(digest)
    return 0


def policy_bundle_main(argv: Sequence[str]) -> int:
    if argv and argv[0] == "sign":
        return policy_bundle_sign_main(argv[1:])
    if argv and argv[0] == "verify":
        return policy_bundle_verify_main(argv[1:])
    print("Usage: velvet policy-bundle sign|verify [options]", file=sys.stderr)
    return 2


def policy_main(argv: Sequence[str]) -> int:
    if argv and argv[0] == "compile":
        return policy_compile_main(argv[1:])
    if argv and argv[0] == "verify-compile":
        return policy_verify_compile_main(argv[1:])
    print(
        "Usage: velvet policy compile <policy.md> --out bundle/ [options] | "
        "velvet policy verify-compile <bundle_dir>",
        file=sys.stderr,
    )
    return 2


def policy_compile_main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Compile a Markdown policy document into a signed Velvet policy bundle."
    )
    parser.add_argument("policy")
    parser.add_argument("--out", required=True)
    parser.add_argument(
        "--model",
        default=DEFAULT_POLICY_COMPILE_MODEL_SPEC,
        help=(
            "offline-heuristic, anthropic:<id>, or openai:<id>@<base_url>. "
            f"The offline model id is {DEFAULT_POLICY_COMPILE_MODEL_ID}."
        ),
    )
    parser.add_argument("--chain", default=DEFAULT_POLICY_COMPILE_CHAIN)
    parser.add_argument("--runtime-llm-atoms", action="store_true")
    parser.add_argument("--tenant-id", default="local")
    parser.add_argument(
        "--environment",
        default="local",
        choices=["local", "saas", "vpc", "on_prem"],
    )
    parser.add_argument(
        "--signing-key",
        default="velvet-local-deterministic-demo-key",
        help=(
            "HMAC key for the local compiled-policy bundle and for provenance only "
            "when --insecure-hmac is set."
        ),
    )
    parser.add_argument(
        "--insecure-hmac",
        action="store_true",
        help="Use the legacy local HMAC provenance signature instead of Ed25519.",
    )
    _add_signing_args(parser, default_profile="demo")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    try:
        signer = None if args.insecure_hmac else _resolve_cli_signer(args)
        result = compile_policy_document(
            args.policy,
            output_dir=args.out,
            model_id=args.model,
            chain=args.chain,
            runtime_llm_atoms=args.runtime_llm_atoms,
            signing_key=args.signing_key,
            signer=signer,
            insecure_hmac_provenance=args.insecure_hmac,
            tenant_id=args.tenant_id,
            environment=args.environment,
        )
    except PolicyCompileError as error:
        print(f"policy compile error: {error}", file=sys.stderr)
        return 2

    payload = result.to_dict()
    if args.json:
        print(json.dumps(payload, sort_keys=True))
    else:
        print(render_policy_compile_markdown(result.manifest))
    if signer is not None:
        _emit_ephemeral_public_key_notice(signer)
    return 0


def policy_verify_compile_main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(description="Verify policy compile provenance.")
    parser.add_argument("bundle_dir")
    parser.add_argument("--public-key")
    parser.add_argument("--public-key-file")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    public_key = args.public_key
    if public_key is None and args.public_key_file:
        public_key = Path(args.public_key_file).read_text(encoding="utf-8")
    provenance_path = Path(args.bundle_dir) / "compile_provenance.json"
    report = verify_policy_compile_provenance(provenance_path, public_key=public_key)
    if args.json:
        print(json.dumps(report, sort_keys=True))
    else:
        status = "verified" if report["verified"] else "failed"
        print(f"policy compile provenance {status}: {provenance_path}")
    return 0 if report["verified"] else 1


def policy_bundle_sign_main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(description="Create a signed Velvet policy bundle.")
    parser.add_argument("--policies-dir", required=True)
    parser.add_argument("--chain", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--tenant-id", default="local")
    parser.add_argument(
        "--environment",
        default="local",
        choices=["local", "saas", "vpc", "on_prem"],
    )
    parser.add_argument("--policy-version")
    parser.add_argument("--expires-at")
    parser.add_argument("--signing-key", required=True)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    try:
        output = write_signed_policy_bundle(
            args.output,
            policy_dir=args.policies_dir,
            chain=args.chain,
            signing_key=args.signing_key,
            tenant_id=args.tenant_id,
            environment=args.environment,
            policy_version=args.policy_version,
            expires_at=args.expires_at,
        )
        bundle = load_policy_bundle(output, signing_key=args.signing_key)
    except PolicyBundleError as error:
        print(f"policy bundle error: {error}", file=sys.stderr)
        return 2

    payload = {"policy_bundle_path": str(output), "policy_bundle": bundle.summary}
    if args.json:
        print(json.dumps(payload, sort_keys=True))
    else:
        print(f"Signed policy bundle {output}: {bundle.policy_hash}")
    return 0


def policy_bundle_verify_main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(description="Verify a signed Velvet policy bundle.")
    parser.add_argument("--bundle", required=True)
    parser.add_argument("--signing-key", required=True)
    parser.add_argument("--allow-expired", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    try:
        bundle = load_policy_bundle(
            args.bundle,
            signing_key=args.signing_key,
            allow_expired=bool(args.allow_expired),
        )
        payload = {"status": "pass", "policy_bundle": bundle.summary}
    except PolicyBundleError as error:
        payload = {"status": "fail", "reason": str(error), "error_status": error.status}
        if args.json:
            print(json.dumps(payload, sort_keys=True))
        else:
            print(f"fail: {error}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(payload, sort_keys=True))
    else:
        print(f"pass: {bundle.bundle_id} {bundle.policy_hash}")
    return 0


def registry_main(argv: Sequence[str]) -> int:
    if argv and argv[0] == "diff":
        return registry_diff_main(argv[1:])
    if argv and argv[0] == "approve-schema":
        return registry_approve_schema_main(argv[1:])
    if argv and argv[0] == "report":
        return registry_report_main(argv[1:])

    parser = argparse.ArgumentParser(description="Build or inspect the Velvet agent registry.")
    parser.add_argument("--mcp-list", action="append", default=[])
    parser.add_argument("--registry")
    parser.add_argument("--output")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    if args.registry:
        registry = AgentRegistry.load(args.registry)
    elif args.mcp_list:
        registry = registry_from_mcp_lists(args.mcp_list)
    else:
        parser.error("provide --registry or at least one --mcp-list")

    if args.output:
        registry.save(args.output)
    payload = registry.to_dict()
    if args.json:
        print(json.dumps(payload, sort_keys=True))
    else:
        summary = payload["summary"]
        print(
            f"Registry: {summary['agents']} agent(s), {summary['tools']} tool(s), "
            f"{summary['findings']} finding(s)"
        )
    return 0


def registry_diff_main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(description="Diff two Velvet tool inventories.")
    parser.add_argument("--old", required=True)
    parser.add_argument("--new", required=True)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    old_registry = AgentRegistry.load(args.old)
    new_registry = AgentRegistry.load(args.new)
    payload = old_registry.diff_tool_inventory(new_registry)
    if args.json:
        print(json.dumps(payload, sort_keys=True))
    else:
        summary = payload["summary"]
        print(
            f"Registry diff: {summary['new_tools']} new, "
            f"{summary['removed_tools']} removed, "
            f"{summary['schema_drift']} drifted schema(s)"
        )
    return 0


def registry_approve_schema_main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(description="Approve a tool's current schema hash.")
    parser.add_argument("--tool", required=True)
    parser.add_argument("--schema-hash", required=True)
    parser.add_argument("--registry", default="registry.json")
    parser.add_argument("--output")
    parser.add_argument("--approver", default="velvet-operator")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    registry = AgentRegistry.load(args.registry).approve_schema_hash(
        args.tool,
        args.schema_hash,
        approved_by=args.approver,
    )
    output = args.output or args.registry
    registry.save(output)
    payload = registry.to_dict()
    if args.json:
        print(json.dumps(payload, sort_keys=True))
    else:
        print(f"Approved schema for {args.tool} in {output}")
    return 0


def registry_report_main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(description="Write Velvet tool registry reports.")
    parser.add_argument("--registry", required=True)
    parser.add_argument("--output-dir", default="reports/registry")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    registry = AgentRegistry.load(args.registry)
    json_path, markdown_path, policy_path, report = write_registry_report(
        registry,
        args.output_dir,
    )
    payload = {
        "registry_report": report,
        "artifacts": {
            "json_path": str(json_path),
            "markdown_path": str(markdown_path),
            "policy_bundle_path": str(policy_path),
        },
    }
    if args.json:
        print(json.dumps(payload, sort_keys=True))
    else:
        print(f"Wrote registry report: {json_path}, {markdown_path}, {policy_path}")
    return 0


def gateway_main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Authorize a canonical action through Inline Gateway."
    )
    parser.add_argument("--request", required=True)
    parser.add_argument("--registry")
    parser.add_argument("--thread")
    parser.add_argument("--ledger")
    parser.add_argument("--approvals")
    parser.add_argument("--policies-dir", default="policies")
    parser.add_argument("--chain", default="default")
    parser.add_argument("--policy-bundle")
    parser.add_argument("--policy-signing-key")
    parser.add_argument("--require-policy-bundle", action="store_true")
    parser.add_argument("--allow-expired-policy-degraded", action="store_true")
    parser.add_argument("--allow-unlisted-mcp", action="store_true")
    _add_signing_args(parser)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    gateway = InlineGateway(
        ledger_path=args.ledger,
        approval_store=ApprovalStore(args.approvals) if args.approvals else None,
    )
    outputs = [
        gateway.authorize(request).to_dict() for request in _load_gateway_requests(args.request)
    ]
    payload: object = outputs[0] if len(outputs) == 1 else {"decisions": outputs}
    if args.json:
        print(json.dumps(payload, sort_keys=True))
    else:
        for output in outputs:
            print(
                f"{output['decision']}: {output['canonical_action']['surface']} - "
                f"{output['canonical_action_hash']}"
            )
    return 0


def approvals_main(argv: Sequence[str]) -> int:
    if argv and argv[0] == "serve":
        parser = argparse.ArgumentParser(description="Serve the local Velvet approval workbench.")
        parser.add_argument("--approvals", required=True)
        parser.add_argument("--host", default="127.0.0.1")
        parser.add_argument("--port", type=int, default=8765)
        parser.add_argument("--auth-token-env")
        parser.add_argument("--csrf-secret-env")
        parser.add_argument("--local-dev-no-auth", action="store_true")
        args = parser.parse_args(argv[1:])
        from velvet.approval_workbench import create_approval_app

        try:
            import uvicorn
        except ImportError as error:
            raise RuntimeError("uvicorn is required to serve the approval workbench") from error
        if args.local_dev_no_auth:
            if args.host not in {"127.0.0.1", "localhost", "::1"}:
                raise RuntimeError("--local-dev-no-auth may only be used on a loopback host")
            app = create_approval_app(args.approvals, allow_unauthenticated_local=True)
        else:
            if not args.auth_token_env or not args.csrf_secret_env:
                raise RuntimeError(
                    "approval workbench requires --auth-token-env and --csrf-secret-env "
                    "unless --local-dev-no-auth is used on loopback"
                )
            auth_token = os.environ.get(args.auth_token_env)
            csrf_secret = os.environ.get(args.csrf_secret_env)
            if not auth_token or not csrf_secret:
                raise RuntimeError("approval workbench auth and CSRF env vars must be non-empty")
            app = create_approval_app(
                args.approvals,
                auth_token=auth_token,
                csrf_secret=csrf_secret,
            )
        uvicorn.run(app, host=args.host, port=args.port)
        return 0

    parser = argparse.ArgumentParser(description="Inspect or decide Velvet approval requests.")
    parser.add_argument("--approvals", required=True)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--list", action="store_true")
    action.add_argument("--approve")
    action.add_argument("--deny")
    parser.add_argument("--approver", default="velvet-operator")
    parser.add_argument("--reason", default="Reviewed in Velvet approval workbench.")
    parser.add_argument("--condition", action="append", default=[])
    _add_signing_args(parser)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    signer = _resolve_cli_signer(args) if _cli_signing_config_requested(args) else None
    store = (
        ApprovalStore(
            args.approvals,
            signer=signer,
            signing_key_id=signer_default_key_id(signer),
        )
        if signer is not None
        else ApprovalStore(args.approvals)
    )
    if args.approve:
        payload: object = store.decide(
            args.approve,
            status=ApprovalStatus.APPROVED,
            approver=args.approver,
            reason=args.reason,
            conditions=tuple(args.condition),
        ).to_dict()
    elif args.deny:
        payload = store.decide(
            args.deny,
            status=ApprovalStatus.DENIED,
            approver=args.approver,
            reason=args.reason,
            conditions=tuple(args.condition),
        ).to_dict()
    else:
        payload = store.load().to_dict()
    if args.json:
        print(json.dumps(payload, sort_keys=True))
    else:
        if isinstance(payload, dict) and "summary" in payload:
            summary = payload["summary"]
            print(f"Approvals: {summary['pending']} pending, {summary['receipts']} receipt(s)")
        else:
            receipt_payload = cast(Mapping[str, Any], payload)
            status = "approved" if receipt_payload.get("approved") else "denied"
            print(f"Approval receipt: {receipt_payload['approval_receipt_id']} {status}")
    return 0


def evidence_main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(description="Build an agent operations evidence pack.")
    parser.add_argument("--ledger", required=True)
    parser.add_argument("--thread")
    parser.add_argument("--registry")
    parser.add_argument("--approvals")
    parser.add_argument("--output-dir")
    _add_signing_args(parser)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    signer = _resolve_cli_signer(args) if _cli_signing_config_requested(args) else None
    signing_key_id = signer_default_key_id(signer) if signer is not None else None

    if args.output_dir:
        _, _, pack = write_evidence_pack(
            args.ledger,
            thread_path=args.thread,
            registry_path=args.registry,
            approvals_path=args.approvals,
            output_dir=args.output_dir,
            signer=signer,
            signing_key_id=signing_key_id,
        )
    else:
        pack = build_evidence_pack(
            args.ledger,
            thread_path=args.thread,
            registry_path=args.registry,
            approvals_path=args.approvals,
            signer=signer,
            signing_key_id=signing_key_id,
        )
    if args.json:
        print(json.dumps(pack, sort_keys=True))
    else:
        print(render_evidence_pack_markdown(pack))
    return 0


def policy_simulate_main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(description="Replay threads against a policy bundle.")
    parser.add_argument("--thread", required=True)
    parser.add_argument("--policies-dir", default="policies")
    parser.add_argument("--chain", default="default")
    parser.add_argument("--policy-bundle")
    parser.add_argument("--policy-signing-key")
    parser.add_argument("--ledger")
    parser.add_argument("--output-dir")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    if args.output_dir:
        _, _, report = write_policy_simulation_report(
            args.thread,
            policy_dir=args.policies_dir,
            chain=args.chain,
            policy_bundle=args.policy_bundle,
            policy_bundle_signing_key=args.policy_signing_key,
            ledger_path=args.ledger,
            output_dir=args.output_dir,
        )
    else:
        report = simulate_policy(
            args.thread,
            policy_dir=args.policies_dir,
            chain=args.chain,
            policy_bundle=args.policy_bundle,
            policy_bundle_signing_key=args.policy_signing_key,
            ledger_path=args.ledger,
        )
    payload = report.to_dict()
    if args.json:
        print(json.dumps(payload, sort_keys=True))
    else:
        print(render_policy_simulation_markdown(payload))
    return 0


def ops_main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(description="Build a Velvet control-plane snapshot.")
    parser.add_argument("--thread")
    parser.add_argument("--ledger")
    parser.add_argument("--registry")
    parser.add_argument("--approvals")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    payload = build_control_plane_snapshot(
        thread_path=args.thread,
        ledger_path=args.ledger,
        registry_path=args.registry,
        approvals_path=args.approvals,
    )
    if args.json:
        print(json.dumps(payload, sort_keys=True))
    else:
        summary = payload["summary"]
        print(
            f"Agent ops: {summary['registry_agents']} agent(s), "
            f"{summary['registry_tools']} tool(s), "
            f"{summary['approval_pending']} pending approval(s)"
        )
    return 0


def launch_demo_main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(description="Run the launch Velvet MCP + Velvet Ledger demo.")
    parser.add_argument("--output-dir", default="reports/launch")
    parser.add_argument("--list", default="examples/mcp/list.json")
    parser.add_argument("--policy-bundle")
    parser.add_argument("--policy-signing-key")
    parser.add_argument("--allow-expired-policy-degraded", action="store_true")
    _add_signing_args(parser, default_profile="demo")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    signer = _resolve_cli_signer(args)

    launch_kwargs: dict[str, Any] = {}
    if args.policy_signing_key:
        launch_kwargs["policy_bundle_signing_key"] = args.policy_signing_key
    payload = run_launch_demo(
        args.output_dir,
        list_path=args.list,
        policy_bundle=args.policy_bundle,
        allow_expired_policy_degraded=bool(args.allow_expired_policy_degraded),
        signer=signer,
        signing_key_id=signer_default_key_id(signer),
        signing_profile=args.signing_profile,
        dev_ephemeral_key=bool(args.dev_ephemeral_key),
        **launch_kwargs,
    )
    _emit_ephemeral_public_key_notice(signer)
    if args.json:
        print(json.dumps(payload, sort_keys=True))
    else:
        print(
            f"Wrote launch demo artifacts under {args.output_dir}: "
            f"{payload['thread_path']} and {payload['ledger_path']}"
        )
    return 0


def shell_code_demo_main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Run the canonical inline gateway shell/code approval demo."
    )
    parser.add_argument("--output-dir", default="reports/launch/shell-code-inline-gateway")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    payload = run_shell_code_inline_gateway_demo(args.output_dir)
    if args.json:
        print(json.dumps(payload, sort_keys=True))
    else:
        summary = payload["summary"]
        exact = summary["exact_approved_dispatch"]
        drift = summary["drift_after_approval"]
        print(
            f"Shell/code inline gateway demo written to {args.output_dir}: "
            f"exact={exact['status']} drift={drift['status']}"
        )
    return 0


def openai_bypass_demo_main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Serve the GPT-5.5 Velvet control-plane sandbox demo."
    )
    parser.add_argument("--output-dir", default="reports/openai_bypass_demo")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument("--model", default="gpt-5.5")
    parser.add_argument("--offline-fixture", action="store_true")
    parser.add_argument("--claim-packet", action="store_true")
    parser.add_argument("--runs", type=int, default=2)
    parser.add_argument("--live", action="store_true")
    parser.add_argument("--topology-evidence")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    if args.claim_packet:
        payload = run_openai_bypass_claim_packet(
            args.output_dir,
            model=args.model,
            runs=args.runs,
            live=bool(args.live),
            topology_evidence_path=args.topology_evidence,
        )
        if args.json:
            print(json.dumps(payload, sort_keys=True))
        else:
            print(
                "OpenAI bypass claim packet written to "
                f"{args.output_dir}: {payload['claim_status']}"
            )
        return 0

    try:
        import uvicorn
    except ImportError as error:
        raise RuntimeError("uvicorn is required to serve the OpenAI bypass demo") from error
    uvicorn.run(
        create_openai_bypass_demo_app(
            args.output_dir,
            model=args.model,
            offline_fixture=bool(args.offline_fixture),
        ),
        host=args.host,
        port=args.port,
    )
    return 0


def mcp_firewall_main(argv: Sequence[str]) -> int:
    args_list = list(argv)
    if not args_list or args_list[0].startswith("-"):
        args_list = ["pilot", *args_list]
    command = args_list[0]
    if command == "pilot":
        parser = argparse.ArgumentParser(description="Run the Velvet MCP Firewall pilot.")
        parser.add_argument("--output-dir", default="reports/mcp_firewall")
        parser.add_argument("--list", default="examples/mcp/list.json")
        parser.add_argument("--request")
        parser.add_argument("--policies-dir", default="examples/mcp/policies")
        parser.add_argument("--chain", default="mcp_demo")
        _add_signing_args(parser, default_profile="demo")
        parser.add_argument("--json", action="store_true")
        parser.add_argument("--verify-after-run", action="store_true")
        args = parser.parse_args(args_list[1:])
        signer = _resolve_cli_signer(args)
        from velvet.mcp_firewall import load_mcp_firewall_requests

        requests = load_mcp_firewall_requests(args.request) if args.request is not None else None
        payload = run_mcp_firewall_pilot(
            args.output_dir,
            list_path=args.list,
            requests=requests,
            policy_dir=args.policies_dir,
            chain=args.chain,
            signer=signer,
            signing_key_id=signer_default_key_id(signer),
        )
        verification: JsonObject | None = None
        exit_code = 0
        if args.verify_after_run:
            verification = verify_mcp_firewall_pilot(args.output_dir, signer=signer)
            payload["verification"] = verification
            exit_code = 0 if verification["status"] == "pass" else 1
        _emit_ephemeral_public_key_notice(signer)
        if args.json:
            print(json.dumps(payload, sort_keys=True))
        else:
            _print_mcp_firewall_pilot_summary(payload, verification=verification)
        return exit_code
    if command == "verify":
        parser = argparse.ArgumentParser(description="Verify a Velvet MCP Firewall pilot.")
        parser.add_argument("--output-dir", default="reports/mcp_firewall")
        _add_signing_args(parser)
        parser.add_argument("--json", action="store_true")
        args = parser.parse_args(args_list[1:])
        verifier = _resolve_cli_signer(args) if _cli_signing_config_requested(args) else None
        payload = verify_mcp_firewall_pilot(args.output_dir, signer=verifier)
        if args.json:
            print(json.dumps(payload, sort_keys=True))
        else:
            print(
                f"MCP Firewall verification: {payload['status']} "
                f"({payload['summary']['passed']}/{payload['summary']['checks']} checks passed)"
            )
            for check in cast(Sequence[Mapping[str, Any]], payload["checks"]):
                if check["status"] == "fail":
                    print(f"- {check['name']}: {check['message']}")
        return 0 if payload["status"] == "pass" else 1
    if command == "report":
        parser = argparse.ArgumentParser(description="Render a Velvet MCP Firewall report.")
        parser.add_argument("--output-dir", default="reports/mcp_firewall")
        parser.add_argument("--json", action="store_true")
        args = parser.parse_args(args_list[1:])
        try:
            payload = write_mcp_firewall_report(args.output_dir)
        except (OSError, json.JSONDecodeError, ValueError) as error:
            if args.json:
                print(
                    json.dumps(
                        {
                            "schema_version": "velvet.mcp_firewall.report.v1",
                            "status": "fail",
                            "error": str(error),
                        },
                        sort_keys=True,
                    )
                )
            else:
                print(str(error), file=sys.stderr)
            return 1
        if args.json:
            print(json.dumps(payload, sort_keys=True))
        else:
            print(f"Wrote MCP Firewall report: {payload['pilot_markdown_path']}")
        return 0
    if command == "tamper-demo":
        parser = argparse.ArgumentParser(
            description="Run the Velvet MCP Firewall ledger tamper demo."
        )
        parser.add_argument("--output-dir", default="reports/mcp_firewall/tamper")
        parser.add_argument("--json", action="store_true")
        args = parser.parse_args(args_list[1:])
        payload = write_ledger_tamper_demo(args.output_dir)
        if args.json:
            print(json.dumps(payload, sort_keys=True))
        else:
            print(f"Wrote MCP Firewall tamper demo: {payload['markdown_path']}")
        return 0
    print(
        "Usage: velvet mcp-firewall [pilot|verify|report|tamper-demo] "
        "[--output-dir reports/mcp_firewall] [--json]",
        file=sys.stderr,
    )
    return 2


def _print_mcp_firewall_pilot_summary(
    payload: Mapping[str, Any],
    *,
    verification: Mapping[str, Any] | None,
) -> None:
    summary = cast(Mapping[str, Any], payload["summary"])
    artifacts = cast(Mapping[str, Any], payload["artifacts"])
    print(f"Product: {payload['product']}")
    print(f"Boundary: {payload['boundary']}")
    print(f"Total requests: {summary.get('total_requests', summary.get('requests'))}")
    print(f"Decisions: {json.dumps(summary['decision_counts'], sort_keys=True)}")
    print(f"Pending approvals: {summary.get('pending_approvals', summary.get('approval_pending'))}")
    print(f"Ledger verification: {summary['ledger_verification_status']}")
    print(f"Evidence controls passing: {summary['evidence_controls_passing']}")
    if verification is not None:
        print(f"Pilot verification: {verification['status']}")
    print(f"Pilot JSON: {artifacts['pilot_json_path']}")
    print(f"Pilot Markdown: {artifacts['pilot_markdown_path']}")
    print(f"Ledger: {artifacts['ledger_path']}")
    print(f"Evidence pack: {artifacts['evidence_pack_markdown_path']}")


def _run_velvet_rope_proxy(args: Sequence[str]) -> subprocess.CompletedProcess[str]:
    repo_root = Path(__file__).resolve().parents[2]
    binary = shutil.which("velvet-rope-proxy")
    command = (
        [binary, *args]
        if binary is not None
        else [
            "cargo",
            "run",
            "-q",
            "-p",
            "velvet-rope-proxy",
            "--",
            *args,
        ]
    )
    return subprocess.run(  # noqa: S603  # nosec B603
        command,
        cwd=repo_root,
        capture_output=True,
        check=False,
        text=True,
    )


def mcp_proxy_demo_main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Run the Rust Velvet Rope MCP proxy demo.",
    )
    parser.add_argument("--output-dir", default="reports/mcp_proxy")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    completed = _run_velvet_rope_proxy(["demo", "--output-dir", args.output_dir])
    if completed.returncode != 0:
        print(completed.stderr.strip() or completed.stdout.strip(), file=sys.stderr)
        return completed.returncode
    if args.json:
        print(completed.stdout.strip())
        return 0
    payload = json.loads(completed.stdout)
    print(
        f"Wrote MCP proxy demo artifacts under {args.output_dir}: "
        f"{payload['inventory_path']} and {payload['ledger_path']}"
    )
    return 0


def demo_main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Run a zero-Docker Velvet demo and verify its ledger.",
    )
    parser.add_argument("--output-dir", default="reports/demo")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    completed = _run_velvet_rope_proxy(["demo", "--output-dir", args.output_dir])
    if completed.returncode != 0:
        print(completed.stderr.strip() or completed.stdout.strip(), file=sys.stderr)
        return completed.returncode
    demo_payload = json.loads(completed.stdout)
    ledger_path = str(cast(Mapping[str, Any], demo_payload)["ledger_path"])
    verification = verify_velvet_ledger(ledger_path)
    payload = {
        "demo": demo_payload,
        "ledger_verification": verification,
        "status": "pass" if verification.get("status") == "pass" else "fail",
    }
    if args.json:
        print(json.dumps(payload, sort_keys=True))
    else:
        print(f"Demo artifacts: {demo_payload['inventory_path']}")
        print(f"Ledger: {ledger_path}")
        print(f"Ledger verification: {verification['status']}")
    return 0 if payload["status"] == "pass" else 1


def liability_benchmark_main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(description="Run Velvet liability benchmarks.")
    parser.add_argument(
        "--output-dir",
        "--report-dir",
        dest="output_dir",
        default="reports/liability",
    )
    parser.add_argument(
        "--suite",
        choices=["liability", "velvet_rope_liability"],
        default="liability",
    )
    parser.add_argument("--cloud", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    output_dir = args.output_dir
    if args.suite == "velvet_rope_liability" and output_dir == "reports/liability":
        output_dir = "reports/liability/velvet_rope"
    payload = run_liability_benchmark(
        output_dir,
        include_cloud=bool(args.cloud),
        suite=args.suite,
    )
    if args.json:
        print(json.dumps(payload, sort_keys=True))
    else:
        print(
            f"Wrote {args.suite} artifacts under {output_dir}: "
            f"{payload.get('thread_path', payload.get('summary_path'))}"
        )
    return 0


def agent_authorization_benchmark_main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(description="Run the Agent Authorization Benchmark.")
    parser.add_argument(
        "--output-dir",
        "--report-dir",
        dest="output_dir",
        default="reports/agent_auth",
    )
    parser.add_argument(
        "--comparison",
        action="store_true",
        help=(
            "Run the fixture-backed Velvet/OAP/Pipelock/Attested/Cerbos/gateway "
            "comparison harness."
        ),
    )
    parser.add_argument(
        "--shadowpath-only",
        action="store_true",
        help="Run only the ShadowPath effect-level authorization suite.",
    )
    parser.add_argument(
        "--fixture-dir",
        help="Fixture directory for --comparison runs.",
    )
    parser.add_argument(
        "--allow-dirty",
        action="store_true",
        help="Allow dev artifact generation from a dirty worktree and mark output dirty.",
    )
    parser.add_argument(
        "--inventory",
        help="ShadowPath effect inventory JSON (defaults to the committed v0.4 fixture).",
    )
    parser.add_argument(
        "--agent-command",
        help="Interactive JSONL command for the optional ShadowPath live-agent track.",
    )
    parser.add_argument(
        "--agent-trials",
        type=int,
        default=20,
        help="Live-agent trials; publishable rows require at least 20.",
    )
    parser.add_argument(
        "--expect-breach",
        action="store_true",
        help=(
            "Acknowledge the fixture's expected effect breach for process exit only; "
            "the recorded verdict remains CONTROL_FALSE_SUCCESS."
        ),
    )
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    if args.comparison and args.shadowpath_only:
        parser.error("--comparison and --shadowpath-only are mutually exclusive")
    if args.comparison and (args.agent_command or args.inventory):
        parser.error("ShadowPath agent/inventory options cannot be used with --comparison")

    if args.comparison:
        payload = run_agent_authorization_comparison(
            args.output_dir,
            fixture_dir=args.fixture_dir,
            allow_dirty=bool(args.allow_dirty),
        )
    elif args.shadowpath_only:
        from velvet.agent_authorization_benchmark import (
            current_git_commit,
            current_git_worktree_dirty,
        )
        from velvet.shadowpath import run_shadowpath_benchmark

        dirty = current_git_worktree_dirty()
        if dirty and not args.allow_dirty:
            parser.error(
                "refusing benchmark artifact generation from a dirty worktree; "
                "pass --allow-dirty for development output"
            )
        payload = run_shadowpath_benchmark(
            args.output_dir,
            inventory_path=args.inventory,
            agent_command=args.agent_command,
            agent_trials=args.agent_trials,
            source_commit_hash=current_git_commit(),
            source_worktree_dirty=dirty,
        )
    else:
        payload = run_agent_authorization_benchmark(
            args.output_dir,
            allow_dirty=bool(args.allow_dirty),
            shadowpath_agent_command=args.agent_command,
            shadowpath_agent_trials=args.agent_trials,
        )
    if args.json:
        print(json.dumps(payload, sort_keys=True))
    else:
        print(
            "Wrote Agent Authorization Benchmark artifacts under "
            f"{args.output_dir}: {payload['markdown_path']}"
        )
    if "exit_code" in payload:
        exit_code = int(payload["exit_code"])
        if args.expect_breach and exit_code == 3:
            return 0
        return exit_code
    shadowpath = payload.get("shadowpath")
    if isinstance(shadowpath, Mapping):
        exit_code = int(shadowpath.get("exit_code", 0))
        if args.expect_breach and exit_code == 3:
            return 0
        return exit_code
    return 0


def shadowpath_main(argv: Sequence[str]) -> int:
    """Run the effect-level benchmark through a memorable launch command."""

    if not argv or argv[0] in {"-h", "--help"}:
        print("Usage: velvet shadowpath demo [--output-dir DIR] [--json] [--execute]")
        print("       velvet shadowpath init [DIRECTORY] [--force]")
        print("       velvet shadowpath run --project shadowpath.json [--output-dir DIR]")
        print("       velvet shadowpath run [agent-auth-benchmark options]")
        print("       velvet shadowpath render RESULT.json [--output-dir DIR]")
        print()
        print("demo instantly replays the committed hermetic result and creates a share pack.")
        print("demo --execute runs the Playwright-backed fixture from scratch.")
        print("init and run --project test one effect in your own local system.")
        print("portfolio rolls many user-owned effect projects into one assurance summary.")
        print("run without --project keeps strict benchmark exit codes for measurement and CI.")
        return 0

    from velvet.shadowpath_product import shadowpath_product_main

    product_result = shadowpath_product_main(argv)
    if product_result is not None:
        return product_result

    mode = argv[0]
    forwarded = list(argv[1:])
    if mode == "demo":
        forwarded = [item for item in forwarded if item != "--execute"]
        if "--output-dir" not in forwarded and "--report-dir" not in forwarded:
            forwarded = ["--output-dir", "reports/shadowpath", *forwarded]
        return agent_authorization_benchmark_main(
            ["--shadowpath-only", "--allow-dirty", "--expect-breach", *forwarded]
        )
    if mode == "run":
        return agent_authorization_benchmark_main(["--shadowpath-only", *forwarded])

    print(f"Unknown shadowpath command: {mode}", file=sys.stderr)
    return 2


def liability_live_main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Run live competitor liability receipts against sandbox tools.",
    )
    parser.add_argument("--competitor", default="all")
    parser.add_argument("--tier", choices=["sdk", "hosted", "both"], default="both")
    parser.add_argument("--runs", type=int, default=2)
    parser.add_argument("--output-dir", default="reports/liability/live")
    parser.add_argument("--enable-side-effects", default="sandbox")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    try:
        payload = run_live_competitor_liability(
            args.output_dir,
            competitor=args.competitor,
            tier=args.tier,
            runs=args.runs,
            enable_side_effects=args.enable_side_effects,
            require_opt_in=True,
        )
    except (RuntimeError, ValueError) as error:
        print(str(error), file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(payload, sort_keys=True))
    else:
        print(
            f"Wrote live liability receipts under {args.output_dir}: "
            f"{payload['public_claim_packet_path']}"
        )
    return 0


def run_main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(description="Route and execute one scenario.")
    parser.add_argument("--scenario", required=True)
    parser.add_argument("--thread")
    parser.add_argument("--workspace", default=".")
    parser.add_argument("--policies-dir", default="policies")
    parser.add_argument("--chain", default="default")
    parser.add_argument("--interactive", action="store_true")
    parser.add_argument(
        "--sandbox-mode",
        choices=[item.value for item in RuntimeMode],
        default=RuntimeMode.DEVELOPMENT.value,
    )
    parser.add_argument("--sandbox-backend", choices=[item.value for item in SandboxBackendKind])
    parser.add_argument("--container-runtime", choices=[item.value for item in ContainerRuntime])
    parser.add_argument("--container-image")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    with Path(args.scenario).open("r", encoding="utf-8") as file:
        scenario = json.load(file)
    result = Router(policy_dir=args.policies_dir, chain=args.chain).run(
        state=scenario["state"],
        candidates=scenario["candidates"],
        executor=IntegrationExecutor(
            workspace=args.workspace,
            interactive=bool(args.interactive),
            sandbox_config=SandboxConfig(
                mode=RuntimeMode(args.sandbox_mode),
                backend=SandboxBackendKind(args.sandbox_backend) if args.sandbox_backend else None,
                allow_unsafe_exec=os.environ.get("VELVET_ALLOW_UNSAFE_EXEC") == "1",
                container_runtime=ContainerRuntime(args.container_runtime)
                if args.container_runtime
                else None,
                container_image=args.container_image,
            ),
        ),
        thread_logger=ThreadLogger(args.thread) if args.thread else None,
    )
    payload = {
        "decision": result.decision.to_dict(),
        "execution_result": result.execution_result.to_dict(),
        "thread": result.thread.to_dict(),
    }
    if args.json:
        print(json.dumps(payload, sort_keys=True))
    else:
        print(
            f"{payload['decision']['decision']}: {payload['decision']['action_type']} - "
            f"{payload['execution_result']['status']}"
        )
    return 0


def dashboard_main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(description="Serve the local Velvet thread dashboard.")
    parser.add_argument("--thread", default="threads/demo.jsonl")
    parser.add_argument("--ledger")
    parser.add_argument("--registry")
    parser.add_argument("--approvals")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default=8000, type=int)
    args = parser.parse_args(argv)

    import uvicorn

    from velvet.dashboard import create_app

    uvicorn.run(
        create_app(
            args.thread,
            ledger_path=args.ledger,
            registry_path=args.registry,
            approvals_path=args.approvals,
        ),
        host=args.host,
        port=args.port,
        reload=False,
    )
    return 0


def vc_demo_main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(description="Build the VC fundraise demo payload.")
    parser.add_argument("--output-dir", default="reports/vc_demo")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    if args.json:
        print(json.dumps(build_vc_demo_payload(), sort_keys=True))
        return 0

    json_path, markdown_path = write_vc_demo_artifacts(args.output_dir)
    print(f"Wrote VC demo artifacts: {json_path} and {markdown_path}")
    return 0


def investor_demo_main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(description="Run deterministic investor-demo reproductions.")
    selector = parser.add_mutually_exclusive_group(required=True)
    selector.add_argument("--all", action="store_true")
    selector.add_argument("--scenario", choices=INVESTOR_DEMO_IDS)
    parser.add_argument("--output-dir", default="reports/investor_demos")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    payload = (
        run_all_investor_demos(args.output_dir)
        if args.all
        else run_investor_demo(str(args.scenario), args.output_dir)
    )
    if args.json:
        print(json.dumps(payload, sort_keys=True))
    else:
        artifacts = cast(Mapping[str, Any], payload["artifacts"])
        if args.all:
            print(f"Wrote investor demos: {artifacts['html_path']}")
        else:
            print(f"Wrote investor demo {payload['scenario_id']}: {artifacts['html_path']}")
    return 0




def outreach_proof_main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Build a public-key-verifiable Velvet warrant proof pack."
    )
    parser.add_argument("--output-dir", default="reports/outreach_warrant_proof")
    _add_signing_args(parser, default_profile="demo")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    signer = _resolve_cli_signer(args)

    payload = write_outreach_warrant_proof(
        args.output_dir,
        signer=signer,
        signing_profile=args.signing_profile,
        dev_ephemeral_key=bool(args.dev_ephemeral_key),
    )
    _emit_ephemeral_public_key_notice(signer)
    if args.json:
        print(json.dumps(payload, sort_keys=True))
    else:
        print(f"Wrote outreach warrant proof pack: {payload['artifacts']['proof_json']}")
    return 0


def _read_json_object(path: str | Path) -> JsonObject:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"expected JSON object at {path}")
    return cast(JsonObject, payload)


def _add_signing_args(
    parser: argparse.ArgumentParser,
    *,
    default_profile: str | None = None,
) -> None:
    parser.add_argument(
        "--signing-provider",
        "--provider",
        choices=("ed25519", "aws-kms", "vault"),
        help="Signing provider. Enterprise providers require explicit provider config.",
    )
    parser.add_argument(
        "--signing-profile",
        choices=("production", "demo"),
        default=default_profile,
        help="Ed25519 signing profile. Production loads env/file keys; demo uses fixture keys.",
    )
    parser.add_argument(
        "--dev-ephemeral-key",
        action="store_true",
        help="Generate a non-durable per-run Ed25519 key and print public material.",
    )
    parser.add_argument("--kms-key-id", help="AWS KMS key id or alias for enterprise signing.")
    parser.add_argument(
        "--kms-signing-algorithm",
        help="AWS KMS SigningAlgorithm. Defaults to RSASSA_PSS_SHA_256.",
    )
    parser.add_argument("--vault-transit-key", help="Vault Transit key name.")
    parser.add_argument(
        "--vault-mount",
        help="Vault Transit mount point. Defaults to transit.",
    )


def _resolve_cli_signer(args: argparse.Namespace) -> SigningProvider:
    provider = cast(str | None, getattr(args, "signing_provider", None))
    if provider is None and getattr(args, "kms_key_id", None):
        provider = "aws-kms"
    if provider is None and getattr(args, "vault_transit_key", None):
        provider = "vault"
    effective_provider = provider or os.environ.get("VELVET_SIGNING_PROVIDER")
    normalized_provider = (
        effective_provider.strip().lower().replace("_", "-") if effective_provider else None
    )
    profile = cast(str | None, getattr(args, "signing_profile", None))
    if provider is None and profile == "demo" and effective_provider is None:
        return load_demo_ed25519_signer()
    return resolve_signing_provider(
        signing_provider=provider,
        signing_profile=profile,
        dev_ephemeral_key=bool(getattr(args, "dev_ephemeral_key", False)),
        kms_key_id=cast(str | None, getattr(args, "kms_key_id", None)),
        kms_signing_algorithm=cast(str | None, getattr(args, "kms_signing_algorithm", None)),
        vault_transit_key=cast(str | None, getattr(args, "vault_transit_key", None)),
        vault_mount=cast(str | None, getattr(args, "vault_mount", None)),
        create_clients=normalized_provider in {"aws-kms", "kms", "vault", "vault-transit"},
    )


def _resolve_cli_verifier(
    args: argparse.Namespace,
    signature_record: Mapping[str, Any],
) -> SigningProvider | None:
    provider = cast(str | None, getattr(args, "signing_provider", None))
    if provider in {"aws-kms", "vault"}:
        return _resolve_cli_signer(args)
    if bool(getattr(args, "dev_ephemeral_key", False)):
        return _resolve_cli_signer(args)
    if cast(str | None, getattr(args, "signing_profile", None)) is not None:
        return _resolve_cli_signer(args)
    del signature_record
    return None


def _cli_signing_config_requested(args: argparse.Namespace) -> bool:
    return any(
        (
            getattr(args, "signing_provider", None),
            getattr(args, "signing_profile", None),
            bool(getattr(args, "dev_ephemeral_key", False)),
            getattr(args, "kms_key_id", None),
            getattr(args, "kms_signing_algorithm", None),
            getattr(args, "vault_transit_key", None),
            getattr(args, "vault_mount", None),
            os.environ.get("VELVET_SIGNING_PROVIDER"),
        )
    )


def _read_signature_record(path: str | Path) -> JsonObject:
    payload = cast(JsonObject, json.loads(Path(path).read_text(encoding="utf-8")))
    signature = payload.get("signature")
    if isinstance(signature, Mapping) and "provider_name" in signature:
        return dict(cast(Mapping[str, Any], signature))
    if "provider_name" in payload:
        return payload
    raise ValueError("signature file must contain a SignatureBlock or a signature field")


def _emit_ephemeral_public_key_notice(signer: SigningProvider) -> None:
    key_id = signer_default_key_id(signer)
    if key_id != EPHEMERAL_ED25519_KEY_ID:
        return
    material = signer.public_verification_material(key_id) or {}
    print(
        json.dumps(
            {
                "warning": "ephemeral signing key is non-durable; capture this public key",
                "public_key": material,
            },
            sort_keys=True,
        ),
        file=sys.stderr,
    )


def _read_verification_artifact(path: str | Path) -> JsonObject:
    text = Path(path).read_text(encoding="utf-8")
    stripped = text.strip()
    if not stripped:
        raise ValueError("verification file is empty")
    try:
        payload = json.loads(stripped)
    except json.JSONDecodeError:
        first_line = next(line for line in stripped.splitlines() if line.strip())
        payload = json.loads(first_line)
    if not isinstance(payload, dict):
        raise ValueError("verification artifact must be a JSON object")
    return cast(JsonObject, payload)


def _verify_warrant_or_ledger_record(
    artifact: Mapping[str, Any],
    *,
    public_key: str | None,
) -> JsonObject:
    if artifact.get("schema_version") == "velvet.admission_evidence.v1":
        return _verify_admission_evidence_artifact(artifact, public_key=public_key)
    if artifact.get("contract") == "velvet.ledger" or "record_hash" in artifact:
        return _verify_ledger_record_artifact(artifact, public_key=public_key)
    return _verify_warrant_artifact(artifact, public_key=public_key)


def _verify_ledger_record_artifact(
    record: Mapping[str, Any],
    *,
    public_key: str | None,
) -> JsonObject:
    expected_hash = ledger_record_hash(record)
    hash_ok = record.get("record_hash") == expected_hash
    signature = record.get("signature")
    signature_ok = isinstance(signature, Mapping) and verify_signature_record(
        signature,
        expected_hash,
        purpose=PURPOSE_LEDGER_RECORD,
        tenant_id=_mapping_string(record, "tenant_id"),
        key_id=_mapping_string(cast(Mapping[str, Any], signature), "key_id")
        if isinstance(signature, Mapping)
        else None,
        public_key=public_key,
    )
    checks = [
        {"name": "record_hash", "status": "pass" if hash_ok else "fail"},
        {"name": "signature", "status": "pass" if signature_ok else "fail"},
    ]
    evidence = record.get("admission_evidence")
    if isinstance(evidence, Mapping):
        evidence_ok = verify_admission_evidence(evidence, public_key=public_key)
        binding_ok = record.get("admission_evidence_hash") == evidence.get(
            "admission_evidence_hash"
        )
        checks.append(
            {
                "name": "admission_evidence",
                "status": "pass" if evidence_ok and binding_ok else "fail",
            }
        )
    return {
        "artifact_type": "ledger_record",
        "status": _status_from_checks(checks),
        "record_hash": record.get("record_hash"),
        "expected_record_hash": expected_hash,
        "checks": checks,
    }


def _verify_admission_evidence_artifact(
    evidence: Mapping[str, Any],
    *,
    public_key: str | None,
) -> JsonObject:
    expected_hash = admission_evidence_hash(evidence)
    hash_ok = evidence.get("admission_evidence_hash") == expected_hash
    signature_and_raw_ok = verify_admission_evidence(evidence, public_key=public_key)
    checks = [
        {"name": "admission_evidence_hash", "status": "pass" if hash_ok else "fail"},
        {
            "name": "signature_and_raw_ref",
            "status": "pass" if signature_and_raw_ok else "fail",
        },
    ]
    return {
        "artifact_type": "admission_evidence",
        "status": _status_from_checks(checks),
        "admission_evidence_hash": evidence.get("admission_evidence_hash"),
        "expected_admission_evidence_hash": expected_hash,
        "checks": checks,
    }


def _verify_warrant_artifact(
    warrant: Mapping[str, Any],
    *,
    public_key: str | None,
) -> JsonObject:
    expected_hash = VelvetWarrant.compute_hash_for_payload(warrant)
    hash_ok = warrant.get("warrant_hash") == expected_hash
    signature = warrant.get("signature")
    signature_ok = isinstance(signature, Mapping) and verify_signature_record(
        signature,
        expected_hash,
        purpose=PURPOSE_WARRANT,
        tenant_id=_mapping_string(warrant, "tenant_id"),
        key_id=_mapping_string(warrant, "signing_key_id")
        or (
            _mapping_string(cast(Mapping[str, Any], signature), "key_id")
            if isinstance(signature, Mapping)
            else None
        ),
        public_key=public_key,
    )
    checks = [
        {"name": "warrant_hash", "status": "pass" if hash_ok else "fail"},
        {"name": "signature", "status": "pass" if signature_ok else "fail"},
    ]
    return {
        "artifact_type": "warrant",
        "status": _status_from_checks(checks),
        "warrant_hash": warrant.get("warrant_hash"),
        "expected_warrant_hash": expected_hash,
        "checks": checks,
    }


def _permit_cli_validation_context(
    permit: ExecutionPermit,
    *,
    trusted_public_key: str,
    args: argparse.Namespace,
) -> PermitValidationContext:
    scope = permit.scope
    if getattr(args, "actual_request_file", None):
        request_payload = strip_model_controlled_execution_metadata(
            _read_verification_artifact(args.actual_request_file)
        )
        scope = ExecutionPermitScope(
            surface=scope.surface,
            method=scope.method,
            tool_key=scope.tool_key,
            operation=scope.operation,
            request_hash=canonical_hash_sha256(request_payload),
            canonical_action_hash=scope.canonical_action_hash,
            arguments_hash=scope.arguments_hash,
            tool_schema_hash=getattr(args, "tool_schema_hash", None) or scope.tool_schema_hash,
            read_set_hash=scope.read_set_hash,
            resource=scope.resource,
        )
    subject = SubjectBinding(
        subject_id_hash=cast(str | None, getattr(args, "subject_id_hash", None)),
        agent_id_hash=cast(str | None, getattr(args, "agent_id_hash", None)),
        client_id_hash=cast(str | None, getattr(args, "client_id_hash", None)),
        session_id_hash=cast(str | None, getattr(args, "session_id_hash", None)),
    )
    signature = permit.signature if isinstance(permit.signature, Mapping) else {}
    return PermitValidationContext(
        tenant_id=getattr(args, "tenant", None) or permit.tenant_id,
        environment=getattr(args, "environment", None) or permit.environment,
        audience=getattr(args, "audience", None) or permit.audience,
        policy_hash=getattr(args, "policy_hash", None) or permit.policy.policy_hash,
        policy_version=getattr(args, "policy_version", None) or permit.policy.policy_version,
        tool_schema_hash=getattr(args, "tool_schema_hash", None) or permit.scope.tool_schema_hash,
        scope=scope,
        subject=subject,
        now=getattr(args, "verification_time", None),
        logical_step=cast(int | None, getattr(args, "logical_step", None)),
        trusted_public_key=trusted_public_key,
        trusted_key_id=getattr(args, "trusted_key_id", None)
        or _mapping_string(signature, "key_id"),
    )


def _verify_permit_lineage_pack(
    permit: ExecutionPermit,
    evidence_pack_path: str | Path,
) -> JsonObject:
    try:
        pack = _read_verification_artifact(evidence_pack_path)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        return {
            "name": "lineage",
            "status": "fail",
            "code": f"evidence_pack_unreadable:{error}",
        }
    references = {
        (
            permit.lineage.decision_artifact.artifact_type,
            permit.lineage.decision_artifact.artifact_id,
            permit.lineage.decision_artifact.artifact_hash,
        ),
        (
            permit.lineage.pre_execution_record.artifact_type,
            permit.lineage.pre_execution_record.artifact_id,
            permit.lineage.pre_execution_record.artifact_hash,
        ),
        *{
            (item.artifact_type, item.artifact_id, item.artifact_hash)
            for item in permit.lineage.supporting_artifacts
        },
    }
    found: set[tuple[str, str, str]] = set()
    for item in _iter_evidence_artifact_refs(pack):
        found.add(item)
    missing = sorted(references - found)
    return {
        "name": "lineage",
        "status": "pass" if not missing else "fail",
        "code": None if not missing else "lineage_artifact_missing",
        "missing": [
            {"artifact_type": kind, "artifact_id": artifact_id, "artifact_hash": artifact_hash}
            for kind, artifact_id, artifact_hash in missing
        ],
    }


def _iter_evidence_artifact_refs(pack: Mapping[str, Any]) -> set[tuple[str, str, str]]:
    artifacts = pack.get("artifacts")
    output: set[tuple[str, str, str]] = set()
    if isinstance(artifacts, list):
        for artifact in artifacts:
            if not isinstance(artifact, Mapping):
                continue
            artifact_type = _mapping_string(artifact, "artifact_type") or _mapping_string(
                artifact, "type"
            )
            artifact_id = _mapping_string(artifact, "artifact_id") or _mapping_string(
                artifact, "id"
            )
            artifact_hash = (
                _mapping_string(artifact, "artifact_hash")
                or _mapping_string(artifact, "sha256")
                or _mapping_string(artifact, "hash")
            )
            if artifact_type and artifact_id and artifact_hash:
                output.add((artifact_type, artifact_id, artifact_hash))
    return output


def _status_from_checks(checks: Sequence[Mapping[str, Any]]) -> str:
    return "pass" if all(check.get("status") == "pass" for check in checks) else "fail"


def _mapping_string(mapping: Mapping[str, Any], key: str) -> str | None:
    value = mapping.get(key)
    return value if isinstance(value, str) and value else None


def _load_gateway_requests(path: str | Path) -> tuple[InlineGatewayRequest, ...]:
    with Path(path).open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if isinstance(payload, Mapping) and isinstance(payload.get("requests"), list):
        return tuple(
            InlineGatewayRequest.from_dict(cast(Mapping[str, Any], item))
            for item in payload["requests"]
        )
    if isinstance(payload, Mapping):
        return (InlineGatewayRequest.from_dict(payload),)
    raise ValueError("inline gateway request file must contain an object or a requests array")


def verdict_main(argv: Sequence[str]) -> int:
    if argv and argv[0] == "issue":
        return verdict_issue_main(argv[1:])
    if argv and argv[0] == "issue-drift":
        return verdict_issue_drift_main(argv[1:])
    if argv and argv[0] == "verify":
        return verdict_verify_main(argv[1:])
    print(
        "Usage: velvet verdict issue|issue-drift|verify ... (see velvet --help)",
        file=sys.stderr,
    )
    return 2


def _verdict_service(args: argparse.Namespace) -> Any:
    from velvet.verdict.service import VerdictCertificateService

    signer = resolve_signing_provider(
        signing_profile=args.signing_profile,
        dev_ephemeral_key=False,
    )
    return VerdictCertificateService(
        args.store,
        issuer=args.issuer,
        tenant_id=args.tenant_id,
        environment=args.environment,
        signer=signer,
    )


def _verdict_common_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--decision-id", required=True)
    parser.add_argument(
        "--decision-class",
        required=True,
        choices=[
            "retire_tool_route",
            "retire_agent",
            "retire_variant",
            "retire_expert",
            "permanent_lockout",
        ],
    )
    parser.add_argument("--target-id-hash", required=True)
    parser.add_argument("--inputs-hash", required=True)
    parser.add_argument("--rounds-per-day", type=float, default=None)
    parser.add_argument("--ttl-seconds", type=float, default=None)
    parser.add_argument("--store", default="reports/verdicts/verdict_certificates.jsonl")
    parser.add_argument("--issuer", default="velvet")
    parser.add_argument("--tenant-id", default=DEFAULT_TENANT_ID)
    parser.add_argument("--environment", default="local")
    parser.add_argument("--signing-profile", default="demo")
    parser.add_argument("--json", action="store_true")


def _parse_arm_pairs(
    raw: str, *, integral: bool
) -> list[tuple[float, float]] | list[tuple[int, int]]:
    pairs: list[tuple[float, float]] = []
    for chunk in raw.split(";"):
        left, right = chunk.split(",")
        pairs.append((float(left), float(right)))
    if integral:
        return [(int(alpha), int(beta)) for alpha, beta in pairs]
    return pairs


def _emit_verdict_result(result: Any, as_json: bool) -> int:
    certificate = result.certificate
    if as_json:
        print(json.dumps(certificate, indent=2, sort_keys=True))
    else:
        print(
            f"verdict={certificate['verdict']} authorized={result.authorized} "
            f"certificate_hash={certificate['certificate_hash']} "
            f"expires_at={certificate['validity']['expires_at']}"
        )
    return 0 if result.authorized or certificate["verdict"] != "refusal" else 1


def verdict_issue_main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Run the Theorem V finite-horizon verdict and issue a signed "
            "verdict certificate."
        )
    )
    parser.add_argument("--arms", required=True, help="alpha,beta pairs: '2,1;5,45'")
    parser.add_argument("--candidate", type=int, required=True)
    parser.add_argument("--horizon", type=int, required=True)
    parser.add_argument("--gate", type=float, default=0.01)
    parser.add_argument("--delta", type=float, default=0.05)
    _verdict_common_arguments(parser)
    args = parser.parse_args(list(argv))
    service = _verdict_service(args)
    result = service.issue_finite_horizon(
        [(int(a), int(b)) for a, b in _parse_arm_pairs(args.arms, integral=True)],
        args.candidate,
        decision_id=args.decision_id,
        decision_class=args.decision_class,
        target_id_hash=args.target_id_hash,
        inputs_hash=args.inputs_hash,
        horizon_H=args.horizon,
        gate=args.gate,
        delta=args.delta,
        rounds_per_day=args.rounds_per_day,
        ttl_seconds=args.ttl_seconds,
    )
    return _emit_verdict_result(result, args.json)


def verdict_issue_drift_main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Issue a windowed drift-expiry verdict certificate with a "
            "computable expiry horizon."
        )
    )
    parser.add_argument(
        "--posteriors", required=True, help="alpha,beta pairs: '60,40;30,70'"
    )
    parser.add_argument("--candidate", type=int, required=True)
    parser.add_argument("--gate", type=float, required=True)
    parser.add_argument("--delta", type=float, required=True)
    parser.add_argument("--rho", type=float, required=True)
    parser.add_argument("--delta-tail", type=float, default=None)
    _verdict_common_arguments(parser)
    args = parser.parse_args(list(argv))
    service = _verdict_service(args)
    result = service.issue_drift(
        [(float(a), float(b)) for a, b in _parse_arm_pairs(args.posteriors, integral=False)],
        args.candidate,
        decision_id=args.decision_id,
        decision_class=args.decision_class,
        target_id_hash=args.target_id_hash,
        inputs_hash=args.inputs_hash,
        gate=args.gate,
        delta=args.delta,
        rho=args.rho,
        delta_tail=args.delta_tail,
        rounds_per_day=args.rounds_per_day,
        ttl_seconds=args.ttl_seconds,
    )
    return _emit_verdict_result(result, args.json)


def verdict_verify_main(argv: Sequence[str]) -> int:
    from velvet.verdict.certificate import verify_verdict_certificate

    parser = argparse.ArgumentParser(
        description="Verify a verdict certificate against a pinned public key."
    )
    parser.add_argument("--certificate", required=True)
    parser.add_argument("--public-key-file", required=True)
    parser.add_argument("--issuer", default=None)
    parser.add_argument("--tenant-id", default=None)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(list(argv))
    payload = json.loads(Path(args.certificate).read_text(encoding="utf-8"))
    verification = verify_verdict_certificate(
        payload,
        public_key=Path(args.public_key_file).read_text(encoding="utf-8"),
        expected_issuer=args.issuer,
        expected_tenant_id=args.tenant_id,
    )
    if args.json:
        print(
            json.dumps(
                {
                    "status": verification.status,
                    "verdict": verification.verdict,
                    "certificate_hash": verification.certificate_hash,
                    "reason": verification.reason,
                    "licenses_execution": verification.licenses_execution,
                },
                indent=2,
                sort_keys=True,
            )
        )
    else:
        print(
            f"{verification.status}: verdict={verification.verdict} "
            f"licenses_execution={verification.licenses_execution}"
            + (f" reason={verification.reason}" if verification.reason else "")
        )
    if verification.status == "accepted":
        return 0
    return 2 if verification.status == "expired" else 1

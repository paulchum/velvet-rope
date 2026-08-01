"""Signed policy bundles for local Velvet Rope policy distribution."""

from __future__ import annotations

import hashlib
import hmac
import json
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

from jsonschema import Draft202012Validator, FormatChecker

from velvet.serialization import canonical_dumps, canonical_hash, stable_json_object

JsonObject = dict[str, Any]

POLICY_BUNDLE_SCHEMA_VERSION = "velvet.policy_bundle.v1"
POLICY_BUNDLE_CANONICALIZATION = "velvet.policy_bundle.v1.canonical_json.sha256.hmac"
POLICY_BUNDLE_SIGNING_ALGORITHM = "HMAC-SHA256"
DEFAULT_POLICY_BUNDLE_SIGNING_KEY = "velvet-local-deterministic-demo-key"
DEFAULT_POLICY_BUNDLE_SIGNING_KEY_ID = "velvet-local-demo-policy-bundle-key"
DEMO_POLICY_BUNDLE_SIGNING_KEY = DEFAULT_POLICY_BUNDLE_SIGNING_KEY
DEMO_POLICY_BUNDLE_SIGNING_KEY_ID = DEFAULT_POLICY_BUNDLE_SIGNING_KEY_ID

_REPO_ROOT = Path(__file__).resolve().parents[2]
_SCHEMA_PATH = _REPO_ROOT / "schemas" / "velvet_rope" / "policy_bundle.v1.schema.json"
_LATEST_VALID_BUNDLES: dict[str, VerifiedPolicyBundle] = {}


class PolicyBundleError(ValueError):
    """Base class for policy bundle load and verification failures."""

    status: str = "invalid"


class PolicyBundleMissing(PolicyBundleError):
    status = "missing"


class PolicyBundleInvalid(PolicyBundleError):
    status = "invalid"


class PolicyBundleTampered(PolicyBundleError):
    status = "tampered"


class PolicyBundleExpired(PolicyBundleError):
    status = "expired"


class PolicyBundleSchemaDrift(PolicyBundleError):
    status = "schema_drift"


@dataclass
class VerifiedPolicyBundle:
    """A verified signed policy bundle plus a materialized policy directory."""

    payload: JsonObject
    source_path: str | None = None
    expired: bool = False
    _policy_dir: Path | None = field(default=None, init=False, repr=False)
    _temp_dir: tempfile.TemporaryDirectory[str] | None = field(
        default=None, init=False, repr=False
    )

    @property
    def bundle_id(self) -> str:
        return str(self.payload["bundle_id"])

    @property
    def policy_hash(self) -> str:
        return str(self.payload["policy_hash"])

    @property
    def policy_version(self) -> str:
        return str(self.payload["policy_version"])

    @property
    def policy_chain(self) -> str:
        return str(self.payload["policy_chain"])

    @property
    def tenant_id(self) -> str:
        return str(self.payload["tenant_id"])

    @property
    def environment(self) -> str:
        return str(self.payload["environment"])

    @property
    def expires_at(self) -> str:
        return str(self.payload["expires_at"])

    @property
    def signing(self) -> JsonObject:
        return dict(cast(Mapping[str, Any], self.payload["signing"]))

    @property
    def summary(self) -> JsonObject:
        return {
            "bundle_id": self.bundle_id,
            "policy_hash": self.policy_hash,
            "policy_version": self.policy_version,
            "policy_chain": self.policy_chain,
            "tenant_id": self.tenant_id,
            "environment": self.environment,
            "expires_at": self.expires_at,
            "expired": self.expired,
            "signing": self.signing,
            "source_path": self.source_path,
        }

    def materialize_policy_dir(self) -> Path:
        if self._policy_dir is not None:
            return self._policy_dir
        self._temp_dir = tempfile.TemporaryDirectory(prefix="velvet_policy_bundle_")
        root = Path(self._temp_dir.name)
        for policy_file in _policy_files(self.payload):
            relative = _safe_relative_policy_path(str(policy_file["path"]))
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(str(policy_file["content"]), encoding="utf-8")
        self._policy_dir = root
        return root


def create_policy_bundle_payload(
    *,
    policy_dir: str | Path,
    chain: str,
    tenant_id: str = "local",
    environment: str = "local",
    policy_version: str | None = None,
    bundle_id: str | None = None,
    created_at: str | None = None,
    expires_at: str | None = None,
    tool_schema_hashes: Mapping[str, str] | None = None,
    approval_rules: Mapping[str, Any] | None = None,
    data_class_rules: Mapping[str, Any] | None = None,
    default_unknown_tool_behavior: str = "block",
    default_schema_drift_behavior: str = "block",
    signing_key_id: str = DEFAULT_POLICY_BUNDLE_SIGNING_KEY_ID,
    signing_provider: str = "local_demo",
) -> JsonObject:
    now = _now_iso() if created_at is None else created_at
    expiry = expires_at or _isoformat_z(datetime.now(tz=UTC) + timedelta(days=7))
    files = _policy_files_from_dir(policy_dir)
    payload: JsonObject = {
        "bundle_schema_version": POLICY_BUNDLE_SCHEMA_VERSION,
        "bundle_id": bundle_id or _bundle_id(chain, tenant_id, environment, files),
        "policy_hash": "",
        "policy_version": policy_version or f"{chain}.bundle.v1",
        "tenant_id": tenant_id,
        "environment": environment,
        "created_at": now,
        "expires_at": expiry,
        "policy_chain": chain,
        "policy_files": files,
        "tool_schema_hashes": dict(sorted((tool_schema_hashes or {}).items())),
        "approval_rules": stable_json_object(approval_rules),
        "data_class_rules": stable_json_object(data_class_rules),
        "default_unknown_tool_behavior": default_unknown_tool_behavior,
        "default_schema_drift_behavior": default_schema_drift_behavior,
        "signing": {
            "algorithm": POLICY_BUNDLE_SIGNING_ALGORITHM,
            "key_id": signing_key_id,
            "provider": signing_provider,
            "signed_at": now,
            "canonicalization": POLICY_BUNDLE_CANONICALIZATION,
        },
        "signature": "",
    }
    payload["policy_hash"] = compute_policy_hash(payload)
    return payload


def sign_policy_bundle(
    payload: Mapping[str, Any],
    signing_key: str | None = None,
) -> JsonObject:
    signing_key = _require_signing_key(signing_key)
    signed = stable_json_object(payload)
    _validate_policy_file_hashes(signed)
    signed["policy_hash"] = compute_policy_hash(signed)
    _validate_bundle_schema(signed, allow_blank_signature=True)
    signed["signature"] = _sign_unsigned_bundle(signed, signing_key)
    _validate_bundle_schema(signed)
    return signed


def write_signed_policy_bundle(
    output_path: str | Path,
    *,
    policy_dir: str | Path,
    chain: str,
    signing_key: str | None = None,
    tenant_id: str = "local",
    environment: str = "local",
    policy_version: str | None = None,
    expires_at: str | None = None,
    tool_schema_hashes: Mapping[str, str] | None = None,
    approval_rules: Mapping[str, Any] | None = None,
    data_class_rules: Mapping[str, Any] | None = None,
) -> Path:
    payload = create_policy_bundle_payload(
        policy_dir=policy_dir,
        chain=chain,
        tenant_id=tenant_id,
        environment=environment,
        policy_version=policy_version,
        expires_at=expires_at,
        tool_schema_hashes=tool_schema_hashes,
        approval_rules=approval_rules,
        data_class_rules=data_class_rules,
    )
    signed = sign_policy_bundle(payload, signing_key=signing_key)
    target = Path(output_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(signed, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    cache_verified_bundle(VerifiedPolicyBundle(payload=signed, source_path=str(target)))
    return target


def load_policy_bundle(
    path: str | Path,
    *,
    signing_key: str | None = None,
    allow_expired: bool = False,
    now: datetime | None = None,
) -> VerifiedPolicyBundle:
    source = Path(path)
    if not source.exists():
        raise PolicyBundleMissing(f"policy bundle not found: {source}")
    try:
        payload = cast(JsonObject, json.loads(source.read_text(encoding="utf-8")))
    except json.JSONDecodeError as error:
        raise PolicyBundleInvalid(f"policy bundle is not valid JSON: {error.msg}") from error
    return verify_policy_bundle(
        payload,
        signing_key=signing_key,
        source_path=str(source),
        allow_expired=allow_expired,
        now=now,
    )


def verify_policy_bundle(
    payload: Mapping[str, Any],
    *,
    signing_key: str | None = None,
    source_path: str | None = None,
    allow_expired: bool = False,
    now: datetime | None = None,
) -> VerifiedPolicyBundle:
    signing_key = _require_signing_key(signing_key)
    bundle = stable_json_object(payload)
    _validate_bundle_schema(bundle)
    _validate_policy_file_hashes(bundle)
    expected_policy_hash = compute_policy_hash(bundle)
    if not hmac.compare_digest(str(bundle["policy_hash"]), expected_policy_hash):
        raise PolicyBundleTampered("policy_hash does not match embedded policy material")
    expected_signature = _sign_unsigned_bundle(bundle, signing_key)
    if not hmac.compare_digest(str(bundle["signature"]), expected_signature):
        raise PolicyBundleTampered("policy bundle signature verification failed")
    expired = _is_expired(str(bundle["expires_at"]), now=now)
    verified = VerifiedPolicyBundle(payload=bundle, source_path=source_path, expired=expired)
    if expired and not allow_expired:
        raise PolicyBundleExpired("policy bundle is expired")
    if not expired:
        cache_verified_bundle(verified)
    return verified


def cache_verified_bundle(bundle: VerifiedPolicyBundle, *, cache_key: str | None = None) -> None:
    key = cache_key or bundle.source_path or bundle.bundle_id
    _LATEST_VALID_BUNDLES[key] = bundle


def latest_valid_bundle(cache_key: str | None = None) -> VerifiedPolicyBundle | None:
    if cache_key is not None:
        return _LATEST_VALID_BUNDLES.get(cache_key)
    if not _LATEST_VALID_BUNDLES:
        return None
    return next(reversed(_LATEST_VALID_BUNDLES.values()))


def _require_signing_key(signing_key: str | None) -> str:
    if signing_key is None or signing_key == "":
        raise PolicyBundleInvalid(
            "policy bundle signing key is required; pass an explicit production key "
            "or DEMO_POLICY_BUNDLE_SIGNING_KEY for local demos"
        )
    return signing_key


def compute_policy_hash(payload: Mapping[str, Any]) -> str:
    material = {
        "policy_chain": str(payload["policy_chain"]),
        "policy_files": sorted(
            (
                {
                    "path": str(item["path"]),
                    "sha256": str(item["sha256"]),
                    "content": str(item["content"]),
                }
                for item in _policy_files(payload)
            ),
            key=lambda item: item["path"],
        ),
        "tool_schema_hashes": dict(
            sorted(cast(Mapping[str, str], payload.get("tool_schema_hashes", {})).items())
        ),
        "approval_rules": stable_json_object(
            cast(Mapping[str, Any] | None, payload.get("approval_rules"))
        ),
        "data_class_rules": stable_json_object(
            cast(Mapping[str, Any] | None, payload.get("data_class_rules"))
        ),
        "default_unknown_tool_behavior": str(payload["default_unknown_tool_behavior"]),
        "default_schema_drift_behavior": str(payload["default_schema_drift_behavior"]),
    }
    return canonical_hash(material)


def unsigned_bundle_payload(payload: Mapping[str, Any]) -> JsonObject:
    return {str(key): value for key, value in payload.items() if key != "signature"}


def policy_bundle_status_for_error(error: PolicyBundleError | None) -> str:
    return "valid" if error is None else error.status


def _policy_files_from_dir(policy_dir: str | Path) -> list[JsonObject]:
    root = Path(policy_dir)
    if not root.exists():
        raise PolicyBundleMissing(f"policy directory not found: {root}")
    files: list[JsonObject] = []
    for path in sorted(
        item
        for item in root.rglob("*")
        if item.is_file() and item.suffix.lower() in {".yaml", ".yml"}
    ):
        content = path.read_text(encoding="utf-8")
        relative = path.relative_to(root).as_posix()
        files.append(
            {
                "path": relative,
                "sha256": _sha256_text(content),
                "content": content,
            }
        )
    if not files:
        raise PolicyBundleInvalid(f"policy directory has no YAML policy files: {root}")
    return files


def _policy_files(payload: Mapping[str, Any]) -> tuple[Mapping[str, Any], ...]:
    files = payload.get("policy_files")
    if not isinstance(files, list):
        raise PolicyBundleInvalid("policy_files must be an array")
    return tuple(cast(Mapping[str, Any], item) for item in files)


def _safe_relative_policy_path(value: str) -> Path:
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        raise PolicyBundleInvalid(f"unsafe policy file path in bundle: {value}")
    if path.suffix.lower() not in {".yaml", ".yml"}:
        raise PolicyBundleInvalid(f"policy file path must be YAML: {value}")
    return path


def _validate_policy_file_hashes(payload: Mapping[str, Any]) -> None:
    paths: set[str] = set()
    for item in _policy_files(payload):
        path = str(item.get("path", ""))
        _safe_relative_policy_path(path)
        if path in paths:
            raise PolicyBundleInvalid(f"duplicate policy file path: {path}")
        paths.add(path)
        content = str(item.get("content", ""))
        expected = _sha256_text(content)
        actual = str(item.get("sha256", ""))
        if not hmac.compare_digest(actual, expected):
            raise PolicyBundleTampered(f"policy file hash mismatch: {path}")


def _validate_bundle_schema(
    payload: Mapping[str, Any],
    *,
    allow_blank_signature: bool = False,
) -> None:
    schema = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
    validation_payload = dict(payload)
    if allow_blank_signature and validation_payload.get("signature") == "":
        validation_payload["signature"] = "0" * 64
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = sorted(validator.iter_errors(validation_payload), key=lambda error: error.path)
    if errors:
        first = errors[0]
        path = ".".join(str(item) for item in first.path) or "$"
        message = f"policy bundle schema violation at {path}: {first.message}"
        if "tool_schema_hashes" in path:
            raise PolicyBundleSchemaDrift(message)
        raise PolicyBundleInvalid(message)


def _sign_unsigned_bundle(payload: Mapping[str, Any], signing_key: str) -> str:
    return hmac.new(
        signing_key.encode("utf-8"),
        canonical_dumps(unsigned_bundle_payload(payload)).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _is_expired(expires_at: str, *, now: datetime | None = None) -> bool:
    return _parse_timestamp(expires_at) <= (now or datetime.now(tz=UTC))


def _parse_timestamp(value: str) -> datetime:
    normalized = value.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _now_iso() -> str:
    return _isoformat_z(datetime.now(tz=UTC))


def _isoformat_z(value: datetime) -> str:
    return value.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _bundle_id(
    chain: str,
    tenant_id: str,
    environment: str,
    files: Sequence[Mapping[str, Any]],
) -> str:
    digest = canonical_hash(
        {
            "chain": chain,
            "tenant_id": tenant_id,
            "environment": environment,
            "files": [{"path": item["path"], "sha256": item["sha256"]} for item in files],
        }
    )
    return f"bundle_{digest[:32]}"

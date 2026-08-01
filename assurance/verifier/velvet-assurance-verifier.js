/* Offline Velvet assurance verifier for Node or modern browsers. */

const PURPOSE = "velvet.assurance.control_state_attestation.v1";
const ENVELOPE_VERSION = "velvet.assurance.control_state_attestation.envelope.v1";
const PAYLOAD_VERSION = "velvet.assurance.control_state_attestation.v1";
const REPORT_VERSION = "velvet.assurance.verification_report.v1";
const PROOF_VERSION = "velvet.vault.merkle_consistency_proof.v1";
const SIGNATURE_VERSIONS = new Set(["velvet.signature.v1", "velvet.signature.v2"]);
const DECISIONS = ["admit", "block", "escalate", "defer", "skip"];
const RISKS = [
  "unknown",
  "low",
  "medium",
  "high",
  "unlisted",
  "destructive",
  "bind_external",
  "spend",
  "irreversible",
  "other",
];
const RETENTION = new Set([
  "unavailable",
  "eu_ai_act_minimum",
  "minimal",
  "standard",
  "extended",
  "legal_hold",
]);
const POLICY_STATUS = new Set(["valid", "invalid", "unavailable", "degraded"]);
const HASH_RE = /^sha256:[0-9a-f]{64}$/;
const ISO_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$/;
const EMPTY_TREE_HASH = hexToBytes("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

function cryptoApi() {
  if (globalThis.crypto && globalThis.crypto.subtle) return globalThis.crypto;
  if (typeof require === "function") return require("node:crypto").webcrypto;
  throw new Error("WebCrypto is unavailable");
}

function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value && typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

async function sha256Bytes(bytes) {
  const digest = await cryptoApi().subtle.digest("SHA-256", bytes);
  return new Uint8Array(digest);
}

async function sha256Prefixed(text) {
  return "sha256:" + bytesToHex(await sha256Bytes(new TextEncoder().encode(text)));
}

function signingMessage(record, payloadHash) {
  return canonical({
    schema_version: record.schema_version,
    provider_name: record.provider_name,
    algorithm: record.algorithm,
    key_version: record.key_version,
    key_id: record.key_id,
    tenant_id: record.tenant_id,
    purpose: record.purpose,
    payload_hash: payloadHash,
  });
}

function base64ToBytes(value) {
  const clean = String(value).replace(/\s+/g, "");
  if (typeof atob === "function") {
    const binary = atob(clean);
    return Uint8Array.from(binary, (char) => char.charCodeAt(0));
  }
  return Uint8Array.from(Buffer.from(clean, "base64"));
}

function publicKeyMaterial(value) {
  const text = String(value).trim();
  if (!text.includes("BEGIN")) return { format: "raw", bytes: base64ToBytes(text) };
  const base64 = text
    .replace(/-----BEGIN PUBLIC KEY-----/g, "")
    .replace(/-----END PUBLIC KEY-----/g, "")
    .replace(/\s+/g, "");
  return { format: "spki", bytes: base64ToBytes(base64) };
}

async function importEd25519PublicKey(material) {
  const key = publicKeyMaterial(material);
  return cryptoApi().subtle.importKey(key.format, key.bytes, { name: "Ed25519" }, false, ["verify"]);
}

function claimedDecisions(payload) {
  let total = 0;
  for (const byRisk of Object.values(payload.decision_counts || {})) {
    for (const count of Object.values(byRisk || {})) total += Number(count);
  }
  return total;
}

async function verifyAttestationSeries(attestations, publicKeyMaterialValue, options = {}) {
  const publicKey = await importEd25519PublicKey(publicKeyMaterialValue);
  const consistencyProofs = options.consistencyProofs || options.consistency_proofs || [];
  const anchoredSths = options.anchoredSths || options.anchored_sths || [];
  const issues = [];
  const checks = [];
  const ordered = [...attestations].sort((a, b) =>
    String(a.payload?.period?.start || "").localeCompare(String(b.payload?.period?.start || "")),
  );
  const payloads = [];
  for (let index = 0; index < ordered.length; index += 1) {
    const envelope = ordered[index];
    const payload = envelope.payload;
    const sig = envelope.signature || {};
    const okShape =
      envelope.schema_version === ENVELOPE_VERSION &&
      payload &&
      typeof payload === "object" &&
      sig &&
      typeof sig === "object" &&
      payload.schema_version === PAYLOAD_VERSION;
    check(checks, "attestation_schema", okShape, { index });
    if (!okShape) {
      issues.push(issue("attestation_schema_unsupported", index));
      continue;
    }
    const shapeErrors = payloadShapeErrors(payload);
    check(checks, "attestation_payload_shape", shapeErrors.length === 0, { index });
    for (const code of shapeErrors) issues.push(issue(code, index));
    if (shapeErrors.length) continue;
    const payloadHash = await sha256Prefixed(canonical(payload));
    if (payloadHash !== envelope.payload_hash) {
      issues.push(issue("payload_hash_mismatch", index));
      check(checks, "payload_hash", false, { index });
    } else {
      check(checks, "payload_hash", true, { index });
    }
    const signatureOk = await verifySignatureRecord(sig, payloadHash, publicKey);
    check(checks, "attestation_signature", signatureOk, { index });
    if (!signatureOk) issues.push(issue("attestation_signature_invalid", index));
    payloads.push(payload);
  }
  verifyPeriods(payloads, checks, issues);
  await verifyTreeGrowthAndCounts(payloads, consistencyProofs, anchoredSths, checks, issues);
  return {
    schema_version: REPORT_VERSION,
    status: issues.some((item) => item.severity === "error") ? "fail" : "pass",
    attestation_count: attestations.length,
    checks,
    issues,
  };
}

async function verifySignatureRecord(record, payloadHash, publicKey) {
  if (!SIGNATURE_VERSIONS.has(record.schema_version)) return false;
  if (record.algorithm !== "Ed25519" || record.purpose !== PURPOSE) return false;
  if (record.payload_hash !== payloadHash) return false;
  try {
    return await cryptoApi().subtle.verify(
      { name: "Ed25519" },
      publicKey,
      base64ToBytes(record.signature),
      new TextEncoder().encode(signingMessage(record, payloadHash)),
    );
  } catch {
    return false;
  }
}

function verifyPeriods(payloads, checks, issues) {
  let ok = true;
  let previousEnd = null;
  for (let index = 0; index < payloads.length; index += 1) {
    const period = payloads[index].period || {};
    let start;
    let end;
    try {
      start = parseIsoMicros(period.start);
      end = parseIsoMicros(period.end);
    } catch {
      issues.push(issue("period_timestamp_invalid", index));
      ok = false;
      continue;
    }
    if (end <= start) {
      issues.push(issue("period_not_positive", index));
      ok = false;
    }
    if (previousEnd !== null && start !== previousEnd) {
      issues.push(issue(start < previousEnd ? "period_overlap" : "period_gap", index));
      ok = false;
    }
    previousEnd = end;
  }
  check(checks, "period_continuity", ok);
}

async function verifyTreeGrowthAndCounts(payloads, consistencyProofs, anchoredSths, checks, issues) {
  const proofByBounds = new Map();
  let proofOk = true;
  for (let index = 0; index < consistencyProofs.length; index += 1) {
    try {
      const key = proofKey(consistencyProofs[index]);
      proofByBounds.set(key, consistencyProofs[index]);
    } catch {
      issues.push(issue("sth_consistency_proof_malformed", index));
      proofOk = false;
    }
  }
  const anchors = [];
  const rootByAnchorSize = new Map();
  let anchorOk = true;
  for (let index = 0; index < anchoredSths.length; index += 1) {
    const anchor = anchoredSths[index];
    if (!isIntNonnegative(anchor?.tree_size) || !isHash(anchor?.root_hash)) {
      issues.push(issue("anchor_sth_invalid", index));
      anchorOk = false;
      continue;
    }
    const prior = rootByAnchorSize.get(anchor.tree_size);
    if (prior && prior !== anchor.root_hash) {
      issues.push({ code: "anchor_sth_conflict", severity: "error" });
      anchorOk = false;
    }
    rootByAnchorSize.set(anchor.tree_size, anchor.root_hash);
    anchors.push([anchor.tree_size, anchor.root_hash]);
  }
  let previousSize = 0;
  let previousRoot = encodeSha256(EMPTY_TREE_HASH);
  if (payloads.length && anchors.length) {
    const firstSize = Number(payloads[0].evidence_plane.latest_sth.tree_size);
    const eligible = anchors.filter(([size]) => size <= firstSize);
    if (eligible.length) {
      eligible.sort((a, b) => a[0] - b[0]);
      [previousSize, previousRoot] = eligible[eligible.length - 1];
    }
  }
  let growthOk = true;
  let countOk = true;
  for (let index = 0; index < payloads.length; index += 1) {
    const sth = payloads[index].evidence_plane.latest_sth;
    const currentSize = Number(sth.tree_size);
    const currentRoot = String(sth.root_hash);
    const anchoredRoot = rootByAnchorSize.get(currentSize);
    if (anchoredRoot && anchoredRoot !== currentRoot) {
      issues.push(issue("anchor_sth_root_mismatch", index));
      anchorOk = false;
    }
    const claimed = claimedDecisions(payloads[index]);
    let added = -1;
    if (currentSize < previousSize) {
      issues.push(issue("sth_tree_size_decreased", index));
      growthOk = false;
    } else {
      added = currentSize - previousSize;
    }
    if (added >= 0 && added < claimed) {
      issues.push({
        code: "decision_counts_exceed_tree_growth",
        severity: "error",
        attestation_index: index,
        expected_minimum: claimed,
        actual: added,
      });
      countOk = false;
    }
    if (currentSize === previousSize) {
      if (currentRoot !== previousRoot) {
        issues.push(issue("sth_root_changed_without_growth", index));
        proofOk = false;
      }
    } else if (previousSize !== 0) {
      const key = proofKey({
        old_tree_size: previousSize,
        new_tree_size: currentSize,
        old_root_hash: previousRoot,
        new_root_hash: currentRoot,
      });
      const proof = proofByBounds.get(key);
      if (!proof) {
        issues.push(issue("sth_consistency_proof_missing", index));
        proofOk = false;
      } else if (!(await verifyConsistencyProofArtifact(proof))) {
        issues.push(issue("sth_consistency_proof_invalid", index));
        proofOk = false;
      }
    }
    previousSize = currentSize;
    previousRoot = currentRoot;
  }
  check(checks, "sth_tree_growth", growthOk);
  check(checks, "sth_consistency_proofs", proofOk);
  check(checks, "decision_counts_vs_tree_growth", countOk);
  check(checks, "anchor_sths", anchorOk);
}

function payloadShapeErrors(payload) {
  try {
    if (!exactKeys(payload, [
      "schema_version",
      "period",
      "deployment_id",
      "gateway_liveness",
      "policy_state",
      "decision_counts",
      "escalation_integrity",
      "drift_rejections",
      "certificate_coverage",
      "budget_safety",
      "evidence_plane",
      "degraded_flags",
    ])) return ["payload_shape_invalid"];
    if (payload.schema_version !== PAYLOAD_VERSION || !isHash(payload.deployment_id)) {
      return ["payload_shape_invalid"];
    }
    if (!exactKeys(payload.period, ["start", "end"]) ||
      !isIso(payload.period.start) ||
      !isIso(payload.period.end)) return ["payload_shape_invalid"];
    if (!exactKeys(payload.gateway_liveness, ["decisions_observed", "max_gap_seconds"]) ||
      !isIntNonnegative(payload.gateway_liveness.decisions_observed) ||
      !isIntNonnegative(payload.gateway_liveness.max_gap_seconds)) return ["payload_shape_invalid"];
    const policy = payload.policy_state;
    if (!exactKeys(policy, ["active_policy_bundle_hash", "bundle_signature_status", "last_change_timestamp"]) ||
      !isOptionalHash(policy.active_policy_bundle_hash) ||
      !POLICY_STATUS.has(policy.bundle_signature_status) ||
      !isOptionalIso(policy.last_change_timestamp)) return ["payload_shape_invalid"];
    if (!exactKeys(payload.decision_counts, DECISIONS)) return ["payload_shape_invalid"];
    for (const decision of DECISIONS) {
      const byRisk = payload.decision_counts[decision];
      if (!exactKeys(byRisk, RISKS)) return ["payload_shape_invalid"];
      for (const risk of RISKS) if (!isIntNonnegative(byRisk[risk])) return ["payload_shape_invalid"];
    }
    const escalation = payload.escalation_integrity;
    if (!exactKeys(escalation, [
      "escalations_in_period",
      "valid_approval_receipts",
      "valid_approval_receipt_fraction",
    ]) ||
      !isIntNonnegative(escalation.escalations_in_period) ||
      !isIntNonnegative(escalation.valid_approval_receipts) ||
      !isFraction(escalation.valid_approval_receipt_fraction)) return ["payload_shape_invalid"];
    if (!exactKeys(payload.drift_rejections, ["canonical_action_mismatch_refusals"]) ||
      !isIntNonnegative(payload.drift_rejections.canonical_action_mismatch_refusals)) {
      return ["payload_shape_invalid"];
    }
    const coverage = payload.certificate_coverage;
    if (!exactKeys(coverage, [
      "spend_class_actions",
      "spend_class_deterministic_budget_certificate_fraction",
      "irreversible_class_actions",
      "irreversible_class_max_de_lockout_inspection_certificate_fraction",
      "irreversible_class_verdict_certificate_fraction",
    ]) ||
      !isIntNonnegative(coverage.spend_class_actions) ||
      !isFraction(coverage.spend_class_deterministic_budget_certificate_fraction) ||
      !isIntNonnegative(coverage.irreversible_class_actions) ||
      !isFraction(coverage.irreversible_class_max_de_lockout_inspection_certificate_fraction) ||
      !isFraction(coverage.irreversible_class_verdict_certificate_fraction)) {
      return ["payload_shape_invalid"];
    }
    const budget = payload.budget_safety;
    if (!exactKeys(budget, [
      "h1_true_hard_caps_present",
      "h2_single_writer_accounting",
      "max_configured_cap_usd",
      "zero_overshoot_observed",
    ]) ||
      typeof budget.h1_true_hard_caps_present !== "boolean" ||
      typeof budget.h2_single_writer_accounting !== "boolean" ||
      !/^[0-9]+\.[0-9]{6}$/.test(budget.max_configured_cap_usd) ||
      typeof budget.zero_overshoot_observed !== "boolean") return ["payload_shape_invalid"];
    const evidence = payload.evidence_plane;
    if (!exactKeys(evidence, [
      "latest_sth",
      "last_successful_external_anchor_timestamp",
      "retention_preset",
    ]) ||
      !exactKeys(evidence.latest_sth, ["tree_size", "root_hash"]) ||
      !isIntNonnegative(evidence.latest_sth.tree_size) ||
      !isHash(evidence.latest_sth.root_hash) ||
      !isOptionalIso(evidence.last_successful_external_anchor_timestamp) ||
      !RETENTION.has(evidence.retention_preset)) return ["payload_shape_invalid"];
    const degraded = payload.degraded_flags;
    if (!exactKeys(degraded, ["signing_degraded", "anchoring_degraded", "fail_open_condition_observed"]) ||
      typeof degraded.signing_degraded !== "boolean" ||
      typeof degraded.anchoring_degraded !== "boolean" ||
      typeof degraded.fail_open_condition_observed !== "boolean") return ["payload_shape_invalid"];
    return [];
  } catch {
    return ["payload_shape_invalid"];
  }
}

async function verifyConsistencyProofArtifact(proof) {
  try {
    if (proof.schema_version !== PROOF_VERSION) return false;
    return await verifyConsistencyProof(
      Number(proof.old_tree_size),
      Number(proof.new_tree_size),
      String(proof.old_root_hash),
      String(proof.new_root_hash),
      (proof.proof || []).map(String),
    );
  } catch {
    return false;
  }
}

async function verifyConsistencyProof(oldSize, newSize, oldRootHash, newRootHash, proof) {
  if (oldSize < 0 || newSize < 0 || oldSize > newSize) return false;
  const oldRoot = decodeSha256(oldRootHash);
  const newRoot = decodeSha256(newRootHash);
  const proofHashes = proof.map(decodeSha256);
  if (oldSize === 0) return proofHashes.length === 0 && bytesEqual(oldRoot, EMPTY_TREE_HASH);
  if (oldSize === newSize) return proofHashes.length === 0 && bytesEqual(oldRoot, newRoot);
  const cursor = { index: 0, hashes: proofHashes };
  const [computedOld, computedNew] = await consistencyRootsFromPath(oldSize, newSize, oldRoot, cursor, true);
  return cursor.index === proofHashes.length &&
    bytesEqual(computedOld, oldRoot) &&
    bytesEqual(computedNew, newRoot);
}

async function consistencyRootsFromPath(oldSize, newSize, oldRoot, cursor, complete) {
  if (oldSize === newSize) {
    const node = complete ? oldRoot : nextProofHash(cursor);
    return [node, node];
  }
  const split = largestPowerOfTwoLessThan(newSize);
  if (oldSize <= split) {
    const [oldHash, newLeft] = await consistencyRootsFromPath(oldSize, split, oldRoot, cursor, complete);
    const right = nextProofHash(cursor);
    return [oldHash, await nodeHash(newLeft, right)];
  }
  const [oldRight, newRight] = await consistencyRootsFromPath(oldSize - split, newSize - split, oldRoot, cursor, false);
  const left = nextProofHash(cursor);
  return [await nodeHash(left, oldRight), await nodeHash(left, newRight)];
}

function nextProofHash(cursor) {
  if (cursor.index >= cursor.hashes.length) throw new Error("proof exhausted");
  const value = cursor.hashes[cursor.index];
  cursor.index += 1;
  return value;
}

async function nodeHash(left, right) {
  const bytes = new Uint8Array(65);
  bytes[0] = 1;
  bytes.set(left, 1);
  bytes.set(right, 33);
  return sha256Bytes(bytes);
}

function largestPowerOfTwoLessThan(value) {
  if (value <= 1) throw new Error("value must be greater than 1");
  return 2 ** (Math.ceil(Math.log2(value)) - 1);
}

function proofKey(proof) {
  const oldSize = Number(proof.old_tree_size);
  const newSize = Number(proof.new_tree_size);
  const oldRoot = String(proof.old_root_hash);
  const newRoot = String(proof.new_root_hash);
  if (!Number.isInteger(oldSize) || !Number.isInteger(newSize) ||
    !isHash(oldRoot) || !isHash(newRoot)) {
    throw new Error("malformed consistency proof bounds");
  }
  return [oldSize, newSize, oldRoot, newRoot].join("|");
}

function exactKeys(value, expected) {
  return value &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.keys(value).sort().join("\u0000") === [...expected].sort().join("\u0000");
}

function parseIsoMicros(value) {
  const match = ISO_RE.exec(String(value));
  if (!match) throw new Error("invalid timestamp");
  const milliseconds = Date.parse(String(value).replace(/(\.\d{3})\d{3}Z$/, "$1Z"));
  if (!Number.isFinite(milliseconds)) throw new Error("invalid timestamp");
  return BigInt(milliseconds) * 1000n + BigInt(String(value).slice(20, 26).slice(3));
}

function isHash(value) {
  return typeof value === "string" && HASH_RE.test(value);
}

function isOptionalHash(value) {
  return value === null || isHash(value);
}

function isIso(value) {
  return typeof value === "string" && ISO_RE.test(value);
}

function isOptionalIso(value) {
  return value === null || isIso(value);
}

function isIntNonnegative(value) {
  return Number.isInteger(value) && value >= 0;
}

function isFraction(value) {
  return typeof value === "string" && /^(?:0|1)\.[0-9]{6}$/.test(value);
}

function decodeSha256(value) {
  if (!isHash(value)) throw new Error("invalid sha256 hash");
  return hexToBytes(String(value).slice("sha256:".length));
}

function encodeSha256(bytes) {
  return "sha256:" + bytesToHex(bytes);
}

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function bytesToHex(bytes) {
  return Array.from(bytes).map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function bytesEqual(left, right) {
  if (left.length !== right.length) return false;
  for (let i = 0; i < left.length; i += 1) if (left[i] !== right[i]) return false;
  return true;
}

function check(checks, name, ok, extra = {}) {
  checks.push({ name, status: ok ? "pass" : "fail", ...extra });
}

function issue(code, index) {
  const payload = { code, severity: "error" };
  if (index !== undefined && index !== null) payload.attestation_index = index;
  return payload;
}

if (typeof module !== "undefined") module.exports = { verifyAttestationSeries };

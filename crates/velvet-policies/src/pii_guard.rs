use std::collections::{BTreeMap, BTreeSet};

use regex::Regex;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use velvet_core::{
    ActionMutation, CandidateAction, Evidence, JsonObject, Policy, PolicyContext, PolicyDecision,
    PolicyReason, Redaction,
};

use crate::{action_key, config_hash};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ResponseMode {
    Block,
    Redact,
    Flag,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct PiiGuardConfig {
    pub default_mode: ResponseMode,
    pub per_action_mode: BTreeMap<String, ResponseMode>,
    pub list_context_keys: Vec<String>,
    pub enabled_detectors: BTreeSet<String>,
}

impl Default for PiiGuardConfig {
    fn default() -> Self {
        Self {
            default_mode: ResponseMode::Redact,
            per_action_mode: BTreeMap::new(),
            list_context_keys: vec!["own_email".to_string(), "account_email".to_string()],
            enabled_detectors: [
                "email",
                "ssn",
                "phone",
                "credit_card",
                "iban",
                "postal_code",
            ]
            .into_iter()
            .map(ToString::to_string)
            .collect(),
        }
    }
}

pub struct PiiGuardPolicy {
    config: PiiGuardConfig,
    config_hash: String,
    email: Regex,
    ssn: Regex,
    phone: Regex,
    credit_card: Regex,
    iban: Regex,
    postal_code: Regex,
}

impl Default for PiiGuardPolicy {
    fn default() -> Self {
        Self::new(PiiGuardConfig::default()).expect("default config is valid")
    }
}

impl PiiGuardPolicy {
    pub fn new(config: PiiGuardConfig) -> Result<Self, String> {
        config.validate()?;
        Ok(Self {
            config_hash: config_hash(&config),
            config,
            email: Regex::new(r"(?i)\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b").unwrap(),
            ssn: Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap(),
            phone: Regex::new(
                r"(?x)\b(?:\+?1[\s.\-]?)?(?:\(?\d{3}\)?[\s.\-]?)\d{3}[\s.\-]?\d{4}\b",
            )
            .unwrap(),
            credit_card: Regex::new(r"\b(?:\d[ -]?){13,19}\b").unwrap(),
            iban: Regex::new(r"(?i)\b[A-Z]{2}\d{2}[A-Z0-9 ]{11,34}\b").unwrap(),
            postal_code: Regex::new(r"(?i)\b(?:\d{5}(?:-\d{4})?|[A-Z]\d[A-Z][ -]?\d[A-Z]\d)\b")
                .unwrap(),
        })
    }

    pub fn from_yaml(input: &str) -> Result<Self, String> {
        Self::new(serde_yaml::from_str(input).map_err(|error| error.to_string())?)
    }

    fn mode_for(&self, candidate: &CandidateAction) -> ResponseMode {
        let key = candidate
            .metadata
            .get("action_name")
            .and_then(Value::as_str)
            .map(ToString::to_string)
            .unwrap_or_else(|| action_key(candidate.action_type));
        self.config
            .per_action_mode
            .get(&key)
            .copied()
            .unwrap_or(self.config.default_mode)
    }

    fn detect(&self, candidate: &CandidateAction, context: &PolicyContext) -> Vec<PiiMatch> {
        let list = self.list(context);
        let mut matches = Vec::new();
        for (key, value) in &candidate.parameters {
            self.detect_value(&format!("parameters.{key}"), value, &list, &mut matches);
        }
        for (key, value) in &candidate.metadata {
            self.detect_value(&format!("metadata.{key}"), value, &list, &mut matches);
        }
        matches.sort_by(|left, right| {
            left.field_path
                .cmp(&right.field_path)
                .then_with(|| left.value.cmp(&right.value))
                .then_with(|| left.kind.cmp(&right.kind))
        });
        matches.dedup_by(|left, right| {
            left.field_path == right.field_path
                && left.value == right.value
                && left.kind == right.kind
        });
        matches
    }

    fn detect_value(
        &self,
        path: &str,
        value: &Value,
        list: &BTreeSet<String>,
        matches: &mut Vec<PiiMatch>,
    ) {
        match value {
            Value::String(text) => self.detect_text(path, text, list, matches),
            Value::Array(values) => {
                for (index, item) in values.iter().enumerate() {
                    self.detect_value(&format!("{path}[{index}]"), item, list, matches);
                }
            }
            Value::Object(values) => {
                for (key, item) in values {
                    self.detect_value(&format!("{path}.{key}"), item, list, matches);
                }
            }
            _ => {}
        }
    }

    fn detect_text(
        &self,
        path: &str,
        text: &str,
        list: &BTreeSet<String>,
        matches: &mut Vec<PiiMatch>,
    ) {
        self.push_regex("email", &self.email, path, text, list, matches);
        self.push_regex("ssn", &self.ssn, path, text, list, matches);
        self.push_regex("phone", &self.phone, path, text, list, matches);
        self.push_regex("postal_code", &self.postal_code, path, text, list, matches);
        if self.detector_enabled("credit_card") {
            for hit in self.credit_card.find_iter(text) {
                let raw = hit.as_str();
                let digits: String = raw.chars().filter(|char| char.is_ascii_digit()).collect();
                if valid_card_candidate(&digits) && !list.contains(&raw.to_lowercase()) {
                    matches.push(PiiMatch::new("credit_card", path, raw));
                }
            }
        }
        if self.detector_enabled("iban") {
            for hit in self.iban.find_iter(text) {
                let raw = hit.as_str();
                if valid_iban(raw) && !list.contains(&raw.to_lowercase()) {
                    matches.push(PiiMatch::new("iban", path, raw));
                }
            }
        }
    }

    fn push_regex(
        &self,
        kind: &str,
        regex: &Regex,
        path: &str,
        text: &str,
        list: &BTreeSet<String>,
        matches: &mut Vec<PiiMatch>,
    ) {
        if !self.detector_enabled(kind) {
            return;
        }
        for hit in regex.find_iter(text) {
            let value = hit.as_str();
            if !list.contains(&value.to_lowercase()) {
                matches.push(PiiMatch::new(kind, path, value));
            }
        }
    }

    fn detector_enabled(&self, kind: &str) -> bool {
        self.config.enabled_detectors.contains(kind)
    }

    fn list(&self, context: &PolicyContext) -> BTreeSet<String> {
        let mut values = BTreeSet::new();
        if let Some(user_id) = &context.user_id
            && user_id.contains('@')
        {
            values.insert(user_id.to_lowercase());
        }
        for key in &self.config.list_context_keys {
            if let Some(value) = context.external_observations.get(key) {
                collect_list_values(value, &mut values);
            }
        }
        values
    }

    fn jurisdiction_evidence(&self, matches: &[PiiMatch], rule_id: &str) -> Evidence {
        let mut details = JsonObject::new();
        details.insert("match_count".to_string(), json!(matches.len()));
        details.insert(
            "kinds".to_string(),
            json!(matches.iter().map(|item| &item.kind).collect::<Vec<_>>()),
        );
        details.insert(
            "field_paths".to_string(),
            json!(
                matches
                    .iter()
                    .map(|item| &item.field_path)
                    .collect::<Vec<_>>()
            ),
        );
        details.insert(
            "matched_hashes".to_string(),
            json!(
                matches
                    .iter()
                    .map(|item| stable_hash(item.value.as_bytes()))
                    .collect::<Vec<_>>()
            ),
        );
        Evidence {
            rule_id: rule_id.to_string(),
            evidence_type: "pii_match".to_string(),
            message: "Candidate action arguments matched PII detectors.".to_string(),
            details,
        }
    }
}

impl PiiGuardConfig {
    pub fn validate(&self) -> Result<(), String> {
        let allowed = [
            "email",
            "ssn",
            "phone",
            "credit_card",
            "iban",
            "postal_code",
        ];
        for detector in &self.enabled_detectors {
            if !allowed.contains(&detector.as_str()) {
                return Err(format!(
                    "spec.config.enabled_detectors contains unsupported detector {detector:?}"
                ));
            }
        }
        Ok(())
    }
}

impl Policy for PiiGuardPolicy {
    fn name(&self) -> &str {
        "pii_guard"
    }

    fn version(&self) -> &str {
        "pii_guard_v1"
    }

    fn config_hash(&self) -> &str {
        &self.config_hash
    }

    fn evaluate(&self, candidate: &CandidateAction, context: &PolicyContext) -> PolicyDecision {
        let matches = self.detect(candidate, context);
        if matches.is_empty() {
            return PolicyDecision::Allow;
        }
        match self.mode_for(candidate) {
            ResponseMode::Block => PolicyDecision::Deny {
                reason: PolicyReason::new(
                    "pii_guard.block",
                    "PII appeared in candidate action arguments.",
                    "error",
                ),
                jurisdiction_evidence: self.jurisdiction_evidence(&matches, "pii_guard.block"),
            },
            ResponseMode::Flag => {
                let mut mutation = ActionMutation {
                    jurisdiction_evidence: Some(
                        self.jurisdiction_evidence(&matches, "pii_guard.flag"),
                    ),
                    ..ActionMutation::default()
                };
                mutation
                    .notes
                    .push("PII flag emitted without action mutation.".to_string());
                PolicyDecision::Modify {
                    mutation,
                    reason: PolicyReason::new(
                        "pii_guard.flag",
                        "PII appeared in candidate action arguments.",
                        "warning",
                    ),
                }
            }
            ResponseMode::Redact => {
                let mut mutation = ActionMutation {
                    jurisdiction_evidence: Some(
                        self.jurisdiction_evidence(&matches, "pii_guard.redact"),
                    ),
                    ..ActionMutation::default()
                };
                for (key, value) in &candidate.parameters {
                    let updated = redact_value(
                        value,
                        &format!("parameters.{key}"),
                        &matches,
                        &mut mutation.redactions,
                    );
                    if updated != *value {
                        mutation.parameter_updates.insert(key.clone(), updated);
                    }
                }
                for (key, value) in &candidate.metadata {
                    let updated = redact_value(
                        value,
                        &format!("metadata.{key}"),
                        &matches,
                        &mut mutation.redactions,
                    );
                    if updated != *value {
                        mutation.metadata_updates.insert(key.clone(), updated);
                    }
                }
                PolicyDecision::Modify {
                    mutation,
                    reason: PolicyReason::new(
                        "pii_guard.redact",
                        "PII appeared in candidate action arguments and was redacted.",
                        "warning",
                    ),
                }
            }
        }
    }
}

#[derive(Clone)]
struct PiiMatch {
    kind: String,
    field_path: String,
    value: String,
}

impl PiiMatch {
    fn new(kind: &str, field_path: &str, value: &str) -> Self {
        Self {
            kind: kind.to_string(),
            field_path: field_path.to_string(),
            value: value.to_string(),
        }
    }
}

fn redact_value(
    value: &Value,
    path: &str,
    matches: &[PiiMatch],
    redactions: &mut Vec<Redaction>,
) -> Value {
    match value {
        Value::String(text) => {
            let mut updated = text.clone();
            for item in matches.iter().filter(|item| item.field_path == path) {
                let replacement = format!("[PII:{}:{}]", item.kind, redactions.len());
                if updated.contains(&item.value) {
                    updated = updated.replace(&item.value, &replacement);
                    redactions.push(Redaction {
                        field_path: item.field_path.clone(),
                        original_value: item.value.clone(),
                        replacement,
                        original_hash: stable_hash(item.value.as_bytes()),
                        detector: item.kind.clone(),
                    });
                }
            }
            Value::String(updated)
        }
        Value::Array(values) => Value::Array(
            values
                .iter()
                .enumerate()
                .map(|(index, item)| {
                    redact_value(item, &format!("{path}[{index}]"), matches, redactions)
                })
                .collect(),
        ),
        Value::Object(values) => Value::Object(
            values
                .iter()
                .map(|(key, item)| {
                    (
                        key.clone(),
                        redact_value(item, &format!("{path}.{key}"), matches, redactions),
                    )
                })
                .collect(),
        ),
        _ => value.clone(),
    }
}

fn collect_list_values(value: &Value, output: &mut BTreeSet<String>) {
    match value {
        Value::String(text) => {
            output.insert(text.to_lowercase());
        }
        Value::Array(values) => {
            for value in values {
                collect_list_values(value, output);
            }
        }
        Value::Object(values) => {
            for value in values.values() {
                collect_list_values(value, output);
            }
        }
        _ => {}
    }
}

fn valid_card_candidate(digits: &str) -> bool {
    (13..=19).contains(&digits.len()) && has_major_bin(digits) && luhn_valid(digits)
}

fn has_major_bin(digits: &str) -> bool {
    digits.starts_with('4')
        || digits.starts_with('5')
        || digits.starts_with("34")
        || digits.starts_with("37")
        || digits.starts_with("6011")
        || digits.starts_with("65")
}

fn luhn_valid(digits: &str) -> bool {
    let mut sum = 0;
    let mut double = false;
    for digit in digits.chars().rev().filter_map(|char| char.to_digit(10)) {
        let mut value = digit;
        if double {
            value *= 2;
            if value > 9 {
                value -= 9;
            }
        }
        sum += value;
        double = !double;
    }
    sum % 10 == 0
}

fn valid_iban(value: &str) -> bool {
    let compact: String = value
        .chars()
        .filter(|char| !char.is_whitespace())
        .map(|char| char.to_ascii_uppercase())
        .collect();
    if compact.len() < 15 || compact.len() > 34 {
        return false;
    }
    let rearranged = format!("{}{}", &compact[4..], &compact[..4]);
    let mut remainder = 0u32;
    for char in rearranged.chars() {
        if char.is_ascii_digit() {
            remainder = (remainder * 10 + char.to_digit(10).unwrap_or(0)) % 97;
        } else if char.is_ascii_uppercase() {
            let value = char as u32 - 'A' as u32 + 10;
            remainder = (remainder * 100 + value) % 97;
        } else {
            return false;
        }
    }
    remainder == 1
}

fn stable_hash(bytes: &[u8]) -> String {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}

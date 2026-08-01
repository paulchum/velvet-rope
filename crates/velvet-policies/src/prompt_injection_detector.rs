use std::collections::BTreeMap;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use regex::Regex;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use unicode_normalization::UnicodeNormalization;
use velvet_core::{
    CandidateAction, Evidence, JsonObject, Policy, PolicyContext, PolicyDecision, PolicyReason,
};

use crate::config_hash;

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct PromptInjectionConfig {
    pub default_action: String,
    pub source_rules: BTreeMap<String, Vec<PromptRule>>,
    pub embedding_threshold: Option<f64>,
    pub distance_metric: String,
    pub pid_classifier_path: Option<String>,
}

impl Default for PromptInjectionConfig {
    fn default() -> Self {
        let rules = default_rules();
        Self {
            default_action: "block".to_string(),
            source_rules: rules,
            embedding_threshold: Some(0.86),
            distance_metric: "cosine".to_string(),
            pid_classifier_path: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct PromptRule {
    pub id: String,
    pub pattern: String,
    pub severity: String,
}

impl Default for PromptRule {
    fn default() -> Self {
        Self {
            id: "unnamed".to_string(),
            pattern: String::new(),
            severity: "warning".to_string(),
        }
    }
}

pub struct PromptInjectionPolicy {
    config: PromptInjectionConfig,
    config_hash: String,
    compiled: BTreeMap<String, Vec<CompiledRule>>,
}

impl Default for PromptInjectionPolicy {
    fn default() -> Self {
        Self::new(PromptInjectionConfig::default()).expect("default config is valid")
    }
}

impl PromptInjectionPolicy {
    pub fn new(config: PromptInjectionConfig) -> Result<Self, String> {
        config.validate()?;
        let mut compiled = BTreeMap::new();
        for (source, rules) in &config.source_rules {
            let mut source_rules = Vec::new();
            for rule in rules {
                source_rules.push(CompiledRule {
                    id: rule.id.clone(),
                    severity: rule.severity.clone(),
                    regex: Regex::new(&rule.pattern).map_err(|error| {
                        format!("invalid prompt injection pattern {}: {error}", rule.id)
                    })?,
                });
            }
            compiled.insert(source.clone(), source_rules);
        }
        Ok(Self {
            config_hash: config_hash(&config),
            config,
            compiled,
        })
    }

    pub fn from_yaml(input: &str) -> Result<Self, String> {
        Self::new(serde_yaml::from_str(input).map_err(|error| error.to_string())?)
    }

    fn source_for(&self, candidate: &CandidateAction) -> String {
        candidate
            .metadata
            .get("input_source")
            .or_else(|| candidate.metadata.get("source_kind"))
            .and_then(Value::as_str)
            .unwrap_or("user_input")
            .to_string()
    }

    fn detect(&self, candidate: &CandidateAction, context: &PolicyContext) -> Option<Evidence> {
        let source = self.source_for(candidate);
        let mut texts = Vec::new();
        collect_map_strings("parameters", &candidate.parameters, &mut texts);
        collect_map_strings("metadata", &candidate.metadata, &mut texts);

        let rules = self
            .compiled
            .get(&source)
            .or_else(|| self.compiled.get("default"))
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();

        for (field_path, text) in texts {
            for normalized in normalized_variants(&text) {
                for rule in &rules {
                    if let Some(hit) = rule.regex.find(&normalized) {
                        let mut details = JsonObject::new();
                        details.insert("source".to_string(), json!(source));
                        details.insert("field_path".to_string(), json!(field_path));
                        details.insert("rule_id".to_string(), json!(rule.id));
                        details.insert("severity".to_string(), json!(rule.severity));
                        details.insert("matched_pattern".to_string(), json!(rule.regex.as_str()));
                        details.insert("matched_span".to_string(), json!([hit.start(), hit.end()]));
                        return Some(Evidence {
                            rule_id: rule.id.clone(),
                            evidence_type: "prompt_injection_pattern".to_string(),
                            message: "Prompt-injection detector matched a source-aware rule."
                                .to_string(),
                            details,
                        });
                    }
                }
            }
        }

        if let Some(threshold) = self.config.embedding_threshold
            && let Some(score) = context
                .external_observations
                .get("pid_embedding_similarity")
                .and_then(Value::as_f64)
            && score >= threshold
        {
            let mut details = JsonObject::new();
            details.insert("score".to_string(), json!(score));
            details.insert("threshold".to_string(), json!(threshold));
            details.insert(
                "distance_metric".to_string(),
                json!(self.config.distance_metric),
            );
            return Some(Evidence {
                rule_id: "embedding_similarity_threshold".to_string(),
                evidence_type: "prompt_injection_embedding_similarity".to_string(),
                message: "Precomputed embedding similarity crossed prompt-injection threshold."
                    .to_string(),
                details,
            });
        }

        if context
            .external_observations
            .get("pid_classifier_verdict")
            .and_then(Value::as_str)
            .is_some_and(|value| value == "attack")
        {
            return Some(Evidence {
                rule_id: "classifier_attack_verdict".to_string(),
                evidence_type: "prompt_injection_classifier".to_string(),
                message: "Precomputed classifier verdict marked content as an attack.".to_string(),
                details: JsonObject::from([(
                    "pid_classifier_path".to_string(),
                    json!(self.config.pid_classifier_path),
                )]),
            });
        }
        None
    }
}

impl PromptInjectionConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.default_action != "block" {
            return Err("spec.config.default_action must be \"block\"".to_string());
        }
        if !["cosine", "dot", "euclidean"].contains(&self.distance_metric.as_str()) {
            return Err(
                "spec.config.distance_metric must be one of cosine, dot, euclidean".to_string(),
            );
        }
        if self
            .embedding_threshold
            .is_some_and(|value| !value.is_finite() || !(0.0..=1.0).contains(&value))
        {
            return Err("spec.config.embedding_threshold must be in range [0.0, 1.0]".to_string());
        }
        for (source, rules) in &self.source_rules {
            for rule in rules {
                if rule.id.is_empty() {
                    return Err(format!(
                        "spec.config.source_rules.{source} has an empty rule id"
                    ));
                }
                if !["info", "warning", "error"].contains(&rule.severity.as_str()) {
                    return Err(format!(
                        "spec.config.source_rules.{source}.{}.severity must be info, warning, or error",
                        rule.id
                    ));
                }
            }
        }
        Ok(())
    }
}

impl Policy for PromptInjectionPolicy {
    fn name(&self) -> &str {
        "prompt_injection_detector"
    }

    fn version(&self) -> &str {
        "prompt_injection_detector_v1"
    }

    fn config_hash(&self) -> &str {
        &self.config_hash
    }

    fn evaluate(&self, candidate: &CandidateAction, context: &PolicyContext) -> PolicyDecision {
        let Some(jurisdiction_evidence) = self.detect(candidate, context) else {
            return PolicyDecision::Allow;
        };
        PolicyDecision::Deny {
            reason: PolicyReason::new(
                "prompt_injection_detector.block",
                "Candidate action arguments contain prompt-injection content.",
                "error",
            ),
            jurisdiction_evidence,
        }
    }
}

struct CompiledRule {
    id: String,
    severity: String,
    regex: Regex,
}

fn default_rules() -> BTreeMap<String, Vec<PromptRule>> {
    let rules = vec![
        PromptRule {
            id: "ignore_previous_instructions".to_string(),
            pattern: r"(?i)\b(ignore|disregard|forget)\b.{0,40}\b(previous|prior|system|developer)\b.{0,30}\b(instruction|message|prompt)s?\b".to_string(),
            severity: "error".to_string(),
        },
        PromptRule {
            id: "role_hijack".to_string(),
            pattern: r"(?i)\b(you are now|act as|pretend to be)\b.{0,40}\b(system|developer|admin|root)\b".to_string(),
            severity: "error".to_string(),
        },
        PromptRule {
            id: "jailbreak_marker".to_string(),
            pattern: r"(?i)\b(DAN|jailbreak|do anything now|developer mode)\b".to_string(),
            severity: "error".to_string(),
        },
        PromptRule {
            id: "secret_exfiltration".to_string(),
            pattern: r"(?i)\b(reveal|print|dump|exfiltrate)\b.{0,40}\b(system prompt|hidden prompt|secrets?|api keys?)\b".to_string(),
            severity: "error".to_string(),
        },
    ];
    BTreeMap::from([
        ("default".to_string(), rules.clone()),
        ("user_input".to_string(), rules.clone()),
        ("retrieved_content".to_string(), rules.clone()),
        ("tool_output".to_string(), rules),
    ])
}

fn collect_strings(path: &str, value: &Value, output: &mut Vec<(String, String)>) {
    match value {
        Value::String(text) => output.push((path.to_string(), text.clone())),
        Value::Array(values) => {
            for (index, item) in values.iter().enumerate() {
                collect_strings(&format!("{path}[{index}]"), item, output);
            }
        }
        Value::Object(values) => {
            for (key, item) in values {
                collect_strings(&format!("{path}.{key}"), item, output);
            }
        }
        _ => {}
    }
}

fn collect_map_strings(
    path: &str,
    values: &BTreeMap<String, Value>,
    output: &mut Vec<(String, String)>,
) {
    for (key, item) in values {
        collect_strings(&format!("{path}.{key}"), item, output);
    }
}

fn normalized_variants(text: &str) -> Vec<String> {
    let nfkc = text.nfkc().collect::<String>();
    let homoglyph = replace_homoglyphs(&nfkc);
    let mut variants = vec![
        text.to_string(),
        nfkc.clone(),
        homoglyph.clone(),
        rot13(&homoglyph),
    ];
    for token in homoglyph.split_whitespace() {
        if token.len() >= 16
            && token.len() % 4 == 0
            && let Ok(decoded) = STANDARD.decode(token)
            && let Ok(text) = String::from_utf8(decoded)
        {
            variants.push(text.nfkc().collect());
        }
    }
    variants.sort();
    variants.dedup();
    variants
}

fn replace_homoglyphs(text: &str) -> String {
    text.chars()
        .map(|char| match char {
            'а' | 'à' | 'á' | 'â' | 'ã' | 'ä' | 'å' => 'a',
            'е' | 'è' | 'é' | 'ê' | 'ë' => 'e',
            'і' | 'í' | 'ì' | 'î' | 'ï' => 'i',
            'о' | 'ò' | 'ó' | 'ô' | 'õ' | 'ö' => 'o',
            'р' => 'p',
            'с' | 'ç' => 'c',
            'у' | 'ý' | 'ÿ' => 'y',
            _ => char,
        })
        .collect()
}

fn rot13(text: &str) -> String {
    text.chars()
        .map(|char| match char {
            'a'..='m' | 'A'..='M' => ((char as u8) + 13) as char,
            'n'..='z' | 'N'..='Z' => ((char as u8) - 13) as char,
            _ => char,
        })
        .collect()
}

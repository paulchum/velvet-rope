use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use arc_swap::ArcSwap;
use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use schemars::{JsonSchema, schema_for};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use velvet_core::{
    CandidateAction, Policy, PolicyChain, PolicyContext, PolicyGraph, PolicyInstance,
};
use velvet_policies::{
    config_hash,
    cost_ceiling::{CostCeilingConfig, CostCeilingPolicy},
    escalation_gate::{EscalationGateConfig, EscalationGatePolicy},
    llm_atom::{LlmAtomConfig, LlmAtomPolicy},
    pii_guard::{PiiGuardConfig, PiiGuardPolicy},
    prompt_injection_detector::{PromptInjectionConfig, PromptInjectionPolicy},
    rate_limiter::{RateLimiterConfig, RateLimiterPolicy},
};
use walkdir::WalkDir;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum ApiVersion {
    #[serde(rename = "velvet.io/v1alpha1")]
    #[schemars(rename = "velvet.io/v1alpha1")]
    V1Alpha1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Metadata {
    pub name: String,
    pub version: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", content = "config", rename_all = "snake_case")]
pub enum PolicySpec {
    CostCeiling(CostCeilingConfig),
    PiiGuard(PiiGuardConfig),
    PromptInjectionDetector(PromptInjectionConfig),
    RateLimiter(RateLimiterConfig),
    EscalationGate(EscalationGateConfig),
    LlmAtom(LlmAtomConfig),
}

impl PolicySpec {
    fn kind_name(&self) -> &'static str {
        match self {
            Self::CostCeiling(_) => "cost_ceiling",
            Self::PiiGuard(_) => "pii_guard",
            Self::PromptInjectionDetector(_) => "prompt_injection_detector",
            Self::RateLimiter(_) => "rate_limiter",
            Self::EscalationGate(_) => "escalation_gate",
            Self::LlmAtom(_) => "llm_atom",
        }
    }

    fn instantiate(&self) -> Result<Arc<dyn Policy>, String> {
        match self {
            Self::CostCeiling(config) => Ok(Arc::new(CostCeilingPolicy::new(config.clone())?)),
            Self::PiiGuard(config) => Ok(Arc::new(PiiGuardPolicy::new(config.clone())?)),
            Self::PromptInjectionDetector(config) => {
                Ok(Arc::new(PromptInjectionPolicy::new(config.clone())?))
            }
            Self::RateLimiter(config) => Ok(Arc::new(RateLimiterPolicy::new(config.clone())?)),
            Self::EscalationGate(config) => {
                Ok(Arc::new(EscalationGatePolicy::new(config.clone())?))
            }
            Self::LlmAtom(config) => Ok(Arc::new(LlmAtomPolicy::new(config.clone())?)),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyChainSpec {
    pub policies: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "PascalCase")]
pub enum ExpectedDecision {
    Allow,
    Deny,
    Modify,
    Defer,
}

impl ExpectedDecision {
    fn as_policy_kind(&self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Modify => "modify",
            Self::Defer => "defer",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyTestExpectation {
    pub decision: ExpectedDecision,
    #[serde(default)]
    pub reason_contains: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyTestSpec {
    pub policy: String,
    #[serde(default)]
    pub context: Value,
    pub candidate: Value,
    pub expect: PolicyTestExpectation,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind")]
pub enum Document {
    Policy {
        #[serde(rename = "apiVersion")]
        api_version: ApiVersion,
        metadata: Metadata,
        spec: PolicySpec,
    },
    PolicyChain {
        #[serde(rename = "apiVersion")]
        api_version: ApiVersion,
        metadata: Metadata,
        spec: PolicyChainSpec,
    },
    PolicyTest {
        #[serde(rename = "apiVersion")]
        api_version: ApiVersion,
        metadata: Metadata,
        spec: PolicyTestSpec,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyLoadError {
    pub path: PathBuf,
    pub line: usize,
    pub field_path: String,
    pub message: String,
    pub hint: String,
}

impl fmt::Display for PolicyLoadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.field_path.is_empty() {
            write!(
                formatter,
                "{}:{}: {}; {}",
                self.path.display(),
                self.line,
                self.message,
                self.hint
            )
        } else {
            write!(
                formatter,
                "{}:{}: {} = {}; {}",
                self.path.display(),
                self.line,
                self.field_path,
                self.message,
                self.hint
            )
        }
    }
}

#[derive(Debug, Clone)]
struct SourceDocument {
    path: PathBuf,
    source: String,
    document: Document,
    json: Value,
}

pub fn policy_schema_json() -> Value {
    serde_json::to_value(schema_for!(Document)).expect("policy schema serializes")
}

pub fn schema_markdown() -> String {
    let schema = policy_schema_json();
    let kinds = schema["oneOf"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|entry| entry["properties"]["kind"]["const"].as_str())
        .collect::<Vec<_>>();
    let policy_types = schema["$defs"]["PolicySpec"]["oneOf"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|entry| entry["properties"]["type"]["const"].as_str())
        .collect::<Vec<_>>();
    let config_rows = policy_types
        .iter()
        .filter_map(|policy_type| {
            let config_ref = schema["$defs"]["PolicySpec"]["oneOf"]
                .as_array()?
                .iter()
                .find(|entry| entry["properties"]["type"]["const"] == **policy_type)?["properties"]
                ["config"]["$ref"]
                .as_str()?;
            let config_name = config_ref.rsplit('/').next()?;
            let fields = schema["$defs"][config_name]["properties"]
                .as_object()?
                .keys()
                .cloned()
                .collect::<Vec<_>>()
                .join(", ");
            Some(format!("| `{policy_type}` | `{fields}` |"))
        })
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "# Policy YAML Schema\n\n\
Generated from the Rust `Document` schema.\n\n\
## Document Kinds\n\n{}\n\n\
## Policy Types\n\n\
| Type | Config fields |\n\
| --- | --- |\n\
{}\n",
        kinds
            .iter()
            .map(|kind| format!("- `{kind}`"))
            .collect::<Vec<_>>()
            .join("\n"),
        config_rows
    )
}

pub fn write_generated_artifacts(schema_path: &Path, docs_path: &Path) -> Result<(), String> {
    if let Some(parent) = schema_path.parent() {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    if let Some(parent) = docs_path.parent() {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    fs::write(
        schema_path,
        serde_json::to_string_pretty(&policy_schema_json()).map_err(|error| error.to_string())?,
    )
    .map_err(|error| error.to_string())?;
    fs::write(docs_path, schema_markdown()).map_err(|error| error.to_string())
}

pub fn validate_yaml_document(source: &str) -> Result<Vec<Document>, Vec<String>> {
    let validator =
        jsonschema::validator_for(&policy_schema_json()).expect("generated policy schema is valid");
    let mut documents = Vec::new();
    let mut errors = Vec::new();
    for raw in serde_yaml::Deserializer::from_str(source) {
        let yaml_value = match serde_yaml::Value::deserialize(raw) {
            Ok(value) => value,
            Err(error) => {
                errors.push(error.to_string());
                continue;
            }
        };
        let json_value = match serde_json::to_value(yaml_value) {
            Ok(value) => value,
            Err(error) => {
                errors.push(error.to_string());
                continue;
            }
        };
        if let Some(error) = validator.iter_errors(&json_value).next() {
            errors.push(format!("{} at {}", error, error.instance_path()));
            continue;
        }
        match serde_json::from_value(json_value) {
            Ok(document) => documents.push(document),
            Err(error) => errors.push(error.to_string()),
        }
    }
    if errors.is_empty() {
        Ok(documents)
    } else {
        Err(errors)
    }
}

pub fn load_policy_graph(root: &Path) -> Result<PolicyGraph, Vec<PolicyLoadError>> {
    let source_documents = load_source_documents(root)?;
    build_policy_graph(&source_documents)
}

fn load_source_documents(root: &Path) -> Result<Vec<SourceDocument>, Vec<PolicyLoadError>> {
    let mut paths = WalkDir::new(root)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .map(|entry| entry.into_path())
        .filter(|path| {
            matches!(
                path.extension().and_then(|value| value.to_str()),
                Some("yaml" | "yml")
            )
        })
        .collect::<Vec<_>>();
    paths.sort();

    let validator =
        jsonschema::validator_for(&policy_schema_json()).expect("generated policy schema is valid");
    let mut documents = Vec::new();
    let mut errors = Vec::new();
    for path in paths {
        let source = match fs::read_to_string(&path) {
            Ok(source) => source,
            Err(error) => {
                errors.push(PolicyLoadError {
                    path,
                    line: 1,
                    field_path: String::new(),
                    message: error.to_string(),
                    hint: "ensure the policy file is readable".to_string(),
                });
                continue;
            }
        };
        for raw in serde_yaml::Deserializer::from_str(&source) {
            let yaml_value = match serde_yaml::Value::deserialize(raw) {
                Ok(value) => value,
                Err(error) => {
                    let location = error.location();
                    errors.push(PolicyLoadError {
                        path: path.clone(),
                        line: location.map_or(1, |location| location.line()),
                        field_path: String::new(),
                        message: error.to_string(),
                        hint: "fix the YAML syntax and save again".to_string(),
                    });
                    continue;
                }
            };
            let json_value = match serde_json::to_value(yaml_value) {
                Ok(value) => value,
                Err(error) => {
                    errors.push(PolicyLoadError {
                        path: path.clone(),
                        line: 1,
                        field_path: String::new(),
                        message: error.to_string(),
                        hint: "ensure the YAML document can be represented as JSON".to_string(),
                    });
                    continue;
                }
            };
            if let Some(error) = validator.iter_errors(&json_value).next() {
                let field_path = pointer_to_field_path(&error.instance_path().to_string());
                errors.push(PolicyLoadError {
                    path: path.clone(),
                    line: line_for_field(&source, &field_path),
                    field_path,
                    message: error.to_string(),
                    hint: "match the generated velvet.io/v1alpha1 schema".to_string(),
                });
                continue;
            }
            match serde_json::from_value::<Document>(json_value.clone()) {
                Ok(document) => documents.push(SourceDocument {
                    path: path.clone(),
                    source: source.clone(),
                    document,
                    json: json_value,
                }),
                Err(error) => errors.push(PolicyLoadError {
                    path: path.clone(),
                    line: 1,
                    field_path: String::new(),
                    message: error.to_string(),
                    hint: "match the generated velvet.io/v1alpha1 schema".to_string(),
                }),
            }
        }
    }
    if errors.is_empty() {
        Ok(documents)
    } else {
        Err(errors)
    }
}

fn build_policy_graph(
    source_documents: &[SourceDocument],
) -> Result<PolicyGraph, Vec<PolicyLoadError>> {
    let mut errors = Vec::new();
    let mut policies = BTreeMap::<String, Arc<dyn Policy>>::new();
    let mut policy_origins = BTreeMap::<String, (&Path, &str)>::new();
    let mut chains = Vec::<(&SourceDocument, &PolicyChainSpec)>::new();
    let mut chain_names = BTreeSet::new();

    for source in source_documents {
        match &source.document {
            Document::Policy { metadata, spec, .. } => {
                if let Some((existing_path, _)) = policy_origins.get(&metadata.name) {
                    errors.push(PolicyLoadError {
                        path: source.path.clone(),
                        line: line_for_field(&source.source, "metadata.name"),
                        field_path: "metadata.name".to_string(),
                        message: format!("duplicate policy name {:?}", metadata.name),
                        hint: format!(
                            "policy names must be unique; first declared in {}",
                            existing_path.display()
                        ),
                    });
                    continue;
                }
                match spec.instantiate() {
                    Ok(policy) => {
                        let wrapped = Arc::new(PolicyInstance::new(
                            metadata.name.clone(),
                            spec.kind_name(),
                            metadata.version.to_string(),
                            config_hash(spec),
                            policy,
                        ));
                        policy_origins
                            .insert(metadata.name.clone(), (&source.path, &source.source));
                        policies.insert(metadata.name.clone(), wrapped);
                    }
                    Err(message) => errors.push(PolicyLoadError {
                        path: source.path.clone(),
                        line: line_for_field(&source.source, field_for_semantic_error(&message)),
                        field_path: field_for_semantic_error(&message).to_string(),
                        hint: remediation_hint(&message),
                        message,
                    }),
                }
            }
            Document::PolicyChain { metadata, spec, .. } => {
                if !chain_names.insert(metadata.name.clone()) {
                    errors.push(PolicyLoadError {
                        path: source.path.clone(),
                        line: line_for_field(&source.source, "metadata.name"),
                        field_path: "metadata.name".to_string(),
                        message: format!("duplicate policy chain name {:?}", metadata.name),
                        hint: "policy chain names must be unique".to_string(),
                    });
                } else {
                    chains.push((source, spec));
                }
            }
            Document::PolicyTest { .. } => {}
        }
    }

    let mut graph_chains = BTreeMap::new();
    for (source, spec) in chains {
        let mut instances = Vec::new();
        for policy_name in &spec.policies {
            let Some(policy) = policies.get(policy_name) else {
                errors.push(PolicyLoadError {
                    path: source.path.clone(),
                    line: line_for_value(&source.source, policy_name),
                    field_path: "spec.policies".to_string(),
                    message: format!("references undefined policy {policy_name:?}"),
                    hint: "define the policy or remove the chain reference".to_string(),
                });
                continue;
            };
            instances.push(policy.clone());
        }
        if let Document::PolicyChain { metadata, .. } = &source.document {
            graph_chains.insert(metadata.name.clone(), PolicyChain::new(instances));
        }
    }

    if !errors.is_empty() {
        return Err(errors);
    }
    let revision_payload = source_documents
        .iter()
        .map(|source| source.json.clone())
        .collect::<Vec<_>>();
    Ok(PolicyGraph::new(
        format!("policy_graph_{}", stable_hash_json(&revision_payload)),
        graph_chains,
    ))
}

fn stable_hash_json<T: Serialize>(value: &T) -> String {
    let serialized = serde_json::to_string(value).unwrap_or_default();
    let mut hash = 0xcbf29ce484222325u64;
    for byte in serialized.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}

fn pointer_to_field_path(pointer: &str) -> String {
    pointer
        .trim_start_matches('/')
        .split('/')
        .filter(|segment| !segment.is_empty())
        .map(|segment| segment.replace("~1", "/").replace("~0", "~"))
        .collect::<Vec<_>>()
        .join(".")
}

fn line_for_field(source: &str, field_path: &str) -> usize {
    let field = field_path
        .rsplit('.')
        .next()
        .filter(|value| !value.is_empty())
        .unwrap_or(field_path);
    source
        .lines()
        .position(|line| line.trim_start().starts_with(&format!("{field}:")))
        .map_or(1, |index| index + 1)
}

fn line_for_value(source: &str, value: &str) -> usize {
    source
        .lines()
        .position(|line| line.contains(value))
        .map_or(1, |index| index + 1)
}

fn field_for_semantic_error(message: &str) -> &str {
    message
        .split_whitespace()
        .next()
        .filter(|value| value.starts_with("spec."))
        .unwrap_or("")
}

fn remediation_hint(message: &str) -> String {
    if message.contains("soft_ceiling_fraction") {
        "soft ceiling must be a fraction less than the hard ceiling".to_string()
    } else if message.contains("must be in range [0.0, 1.0]") {
        "use a finite fraction between 0.0 and 1.0".to_string()
    } else if message.contains("unsupported detector") {
        "choose a detector name published by the schema".to_string()
    } else if message.contains("invalid prompt injection pattern") {
        "fix the regular expression".to_string()
    } else {
        "fix the policy configuration and save again".to_string()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReloadEvent {
    pub event: String,
    pub root: PathBuf,
    pub errors: Vec<PolicyLoadError>,
}

type ReloadSink = Arc<dyn Fn(ReloadEvent) + Send + Sync>;

pub struct PolicyRuntime {
    root: PathBuf,
    active: Arc<ArcSwap<PolicyGraph>>,
    sink: ReloadSink,
    stop: Arc<AtomicBool>,
    _watcher: Option<RecommendedWatcher>,
    worker: Option<thread::JoinHandle<()>>,
}

impl PolicyRuntime {
    pub fn new(root: impl Into<PathBuf>, watch: bool) -> Result<Self, Vec<PolicyLoadError>> {
        Self::new_with_sink(
            root,
            watch,
            Arc::new(|event| {
                eprintln!(
                    "{}",
                    serde_json::to_string(&event)
                        .unwrap_or_else(|_| "{\"event\":\"policy_reload_failed\"}".to_string())
                );
            }),
        )
    }

    pub fn new_with_sink(
        root: impl Into<PathBuf>,
        watch: bool,
        sink: ReloadSink,
    ) -> Result<Self, Vec<PolicyLoadError>> {
        let root = root.into();
        let graph = load_policy_graph(&root)?;
        let active = Arc::new(ArcSwap::from_pointee(graph));
        let stop = Arc::new(AtomicBool::new(false));
        let (watcher, worker) = if watch {
            let (tx, rx) = mpsc::channel();
            let mut watcher = notify::recommended_watcher(tx)
                .expect("notify watcher construction should succeed");
            watcher
                .watch(&root, RecursiveMode::Recursive)
                .expect("policy root should be watchable");
            let worker_active = active.clone();
            let worker_root = root.clone();
            let worker_sink = sink.clone();
            let worker_stop = stop.clone();
            let worker = thread::spawn(move || {
                while !worker_stop.load(Ordering::Relaxed) {
                    match rx.recv_timeout(Duration::from_millis(100)) {
                        Ok(_) => {
                            while rx.recv_timeout(Duration::from_millis(500)).is_ok() {}
                            reload_into(&worker_root, &worker_active, &worker_sink);
                        }
                        Err(mpsc::RecvTimeoutError::Timeout) => {}
                        Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    }
                }
            });
            (Some(watcher), Some(worker))
        } else {
            (None, None)
        };
        Ok(Self {
            root,
            active,
            sink,
            stop,
            _watcher: watcher,
            worker,
        })
    }

    pub fn snapshot(&self) -> Arc<PolicyGraph> {
        self.active.load_full()
    }

    pub fn reload_now(&self) -> bool {
        reload_into(&self.root, &self.active, &self.sink)
    }
}

impl Drop for PolicyRuntime {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn reload_into(root: &Path, active: &Arc<ArcSwap<PolicyGraph>>, sink: &ReloadSink) -> bool {
    match load_policy_graph(root) {
        Ok(graph) => {
            active.store(Arc::new(graph));
            true
        }
        Err(errors) => {
            sink(ReloadEvent {
                event: "policy_reload_failed".to_string(),
                root: root.to_path_buf(),
                errors,
            });
            false
        }
    }
}

pub fn run_policy_tests(policy_file: &Path, test_file: &Path) -> Result<(), Vec<String>> {
    let policies_source = fs::read_to_string(policy_file)
        .map_err(|error| vec![format!("{}: {error}", policy_file.display())])?;
    let tests_source = fs::read_to_string(test_file)
        .map_err(|error| vec![format!("{}: {error}", test_file.display())])?;
    let policy_documents = validate_yaml_document(&policies_source)?;
    let test_documents = validate_yaml_document(&tests_source)?;

    let mut policies = BTreeMap::<String, Arc<dyn Policy>>::new();
    for document in policy_documents {
        if let Document::Policy { metadata, spec, .. } = document {
            let policy = spec
                .instantiate()
                .map_err(|error| vec![format!("{}: {error}", metadata.name)])?;
            policies.insert(
                metadata.name.clone(),
                Arc::new(PolicyInstance::new(
                    metadata.name,
                    spec.kind_name(),
                    metadata.version.to_string(),
                    config_hash(&spec),
                    policy,
                )),
            );
        }
    }

    let mut failures = Vec::new();
    for document in test_documents {
        let Document::PolicyTest { metadata, spec, .. } = document else {
            continue;
        };
        let Some(policy) = policies.get(&spec.policy) else {
            failures.push(format!(
                "{}: references undefined policy {:?}",
                metadata.name, spec.policy
            ));
            continue;
        };
        let candidate = match serde_json::from_value::<CandidateAction>(spec.candidate.clone()) {
            Ok(candidate) => candidate,
            Err(error) => {
                failures.push(format!("{}: invalid candidate: {error}", metadata.name));
                continue;
            }
        };
        let context = match serde_json::from_value::<PolicyContext>(spec.context.clone()) {
            Ok(context) => context,
            Err(error) => {
                failures.push(format!("{}: invalid context: {error}", metadata.name));
                continue;
            }
        };
        let decision = policy.evaluate(&candidate, &context);
        if decision.kind() != spec.expect.decision.as_policy_kind() {
            failures.push(format!(
                "{}: expected {}, got {}",
                metadata.name,
                spec.expect.decision.as_policy_kind(),
                decision.kind()
            ));
            continue;
        }
        if let Some(needle) = &spec.expect.reason_contains {
            let haystack = serde_json::to_string(&decision).unwrap_or_default();
            if !haystack.contains(needle) {
                failures.push(format!(
                    "{}: expected serialized decision to contain {:?}",
                    metadata.name, needle
                ));
            }
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures)
    }
}

pub fn migrate_paths(paths: &[PathBuf]) -> Result<Vec<PathBuf>, Vec<String>> {
    let mut rewritten = Vec::new();
    let mut errors = Vec::new();
    for path in paths {
        if path.is_dir() {
            for entry in WalkDir::new(path).into_iter().filter_map(Result::ok) {
                if entry.file_type().is_file()
                    && matches!(
                        entry.path().extension().and_then(|value| value.to_str()),
                        Some("yaml" | "yml")
                    )
                {
                    migrate_one(entry.path(), &mut rewritten, &mut errors);
                }
            }
        } else {
            migrate_one(path, &mut rewritten, &mut errors);
        }
    }
    if errors.is_empty() {
        Ok(rewritten)
    } else {
        Err(errors)
    }
}

fn migrate_one(path: &Path, rewritten: &mut Vec<PathBuf>, errors: &mut Vec<String>) {
    let source = match fs::read_to_string(path) {
        Ok(source) => source,
        Err(error) => {
            errors.push(format!("{}: {error}", path.display()));
            return;
        }
    };
    match migrate_legacy_document(path, &source) {
        Ok(Some(output)) => {
            if let Err(error) = fs::write(path, output) {
                errors.push(format!("{}: {error}", path.display()));
            } else {
                rewritten.push(path.to_path_buf());
            }
        }
        Ok(None) => {}
        Err(error) => errors.push(format!("{}: {error}", path.display())),
    }
}

pub fn migrate_legacy_document(path: &Path, source: &str) -> Result<Option<String>, String> {
    let mut value: serde_yaml::Value =
        serde_yaml::from_str(source).map_err(|error| error.to_string())?;
    let Some(mapping) = value.as_mapping_mut() else {
        return Ok(None);
    };
    let schema_key = serde_yaml::Value::String("schema_version".to_string());
    let Some(schema_version) = mapping
        .remove(&schema_key)
        .and_then(|value| value.as_str().map(ToString::to_string))
    else {
        return Ok(None);
    };
    mapping.remove(serde_yaml::Value::String("config_version".to_string()));
    let (kind, config) = migrate_legacy_config(schema_version.as_str(), value)?;
    let stem = path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("policy");
    let document = json!({
        "apiVersion": "velvet.io/v1alpha1",
        "kind": "Policy",
        "metadata": {
            "name": format!("{kind}-{stem}"),
            "version": 1,
        },
        "spec": {
            "type": kind,
            "config": config,
        }
    });
    serde_yaml::to_string(&document)
        .map(Some)
        .map_err(|error| error.to_string())
}

fn migrate_legacy_config(
    schema_version: &str,
    value: serde_yaml::Value,
) -> Result<(String, serde_yaml::Value), String> {
    match schema_version {
        "cost_ceiling.v1" => {
            let mut mapping = value
                .as_mapping()
                .cloned()
                .ok_or_else(|| "legacy cost ceiling config must be a mapping".to_string())?;
            let scopes = mapping
                .remove(serde_yaml::Value::String("scopes".to_string()))
                .and_then(|value| value.as_mapping().cloned())
                .unwrap_or_default();
            rename_key(&mut mapping, "soft_ceiling_ratio", "soft_ceiling_fraction");
            rename_key(&mut mapping, "action_costs", "cost_model");
            copy_nested_key(&scopes, &mut mapping, "task_usd", "per_task_usd_limit");
            copy_nested_key(
                &scopes,
                &mut mapping,
                "user_usd",
                "per_user_daily_usd_limit",
            );
            copy_nested_key(
                &scopes,
                &mut mapping,
                "organization_usd",
                "per_org_monthly_usd_limit",
            );
            Ok((
                "cost_ceiling".to_string(),
                serde_yaml::Value::Mapping(mapping),
            ))
        }
        "pii_guard.v1" => Ok(("pii_guard".to_string(), value)),
        "prompt_injection_detector.v1" => Ok(("prompt_injection_detector".to_string(), value)),
        "rate_limiter.v1" => Ok(("rate_limiter".to_string(), value)),
        "escalation_gate.v1" => Ok(("escalation_gate".to_string(), value)),
        other => Err(format!(
            "no migrator registered for legacy schema {other:?}"
        )),
    }
}

fn rename_key(mapping: &mut serde_yaml::Mapping, from: &str, to: &str) {
    if let Some(value) = mapping.remove(serde_yaml::Value::String(from.to_string())) {
        mapping.insert(serde_yaml::Value::String(to.to_string()), value);
    }
}

fn copy_nested_key(
    source: &serde_yaml::Mapping,
    target: &mut serde_yaml::Mapping,
    from: &str,
    to: &str,
) {
    if let Some(value) = source.get(serde_yaml::Value::String(from.to_string())) {
        target.insert(serde_yaml::Value::String(to.to_string()), value.clone());
    }
}

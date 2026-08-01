use std::collections::BTreeMap;
use std::fmt;

use chrono::{DateTime, SecondsFormat, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

pub const CANONICAL_ACTION_SCHEMA_VERSION: &str = "velvet.canonical_action.v1";
pub const PROPOSED_ACTION_SCHEMA_VERSION: &str = "velvet.proposed_action.v1";

type JsonObject = BTreeMap<String, Value>;

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum SurfaceKind {
    Mcp,
    Function,
    Rest,
    Sql,
    Github,
    ShellCode,
    Workflow,
    Connector,
}

impl SurfaceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Mcp => "mcp",
            Self::Function => "function",
            Self::Rest => "rest",
            Self::Sql => "sql",
            Self::Github => "github",
            Self::ShellCode => "shell_code",
            Self::Workflow => "workflow",
            Self::Connector => "connector",
        }
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuthorityClass {
    Observe,
    Append,
    Alter,
    Destroy,
    SpendLow,
    SpendHigh,
    BindExternal,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum MutationKind {
    None,
    Append,
    Alter,
    Destroy,
    Spend,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Reversibility {
    None,
    Reversible,
    Partial,
    Irreversible,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ProposedActionV1 {
    pub schema_version: String,
    pub surface: SurfaceKind,
    #[serde(default)]
    pub operation: Option<String>,
    #[serde(default)]
    pub payload: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RedactionSummary {
    pub redaction_count: usize,
    pub redacted_fields: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct CanonicalActionV1 {
    pub schema_version: String,
    pub action_id: String,
    pub actor_id: String,
    pub agent_id: String,
    pub tenant_id: String,
    pub environment: String,
    pub boundary_key: String,
    pub surface: SurfaceKind,
    pub tool_name: String,
    pub canonical_type: String,
    pub operation: String,
    pub authority_class: AuthorityClass,
    pub target_resource: String,
    pub economic_exposure: i64,
    pub external_party: Option<String>,
    pub mutation_kind: MutationKind,
    pub reversibility: Reversibility,
    pub read_set_hash: String,
    pub proposed_payload_hash: String,
    pub arguments_hash: String,
    pub tool_schema_hash: Option<String>,
    pub normalized_payload: JsonObject,
    pub redaction_summary: RedactionSummary,
    pub timestamp_input: String,
    pub contract_version: String,
    pub policy_version: String,
    pub provenance: JsonObject,
}

impl CanonicalActionV1 {
    pub fn canonical_action_hash(&self) -> String {
        sha256_hex_value(&serde_json::to_value(self).expect("canonical action serializes"))
    }

    pub fn to_payload(&self) -> Value {
        let mut payload = serde_json::to_value(self).expect("canonical action serializes");
        if let Value::Object(object) = &mut payload {
            object.insert(
                "canonical_action_hash".to_string(),
                Value::String(self.canonical_action_hash()),
            );
        }
        payload
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct NormalizationFailure {
    pub schema_version: String,
    pub reason: String,
    pub proposed_payload_hash: String,
    pub ambiguity_set: Vec<CanonicalActionV1>,
}

impl NormalizationFailure {
    fn new(reason: impl Into<String>, proposed: &Value) -> Self {
        Self {
            schema_version: "velvet.normalization_failure.v1".to_string(),
            reason: reason.into(),
            proposed_payload_hash: sha256_hex_value(proposed),
            ambiguity_set: Vec::new(),
        }
    }
}

impl fmt::Display for NormalizationFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.reason)
    }
}

impl std::error::Error for NormalizationFailure {}

#[derive(Debug, Clone)]
struct NormalizationConfig {
    contract_version: String,
    policy_version: String,
    spend_cap: i64,
    sql_dialect: String,
}

impl NormalizationConfig {
    fn from_value(value: Option<&Value>) -> Self {
        let default = Self {
            contract_version: "velvet.contract.v1".to_string(),
            policy_version: "velvet.policy.v1".to_string(),
            spend_cap: 500,
            sql_dialect: "postgres".to_string(),
        };
        let Some(value) = value else {
            return default;
        };
        Self {
            contract_version: string_at(value, "contract_version")
                .unwrap_or(default.contract_version),
            policy_version: string_at(value, "policy_version").unwrap_or(default.policy_version),
            spend_cap: int_at(value, "spend_cap").unwrap_or(default.spend_cap),
            sql_dialect: string_at(value, "sql_dialect").unwrap_or(default.sql_dialect),
        }
    }
}

#[derive(Debug, Clone)]
struct SurfaceFacts {
    surface: SurfaceKind,
    operation: String,
    tool_name: String,
    target_resource: String,
    arguments: Value,
    sql: Option<String>,
    normalized_payload: JsonObject,
    provenance: JsonObject,
    proxy_detected: bool,
}

pub fn normalize_action_v1(
    proposal: &Value,
    contract: Option<&Value>,
) -> Result<CanonicalActionV1, NormalizationFailure> {
    let raw_object = proposal.as_object().ok_or_else(|| {
        NormalizationFailure::new("Proposed action must be a JSON object.", proposal)
    })?;
    let config = NormalizationConfig::from_value(contract);
    let surface = discover_surface(proposal).ok_or_else(|| {
        NormalizationFailure::new("Proposed action surface is ambiguous.", proposal)
    })?;
    let facts = facts_for_surface(proposal, raw_object, surface, &config)?;
    let redaction = redact_value(&facts.arguments);
    let mut normalized_payload = facts.normalized_payload;
    normalized_payload.insert(
        "schema_version".to_string(),
        json!(CANONICAL_ACTION_SCHEMA_VERSION),
    );
    normalized_payload.insert("surface".to_string(), json!(facts.surface.as_str()));
    normalized_payload.insert("operation".to_string(), json!(facts.operation));
    normalized_payload.insert("tool_name".to_string(), json!(facts.tool_name));
    normalized_payload.insert("target_resource".to_string(), json!(facts.target_resource));
    normalized_payload.insert("arguments_redacted".to_string(), redaction.value);
    normalized_payload.insert("proxy_detected".to_string(), json!(facts.proxy_detected));

    let economic_exposure = economic_exposure(proposal);
    let external_party = external_party(proposal, facts.surface, &facts.operation);
    let mutation_kind = mutation_kind(facts.surface, &facts.operation, economic_exposure);
    let reversibility = reversibility(proposal, facts.surface, mutation_kind);
    let canonical_type = canonical_type(
        facts.surface,
        &facts.operation,
        mutation_kind,
        external_party.as_deref(),
        economic_exposure,
    );
    normalized_payload.insert("canonical_type".to_string(), json!(canonical_type));
    normalized_payload.insert(
        "mutation_kind".to_string(),
        json!(mutation_kind_value(mutation_kind)),
    );
    normalized_payload.insert("economic_exposure".to_string(), json!(economic_exposure));
    if let Some(aggregate) = split_aggregate_exposure(proposal, economic_exposure) {
        normalized_payload.insert("aggregated_economic_exposure".to_string(), json!(aggregate));
    }
    if let Some(split_group_key) = split_group_key(proposal, economic_exposure) {
        normalized_payload.insert("split_group_key".to_string(), json!(split_group_key));
    }
    if let Some(external_party) = &external_party {
        normalized_payload.insert("external_party".to_string(), json!(external_party));
        normalized_payload.insert("binds_external".to_string(), json!(true));
    }
    if let Some(sql) = &facts.sql {
        normalized_payload.insert(
            "sql_fingerprint".to_string(),
            json!(sha256_hex_value(&json!({"sql": sql}))),
        );
        normalized_payload.insert("sql_dialect".to_string(), json!(config.sql_dialect));
    }

    let authority_class = authority_class(
        external_party.as_deref(),
        mutation_kind,
        reversibility,
        economic_exposure,
        config.spend_cap,
    );
    normalized_payload.insert(
        "authority_class".to_string(),
        json!(authority_class_value(authority_class)),
    );

    let boundary_key = boundary_key(proposal);
    let proposed_payload_hash = sha256_hex_value(proposal);
    let arguments_hash = sha256_hex_value(&facts.arguments);
    let read_set_hash = string_at(proposal, "read_set_hash")
        .unwrap_or_else(|| sha256_hex_value(&json!({"read_set": value_at(proposal, "read_set").unwrap_or_else(|| json!(facts.target_resource))})));
    let tool_schema_hash = string_at(proposal, "tool_schema_hash")
        .or_else(|| string_at(proposal, "schema_hash"))
        .or_else(|| value_at(proposal, "input_schema").map(|schema| sha256_hex_value(&schema)));
    let action_id = string_at(proposal, "action_id").unwrap_or_else(|| {
        format!(
            "act_{}",
            &sha256_hex_value(&json!({
                "payload": proposed_payload_hash,
                "boundary": boundary_key,
                "surface": facts.surface.as_str(),
            }))[..24]
        )
    });

    Ok(CanonicalActionV1 {
        schema_version: CANONICAL_ACTION_SCHEMA_VERSION.to_string(),
        action_id,
        actor_id: string_at(proposal, "actor_id")
            .or_else(|| string_at(proposal, "user_id"))
            .unwrap_or_else(|| "actor".to_string()),
        agent_id: string_at(proposal, "agent_id").unwrap_or_else(|| "agent".to_string()),
        tenant_id: string_at(proposal, "tenant_id")
            .or_else(|| string_at(proposal, "organization_id"))
            .unwrap_or_else(|| "tenant:default".to_string()),
        environment: string_at(proposal, "environment").unwrap_or_else(|| "local".to_string()),
        boundary_key,
        surface: facts.surface,
        tool_name: facts.tool_name,
        canonical_type,
        operation: facts.operation,
        authority_class,
        target_resource: facts.target_resource,
        economic_exposure,
        external_party,
        mutation_kind,
        reversibility,
        read_set_hash,
        proposed_payload_hash,
        arguments_hash,
        tool_schema_hash,
        normalized_payload,
        redaction_summary: redaction.summary,
        timestamp_input: timestamp_input(proposal),
        contract_version: config.contract_version,
        policy_version: config.policy_version,
        provenance: facts.provenance,
    })
}

fn facts_for_surface(
    proposal: &Value,
    object: &Map<String, Value>,
    surface: SurfaceKind,
    config: &NormalizationConfig,
) -> Result<SurfaceFacts, NormalizationFailure> {
    match surface {
        SurfaceKind::Mcp => mcp_facts(proposal, object),
        SurfaceKind::Function => function_facts(proposal, object),
        SurfaceKind::Rest => rest_facts(proposal, object),
        SurfaceKind::Sql => sql_facts(proposal, object, config),
        SurfaceKind::Github => github_facts(proposal, object),
        SurfaceKind::ShellCode => shell_code_facts(proposal, object),
        SurfaceKind::Workflow => workflow_facts(proposal, object),
        SurfaceKind::Connector => connector_facts(proposal, object),
    }
}

fn discover_surface(proposal: &Value) -> Option<SurfaceKind> {
    if let Some(surface) = string_at(proposal, "surface")
        .or_else(|| string_at(proposal, "protocol"))
        .or_else(|| string_at(proposal, "kind"))
        .and_then(|surface| parse_surface(&surface))
    {
        return Some(surface);
    }
    if string_at(proposal, "method").as_deref() == Some("tools/call")
        || (value_at(proposal, "server").is_some() && value_at(proposal, "tool").is_some())
        || (value_at(proposal, "mcp_server").is_some() && value_at(proposal, "mcp_tool").is_some())
    {
        return Some(SurfaceKind::Mcp);
    }
    if value_at(proposal, "sql").is_some()
        || value_at(proposal, "query")
            .is_some_and(|value| value.as_str().is_some_and(looks_like_sql))
    {
        return Some(SurfaceKind::Sql);
    }
    if value_at(proposal, "url").is_some() && value_at(proposal, "method").is_some() {
        return Some(SurfaceKind::Rest);
    }
    if value_at(proposal, "github").is_some()
        || value_at(proposal, "repository").is_some()
        || value_at(proposal, "repo").is_some()
    {
        return Some(SurfaceKind::Github);
    }
    if value_at(proposal, "command").is_some()
        || value_at(proposal, "argv").is_some()
        || value_at(proposal, "code").is_some()
    {
        return Some(SurfaceKind::ShellCode);
    }
    if value_at(proposal, "workflow_id").is_some() || value_at(proposal, "workflow_name").is_some()
    {
        return Some(SurfaceKind::Workflow);
    }
    if value_at(proposal, "connector_id").is_some() || value_at(proposal, "connector").is_some() {
        return Some(SurfaceKind::Connector);
    }
    if value_at(proposal, "function").is_some() || value_at(proposal, "name").is_some() {
        return Some(SurfaceKind::Function);
    }
    None
}

fn parse_surface(value: &str) -> Option<SurfaceKind> {
    match normalize_token(value).as_str() {
        "mcp" => Some(SurfaceKind::Mcp),
        "function" | "function_call" | "tool_call" => Some(SurfaceKind::Function),
        "rest" | "http" | "https" => Some(SurfaceKind::Rest),
        "sql" | "database" => Some(SurfaceKind::Sql),
        "github" | "gh" => Some(SurfaceKind::Github),
        "shell" | "code" | "shell_code" | "execute_code" => Some(SurfaceKind::ShellCode),
        "workflow" | "workflow_engine" => Some(SurfaceKind::Workflow),
        "connector" | "app_connector" => Some(SurfaceKind::Connector),
        _ => None,
    }
}

fn mcp_facts(
    proposal: &Value,
    object: &Map<String, Value>,
) -> Result<SurfaceFacts, NormalizationFailure> {
    let (server, tool, arguments) = if string_at(proposal, "method").as_deref()
        == Some("tools/call")
    {
        let params = proposal
            .get("params")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                NormalizationFailure::new("MCP tools/call requires object params.", proposal)
            })?;
        let tool = params
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                NormalizationFailure::new("MCP tools/call requires params.name.", proposal)
            })?
            .to_string();
        let server = string_at(proposal, "server")
            .or_else(|| string_at(proposal, "mcp_server"))
            .unwrap_or_else(|| "mcp".to_string());
        let arguments = params
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| json!({}));
        (server, tool, arguments)
    } else {
        let server = string_from_object(object, "server")
            .or_else(|| string_from_object(object, "mcp_server"))
            .ok_or_else(|| NormalizationFailure::new("MCP action requires server.", proposal))?;
        let tool = string_from_object(object, "tool")
            .or_else(|| string_from_object(object, "mcp_tool"))
            .ok_or_else(|| NormalizationFailure::new("MCP action requires tool.", proposal))?;
        let arguments = object
            .get("arguments")
            .cloned()
            .unwrap_or_else(|| json!({}));
        (server, tool, arguments)
    };
    let operation = explicit_operation(proposal).unwrap_or_else(|| operation_from_name(&tool));
    let mut normalized_payload = JsonObject::new();
    normalized_payload.insert("mcp_server".to_string(), json!(server));
    normalized_payload.insert("mcp_tool".to_string(), json!(tool));
    Ok(SurfaceFacts {
        surface: SurfaceKind::Mcp,
        operation,
        tool_name: format!("{server}/{tool}"),
        target_resource: explicit_target(proposal)
            .unwrap_or_else(|| format!("mcp:{server}/{tool}")),
        arguments,
        sql: None,
        normalized_payload,
        provenance: provenance("mcp", "tools/call"),
        proxy_detected: false,
    })
}

fn function_facts(
    proposal: &Value,
    object: &Map<String, Value>,
) -> Result<SurfaceFacts, NormalizationFailure> {
    let function = object.get("function").and_then(Value::as_object);
    let name = function
        .and_then(|value| value.get("name"))
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .or_else(|| string_from_object(object, "name"))
        .or_else(|| string_from_object(object, "tool_name"))
        .ok_or_else(|| {
            NormalizationFailure::new("Function action requires a function name.", proposal)
        })?;
    let arguments = function
        .and_then(|value| value.get("arguments"))
        .cloned()
        .or_else(|| object.get("arguments").cloned())
        .unwrap_or_else(|| json!({}));
    let operation = explicit_operation(proposal).unwrap_or_else(|| operation_from_name(&name));
    let mut normalized_payload = JsonObject::new();
    normalized_payload.insert("function_name".to_string(), json!(name));
    Ok(SurfaceFacts {
        surface: SurfaceKind::Function,
        operation,
        tool_name: format!("function/{name}"),
        target_resource: explicit_target(proposal).unwrap_or_else(|| format!("function:{name}")),
        arguments,
        sql: None,
        normalized_payload,
        provenance: provenance("function", "function_call"),
        proxy_detected: false,
    })
}

fn rest_facts(
    proposal: &Value,
    object: &Map<String, Value>,
) -> Result<SurfaceFacts, NormalizationFailure> {
    let method = string_from_object(object, "method")
        .ok_or_else(|| NormalizationFailure::new("REST action requires method.", proposal))?
        .to_uppercase();
    let url = string_from_object(object, "url")
        .ok_or_else(|| NormalizationFailure::new("REST action requires url.", proposal))?;
    let arguments = object
        .get("body")
        .or_else(|| object.get("json"))
        .or_else(|| object.get("data"))
        .cloned()
        .unwrap_or_else(|| json!({}));
    let operation = explicit_operation(proposal).unwrap_or_else(|| rest_operation(&method));
    let mut normalized_payload = JsonObject::new();
    normalized_payload.insert("http_method".to_string(), json!(method));
    normalized_payload.insert("url_redacted".to_string(), json!(redact_url(&url)));
    Ok(SurfaceFacts {
        surface: SurfaceKind::Rest,
        operation,
        tool_name: format!("rest/{}", method.to_lowercase()),
        target_resource: explicit_target(proposal)
            .unwrap_or_else(|| format!("rest:{method}:{}", redact_url(&url))),
        arguments,
        sql: None,
        normalized_payload,
        provenance: provenance("rest", "http_request"),
        proxy_detected: false,
    })
}

fn sql_facts(
    proposal: &Value,
    object: &Map<String, Value>,
    _config: &NormalizationConfig,
) -> Result<SurfaceFacts, NormalizationFailure> {
    let sql = string_from_object(object, "sql")
        .or_else(|| string_from_object(object, "query"))
        .ok_or_else(|| NormalizationFailure::new("SQL action requires sql.", proposal))?;
    let parsed =
        parse_sql_intent(&sql).map_err(|reason| NormalizationFailure::new(reason, proposal))?;
    let mut normalized_payload = JsonObject::new();
    normalized_payload.insert("sql_ast_kind".to_string(), json!(parsed.ast_kind));
    normalized_payload.insert("sql_target_resources".to_string(), json!(parsed.targets));
    normalized_payload.insert("sql_lift_rule".to_string(), json!(parsed.lift_rule));
    normalized_payload.insert("sql_intent".to_string(), json!(parsed.operation));
    Ok(SurfaceFacts {
        surface: SurfaceKind::Sql,
        operation: parsed.operation,
        tool_name: parsed.tool_name,
        target_resource: explicit_target(proposal).unwrap_or(parsed.target_resource),
        arguments: json!({"sql": sql}),
        sql: Some(parsed.normalized_sql),
        normalized_payload,
        provenance: provenance("sql", "sql_lift"),
        proxy_detected: true,
    })
}

fn github_facts(
    proposal: &Value,
    object: &Map<String, Value>,
) -> Result<SurfaceFacts, NormalizationFailure> {
    let repo = string_from_object(object, "repository")
        .or_else(|| string_from_object(object, "repo"))
        .or_else(|| {
            let owner = string_from_object(object, "owner")?;
            let name = string_from_object(object, "repo_name")
                .or_else(|| string_from_object(object, "name"))?;
            Some(format!("{owner}/{name}"))
        })
        .ok_or_else(|| NormalizationFailure::new("GitHub action requires repository.", proposal))?;
    let operation = explicit_operation(proposal)
        .or_else(|| string_from_object(object, "github_operation"))
        .unwrap_or_else(|| {
            operation_from_name(
                &string_from_object(object, "tool").unwrap_or_else(|| "read".to_string()),
            )
        });
    let arguments = object
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let mut normalized_payload = JsonObject::new();
    normalized_payload.insert("repository".to_string(), json!(repo));
    if let Some(issue) = object.get("issue_number").and_then(Value::as_i64) {
        normalized_payload.insert("issue_number".to_string(), json!(issue));
    }
    if let Some(pr) = object.get("pull_request_number").and_then(Value::as_i64) {
        normalized_payload.insert("pull_request_number".to_string(), json!(pr));
    }
    Ok(SurfaceFacts {
        surface: SurfaceKind::Github,
        operation: normalize_token(&operation),
        tool_name: format!("github/{}", normalize_token(&operation)),
        target_resource: explicit_target(proposal).unwrap_or_else(|| format!("github:repo:{repo}")),
        arguments,
        sql: None,
        normalized_payload,
        provenance: provenance("github", "github_api"),
        proxy_detected: false,
    })
}

fn shell_code_facts(
    proposal: &Value,
    object: &Map<String, Value>,
) -> Result<SurfaceFacts, NormalizationFailure> {
    let arguments = json!({
        "command": object.get("command").cloned(),
        "argv": object.get("argv").cloned(),
        "code": object.get("code").cloned(),
        "cwd": object.get("cwd").cloned(),
        "env": object.get("env").cloned(),
    });
    if object.get("command").is_none()
        && object.get("argv").is_none()
        && object.get("code").is_none()
    {
        return Err(NormalizationFailure::new(
            "Shell/code action requires command, argv, or code.",
            proposal,
        ));
    }
    let operation = explicit_operation(proposal).unwrap_or_else(|| "execute".to_string());
    let command_label = string_from_object(object, "command")
        .or_else(|| object.get("argv").map(short_value_label))
        .or_else(|| {
            string_from_object(object, "language").map(|language| format!("{language}:code"))
        })
        .unwrap_or_else(|| "code".to_string());
    let mut normalized_payload = JsonObject::new();
    normalized_payload.insert("sandbox_required".to_string(), json!(true));
    normalized_payload.insert(
        "command_fingerprint".to_string(),
        json!(sha256_hex_value(&arguments)),
    );
    Ok(SurfaceFacts {
        surface: SurfaceKind::ShellCode,
        operation: normalize_token(&operation),
        tool_name: "shell_code/execute".to_string(),
        target_resource: explicit_target(proposal)
            .unwrap_or_else(|| format!("shell_code:{}", command_label)),
        arguments,
        sql: None,
        normalized_payload,
        provenance: provenance("shell_code", "sandbox_required"),
        proxy_detected: false,
    })
}

fn workflow_facts(
    proposal: &Value,
    object: &Map<String, Value>,
) -> Result<SurfaceFacts, NormalizationFailure> {
    let workflow = string_from_object(object, "workflow_id")
        .or_else(|| string_from_object(object, "workflow_name"))
        .ok_or_else(|| {
            NormalizationFailure::new(
                "Workflow action requires workflow_id or workflow_name.",
                proposal,
            )
        })?;
    let operation = explicit_operation(proposal).unwrap_or_else(|| "trigger".to_string());
    let arguments = object
        .get("inputs")
        .or_else(|| object.get("arguments"))
        .cloned()
        .unwrap_or_else(|| json!({}));
    let mut normalized_payload = JsonObject::new();
    normalized_payload.insert("workflow_id".to_string(), json!(workflow));
    Ok(SurfaceFacts {
        surface: SurfaceKind::Workflow,
        operation: normalize_token(&operation),
        tool_name: format!("workflow/{workflow}"),
        target_resource: explicit_target(proposal)
            .unwrap_or_else(|| format!("workflow:{workflow}")),
        arguments,
        sql: None,
        normalized_payload,
        provenance: provenance("workflow", "workflow_engine"),
        proxy_detected: false,
    })
}

fn connector_facts(
    proposal: &Value,
    object: &Map<String, Value>,
) -> Result<SurfaceFacts, NormalizationFailure> {
    let connector = string_from_object(object, "connector_id")
        .or_else(|| string_from_object(object, "connector"))
        .ok_or_else(|| {
            NormalizationFailure::new("Connector action requires connector_id.", proposal)
        })?;
    let provider =
        string_from_object(object, "provider").unwrap_or_else(|| "connector".to_string());
    let operation = explicit_operation(proposal).unwrap_or_else(|| operation_from_name(&connector));
    let arguments = object
        .get("inputs")
        .or_else(|| object.get("arguments"))
        .cloned()
        .unwrap_or_else(|| json!({}));
    let mut normalized_payload = JsonObject::new();
    normalized_payload.insert("connector_id".to_string(), json!(connector));
    normalized_payload.insert("provider".to_string(), json!(provider));
    Ok(SurfaceFacts {
        surface: SurfaceKind::Connector,
        operation: normalize_token(&operation),
        tool_name: format!("connector/{provider}/{connector}"),
        target_resource: explicit_target(proposal)
            .unwrap_or_else(|| format!("connector:{provider}:{connector}")),
        arguments,
        sql: None,
        normalized_payload,
        provenance: provenance("connector", "app_connector"),
        proxy_detected: false,
    })
}

#[derive(Debug, Clone)]
struct ParsedSql {
    normalized_sql: String,
    ast_kind: String,
    operation: String,
    tool_name: String,
    target_resource: String,
    targets: Vec<String>,
    lift_rule: String,
}

fn parse_sql_intent(sql: &str) -> Result<ParsedSql, String> {
    let normalized_sql = normalize_sql_text(sql);
    if normalized_sql.is_empty() {
        return Err("SQL payload is empty.".to_string());
    }
    let statements = split_sql_statements(&normalized_sql)?;
    if statements.len() != 1 {
        return Err("SQL payload did not resolve to one canonical statement.".to_string());
    }
    let statement = statements[0].trim();
    let upper = statement.to_uppercase();
    let first = upper
        .split_whitespace()
        .next()
        .ok_or_else(|| "SQL payload is empty.".to_string())?;
    let targets = sql_targets(statement);
    let target_resource = if targets.is_empty() {
        "sql:resource:unknown".to_string()
    } else {
        targets.join(",")
    };
    let (operation, tool_name, lift_rule) = match first {
        "DROP" => ("drop_table", "sql.destroy_proxy", "sql:drop:destroy"),
        "TRUNCATE" => ("drop_table", "sql.destroy_proxy", "sql:truncate:destroy"),
        "DELETE" => {
            if !upper.contains(" FROM ") {
                return Err("DELETE SQL payload is missing FROM.".to_string());
            }
            ("delete_rows", "sql.destroy_proxy", "sql:delete:destroy")
        }
        "ALTER" => {
            if upper.contains(" DROP ") {
                (
                    "sql_destructive_alter",
                    "sql.destroy_proxy",
                    "sql:alter-drop:destroy",
                )
            } else {
                ("sql_alter", "sql.alter_proxy", "sql:alter:alter")
            }
        }
        "UPDATE" => {
            if !upper.contains(" SET ") {
                return Err("UPDATE SQL payload is missing SET.".to_string());
            }
            ("sql_alter", "sql.alter_proxy", "sql:update:alter")
        }
        "CREATE" => ("sql_create", "sql.append_proxy", "sql:create:append"),
        "INSERT" => {
            if !upper.contains(" INTO ") {
                return Err("INSERT SQL payload is missing INTO.".to_string());
            }
            ("sql_append", "sql.append_proxy", "sql:insert:append")
        }
        "SELECT" => {
            if upper.starts_with("SELECT FROM") || upper == "SELECT" {
                return Err("SELECT SQL payload is malformed.".to_string());
            }
            ("sql_observe", "sql.observe", "sql:select:observe")
        }
        "SHOW" | "DESCRIBE" | "EXPLAIN" => ("sql_observe", "sql.observe", "sql:command:observe"),
        _ => return Err("SQL payload did not match a deterministic lift rule.".to_string()),
    };
    Ok(ParsedSql {
        normalized_sql: statement.to_string(),
        ast_kind: first.to_lowercase(),
        operation: operation.to_string(),
        tool_name: tool_name.to_string(),
        target_resource,
        targets,
        lift_rule: lift_rule.to_string(),
    })
}

fn normalize_sql_text(sql: &str) -> String {
    let mut output = String::new();
    let chars = sql.chars().collect::<Vec<_>>();
    let mut index = 0;
    let mut in_block = false;
    while index < chars.len() {
        if in_block {
            if chars[index] == '*' && chars.get(index + 1) == Some(&'/') {
                in_block = false;
                index += 2;
            } else {
                index += 1;
            }
            continue;
        }
        if chars[index] == '/' && chars.get(index + 1) == Some(&'*') {
            in_block = true;
            index += 2;
            continue;
        }
        if chars[index] == '-' && chars.get(index + 1) == Some(&'-') {
            while index < chars.len() && chars[index] != '\n' {
                index += 1;
            }
            continue;
        }
        output.push(chars[index]);
        index += 1;
    }
    output.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn split_sql_statements(sql: &str) -> Result<Vec<String>, String> {
    let mut statements = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let mut previous = '\0';
    for character in sql.chars() {
        if let Some(active) = quote {
            current.push(character);
            if character == active && previous != '\\' {
                quote = None;
            }
            previous = character;
            continue;
        }
        match character {
            '\'' | '"' => {
                quote = Some(character);
                current.push(character);
            }
            ';' => {
                if !current.trim().is_empty() {
                    statements.push(current.trim().to_string());
                }
                current.clear();
            }
            _ => current.push(character),
        }
        previous = character;
    }
    if quote.is_some() {
        return Err("SQL payload contains an unterminated quoted string.".to_string());
    }
    if !current.trim().is_empty() {
        statements.push(current.trim().to_string());
    }
    Ok(statements)
}

fn sql_targets(statement: &str) -> Vec<String> {
    let tokens = statement
        .split(|character: char| {
            character.is_whitespace() || matches!(character, ',' | '(' | ')' | ';')
        })
        .filter(|token| !token.is_empty())
        .collect::<Vec<_>>();
    let mut targets = Vec::new();
    for (index, token) in tokens.iter().enumerate() {
        let upper = token.to_uppercase();
        if matches!(
            upper.as_str(),
            "FROM" | "JOIN" | "UPDATE" | "INTO" | "TABLE"
        ) && let Some(next) = tokens.get(index + 1)
        {
            let cleaned = next.trim_matches('"').trim_matches('`').to_lowercase();
            if !cleaned.is_empty()
                && !matches!(cleaned.as_str(), "if" | "only" | "where" | "set" | "values")
            {
                targets.push(format!("sql_table:{cleaned}"));
            }
        }
    }
    targets.sort();
    targets.dedup();
    targets
}

fn explicit_operation(proposal: &Value) -> Option<String> {
    for key in ["operation", "action", "tool_operation", "intent"] {
        if let Some(value) = string_at(proposal, key) {
            return Some(normalize_token(&value));
        }
    }
    None
}

fn explicit_target(proposal: &Value) -> Option<String> {
    for key in ["target_resource", "resource", "target"] {
        if let Some(value) = string_at(proposal, key) {
            return Some(value);
        }
    }
    None
}

fn operation_from_name(name: &str) -> String {
    let normalized = normalize_token(name);
    normalized
        .split('_')
        .next()
        .filter(|value| !value.is_empty())
        .unwrap_or("call")
        .to_string()
}

fn rest_operation(method: &str) -> String {
    match method {
        "GET" | "HEAD" | "OPTIONS" => "read".to_string(),
        "POST" => "append".to_string(),
        "PUT" | "PATCH" => "update".to_string(),
        "DELETE" => "delete".to_string(),
        _ => "call".to_string(),
    }
}

fn mutation_kind(surface: SurfaceKind, operation: &str, economic_exposure: i64) -> MutationKind {
    if economic_exposure > 0 || SPEND_OPS.contains(&operation) {
        return MutationKind::Spend;
    }
    if DESTROY_OPS.contains(&operation) {
        return MutationKind::Destroy;
    }
    if ALTER_OPS.contains(&operation) {
        return MutationKind::Alter;
    }
    if APPEND_OPS.contains(&operation) {
        return MutationKind::Append;
    }
    if READ_OPS.contains(&operation) {
        return MutationKind::None;
    }
    match surface {
        SurfaceKind::ShellCode => MutationKind::Alter,
        SurfaceKind::Workflow | SurfaceKind::Connector => MutationKind::Alter,
        SurfaceKind::Rest | SurfaceKind::Mcp | SurfaceKind::Function | SurfaceKind::Github => {
            MutationKind::Alter
        }
        SurfaceKind::Sql => MutationKind::None,
    }
}

fn reversibility(
    proposal: &Value,
    surface: SurfaceKind,
    mutation_kind: MutationKind,
) -> Reversibility {
    if let Some(value) = string_at(proposal, "reversibility") {
        match normalize_token(&value).as_str() {
            "none" => return Reversibility::None,
            "reversible" => return Reversibility::Reversible,
            "partial" => return Reversibility::Partial,
            "irreversible" => return Reversibility::Irreversible,
            _ => {}
        }
    }
    match mutation_kind {
        MutationKind::None => Reversibility::None,
        MutationKind::Destroy => Reversibility::Irreversible,
        MutationKind::Spend => Reversibility::Partial,
        MutationKind::Alter if surface == SurfaceKind::ShellCode => Reversibility::Partial,
        MutationKind::Alter => Reversibility::Reversible,
        MutationKind::Append => Reversibility::Reversible,
    }
}

fn canonical_type(
    surface: SurfaceKind,
    operation: &str,
    mutation_kind: MutationKind,
    external_party: Option<&str>,
    economic_exposure: i64,
) -> String {
    if external_party.is_some() && economic_exposure == 0 {
        return "external_commitment".to_string();
    }
    if mutation_kind == MutationKind::Spend {
        return "monetary_transfer".to_string();
    }
    if surface == SurfaceKind::Sql {
        return operation.to_string();
    }
    match mutation_kind {
        MutationKind::None => format!("{}_observe", surface.as_str()),
        MutationKind::Append => format!("{}_append", surface.as_str()),
        MutationKind::Alter => format!("{}_alter", surface.as_str()),
        MutationKind::Destroy => format!("{}_destroy", surface.as_str()),
        MutationKind::Spend => "monetary_transfer".to_string(),
    }
}

fn authority_class(
    external_party: Option<&str>,
    mutation_kind: MutationKind,
    reversibility: Reversibility,
    economic_exposure: i64,
    spend_cap: i64,
) -> AuthorityClass {
    if external_party.is_some() {
        return AuthorityClass::BindExternal;
    }
    if mutation_kind == MutationKind::Destroy || reversibility == Reversibility::Irreversible {
        return AuthorityClass::Destroy;
    }
    if economic_exposure > spend_cap {
        return AuthorityClass::SpendHigh;
    }
    if economic_exposure > 0 {
        return AuthorityClass::SpendLow;
    }
    match mutation_kind {
        MutationKind::None => AuthorityClass::Observe,
        MutationKind::Append => AuthorityClass::Append,
        MutationKind::Alter => AuthorityClass::Alter,
        MutationKind::Destroy => AuthorityClass::Destroy,
        MutationKind::Spend => AuthorityClass::SpendLow,
    }
}

fn economic_exposure(proposal: &Value) -> i64 {
    for key in [
        "economic_exposure",
        "amount",
        "refund_amount",
        "coupon_amount",
        "payment_amount",
        "spend_amount",
    ] {
        if let Some(value) = int_at(proposal, key) {
            return value.max(0);
        }
    }
    0
}

fn split_aggregate_exposure(proposal: &Value, economic_exposure: i64) -> Option<i64> {
    let batch_count = int_at(proposal, "_velvet_batch_count").unwrap_or(0);
    let aggregate = int_at(proposal, "_velvet_batch_aggregate_exposure")?;
    if batch_count > 1 && aggregate > economic_exposure {
        return Some(aggregate);
    }
    None
}

fn split_group_key(proposal: &Value, economic_exposure: i64) -> Option<String> {
    if let Some(value) = string_at(proposal, "split_group_key") {
        return Some(value);
    }
    if economic_exposure <= 0 || int_at(proposal, "_velvet_batch_count").unwrap_or(0) <= 1 {
        return None;
    }
    let customer = string_at(proposal, "customer_id");
    let refund_case = string_at(proposal, "refund_case_id");
    if customer.is_none() && refund_case.is_none() {
        return None;
    }
    Some(format!(
        "money:{}:{}:{}",
        boundary_key(proposal),
        customer.unwrap_or_else(|| "none".to_string()),
        refund_case.unwrap_or_else(|| "none".to_string())
    ))
}

fn external_party(proposal: &Value, surface: SurfaceKind, operation: &str) -> Option<String> {
    for key in ["external_party", "email_to", "vendor_id", "third_party"] {
        if let Some(value) = string_at(proposal, key) {
            return Some(value);
        }
    }
    if bool_at(proposal, "binds_external") == Some(true) || EXTERNAL_OPS.contains(&operation) {
        return Some("external:declared".to_string());
    }
    if matches!(surface, SurfaceKind::Workflow | SurfaceKind::Connector)
        && mutation_kind(surface, operation, economic_exposure(proposal)) != MutationKind::None
    {
        return Some(format!("{}:declared", surface.as_str()));
    }
    None
}

fn boundary_key(proposal: &Value) -> String {
    if let Some(boundary_key) = string_at(proposal, "boundary_key") {
        return boundary_key;
    }
    let agent_id = string_at(proposal, "agent_id").unwrap_or_else(|| "agent".to_string());
    if let (Some(org), Some(workflow)) = (
        string_at(proposal, "organization_id"),
        string_at(proposal, "workflow_id"),
    ) {
        return format!("organization:{org}:agent:{agent_id}:workflow:{workflow}");
    }
    if let (Some(user), Some(session)) = (
        string_at(proposal, "user_id"),
        string_at(proposal, "session_id"),
    ) {
        return format!("user:{user}:agent:{agent_id}:session:{session}");
    }
    if let (Some(customer), Some(case_id)) = (
        string_at(proposal, "customer_id"),
        string_at(proposal, "refund_case_id"),
    ) {
        return format!("customer:{customer}:refund_case:{case_id}");
    }
    if let (Some(database), Some(migration)) = (
        string_at(proposal, "database_id"),
        string_at(proposal, "migration_task_id"),
    ) {
        return format!("database:{database}:migration:{migration}");
    }
    format!("agent:{agent_id}:default")
}

fn timestamp_input(proposal: &Value) -> String {
    let Some(value) = string_at(proposal, "timestamp_input")
        .or_else(|| string_at(proposal, "timestamp"))
        .or_else(|| string_at(proposal, "requested_at"))
    else {
        return "1970-01-01T00:00:00.000Z".to_string();
    };
    if let Ok(parsed) = DateTime::parse_from_rfc3339(&value) {
        return parsed
            .with_timezone(&Utc)
            .to_rfc3339_opts(SecondsFormat::Millis, true);
    }
    value
}

fn provenance(adapter: &str, rule: &str) -> JsonObject {
    BTreeMap::from([
        ("normalizer".to_string(), json!("velvet-core")),
        ("adapter".to_string(), json!(adapter)),
        ("rule".to_string(), json!(rule)),
        (
            "schema_version".to_string(),
            json!(PROPOSED_ACTION_SCHEMA_VERSION),
        ),
    ])
}

struct Redacted {
    value: Value,
    summary: RedactionSummary,
}

fn redact_value(value: &Value) -> Redacted {
    let mut fields = Vec::new();
    let value = redact_value_inner(value, "$", &mut fields);
    fields.sort();
    fields.dedup();
    Redacted {
        value,
        summary: RedactionSummary {
            redaction_count: fields.len(),
            redacted_fields: fields,
        },
    }
}

fn redact_value_inner(value: &Value, path: &str, fields: &mut Vec<String>) -> Value {
    match value {
        Value::Object(object) => {
            let mut redacted = Map::new();
            for (key, child) in object {
                let child_path = format!("{path}.{key}");
                if is_sensitive_key(key) {
                    redacted.insert(key.clone(), json!("[REDACTED]"));
                    fields.push(child_path);
                } else {
                    redacted.insert(key.clone(), redact_value_inner(child, &child_path, fields));
                }
            }
            Value::Object(redacted)
        }
        Value::Array(items) => Value::Array(
            items
                .iter()
                .enumerate()
                .map(|(index, child)| {
                    redact_value_inner(child, &format!("{path}[{index}]"), fields)
                })
                .collect(),
        ),
        _ => value.clone(),
    }
}

fn is_sensitive_key(key: &str) -> bool {
    let normalized = normalize_token(key);
    normalized.contains("password")
        || normalized.contains("secret")
        || normalized.contains("token")
        || normalized.contains("authorization")
        || normalized.contains("api_key")
        || normalized == "key"
}

fn redact_url(url: &str) -> String {
    let Some((prefix, _query)) = url.split_once('?') else {
        return url.to_string();
    };
    format!("{prefix}?[REDACTED]")
}

fn looks_like_sql(value: &str) -> bool {
    matches!(
        value
            .split_whitespace()
            .next()
            .map(|token| token.to_uppercase())
            .as_deref(),
        Some(
            "SELECT"
                | "UPDATE"
                | "DELETE"
                | "INSERT"
                | "CREATE"
                | "DROP"
                | "ALTER"
                | "TRUNCATE"
                | "SHOW"
                | "DESCRIBE"
                | "EXPLAIN"
        )
    )
}

fn normalize_token(value: &str) -> String {
    value
        .trim()
        .to_lowercase()
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character
            } else {
                '_'
            }
        })
        .collect::<String>()
        .split('_')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("_")
}

fn value_at(value: &Value, key: &str) -> Option<Value> {
    value
        .get(key)
        .cloned()
        .or_else(|| {
            value
                .get("payload")
                .and_then(|payload| payload.get(key))
                .cloned()
        })
        .or_else(|| {
            value
                .get("metadata")
                .and_then(|metadata| metadata.get(key))
                .cloned()
        })
}

fn string_at(value: &Value, key: &str) -> Option<String> {
    value_at(value, key).and_then(|value| match value {
        Value::String(value) if !value.trim().is_empty() => Some(value),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        _ => None,
    })
}

fn int_at(value: &Value, key: &str) -> Option<i64> {
    value_at(value, key).and_then(|value| match value {
        Value::Number(value) => value
            .as_i64()
            .or_else(|| value.as_u64().map(|value| value as i64)),
        Value::String(value) => value.parse::<i64>().ok(),
        Value::Bool(value) => Some(i64::from(value)),
        _ => None,
    })
}

fn bool_at(value: &Value, key: &str) -> Option<bool> {
    value_at(value, key).and_then(|value| match value {
        Value::Bool(value) => Some(value),
        Value::String(value) => match normalize_token(&value).as_str() {
            "true" | "yes" | "1" => Some(true),
            "false" | "no" | "0" => Some(false),
            _ => None,
        },
        _ => None,
    })
}

fn string_from_object(object: &Map<String, Value>, key: &str) -> Option<String> {
    object.get(key).and_then(|value| match value {
        Value::String(value) if !value.trim().is_empty() => Some(value.to_string()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        _ => None,
    })
}

fn short_value_label(value: &Value) -> String {
    let hash = sha256_hex_value(value);
    format!("hash:{}", &hash[..16])
}

fn sha256_hex_value(value: &Value) -> String {
    let bytes = serde_json::to_vec(value).expect("JSON value serializes");
    let digest = Sha256::digest(bytes);
    format!("{digest:x}")
}

fn authority_class_value(value: AuthorityClass) -> &'static str {
    match value {
        AuthorityClass::Observe => "OBSERVE",
        AuthorityClass::Append => "APPEND",
        AuthorityClass::Alter => "ALTER",
        AuthorityClass::Destroy => "DESTROY",
        AuthorityClass::SpendLow => "SPEND_LOW",
        AuthorityClass::SpendHigh => "SPEND_HIGH",
        AuthorityClass::BindExternal => "BIND_EXTERNAL",
    }
}

fn mutation_kind_value(value: MutationKind) -> &'static str {
    match value {
        MutationKind::None => "none",
        MutationKind::Append => "append",
        MutationKind::Alter => "alter",
        MutationKind::Destroy => "destroy",
        MutationKind::Spend => "spend",
    }
}

const READ_OPS: &[&str] = &[
    "read",
    "select",
    "get",
    "list",
    "search",
    "observe",
    "head",
    "show",
    "describe",
    "explain",
    "read_rows",
    "select_rows",
    "sql_observe",
];
const APPEND_OPS: &[&str] = &[
    "append",
    "insert",
    "create",
    "add",
    "comment",
    "open",
    "post",
    "log",
    "append_record",
    "append_audit_note",
    "sql_append",
    "sql_create",
];
const ALTER_OPS: &[&str] = &[
    "update",
    "modify",
    "patch",
    "edit",
    "merge",
    "close",
    "trigger",
    "run",
    "execute",
    "call",
    "put",
    "alter",
    "update_customer",
    "update_row",
    "sql_alter",
];
const DESTROY_OPS: &[&str] = &[
    "delete",
    "remove",
    "destroy",
    "drop",
    "truncate",
    "delete_row",
    "delete_rows",
    "drop_table",
    "sql_destructive_alter",
];
const SPEND_OPS: &[&str] = &[
    "refund",
    "issue_refund",
    "coupon",
    "payment",
    "credit",
    "charge",
    "transfer",
    "monetary_transfer",
];
const EXTERNAL_OPS: &[&str] = &[
    "send",
    "send_email",
    "email",
    "notify",
    "notify_customer",
    "publish",
    "vendor_commitment",
    "legal_filing",
    "external_api_mutation",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sql_drop_normalizes_to_destroy() {
        let action = normalize_action_v1(
            &json!({"surface": "sql", "sql": "/* maintenance */ DROP TABLE customers"}),
            None,
        )
        .unwrap();
        assert_eq!(action.authority_class, AuthorityClass::Destroy);
        assert_eq!(action.canonical_type, "drop_table");
        assert_eq!(action.normalized_payload["proxy_detected"], json!(true));
    }

    #[test]
    fn malformed_sql_fails_closed() {
        let error =
            normalize_action_v1(&json!({"surface": "sql", "sql": "SELECT FROM WHERE"}), None)
                .unwrap_err();
        assert!(error.reason.contains("malformed"));
    }

    #[test]
    fn all_surfaces_normalize() {
        let proposals = [
            json!({"surface": "mcp", "server": "servicenow", "tool": "search_records", "arguments": {"q": "x"}}),
            json!({"surface": "function", "name": "update_customer", "arguments": {"id": 1}}),
            json!({"surface": "rest", "method": "DELETE", "url": "https://api.example.com/a?token=secret"}),
            json!({"surface": "github", "repository": "acme/repo", "operation": "merge"}),
            json!({"surface": "shell_code", "command": "make deploy", "env": {"API_TOKEN": "x"}}),
            json!({"surface": "workflow", "workflow_id": "deploy-prod"}),
            json!({"surface": "connector", "provider": "salesforce", "connector_id": "case-update"}),
        ];
        for proposal in proposals {
            let action = normalize_action_v1(&proposal, None).unwrap();
            assert_eq!(action.schema_version, CANONICAL_ACTION_SCHEMA_VERSION);
            assert!(!action.canonical_action_hash().is_empty());
        }
    }

    #[test]
    fn redacts_sensitive_arguments() {
        let action = normalize_action_v1(
            &json!({
                "surface": "function",
                "name": "send_email",
                "arguments": {"api_token": "secret", "body": "hello"}
            }),
            None,
        )
        .unwrap();
        assert_eq!(action.redaction_summary.redaction_count, 1);
        assert_eq!(
            action.normalized_payload["arguments_redacted"]["api_token"],
            json!("[REDACTED]")
        );
    }
}

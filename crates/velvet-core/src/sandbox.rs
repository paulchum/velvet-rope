use std::{collections::BTreeMap, path::Path};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::{ActionType, CandidateAction, JsonObject};

#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeMode {
    #[default]
    Development,
    Production,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum SandboxBackendKind {
    None,
    Lightweight,
    Container,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ContainerRuntime {
    Podman,
    Docker,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum MountMode {
    ReadOnly,
    ReadWrite,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
pub struct MountSpec {
    pub host_path: String,
    pub sandbox_path: String,
    pub mode: MountMode,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
pub struct EgressRule {
    pub host: String,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default = "default_egress_protocol")]
    pub protocol: String,
}

fn default_egress_protocol() -> String {
    "tcp".to_string()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SandboxedCommand {
    pub argv: Vec<String>,
    pub cwd: String,
    #[serde(default)]
    pub env_list: Vec<String>,
    #[serde(default)]
    pub stdin: Option<Vec<u8>>,
    #[serde(default)]
    pub mounts: Vec<MountSpec>,
    #[serde(default)]
    pub egress_list: Vec<EgressRule>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ResourceLimits {
    pub cpu_seconds: u32,
    pub memory_bytes: u64,
    pub wall_clock_ms: u32,
    pub max_fs_writes_bytes: u64,
    pub max_stdout_bytes: u64,
    pub max_processes: u32,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            cpu_seconds: 10,
            memory_bytes: 512 * 1024 * 1024,
            wall_clock_ms: 10_000,
            max_fs_writes_bytes: 8 * 1024 * 1024,
            max_stdout_bytes: 12_000,
            max_processes: 64,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum OutputTransform {
    StripTimestampsV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum NetworkPolicy {
    DenyAll,
    List { rules: Vec<EgressRule> },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SandboxProvenance {
    pub backend: SandboxBackendKind,
    pub profile_hash: String,
    #[serde(default)]
    pub image_digest: Option<String>,
    #[serde(default)]
    pub container_runtime: Option<ContainerRuntime>,
    pub mount_spec: Vec<MountSpec>,
    pub network_policy: NetworkPolicy,
    pub applied_limits: ResourceLimits,
    #[serde(default)]
    pub backend_guarantees: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SandboxExecutionPlan {
    pub backend: SandboxBackendKind,
    pub command: SandboxedCommand,
    pub limits: ResourceLimits,
    pub output_transforms: Vec<OutputTransform>,
    pub provenance: SandboxProvenance,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SandboxViolation {
    pub kind: String,
    pub message: String,
    #[serde(default)]
    pub details: JsonObject,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct SandboxConfig {
    pub mode: RuntimeMode,
    pub backend: Option<SandboxBackendKind>,
    pub allow_unsafe_exec: bool,
    pub allow_macos_lightweight_broad_reads: bool,
    pub container_runtime: Option<ContainerRuntime>,
    pub container_image: Option<String>,
    pub env_list: Vec<String>,
    pub mounts: Vec<MountSpec>,
    pub egress_list: Vec<EgressRule>,
    pub limits: ResourceLimits,
    pub output_transforms: Vec<OutputTransform>,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            mode: RuntimeMode::Development,
            backend: None,
            allow_unsafe_exec: false,
            allow_macos_lightweight_broad_reads: false,
            container_runtime: None,
            container_image: None,
            env_list: Vec::new(),
            mounts: Vec::new(),
            egress_list: Vec::new(),
            limits: ResourceLimits::default(),
            output_transforms: vec![OutputTransform::StripTimestampsV1],
        }
    }
}

impl SandboxConfig {
    pub fn from_state(state: &Value) -> Result<Self, String> {
        let raw = state.get("sandbox_config").or_else(|| {
            state
                .get("router_config")
                .and_then(|config| config.get("sandbox"))
        });
        match raw {
            Some(value) => serde_json::from_value(value.clone())
                .map_err(|error| format!("invalid sandbox_config: {error}")),
            None => Ok(Self::default()),
        }
    }

    pub fn selected_backend(&self) -> Result<SandboxBackendKind, String> {
        let selected = self.backend.unwrap_or(match self.mode {
            RuntimeMode::Development => SandboxBackendKind::Lightweight,
            RuntimeMode::Production => SandboxBackendKind::Container,
        });
        if selected == SandboxBackendKind::None {
            #[cfg(feature = "sandbox-required")]
            {
                return Err(
                    "sandbox backend none is unavailable when sandbox-required is enabled"
                        .to_string(),
                );
            }
            #[cfg(not(feature = "sandbox-required"))]
            {
                if self.mode != RuntimeMode::Development {
                    return Err(
                        "sandbox backend none is forbidden outside development mode".to_string()
                    );
                }
                if !self.allow_unsafe_exec {
                    return Err(
                        "sandbox backend none requires VELVET_ALLOW_UNSAFE_EXEC=1 in the resolved config"
                            .to_string(),
                    );
                }
            }
        }
        if selected == SandboxBackendKind::Container {
            if self.container_runtime.is_none() {
                return Err(
                    "container backend requires container_runtime=podman|docker".to_string()
                );
            }
            let image = self.container_image.as_deref().ok_or_else(|| {
                "container backend requires a digest-pinned container_image".to_string()
            })?;
            if !is_digest_pinned(image) {
                return Err(
                    "container backend requires container_image to be pinned by sha256 digest"
                        .to_string(),
                );
            }
        }
        Ok(selected)
    }
}

pub trait SandboxBackend: Send + Sync {
    fn name(&self) -> &'static str;
    fn profile_hash(&self, material: &CanonicalSandboxProfile) -> [u8; 32];
    fn plan(
        &self,
        command: SandboxedCommand,
        limits: ResourceLimits,
        transforms: Vec<OutputTransform>,
        config: &SandboxConfig,
    ) -> Result<SandboxExecutionPlan, String>;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CanonicalSandboxProfile {
    backend: SandboxBackendKind,
    command: SandboxedCommand,
    limits: ResourceLimits,
    transforms: Vec<OutputTransform>,
    image_digest: Option<String>,
    container_runtime: Option<ContainerRuntime>,
}

pub struct NoneBackend;
pub struct LightweightBackend;
pub struct ContainerBackend;

impl SandboxBackend for NoneBackend {
    fn name(&self) -> &'static str {
        "none"
    }

    fn profile_hash(&self, material: &CanonicalSandboxProfile) -> [u8; 32] {
        hash_profile(material)
    }

    fn plan(
        &self,
        command: SandboxedCommand,
        limits: ResourceLimits,
        transforms: Vec<OutputTransform>,
        config: &SandboxConfig,
    ) -> Result<SandboxExecutionPlan, String> {
        build_plan(
            self,
            SandboxBackendKind::None,
            command,
            limits,
            transforms,
            config,
        )
    }
}

impl SandboxBackend for LightweightBackend {
    fn name(&self) -> &'static str {
        "lightweight"
    }

    fn profile_hash(&self, material: &CanonicalSandboxProfile) -> [u8; 32] {
        hash_profile(material)
    }

    fn plan(
        &self,
        command: SandboxedCommand,
        limits: ResourceLimits,
        transforms: Vec<OutputTransform>,
        config: &SandboxConfig,
    ) -> Result<SandboxExecutionPlan, String> {
        build_plan(
            self,
            SandboxBackendKind::Lightweight,
            command,
            limits,
            transforms,
            config,
        )
    }
}

impl SandboxBackend for ContainerBackend {
    fn name(&self) -> &'static str {
        "container"
    }

    fn profile_hash(&self, material: &CanonicalSandboxProfile) -> [u8; 32] {
        hash_profile(material)
    }

    fn plan(
        &self,
        command: SandboxedCommand,
        limits: ResourceLimits,
        transforms: Vec<OutputTransform>,
        config: &SandboxConfig,
    ) -> Result<SandboxExecutionPlan, String> {
        build_plan(
            self,
            SandboxBackendKind::Container,
            command,
            limits,
            transforms,
            config,
        )
    }
}

pub fn plan_for_candidate(
    state: &Value,
    candidate: &CandidateAction,
) -> Result<Option<SandboxExecutionPlan>, String> {
    if candidate.action_type != ActionType::ExecuteCode {
        return Ok(None);
    }
    let config = SandboxConfig::from_state(state)?;
    let backend = config.selected_backend()?;
    let command = command_from_candidate(candidate, &config)?;
    let command = canonicalize_command(command);
    let limits = config.limits.clone();
    let transforms = canonicalize_transforms(config.output_transforms.clone());
    let plan = match backend {
        SandboxBackendKind::None => NoneBackend.plan(command, limits, transforms, &config),
        SandboxBackendKind::Lightweight => {
            LightweightBackend.plan(command, limits, transforms, &config)
        }
        SandboxBackendKind::Container => {
            ContainerBackend.plan(command, limits, transforms, &config)
        }
    }?;
    Ok(Some(plan))
}

pub fn seal_material_for_candidate(state: &Value, candidate: &CandidateAction) -> Value {
    match plan_for_candidate(state, candidate) {
        Ok(Some(plan)) => {
            serde_json::to_value(plan).unwrap_or_else(|_| json!({"error": "serialize"}))
        }
        Ok(None) => Value::Null,
        Err(error) => json!({ "error": error }),
    }
}

fn command_from_candidate(
    candidate: &CandidateAction,
    config: &SandboxConfig,
) -> Result<SandboxedCommand, String> {
    let argv = candidate
        .parameters
        .get("command")
        .and_then(Value::as_array)
        .ok_or_else(|| "EXECUTE_CODE command must be a list of strings".to_string())?
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(ToString::to_string)
                .ok_or_else(|| "EXECUTE_CODE command must be a list of strings".to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    if argv.is_empty() {
        return Err("EXECUTE_CODE command must not be empty".to_string());
    }
    let cwd = candidate
        .parameters
        .get("cwd")
        .and_then(Value::as_str)
        .unwrap_or(".")
        .to_string();
    Ok(SandboxedCommand {
        argv,
        cwd,
        env_list: config.env_list.clone(),
        stdin: None,
        mounts: config.mounts.clone(),
        egress_list: config.egress_list.clone(),
    })
}

fn build_plan(
    backend: &dyn SandboxBackend,
    backend_kind: SandboxBackendKind,
    command: SandboxedCommand,
    limits: ResourceLimits,
    transforms: Vec<OutputTransform>,
    config: &SandboxConfig,
) -> Result<SandboxExecutionPlan, String> {
    validate_command(&command, config, backend_kind)?;
    validate_limits(&limits)?;
    let network_policy = if command.egress_list.is_empty() {
        NetworkPolicy::DenyAll
    } else {
        NetworkPolicy::List {
            rules: command.egress_list.clone(),
        }
    };
    let profile = CanonicalSandboxProfile {
        backend: backend_kind,
        command: command.clone(),
        limits: limits.clone(),
        transforms: transforms.clone(),
        image_digest: config.container_image.clone(),
        container_runtime: config.container_runtime,
    };
    let provenance = SandboxProvenance {
        backend: backend_kind,
        profile_hash: hex_encode(&backend.profile_hash(&profile)),
        image_digest: config.container_image.clone(),
        container_runtime: config.container_runtime,
        mount_spec: command.mounts.clone(),
        network_policy,
        applied_limits: limits.clone(),
        backend_guarantees: backend_guarantees(backend_kind),
    };
    Ok(SandboxExecutionPlan {
        backend: backend_kind,
        command,
        limits,
        output_transforms: transforms,
        provenance,
    })
}

fn canonicalize_command(mut command: SandboxedCommand) -> SandboxedCommand {
    command.env_list.sort();
    command.env_list.dedup();
    command.mounts.sort();
    command.mounts.dedup();
    command.egress_list.sort();
    command.egress_list.dedup();
    command
}

fn canonicalize_transforms(mut transforms: Vec<OutputTransform>) -> Vec<OutputTransform> {
    transforms.sort();
    transforms.dedup();
    transforms
}

fn validate_command(
    command: &SandboxedCommand,
    config: &SandboxConfig,
    backend: SandboxBackendKind,
) -> Result<(), String> {
    if command.argv.is_empty() {
        return Err("sandbox command argv must not be empty".to_string());
    }
    if !command_cwd_allowed(command, config, backend) {
        return Err(
            "sandbox command cwd must be relative, /workspace, or under a configured mount"
                .to_string(),
        );
    }
    for mount in &command.mounts {
        if mount.host_path.is_empty() || mount.sandbox_path.is_empty() {
            return Err("mount paths must not be empty".to_string());
        }
    }
    for rule in &command.egress_list {
        if rule.host.is_empty() {
            return Err("egress list host must not be empty".to_string());
        }
        if !matches!(rule.protocol.as_str(), "tcp" | "udp") {
            return Err("egress list protocol must be tcp or udp".to_string());
        }
    }
    Ok(())
}

fn command_cwd_allowed(
    command: &SandboxedCommand,
    config: &SandboxConfig,
    backend: SandboxBackendKind,
) -> bool {
    let cwd = Path::new(&command.cwd);
    if command.cwd.is_empty() {
        return false;
    }
    if !cwd.is_absolute() || backend == SandboxBackendKind::Container {
        return true;
    }
    if command.cwd == "/workspace" {
        return true;
    }
    config
        .mounts
        .iter()
        .any(|mount| cwd.starts_with(Path::new(&mount.sandbox_path)))
}

fn validate_limits(limits: &ResourceLimits) -> Result<(), String> {
    if limits.cpu_seconds == 0
        || limits.memory_bytes == 0
        || limits.wall_clock_ms == 0
        || limits.max_stdout_bytes == 0
        || limits.max_processes == 0
    {
        return Err("sandbox resource limits must be greater than zero".to_string());
    }
    Ok(())
}

fn backend_guarantees(backend: SandboxBackendKind) -> Vec<String> {
    match backend {
        SandboxBackendKind::None => vec!["unsafe_host_execution".to_string()],
        SandboxBackendKind::Lightweight => vec![
            "filesystem_visibility_limited_by_profile".to_string(),
            "deny_all_network_when_no_egress_rules".to_string(),
            "macos_network_list_not_equivalent_to_linux".to_string(),
        ],
        SandboxBackendKind::Container => vec![
            "rootless_container_boundary".to_string(),
            "digest_pinned_image".to_string(),
            "deny_all_network_when_no_egress_rules".to_string(),
        ],
    }
}

fn hash_profile(material: &CanonicalSandboxProfile) -> [u8; 32] {
    let payload = serde_json::to_vec(material).unwrap_or_default();
    let digest = Sha256::digest(payload);
    let mut bytes = [0_u8; 32];
    bytes.copy_from_slice(&digest);
    bytes
}

fn hex_encode(bytes: &[u8; 32]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

fn is_digest_pinned(image: &str) -> bool {
    let Some((_, digest)) = image.rsplit_once('@') else {
        return false;
    };
    let Some(value) = digest.strip_prefix("sha256:") else {
        return false;
    };
    value.len() == 64 && value.chars().all(|character| character.is_ascii_hexdigit())
}

#[allow(dead_code)]
fn _metadata(details: impl IntoIterator<Item = (String, Value)>) -> JsonObject {
    BTreeMap::from_iter(details)
}

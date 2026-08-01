use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Result;
use chrono::{Duration, Utc};
use serde_json::{Value, json};
use velvet_closure::{ClosureMonitor, load_contract};
use velvet_policy_loader::load_policy_graph;
use velvet_rope_proxy::{
    ApprovalReceiptConfig, ApprovalTier, AuthConfig, ControlPlaneConfig, EnforcementMode,
    EvidenceConfig, ForwardingConfig, GatewayConfig, HttpConfig, IdentityConfig, LedgerConfig,
    LimitConfig, MethodDispositionConfig, OapConfig, POLICY_BUNDLE_SCHEMA_VERSION,
    PolicyBundleManifest, PolicyConfig, ProxyConfig, RiskClass, SigningConfig, ToolApproval,
    ToolInventory, TransportKind, UpstreamConfig, policy_dir_hash, tool_schema_hash,
    verify_policy_bundle,
};

const SECRET: &str = "db_password=hunter2-prod";

struct Vault {
    reads: Vec<&'static str>,
}

impl Vault {
    fn read(&mut self, who: &'static str) -> &'static str {
        self.reads.push(who);
        SECRET
    }
}

fn main() -> Result<()> {
    let baseline_leaked = run_baseline();
    let portcullis_leaked = run_portcullis()?;
    println!("baseline leaked = {baseline_leaked}");
    println!("portcullis leaked = {portcullis_leaked}");
    Ok(())
}

fn run_baseline() -> bool {
    let mut vault = Vault { reads: Vec::new() };
    let _ = vault.read("legit_check");
    let _ = vault.read("injected_replay");
    vault.reads.len() > 1
}

fn run_portcullis() -> Result<bool> {
    let mut vault = Vault { reads: Vec::new() };
    let root = demo_root()?;
    let (config, bundle_proof, policy_graph, inventory) = monitor_context(&root)?;
    let contract = load_contract(json!({
        "contract_id": "demo/one-time-secret-read",
        "initial_envelope": [{"name": "log:write", "resource": "local:run.log"}],
        "grant_rules": [{
            "subgoal": "verify_secret",
            "capability": "secret:read",
            "resource": "vault:/db/password",
            "single_dispatch": true,
            "max_grants": 1
        }],
        "closure_predicates": [{
            "subgoal": "verify_secret",
            "kind": "on_receipt",
            "capability": "secret:read"
        }],
        "deny_rules": [{
            "capability": "net:write",
            "resource": "external:attacker.example",
            "reason": "exfil sink"
        }]
    }))?;
    let mut monitor = ClosureMonitor::new(
        contract,
        config,
        bundle_proof,
        Arc::new(policy_graph),
        inventory,
    );
    monitor.open_subgoal("verify_secret")?;
    let grant = monitor.request(
        "verify_secret",
        "secret:read",
        "vault:/db/password",
        json!({"path": "/db/password"}),
    );
    if grant.allowed {
        let permit_id = grant.permit_id.as_deref().unwrap_or_default();
        let invoke = monitor.invoke(permit_id, json!({"path": "/db/password"}));
        if invoke.allowed {
            let _ = vault.read("legit_check");
        }
        let replay = monitor.invoke(permit_id, json!({"path": "/db/password"}));
        if replay.allowed {
            let _ = vault.read("injected_replay");
        }
    }
    let regrant = monitor.request(
        "verify_secret",
        "secret:read",
        "vault:/db/password",
        json!({"path": "/db/password"}),
    );
    if regrant.allowed {
        let _ = vault.read("injected_regrant");
    }
    Ok(vault.reads.len() > 1)
}

fn monitor_context(
    root: &Path,
) -> Result<(
    ProxyConfig,
    velvet_rope_proxy::PolicyBundleProof,
    velvet_core::PolicyGraph,
    ToolInventory,
)> {
    ensure_signing_env();
    let policy = write_policy_bundle(root)?;
    let tool = secret_tool();
    let approved_schema_hash = tool_schema_hash(&tool)?;
    let mut config = ProxyConfig {
        mode: EnforcementMode::Development,
        identity: IdentityConfig {
            tenant_id: "tenant-demo".to_string(),
            environment: "local".to_string(),
            product_surface: "velvet_inline_gateway.mcp".to_string(),
            subject_id: Some("user-demo".to_string()),
            agent_id: Some("agent-demo".to_string()),
            client_id: Some("client-demo".to_string()),
            session_id: Some("session-demo".to_string()),
        },
        oap: OapConfig {
            passport_created_at: Some("2026-05-28T00:00:00Z".to_string()),
            passport_updated_at: Some("2026-05-28T00:00:00Z".to_string()),
            require_max_de_certificate: false,
            require_max_de_for_all_tool_calls: false,
            allow_missing_max_de_in_development: true,
            ..OapConfig::default()
        },
        transport: TransportKind::Fake,
        upstream: UpstreamConfig {
            server: "vault".to_string(),
            ..UpstreamConfig::default()
        },
        policy,
        tools: vec![ToolApproval {
            server: "vault".to_string(),
            name: "secret:read".to_string(),
            approved_schema_hash,
            risk_class: RiskClass::Low,
            approval_tier: ApprovalTier::AutoApprove,
            ..ToolApproval::default()
        }],
        approvals: Vec::new(),
        approval_receipts: ApprovalReceiptConfig {
            require_signature: false,
            allow_unsigned_local_demo_only: true,
            trusted_keys: Vec::new(),
        },
        method_dispositions: MethodDispositionConfig::default(),
        ledger_path: root.join("closure.vledger"),
        ledger: LedgerConfig::default(),
        control_plane: ControlPlaneConfig::default(),
        evidence: EvidenceConfig::default(),
        signing: SigningConfig::default(),
        gateway: GatewayConfig::default(),
        thread_path: Some(root.join("thread.jsonl")),
        inventory_path: Some(root.join("inventory.json")),
        approval_requests_path: Some(root.join("approval_requests.jsonl")),
        evidence_pack_path: Some(root.join("evidence_pack.json")),
        schema_drift_action: velvet_rope_proxy::SchemaDriftAction::Deny,
        limits: LimitConfig::default(),
        auth: AuthConfig::default(),
        http: HttpConfig::default(),
        forwarding: ForwardingConfig::default(),
        demo_requests: Vec::new(),
    };
    config.tools[0].server = "vault".to_string();
    let inventory = ToolInventory::build(&config, &[tool])?;
    let bundle_proof = verify_policy_bundle(&config.policy)?;
    let policy_graph =
        load_policy_graph(&config.policy.dir).map_err(|errors| anyhow::anyhow!("{errors:?}"))?;
    Ok((config, bundle_proof, policy_graph, inventory))
}

fn write_policy_bundle(root: &Path) -> Result<PolicyConfig> {
    let policy_dir = root.join("policies");
    fs::create_dir_all(&policy_dir)?;
    fs::write(
        policy_dir.join("mcp_demo.yaml"),
        velvet_rope_proxy::EXAMPLE_POLICY,
    )?;
    let manifest_path = root.join("policy-bundle.yaml");
    let manifest = PolicyBundleManifest {
        schema_version: POLICY_BUNDLE_SCHEMA_VERSION.to_string(),
        bundle_hash: policy_dir_hash(&policy_dir, &manifest_path)?,
        expires_at: (Utc::now() + Duration::days(2)).to_rfc3339(),
        signature: None,
    };
    fs::write(&manifest_path, serde_yaml::to_string(&manifest)?)?;
    Ok(PolicyConfig {
        dir: policy_dir,
        chain: "mcp_demo".to_string(),
        bundle_manifest: manifest_path,
        require_signature: false,
        trusted_signature_public_key_hex: None,
        trusted_signature_public_key_hex_env: None,
    })
}

fn secret_tool() -> Value {
    json!({
        "name": "secret:read",
        "description": "Read one secret",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
            "additionalProperties": false
        }
    })
}

fn demo_root() -> Result<PathBuf> {
    let root = std::env::temp_dir().join(format!(
        "velvet-closure-demo-{}-{}",
        std::process::id(),
        Utc::now().timestamp_nanos_opt().unwrap_or_default()
    ));
    fs::create_dir_all(&root)?;
    Ok(root)
}

fn ensure_signing_env() {
    unsafe {
        std::env::set_var(
            "VELVET_OAP_ED25519_PRIVATE_KEY",
            "0707070707070707070707070707070707070707070707070707070707070707",
        );
        std::env::set_var(
            "VELVET_MAXDE_ED25519_PRIVATE_KEY",
            "0909090909090909090909090909090909090909090909090909090909090909",
        );
        std::env::set_var(
            "VELVET_MAXDE_ED25519_PUBLIC_KEY",
            "fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618",
        );
    }
}

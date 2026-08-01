use super::*;

#[test]
fn streamable_http_upstream_accepts_https() -> Result<()> {
    let config = HttpConfig::default();
    let url =
        validate_streamable_http_upstream_endpoint(&config, "https://mcp.example.internal/mcp")?;
    assert_eq!(url.scheme(), "https");
    Ok(())
}

#[test]
fn streamable_http_upstream_rejects_non_loopback_http() {
    let config = HttpConfig::default();
    let error =
        validate_streamable_http_upstream_endpoint(&config, "http://mcp.example.internal/mcp")
            .unwrap_err()
            .to_string();
    assert!(error.contains("must use https"));
}

#[test]
fn streamable_http_upstream_rejects_loopback_http_unless_enabled() {
    let config = HttpConfig::default();
    let error = validate_streamable_http_upstream_endpoint(&config, "http://127.0.0.1:8792/mcp")
        .unwrap_err()
        .to_string();
    assert!(error.contains("allow_plaintext_loopback_upstream"));
}

#[test]
fn streamable_http_upstream_accepts_explicit_plaintext_loopback() -> Result<()> {
    let config = HttpConfig {
        allow_plaintext_loopback_upstream: true,
        ..HttpConfig::default()
    };
    for endpoint in [
        "http://localhost:8792/mcp",
        "http://127.0.0.1:8792/mcp",
        "http://[::1]:8792/mcp",
    ] {
        let url = validate_streamable_http_upstream_endpoint(&config, endpoint)?;
        assert_eq!(url.scheme(), "http");
    }
    Ok(())
}

#[test]
fn strict_tunnel_config_requires_upstream_no_bypass_boundary() -> Result<()> {
    let temp = TempDir::new()?;
    let mut config = test_config(temp.path())?;
    config.transport = TransportKind::StreamableHttp;
    config.upstream.endpoint = Some("https://private-mcp.example/mcp".to_string());
    config
        .oap
        .transport_context
        .openai_secure_mcp_tunnel
        .enabled = true;

    let error = build_upstream_http_client(&config, "https://private-mcp.example/mcp")
        .unwrap_err()
        .to_string();
    assert!(error.contains("requires upstream.boundary.required"));
    Ok(())
}

#[test]
fn strict_tunnel_config_rejects_partial_upstream_boundary() -> Result<()> {
    let temp = TempDir::new()?;
    let token_env = "VELVET_TEST_PRIVATE_MCP_PARTIAL_TOKEN";
    set_test_env(token_env, "private-upstream-token");
    let mut bearer_only = test_config(temp.path())?;
    bearer_only.transport = TransportKind::StreamableHttp;
    bearer_only.upstream.endpoint = Some("https://private-mcp.example/mcp".to_string());
    bearer_only
        .oap
        .transport_context
        .openai_secure_mcp_tunnel
        .enabled = true;
    bearer_only.upstream.boundary = private_mcp_boundary_config(token_env);
    let bearer_error = build_upstream_http_client(&bearer_only, "https://private-mcp.example/mcp")
        .unwrap_err()
        .to_string();
    assert!(bearer_error.contains("require_bearer, and require_mtls"));

    let identity_env = "VELVET_TEST_PRIVATE_MCP_PARTIAL_IDENTITY";
    set_test_env(identity_env, &test_mtls_identity_pem());
    let mut mtls_only = test_config(temp.path())?;
    mtls_only.transport = TransportKind::StreamableHttp;
    mtls_only.upstream.endpoint = Some("https://private-mcp.example/mcp".to_string());
    mtls_only
        .oap
        .transport_context
        .openai_secure_mcp_tunnel
        .enabled = true;
    mtls_only.upstream.boundary = UpstreamBoundaryConfig {
        required: true,
        require_bearer: false,
        require_mtls: true,
        bearer: UpstreamBoundaryBearerConfig::default(),
        mtls: UpstreamBoundaryMtlsConfig {
            identity_pem_env: Some(identity_env.to_string()),
            ..UpstreamBoundaryMtlsConfig::default()
        },
    };
    let mtls_error = build_upstream_http_client(&mtls_only, "https://private-mcp.example/mcp")
        .unwrap_err()
        .to_string();
    assert!(mtls_error.contains("require_bearer, and require_mtls"));
    remove_test_env(token_env);
    remove_test_env(identity_env);
    Ok(())
}

#[test]
fn upstream_private_bearer_config_fails_closed_for_bad_sources() -> Result<()> {
    let temp = TempDir::new()?;
    let missing_env = "VELVET_TEST_PRIVATE_MCP_MISSING_TOKEN";
    remove_test_env(missing_env);
    let mut missing = test_config(temp.path())?;
    missing.http.allow_plaintext_loopback_upstream = true;
    missing.upstream.boundary = private_mcp_boundary_config(missing_env);
    assert!(
        build_upstream_http_client(&missing, "http://127.0.0.1:8792/mcp")
            .unwrap_err()
            .to_string()
            .contains("read upstream bearer token env")
    );

    let empty_env = "VELVET_TEST_PRIVATE_MCP_EMPTY_TOKEN";
    set_test_env(empty_env, "   ");
    let mut empty = test_config(temp.path())?;
    empty.http.allow_plaintext_loopback_upstream = true;
    empty.upstream.boundary = private_mcp_boundary_config(empty_env);
    assert!(
        build_upstream_http_client(&empty, "http://127.0.0.1:8792/mcp")
            .unwrap_err()
            .to_string()
            .contains("is empty")
    );

    let ambiguous_env = "VELVET_TEST_PRIVATE_MCP_AMBIGUOUS_TOKEN";
    set_test_env(ambiguous_env, "private-upstream-token");
    let token_file = temp.path().join("private-upstream-token.txt");
    fs::write(&token_file, "private-upstream-token")?;
    let mut ambiguous = test_config(temp.path())?;
    ambiguous.http.allow_plaintext_loopback_upstream = true;
    ambiguous.upstream.boundary = private_mcp_boundary_config(ambiguous_env);
    ambiguous.upstream.boundary.bearer.token_file = Some(token_file);
    assert!(
        build_upstream_http_client(&ambiguous, "http://127.0.0.1:8792/mcp")
            .unwrap_err()
            .to_string()
            .contains("exactly one env or file")
    );
    remove_test_env(empty_env);
    remove_test_env(ambiguous_env);
    Ok(())
}

#[test]
fn upstream_mtls_identity_and_ca_bundle_load_or_fail_closed() -> Result<()> {
    let temp = TempDir::new()?;
    let identity_env = "VELVET_TEST_PRIVATE_MCP_IDENTITY_PEM";
    let ca_env = "VELVET_TEST_PRIVATE_MCP_CA_BUNDLE_PEM";
    set_test_env(identity_env, &test_mtls_identity_pem());
    set_test_env(ca_env, TEST_MTLS_CERT_PEM);
    let mut config = test_config(temp.path())?;
    config.upstream.boundary = UpstreamBoundaryConfig {
        required: true,
        require_bearer: false,
        require_mtls: true,
        bearer: UpstreamBoundaryBearerConfig::default(),
        mtls: UpstreamBoundaryMtlsConfig {
            identity_pem_env: Some(identity_env.to_string()),
            ca_bundle_pem_env: Some(ca_env.to_string()),
            ..UpstreamBoundaryMtlsConfig::default()
        },
    };
    build_upstream_http_client(&config, "https://private-mcp.example/mcp")?;

    set_test_env(identity_env, "not a pem");
    assert!(
        build_upstream_http_client(&config, "https://private-mcp.example/mcp")
            .unwrap_err()
            .to_string()
            .contains("identity PEM")
    );
    set_test_env(identity_env, &test_mtls_identity_pem());
    set_test_env(ca_env, "not a pem");
    assert!(
        build_upstream_http_client(&config, "https://private-mcp.example/mcp")
            .unwrap_err()
            .to_string()
            .contains("CA bundle PEM")
    );
    remove_test_env(identity_env);
    remove_test_env(ca_env);
    Ok(())
}

#[test]
fn upstream_private_bearer_conflicts_with_forwarded_downstream_authorization() -> Result<()> {
    let temp = TempDir::new()?;
    let token_env = "VELVET_TEST_PRIVATE_MCP_FORWARD_CONFLICT";
    set_test_env(token_env, "private-upstream-token");
    let mut config = test_config(temp.path())?;
    config.http.allow_plaintext_loopback_upstream = true;
    config.auth.forward_authorization = true;
    config.upstream.boundary = private_mcp_boundary_config(token_env);
    let error = build_upstream_http_client(&config, "http://127.0.0.1:8792/mcp")
        .unwrap_err()
        .to_string();
    assert!(error.contains("forward_authorization cannot be enabled"));
    remove_test_env(token_env);
    Ok(())
}

#[tokio::test]
async fn tls_check_rejects_http_without_network_access() {
    let error = run_tls_check("http://127.0.0.1:1/mcp")
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("tls-check URL must use https"));
}

#[test]
fn deployment_dockerfile_installs_ca_bundle() -> Result<()> {
    let dockerfile_path =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deploy/mcp_proxy/Dockerfile");
    let dockerfile = fs::read_to_string(dockerfile_path)?;
    assert!(dockerfile.contains("ca-certificates"));
    assert!(dockerfile.contains("rm -rf /var/lib/apt/lists/*"));
    assert!(dockerfile.contains("SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt"));
    Ok(())
}

#[test]
fn secure_tunnel_kubernetes_gateway_manifest_enforces_no_bypass_network_policy() -> Result<()> {
    let manifest_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/deployment/openai-secure-mcp-tunnel/kubernetes-gateway.yaml");
    let manifest = fs::read_to_string(manifest_path)?;
    for expected in [
        "kind: NetworkPolicy",
        "name: tunnel-client-egress-only-to-velvet",
        "name: private-mcp-ingress-only-from-velvet",
        "name: velvet-egress-to-private-mcp",
        "app: private-mcp",
        "app: velvet-rope-proxy",
        "app: tunnel-client",
        "port: 8791",
        "port: 8443",
    ] {
        assert!(
            manifest.contains(expected),
            "gateway manifest missing {expected}"
        );
    }
    assert!(manifest.contains("replicas: 1"));
    assert!(!manifest.contains("replicas: 2"));
    Ok(())
}

#[test]
fn secure_tunnel_compose_keeps_tunnel_client_off_private_mcp_network() -> Result<()> {
    let compose_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples/deployment/openai-secure-mcp-tunnel/docker-compose.yaml");
    let compose = fs::read_to_string(compose_path)?;
    let value: Value = serde_yaml::from_str(&compose)?;
    let tunnel_networks = value
        .pointer("/services/tunnel-client/networks")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("tunnel-client networks must be a list"))?;
    let tunnel_networks = tunnel_networks
        .iter()
        .filter_map(Value::as_str)
        .collect::<BTreeSet<_>>();
    assert!(tunnel_networks.contains("tunnel-net"));
    assert!(!tunnel_networks.contains("private-mcp-net"));
    let private_networks = value
        .pointer("/services/private-mcp/networks")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("private-mcp networks must be a list"))?;
    let private_networks = private_networks
        .iter()
        .filter_map(Value::as_str)
        .collect::<BTreeSet<_>>();
    assert!(private_networks.contains("private-mcp-net"));
    assert!(!private_networks.contains("tunnel-net"));
    Ok(())
}

#[test]
fn hosted_shared_saas_config_fields_parse() -> Result<()> {
    let source = r#"
mode: strict
control_plane:
  base_url: https://api.velvet.example.com
  gateway_token_env: VELVET_GATEWAY_TOKEN
  timeout_ms: 5000
ledger:
  strict: true
  fsync: true
  sink: control_plane
evidence:
  sink: control_plane_s3_object_lock
signing:
  provider: aws_kms
  kms_key_id_env: VELVET_KMS_KEY_ID
  algorithm: RSASSA_PSS_SHA_256
gateway:
  gateway_deployment_id: 86ed6409-3797-4cff-80bf-59bf2a99d857
  hostname: servicenow-prod.velvet.example.com
"#;
    let config: ProxyConfig = serde_yaml::from_str(source)?;
    assert_eq!(config.ledger.sink, LedgerSink::ControlPlane);
    assert_eq!(config.evidence.sink, EvidenceSink::ControlPlaneS3ObjectLock);
    assert_eq!(config.signing.provider, SigningProviderKind::AwsKms);
    assert!(config.control_plane.enabled());
    assert_eq!(
        config.control_plane.gateway_token_env.as_deref(),
        Some("VELVET_GATEWAY_TOKEN")
    );
    assert_eq!(
        config.gateway.gateway_deployment_id.as_deref(),
        Some("86ed6409-3797-4cff-80bf-59bf2a99d857")
    );
    Ok(())
}

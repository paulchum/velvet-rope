use super::*;

#[test]
fn hash_only_bundle_verification_passes_and_hash_mismatch_fails() -> Result<()> {
    let temp = TempDir::new()?;
    let policy = write_policy_bundle(temp.path(), false)?;
    assert!(!verify_policy_bundle(&policy)?.signature_verified);
    fs::write(policy.dir.join("extra.yaml"), EXAMPLE_POLICY)?;
    assert!(verify_policy_bundle(&policy).is_err());
    Ok(())
}

#[test]
fn signed_bundle_verification_passes_and_bad_signature_fails() -> Result<()> {
    let temp = TempDir::new()?;
    let policy = write_policy_bundle(temp.path(), true)?;
    assert!(verify_policy_bundle(&policy)?.signature_verified);
    let mut source = fs::read_to_string(&policy.bundle_manifest)?;
    source = source.replacen("signature_hex: ", "signature_hex: 00", 1);
    fs::write(&policy.bundle_manifest, source)?;
    assert!(verify_policy_bundle(&policy).is_err());
    Ok(())
}

#[test]
fn signed_bundle_rejects_missing_or_wrong_trusted_public_key() -> Result<()> {
    let temp = TempDir::new()?;
    let mut policy = write_policy_bundle(temp.path(), true)?;
    policy.trusted_signature_public_key_hex = None;
    assert!(
        verify_policy_bundle(&policy)
            .unwrap_err()
            .to_string()
            .contains("trusted signature public key is required")
    );
    policy.trusted_signature_public_key_hex = Some("00".repeat(32));
    assert!(
        verify_policy_bundle(&policy)
            .unwrap_err()
            .to_string()
            .contains("does not match configured trust anchor")
    );
    Ok(())
}

#[test]
fn signed_bundle_accepts_trusted_public_key_from_env() -> Result<()> {
    let temp = TempDir::new()?;
    let mut policy = write_policy_bundle(temp.path(), true)?;
    let trusted = policy
        .trusted_signature_public_key_hex
        .take()
        .ok_or_else(|| anyhow!("missing test key"))?;
    let env_name = "VELVET_TEST_POLICY_BUNDLE_TRUSTED_KEY";
    set_test_env(env_name, &trusted);
    policy.trusted_signature_public_key_hex_env = Some(env_name.to_string());
    assert!(verify_policy_bundle(&policy)?.signature_verified);
    policy.trusted_signature_public_key_hex = Some(trusted);
    assert!(
        verify_policy_bundle(&policy)
            .unwrap_err()
            .to_string()
            .contains("configure exactly one")
    );
    remove_test_env(env_name);
    Ok(())
}

#[test]
fn expired_or_missing_bundle_fails_closed() -> Result<()> {
    let temp = TempDir::new()?;
    let policy = write_policy_bundle(temp.path(), false)?;
    let manifest = PolicyBundleManifest {
        schema_version: POLICY_BUNDLE_SCHEMA_VERSION.to_string(),
        bundle_hash: policy_dir_hash(&policy.dir, &policy.bundle_manifest)?,
        expires_at: (Utc::now() - Duration::days(1)).to_rfc3339(),
        signature: None,
    };
    fs::write(&policy.bundle_manifest, serde_yaml::to_string(&manifest)?)?;
    assert!(verify_policy_bundle(&policy).is_err());
    fs::remove_file(&policy.bundle_manifest)?;
    assert!(verify_policy_bundle(&policy).is_err());
    Ok(())
}

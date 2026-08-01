use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fmt;

use crate::JsonObject;

pub const SIGNATURE_SCHEMA_VERSION: &str = "velvet.signature.v2";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SignatureBlock {
    #[serde(default = "signature_schema_version")]
    pub schema_version: String,
    pub provider_name: String,
    pub algorithm: String,
    pub key_id: String,
    pub key_version: String,
    pub purpose: String,
    pub tenant_id: String,
    pub payload_hash: String,
    pub signature: String,
    #[serde(default)]
    pub signed_at: Option<String>,
    #[serde(default)]
    pub public_verification_material: Option<JsonObject>,
    #[serde(default)]
    pub metadata: JsonObject,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SigningContext {
    #[serde(default = "signature_schema_version")]
    pub schema_version: String,
    pub provider_name: String,
    pub algorithm: String,
    pub key_version: String,
    pub key_id: String,
    pub tenant_id: String,
    pub purpose: String,
    pub payload_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SigningError {
    NotConfigured(String),
    Provider(String),
}

impl fmt::Display for SigningError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotConfigured(message) | Self::Provider(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for SigningError {}

pub trait SigningProvider {
    fn provider_name(&self) -> &str;
    fn algorithm(&self) -> &str;
    fn key_version(&self) -> &str;

    fn sign(
        &self,
        payload_hash: &str,
        purpose: &str,
        tenant_id: &str,
        key_id: &str,
    ) -> Result<String, SigningError>;

    fn verify(
        &self,
        payload_hash: &str,
        signature: &str,
        purpose: &str,
        tenant_id: &str,
        key_id: &str,
    ) -> Result<bool, SigningError>;

    fn public_verification_material(
        &self,
        key_id: &str,
    ) -> Result<Option<JsonObject>, SigningError>;
}

impl SigningContext {
    pub fn new(
        payload_hash: impl Into<String>,
        purpose: impl Into<String>,
        tenant_id: impl Into<String>,
        key_id: impl Into<String>,
        provider_name: impl Into<String>,
        algorithm: impl Into<String>,
        key_version: impl Into<String>,
    ) -> Self {
        Self {
            schema_version: signature_schema_version(),
            provider_name: provider_name.into(),
            algorithm: algorithm.into(),
            key_version: key_version.into(),
            key_id: key_id.into(),
            tenant_id: tenant_id.into(),
            purpose: purpose.into(),
            payload_hash: payload_hash.into(),
        }
    }

    pub fn to_json_value(&self) -> Value {
        json!({
            "schema_version": self.schema_version,
            "provider_name": self.provider_name,
            "algorithm": self.algorithm,
            "key_version": self.key_version,
            "key_id": self.key_id,
            "tenant_id": self.tenant_id,
            "purpose": self.purpose,
            "payload_hash": self.payload_hash,
        })
    }

    pub fn signing_message_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&self.to_json_value()).unwrap_or_default()
    }
}

pub fn signing_message_bytes(
    payload_hash: &str,
    purpose: &str,
    tenant_id: &str,
    key_id: &str,
    provider_name: &str,
    algorithm: &str,
    key_version: &str,
) -> Vec<u8> {
    SigningContext::new(
        payload_hash,
        purpose,
        tenant_id,
        key_id,
        provider_name,
        algorithm,
        key_version,
    )
    .signing_message_bytes()
}

fn signature_schema_version() -> String {
    SIGNATURE_SCHEMA_VERSION.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signing_context_binds_purpose_tenant_and_key() {
        let first = signing_message_bytes(
            "abc",
            "velvet.test",
            "tenant-a",
            "key-a",
            "local_dev_hmac_demo",
            "HMAC-SHA256",
            "demo-v1",
        );
        let second = signing_message_bytes(
            "abc",
            "velvet.test",
            "tenant-b",
            "key-a",
            "local_dev_hmac_demo",
            "HMAC-SHA256",
            "demo-v1",
        );
        assert_ne!(first, second);
    }
}

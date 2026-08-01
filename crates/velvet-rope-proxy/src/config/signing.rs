#![allow(unused_imports)]

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SigningProviderKind {
    #[default]
    Ed25519,
    AwsKms,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SigningConfig {
    pub provider: SigningProviderKind,
    pub kms_key_id_env: Option<String>,
    pub algorithm: String,
}

impl Default for SigningConfig {
    fn default() -> Self {
        Self {
            provider: SigningProviderKind::Ed25519,
            kms_key_id_env: None,
            algorithm: "Ed25519".to_string(),
        }
    }
}

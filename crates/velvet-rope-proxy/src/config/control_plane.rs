#![allow(unused_imports)]

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ControlPlaneConfig {
    pub base_url: String,
    pub gateway_token_env: Option<String>,
    pub timeout_ms: u64,
}

impl ControlPlaneConfig {
    pub(crate) fn enabled(&self) -> bool {
        !self.base_url.trim().is_empty()
    }

    pub(crate) fn timeout_ms(&self) -> u64 {
        if self.timeout_ms == 0 {
            10_000
        } else {
            self.timeout_ms
        }
    }
}

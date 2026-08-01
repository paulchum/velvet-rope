#![allow(unused_imports)]

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GatewayConfig {
    pub gateway_deployment_id: Option<String>,
    pub hostname: Option<String>,
}

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StandardTlsConfig {
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
    pub self_signed_domain: Option<String>,
}

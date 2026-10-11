use serde::{Deserialize, Serialize};

/// 平铺的证书字段，直接写在节点下：
///
/// ```yaml
/// cert: /path/fullchain.pem
/// key: /path/privkey.pem
/// # 或者
/// self-signed-domain: example.com
/// ```
///
/// 三个字段都不填表示“未配置 TLS”：对可选 TLS 的协议是明文，
/// 对必须 TLS 的协议（hysteria2 / tuic / anytls / naiveproxy）则回退到
/// 自动生成的自签证书。
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct StandardTlsConfig {
    #[serde(default, rename = "cert")]
    pub cert_path: Option<String>,
    #[serde(default, rename = "key")]
    pub key_path: Option<String>,
    #[serde(default, rename = "self-signed-domain")]
    pub self_signed_domain: Option<String>,
}

impl StandardTlsConfig {
    /// 是否配置了任何 TLS 字段。
    pub fn is_set(&self) -> bool {
        self.cert_path.is_some() || self.key_path.is_some() || self.self_signed_domain.is_some()
    }

    /// 已配置 TLS 时返回自身，否则 `None`（用于“可选 TLS”的协议）。
    pub fn as_opt(&self) -> Option<&Self> {
        self.is_set().then_some(self)
    }
}

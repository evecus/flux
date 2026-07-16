use anyhow::{Context, Result};
use serde::{Deserialize, Deserializer, Serialize};
use std::{collections::HashMap, path::Path, time::Duration};
use uuid::Uuid;

use crate::common::tls::config::StandardTlsConfig;

// ── 兼容层：同一字段既能接受单个 table [x] 也能接受数组 [[x]] ──────────────

fn one_or_many<'de, D, T>(d: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany<T> {
        Many(Vec<T>),
        One(T),
    }
    match OneOrMany::<T>::deserialize(d)? {
        OneOrMany::Many(v) => Ok(v),
        OneOrMany::One(t) => Ok(vec![t]),
    }
}

fn one_or_many_opt<'de, D, T>(d: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    one_or_many(d)
}

// ── Top-level config ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    #[serde(default)]
    pub log: LogConfig,

    #[serde(default, deserialize_with = "one_or_many_opt")]
    pub node: Vec<NodeConfig>,
}

impl Config {
    pub fn is_empty(&self) -> bool {
        self.node.is_empty()
    }

    /// 校验所有 tag 唯一，返回第一个重复的 tag
    pub fn check_duplicate_tags(&self) -> Option<&str> {
        let mut seen = std::collections::HashSet::new();
        for n in &self.node {
            if !seen.insert(n.tag.as_str()) {
                return Some(&n.tag);
            }
        }
        None
    }
}

// ── Node（顶层统一入口）──────────────────────────────────────────────────────

/// `[[node]]` 块，tag 必填，type 决定协议
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NodeConfig {
    pub tag: String,

    #[serde(flatten)]
    pub inner: NodeInner,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum NodeInner {
    Hysteria2(Hysteria2Config),
    Vless(VlessConfig),
    Vmess(VmessConfig),
    Trojan(TrojanConfig),
    Shadowsocks(ShadowsocksConfig),
    Tuic(TuicConfig),
    Wireguard(WireGuardConfig),
    Anytls(AnyTlsConfig),
    Socks(SocksConfig),
    Http(HttpConfig),
    Naiveproxy(NaiveproxyConfig),
}

// ── SOCKS5 ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SocksUser {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SocksConfig {
    pub listen: String,
    #[serde(default, deserialize_with = "one_or_many_opt")]
    pub users: Vec<SocksUser>,
    /// 出站时绑定的本地 IPv4 出口 IP（多公网 IP 服务器场景）。
    /// - 两者都不填：使用系统默认路由。
    /// - 只填一个：所有出站流量必须从这个地址族的 IP 走，目标没有对应
    ///   地址族记录时拒绝连接。
    /// - 两者都填：按目标地址族自动选择对应的出口 IP。
    #[serde(default)]
    pub outbound_bind_ipv4: Option<std::net::Ipv4Addr>,
    /// 出站时绑定的本地 IPv6 出口 IP，规则同 `outbound_bind_ipv4`。
    #[serde(default)]
    pub outbound_bind_ipv6: Option<std::net::Ipv6Addr>,
}

// ── TUIC ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TuicConfig {
    pub listen: String,
    pub users: HashMap<Uuid, String>,
    pub tls: Option<StandardTlsConfig>,
    #[serde(default = "default_tuic_idle_time", with = "humantime_serde")]
    pub max_idle_time: Duration,
    #[serde(default = "default_tuic_auth_timeout", with = "humantime_serde")]
    pub auth_timeout: Duration,
    #[serde(default = "default_tuic_udp_timeout", with = "humantime_serde")]
    pub udp_timeout: Duration,
    #[serde(default)]
    pub udp_relay_ipv6: bool,
    #[serde(default = "default_tuic_max_udp_packet_size")]
    pub max_udp_packet_size: usize,
    /// 出站时绑定的本地 IPv4 出口 IP（多公网 IP 服务器场景）。
    /// - 两者都不填：使用系统默认路由。
    /// - 只填一个：所有出站流量必须从这个地址族的 IP 走，目标没有对应
    ///   地址族记录时拒绝连接。
    /// - 两者都填：按目标地址族自动选择对应的出口 IP。
    #[serde(default)]
    pub outbound_bind_ipv4: Option<std::net::Ipv4Addr>,
    /// 出站时绑定的本地 IPv6 出口 IP，规则同 `outbound_bind_ipv4`。
    #[serde(default)]
    pub outbound_bind_ipv6: Option<std::net::Ipv6Addr>,
}

fn default_tuic_idle_time() -> Duration { Duration::from_secs(30) }
fn default_tuic_auth_timeout() -> Duration { Duration::from_secs(3) }
fn default_tuic_udp_timeout() -> Duration { Duration::from_secs(30) }
fn default_tuic_max_udp_packet_size() -> usize { 65535 }

// ── Hysteria2 ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Hysteria2Config {
    pub listen: String,
    pub tls: Hy2TlsConfig,
    pub auth: AuthConfig,
    #[serde(default)]
    pub bandwidth: BandwidthConfig,
    #[serde(default)]
    pub masquerade: MasqueradeConfig,
    /// 出站时绑定的本地 IPv4 出口 IP（多公网 IP 服务器场景）。
    /// - 两者都不填：使用系统默认路由。
    /// - 只填一个：所有出站流量必须从这个地址族的 IP 走，目标没有对应
    ///   地址族记录时拒绝连接。
    /// - 两者都填：按目标地址族自动选择对应的出口 IP。
    #[serde(default)]
    pub outbound_bind_ipv4: Option<std::net::Ipv4Addr>,
    /// 出站时绑定的本地 IPv6 出口 IP，规则同 `outbound_bind_ipv4`。
    #[serde(default)]
    pub outbound_bind_ipv6: Option<std::net::Ipv6Addr>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Hy2TlsConfig {
    pub cert_path: Option<String>,
    pub key_path: Option<String>,
    pub self_signed_domain: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum AuthConfig {
    Password { password: String },
    None,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct BandwidthConfig {
    pub up: Option<String>,
    pub down: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct MasqueradeConfig {
    #[serde(default = "default_masquerade_type")]
    pub r#type: String,
    pub proxy: Option<MasqueradeProxy>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MasqueradeProxy {
    pub url: String,
    #[serde(default)]
    pub rewrite_host: bool,
}

// ── Shared Transport config ───────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TransportConfig {
    #[serde(default = "default_transport_type")]
    pub r#type: String,
    #[serde(default = "default_ws_path")]
    pub ws_path: String,
    pub ws_host: Option<String>,
    #[serde(default = "default_xhttp_path")]
    pub xhttp_path: String,
    pub xhttp_host: Option<String>,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            r#type: default_transport_type(),
            ws_path: default_ws_path(),
            ws_host: None,
            xhttp_path: default_xhttp_path(),
            xhttp_host: None,
        }
    }
}

// ── TLS layer ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum VlessTlsConfig {
    Tls {
        #[serde(flatten)]
        standard: StandardTlsConfig,
    },
    Reality(RealityConfig),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RealityConfig {
    pub private_key: String,
    pub short_ids: Vec<String>,
    pub dest: String,
    pub server_name: String,
}

// ── VLESS ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VlessConfig {
    pub listen: String,
    pub uuid: String,
    #[serde(default)]
    pub transport: TransportConfig,
    pub tls: Option<VlessTlsConfig>,
    /// 出站时绑定的本地 IPv4 出口 IP（多公网 IP 服务器场景）。
    /// - 两者都不填：使用系统默认路由。
    /// - 只填一个：所有出站流量必须从这个地址族的 IP 走，目标没有对应
    ///   地址族记录时拒绝连接。
    /// - 两者都填：按目标地址族自动选择对应的出口 IP。
    #[serde(default)]
    pub outbound_bind_ipv4: Option<std::net::Ipv4Addr>,
    /// 出站时绑定的本地 IPv6 出口 IP，规则同 `outbound_bind_ipv4`。
    #[serde(default)]
    pub outbound_bind_ipv6: Option<std::net::Ipv6Addr>,
}

// ── Trojan ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TrojanConfig {
    pub listen: String,
    pub password: String,
    #[serde(default)]
    pub transport: TransportConfig,
    pub tls: Option<StandardTlsConfig>,
    /// 出站时绑定的本地 IPv4 出口 IP（多公网 IP 服务器场景）。
    /// - 两者都不填：使用系统默认路由。
    /// - 只填一个：所有出站流量必须从这个地址族的 IP 走，目标没有对应
    ///   地址族记录时拒绝连接。
    /// - 两者都填：按目标地址族自动选择对应的出口 IP。
    #[serde(default)]
    pub outbound_bind_ipv4: Option<std::net::Ipv4Addr>,
    /// 出站时绑定的本地 IPv6 出口 IP，规则同 `outbound_bind_ipv4`。
    #[serde(default)]
    pub outbound_bind_ipv6: Option<std::net::Ipv6Addr>,
}

// ── HTTP（标准 HTTP CONNECT 代理，RFC 7231/RFC 9110）─────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HttpAuthUser {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HttpConfig {
    pub listen: String,
    /// 不填 = 无认证；填了则要求 Proxy-Authorization: Basic 匹配其中一个用户。
    #[serde(default, deserialize_with = "one_or_many_opt")]
    pub users: Vec<HttpAuthUser>,
    /// 可选 TLS（HTTP CONNECT over TLS，即 HTTPS 代理）。不配置则明文监听。
    pub tls: Option<StandardTlsConfig>,
    /// 出站时绑定的本地 IPv4 出口 IP（多公网 IP 服务器场景）。
    /// - 两者都不填：使用系统默认路由。
    /// - 只填一个：所有出站流量必须从这个地址族的 IP 走，目标没有对应
    ///   地址族记录时拒绝连接。
    /// - 两者都填：按目标地址族自动选择对应的出口 IP。
    #[serde(default)]
    pub outbound_bind_ipv4: Option<std::net::Ipv4Addr>,
    /// 出站时绑定的本地 IPv6 出口 IP，规则同 `outbound_bind_ipv4`。
    #[serde(default)]
    pub outbound_bind_ipv6: Option<std::net::Ipv6Addr>,
}

// ── NaiveProxy（HTTP/2 CONNECT 隧道 + Basic Auth + 长度 padding）────────────
// 参见 https://github.com/klzgrad/naiveproxy
// 服务端只需实现协议本身：HTTP/2 CONNECT 隧道、Proxy-Authorization: Basic
// 认证、以及可选的首 8 次读写 padding；客户端侧的 Chrome TLS 指纹模拟
// （uTLS）与本服务端无关，本服务端的 TLS 层与其他协议一样使用 rustls。

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NaiveproxyConfig {
    pub listen: String,
    /// Proxy-Authorization: Basic 用户名/密码，至少配置一个。
    #[serde(default, deserialize_with = "one_or_many_opt")]
    pub users: Vec<HttpAuthUser>,
    /// TLS 是必须的（协议本身跑在 HTTPS 之上），ALPN 会同时声明 h2/http1.1。
    pub tls: StandardTlsConfig,
    /// 未认证请求的伪装（同 hy2 masquerade）：反代到一个正常网站，
    /// 而不是直接报错，用于抵御主动探测。不配置则返回一个静态 404。
    #[serde(default)]
    pub masquerade: Option<NaiveproxyMasquerade>,
    /// 是否启用 naiveproxy 的首 8 次读写 padding（对等协商，双方都要支持
    /// 才生效，不支持 padding 的客户端/服务端会自动降级为不 padding）。
    /// 默认关闭：核心隧道功能（CONNECT + Basic Auth）优先保证正确可用，
    /// padding 建议在确认连通性正常后再手动开启并自行验证效果。
    #[serde(default)]
    pub padding: bool,
    /// 出站时绑定的本地 IPv4 出口 IP（多公网 IP 服务器场景）。
    #[serde(default)]
    pub outbound_bind_ipv4: Option<std::net::Ipv4Addr>,
    /// 出站时绑定的本地 IPv6 出口 IP，规则同 `outbound_bind_ipv4`。
    #[serde(default)]
    pub outbound_bind_ipv6: Option<std::net::Ipv6Addr>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NaiveproxyMasquerade {
    pub url: String,
    #[serde(default)]
    pub rewrite_host: bool,
}

// ── VMess ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct VmessConfig {
    pub listen: String,
    pub uuid: String,
    #[serde(default)]
    pub transport: TransportConfig,
    pub tls: Option<StandardTlsConfig>,
    /// 出站时绑定的本地 IPv4 出口 IP（多公网 IP 服务器场景）。
    /// - 两者都不填：使用系统默认路由。
    /// - 只填一个：所有出站流量必须从这个地址族的 IP 走，目标没有对应
    ///   地址族记录时拒绝连接。
    /// - 两者都填：按目标地址族自动选择对应的出口 IP。
    #[serde(default)]
    pub outbound_bind_ipv4: Option<std::net::Ipv4Addr>,
    /// 出站时绑定的本地 IPv6 出口 IP，规则同 `outbound_bind_ipv4`。
    #[serde(default)]
    pub outbound_bind_ipv6: Option<std::net::Ipv6Addr>,
}

// ── Shadowsocks 2022 ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ShadowsocksCipher {
    #[serde(rename = "2022-blake3-aes-128-gcm")]
    Blake3Aes128Gcm,
    #[serde(rename = "2022-blake3-aes-256-gcm")]
    Blake3Aes256Gcm,
    #[serde(rename = "2022-blake3-chacha20-poly1305")]
    Blake3Chacha20Poly1305,
}

impl ShadowsocksCipher {
    pub fn key_len(&self) -> usize {
        match self {
            ShadowsocksCipher::Blake3Aes128Gcm => 16,
            ShadowsocksCipher::Blake3Aes256Gcm => 32,
            ShadowsocksCipher::Blake3Chacha20Poly1305 => 32,
        }
    }
    pub fn salt_len(&self) -> usize { self.key_len() }
    pub fn tag_len(&self) -> usize { 16 }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ShadowsocksConfig {
    pub listen: String,
    pub password: String,
    #[serde(default = "default_ss_cipher")]
    pub method: ShadowsocksCipher,
    #[serde(default)]
    pub transport: TransportConfig,
    pub tls: Option<StandardTlsConfig>,
    /// 出站时绑定的本地 IPv4 出口 IP（多公网 IP 服务器场景）。
    /// - 两者都不填：使用系统默认路由。
    /// - 只填一个：所有出站流量必须从这个地址族的 IP 走，目标没有对应
    ///   地址族记录时拒绝连接。
    /// - 两者都填：按目标地址族自动选择对应的出口 IP。
    #[serde(default)]
    pub outbound_bind_ipv4: Option<std::net::Ipv4Addr>,
    /// 出站时绑定的本地 IPv6 出口 IP，规则同 `outbound_bind_ipv4`。
    #[serde(default)]
    pub outbound_bind_ipv6: Option<std::net::Ipv6Addr>,
}

// ── AnyTLS ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AnyTlsConfig {
    pub listen: String,
    pub password: String,
    pub tls: StandardTlsConfig,
    pub padding_scheme: Option<String>,
    /// 出站时绑定的本地 IPv4 出口 IP（多公网 IP 服务器场景）。
    /// - 两者都不填：使用系统默认路由。
    /// - 只填一个：所有出站流量必须从这个地址族的 IP 走，目标没有对应
    ///   地址族记录时拒绝连接。
    /// - 两者都填：按目标地址族自动选择对应的出口 IP。
    #[serde(default)]
    pub outbound_bind_ipv4: Option<std::net::Ipv4Addr>,
    /// 出站时绑定的本地 IPv6 出口 IP，规则同 `outbound_bind_ipv4`。
    #[serde(default)]
    pub outbound_bind_ipv6: Option<std::net::Ipv6Addr>,
}

// ── WireGuard ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WireGuardConfig {
    pub listen: String,
    pub private_key: String,
    #[serde(default)]
    pub server_address: Vec<String>,
    #[serde(default = "default_wg_mtu")]
    pub mtu: u16,
    #[serde(deserialize_with = "one_or_many")]
    pub peers: Vec<WireGuardPeerConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WireGuardPeerConfig {
    pub public_key: String,
    pub pre_shared_key: Option<String>,
    pub allowed_ips: Vec<String>,
    #[serde(default)]
    pub keepalive_interval: Option<u16>,
    #[serde(default)]
    pub dns: Vec<String>,
}

fn default_wg_mtu() -> u16 { 1420 }
fn default_ss_cipher() -> ShadowsocksCipher { ShadowsocksCipher::Blake3Aes256Gcm }

// ── Shared ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LogConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self { level: default_log_level() }
    }
}

/// 用户未配置 [node.bandwidth] 或未配置某个方向时使用的默认值。
/// 选用较保守的数值，避免在完全未知链路条件的机器上过度暴发。
/// 用户应根据自己的实际带宽在配置文件中显式覆盖这两个值。
const DEFAULT_UP_MBPS: f64 = 200.0; // 默认上行（服务端→客户端，即用户下载方向）
const DEFAULT_DOWN_MBPS: f64 = 80.0; // 默认下行（客户端→服务端，即用户上传方向）

impl BandwidthConfig {
    pub fn parse_bps(s: &str) -> Option<u64> {
        let s = s.trim().to_lowercase().replace(' ', "");
        if let Some(n) = s.strip_suffix("gbps") {
            n.parse::<f64>().ok().map(|v| (v * 1e9 / 8.0) as u64)
        } else if let Some(n) = s.strip_suffix("mbps") {
            n.parse::<f64>().ok().map(|v| (v * 1e6 / 8.0) as u64)
        } else if let Some(n) = s.strip_suffix("kbps") {
            n.parse::<f64>().ok().map(|v| (v * 1e3 / 8.0) as u64)
        } else if let Some(n) = s.strip_suffix("bps") {
            n.parse::<u64>().ok()
        } else {
            None
        }
    }

    /// 上行带宽（bytes/sec）。未配置时回退到 `DEFAULT_UP_MBPS`，
    /// 始终返回 Some，即 Brutal 拥塞控制永远启用（不再回退到 CUBIC）。
    pub fn up_bps(&self) -> Option<u64> {
        Some(
            self.up
                .as_deref()
                .and_then(Self::parse_bps)
                .unwrap_or_else(|| (DEFAULT_UP_MBPS * 1e6 / 8.0) as u64),
        )
    }

    /// 下行带宽（bytes/sec，告知客户端用）。未配置时回退到 `DEFAULT_DOWN_MBPS`。
    pub fn down_bps(&self) -> Option<u64> {
        Some(
            self.down
                .as_deref()
                .and_then(Self::parse_bps)
                .unwrap_or_else(|| (DEFAULT_DOWN_MBPS * 1e6 / 8.0) as u64),
        )
    }
}

fn default_log_level() -> String { "info".to_string() }
fn default_masquerade_type() -> String { "none".to_string() }
fn default_transport_type() -> String { "tcp".to_string() }
fn default_ws_path() -> String { "/".to_string() }
fn default_xhttp_path() -> String { "/".to_string() }

pub fn load(path: &str) -> Result<Config> {
    let content = std::fs::read_to_string(Path::new(path))
        .with_context(|| format!("cannot read config file: {path}"))?;
    let cfg: Config =
        toml::from_str(&content).with_context(|| format!("invalid TOML in {path}"))?;
    Ok(cfg)
}

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::{Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
    time::Duration,
};
use uuid::Uuid;

use crate::common::tls::config::StandardTlsConfig;

// ══════════════════════════════════════════════════════════════════════════════
// 配置文件约定
//
// • 节点下所有字段平铺（kebab-case），唯一保留的嵌套是确实成列表/映射的数据：
//   `users` / `peers` / `server-address` / `headers`。
// • 通用字段通过 `#[serde(flatten)]` 复用同一份定义：
//     TLS        cert / key / self-signed-domain
//     传输层     transport / path / host / max-early-data / early-data-header / headers
//     出站       outbound-bind-ipv4 / outbound-bind-ipv6 / outbound-socks5 /
//                outbound-username / outbound-password
// • 未知字段一律报错（见 `Extra`），避免拼写错误或沿用旧版嵌套写法时被静默忽略。
// ══════════════════════════════════════════════════════════════════════════════

/// 没有被任何已知字段消费的键。必须放在 struct 的最后一个 `flatten` 字段，
/// 加载后由 [`Config::validate`] 统一报错。
pub type Extra = HashMap<String, serde_yaml::Value>;

/// Build `SocketAddr` from split `listen` + `port`.
/// Bare IPv6 hosts (containing `:`) are bracketed: `::` + 443 → `[::]:443`.
pub fn join_listen_addr(listen: &str, port: u16) -> Result<std::net::SocketAddr> {
    let s = listen.trim();
    let s = if s.is_empty() { "::" } else { s };
    let joined = if s.starts_with('[') {
        format!("{s}:{port}")
    } else if s.contains(':') {
        // bare IPv6 (including default `::`)
        format!("[{s}]:{port}")
    } else {
        format!("{s}:{port}")
    };
    joined
        .parse()
        .with_context(|| format!("invalid listen address `{joined}`"))
}

pub fn format_listen(listen: &str, port: u16) -> String {
    let s = listen.trim();
    let s = if s.is_empty() { "::" } else { s };
    if s.starts_with('[') {
        format!("{s}:{port}")
    } else if s.contains(':') {
        format!("[{s}]:{port}")
    } else {
        format!("{s}:{port}")
    }
}

// ── Top-level config ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct Config {
    /// error | warn | info | debug | trace | off
    #[serde(default = "default_log_level")]
    pub log_level: String,

    #[serde(default)]
    pub nodes: Vec<NodeConfig>,

    #[serde(flatten)]
    extra: Extra,
}

impl Config {
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// 校验所有 name 唯一，返回第一个重复的 name
    pub fn check_duplicate_names(&self) -> Option<&str> {
        let mut seen = std::collections::HashSet::new();
        for n in &self.nodes {
            if !seen.insert(n.name.as_str()) {
                return Some(&n.name);
            }
        }
        None
    }
}

// ── Node（顶层统一入口）──────────────────────────────────────────────────────

/// `nodes:` 列表项，name 必填，type 决定协议
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NodeConfig {
    pub name: String,

    #[serde(flatten)]
    pub inner: NodeInner,
}

// 每个节点在启动时只构造一次，变体大小差异无关紧要，不值得为此 Box。
#[allow(clippy::large_enum_variant)]
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
    Shadowquic(ShadowquicConfig),
    Spectre(SpectreConfig),
}

impl NodeInner {
    fn extra(&self) -> &Extra {
        match self {
            NodeInner::Hysteria2(c) => &c.extra,
            NodeInner::Vless(c) => &c.extra,
            NodeInner::Vmess(c) => &c.extra,
            NodeInner::Trojan(c) => &c.extra,
            NodeInner::Shadowsocks(c) => &c.extra,
            NodeInner::Tuic(c) => &c.extra,
            NodeInner::Wireguard(c) => &c.extra,
            NodeInner::Anytls(c) => &c.extra,
            NodeInner::Socks(c) => &c.extra,
            NodeInner::Http(c) => &c.extra,
            NodeInner::Naiveproxy(c) => &c.extra,
            NodeInner::Shadowquic(c) => &c.extra,
            NodeInner::Spectre(c) => &c.extra,
        }
    }
}

// ── 通用平铺字段 ─────────────────────────────────────────────────────────────

/// 出站设置（所有协议节点通用；wireguard 除外）。
///
/// - `outbound-bind-ipv4` / `outbound-bind-ipv6`：多公网 IP 服务器指定出口 IP。
///   都不填 → 系统默认路由；只填一个 → 该地址族必须走该 IP，目标没有对应
///   地址族记录时拒绝；都填 → 按目标地址族自动选择。
/// - `outbound-socks5`：链式出站，`host:port`。配置后该节点 TCP/UDP 出站都必须
///   经由这个 SOCKS5，握手 / UDP ASSOCIATE 失败直接判定连接失败（不回退直连），
///   此时 `outbound-bind-*` 不再生效。`outbound-username` / `outbound-password`
///   用于上游认证，必须同时填写。
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct OutboundConfig {
    pub outbound_bind_ipv4: Option<Ipv4Addr>,
    pub outbound_bind_ipv6: Option<Ipv6Addr>,
    pub outbound_socks5: Option<String>,
    pub outbound_username: Option<String>,
    pub outbound_password: Option<String>,
}

/// 传输层（vless / vmess / trojan / shadowsocks 通用）。
///
/// `transport: tcp | ws | xhttp`（默认 tcp）。`path` / `host` 对 ws 与 xhttp 通用；
/// `max-early-data` / `early-data-header` / `headers` 仅 ws 有效。
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct TransportConfig {
    #[serde(default = "default_transport_type", rename = "transport")]
    pub kind: String,
    #[serde(default = "default_path")]
    pub path: String,
    /// 设置后严格校验请求 Host。
    #[serde(default)]
    pub host: Option<String>,
    /// WebSocket 0-RTT 早期数据最大字节数；0（默认）= 不启用。
    /// 配合 `early-data-header` 决定传递方式。
    #[serde(default)]
    pub max_early_data: u32,
    /// 早期数据所在 HTTP 头（如 `Sec-WebSocket-Protocol`，Xray 风格）；
    /// 不填则以 base64url 追加到 URL 路径末尾。
    #[serde(default)]
    pub early_data_header: Option<String>,
    /// 自定义 HTTP 请求头（如 User-Agent）。
    #[serde(default)]
    pub headers: Option<HashMap<String, String>>,
}

// ── SOCKS5 ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct SocksUser {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct SocksConfig {
    /// Bind address. Omit or leave empty → `::` (IPv4+IPv6, external access).
    #[serde(default = "default_listen")]
    pub listen: String,
    pub port: u16,
    /// 留空 = 无认证
    #[serde(default)]
    pub users: Vec<SocksUser>,
    #[serde(flatten)]
    pub outbound: OutboundConfig,
    #[serde(flatten)]
    pub extra: Extra,
}

// ── TUIC ──────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct TuicUser {
    pub uuid: Uuid,
    pub password: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct TuicConfig {
    #[serde(default = "default_listen")]
    pub listen: String,
    pub port: u16,
    pub users: Vec<TuicUser>,
    #[serde(flatten)]
    pub tls: StandardTlsConfig,
    #[serde(default = "default_tuic_idle_time", with = "humantime_serde")]
    pub max_idle_time: Duration,
    #[serde(default = "default_tuic_auth_timeout", with = "humantime_serde")]
    pub auth_timeout: Duration,
    #[serde(default = "default_tuic_udp_timeout", with = "humantime_serde")]
    pub udp_timeout: Duration,
    /// 心跳间隔。对齐 sing-box tuic.ServiceOptions.Heartbeat（默认 10s）：
    /// 服务端定期向客户端发送 TUIC Heartbeat datagram，保持 QUIC 连接活跃，
    /// 防止空闲超时断连。
    #[serde(default = "default_tuic_heartbeat", with = "humantime_serde")]
    pub heartbeat: Duration,
    #[serde(default)]
    pub udp_relay_ipv6: bool,
    #[serde(default = "default_tuic_max_udp_packet_size")]
    pub max_udp_packet_size: usize,
    #[serde(flatten)]
    pub outbound: OutboundConfig,
    #[serde(flatten)]
    pub extra: Extra,
}

fn default_tuic_idle_time() -> Duration {
    Duration::from_secs(30)
}
fn default_tuic_auth_timeout() -> Duration {
    Duration::from_secs(3)
}
fn default_tuic_udp_timeout() -> Duration {
    Duration::from_secs(30)
}
fn default_tuic_heartbeat() -> Duration {
    Duration::from_secs(10)
}
fn default_tuic_max_udp_packet_size() -> usize {
    65535
}

impl TuicConfig {
    pub fn users_map(&self) -> HashMap<Uuid, String> {
        self.users
            .iter()
            .map(|u| (u.uuid, u.password.clone()))
            .collect()
    }
}

// ── Hysteria2 ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct Hysteria2Config {
    #[serde(default = "default_listen")]
    pub listen: String,
    pub port: u16,
    pub password: String,
    #[serde(flatten)]
    pub tls: StandardTlsConfig,
    #[serde(flatten)]
    pub bandwidth: BandwidthConfig,
    #[serde(flatten)]
    pub masquerade: MasqueradeConfig,
    #[serde(flatten)]
    pub outbound: OutboundConfig,
    #[serde(flatten)]
    pub extra: Extra,
}

/// 带宽（强烈建议按真实带宽填写），单位 gbps / mbps / kbps / bps，可带空格。
/// - `up`：服务端→客户端（用户下载方向）
/// - `down`：客户端→服务端（用户上传方向）
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct BandwidthConfig {
    pub up: Option<String>,
    pub down: Option<String>,
}

/// 伪装（hysteria2 / naiveproxy 通用）：未认证请求反代到一个正常网站，
/// 用于抵御主动探测。不填 `masquerade-url` 则返回静态 404。
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct MasqueradeConfig {
    pub masquerade_url: Option<String>,
    #[serde(default)]
    pub masquerade_rewrite_host: bool,
}

// ── TLS layer ─────────────────────────────────────────────────────────────────

/// VLESS 的 TLS 模式（由平铺字段推断，见 [`VlessConfig::resolve_tls`]）。
#[derive(Debug, Clone)]
pub enum VlessTlsConfig {
    Tls { standard: StandardTlsConfig },
    Reality(RealityConfig),
}

#[derive(Debug, Clone)]
pub struct RealityConfig {
    pub private_key: String,
    pub short_ids: Vec<String>,
    pub dest: String,
    pub server_name: String,
    /// 允许的客户端时间偏差（秒）。0 表示不检查（不推荐）。
    pub max_time_diff: u64,
}

/// VLESS 的 Reality 平铺字段。填了 `reality-private-key` 即启用 Reality。
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct RealityFields {
    pub reality_private_key: Option<String>,
    /// 1–8 字节 hex
    pub reality_short_ids: Option<Vec<String>>,
    pub reality_dest: Option<String>,
    pub reality_server_name: Option<String>,
    /// 允许的客户端时间偏差（秒），默认 90；0 = 不检查
    pub reality_max_time_diff: Option<u64>,
}

impl RealityFields {
    fn is_any_set(&self) -> bool {
        self.reality_private_key.is_some()
            || self.reality_short_ids.is_some()
            || self.reality_dest.is_some()
            || self.reality_server_name.is_some()
            || self.reality_max_time_diff.is_some()
    }
}

// ── VLESS ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct VlessConfig {
    #[serde(default = "default_listen")]
    pub listen: String,
    pub port: u16,
    pub uuid: String,
    #[serde(flatten)]
    pub transport: TransportConfig,
    /// 标准 TLS 证书字段（与 Reality 互斥）
    #[serde(flatten)]
    tls_files: StandardTlsConfig,
    #[serde(flatten)]
    reality: RealityFields,
    #[serde(flatten)]
    pub outbound: OutboundConfig,
    #[serde(flatten)]
    pub extra: Extra,
    /// 由上面的平铺字段推断出的 TLS 模式（加载时填充，不来自配置文件）：
    /// 无 TLS 字段 = 明文；`cert`/`key`/`self-signed-domain` = TLS；
    /// `reality-private-key` = Reality。
    #[serde(skip)]
    pub tls: Option<VlessTlsConfig>,
}

impl VlessConfig {
    fn resolve_tls(&self) -> Result<Option<VlessTlsConfig>> {
        let r = &self.reality;
        let Some(private_key) = &r.reality_private_key else {
            if r.is_any_set() {
                bail!("reality-* fields are set but `reality-private-key` is missing");
            }
            return Ok(self.tls_files.as_opt().map(|t| VlessTlsConfig::Tls {
                standard: t.clone(),
            }));
        };
        if self.tls_files.is_set() {
            bail!("reality cannot be combined with cert / key / self-signed-domain");
        }
        let short_ids = r
            .reality_short_ids
            .clone()
            .filter(|v| !v.is_empty())
            .context("`reality-short-ids` is required for reality")?;
        Ok(Some(VlessTlsConfig::Reality(RealityConfig {
            private_key: private_key.clone(),
            short_ids,
            dest: r
                .reality_dest
                .clone()
                .context("`reality-dest` is required for reality")?,
            server_name: r
                .reality_server_name
                .clone()
                .context("`reality-server-name` is required for reality")?,
            max_time_diff: r.reality_max_time_diff.unwrap_or(90),
        })))
    }
}

// ── Trojan ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct TrojanConfig {
    #[serde(default = "default_listen")]
    pub listen: String,
    pub port: u16,
    pub password: String,
    #[serde(flatten)]
    pub transport: TransportConfig,
    #[serde(flatten)]
    pub tls: StandardTlsConfig,
    #[serde(flatten)]
    pub outbound: OutboundConfig,
    #[serde(flatten)]
    pub extra: Extra,
}

// ── HTTP（标准 HTTP CONNECT 代理，RFC 7231/RFC 9110）─────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct HttpAuthUser {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct HttpConfig {
    #[serde(default = "default_listen")]
    pub listen: String,
    pub port: u16,
    /// 不填 = 无认证；填了则要求 Proxy-Authorization: Basic 匹配其中一个用户。
    #[serde(default)]
    pub users: Vec<HttpAuthUser>,
    /// 配置了 cert/key/self-signed-domain 即为 HTTPS 代理，否则明文监听。
    #[serde(flatten)]
    pub tls: StandardTlsConfig,
    #[serde(flatten)]
    pub outbound: OutboundConfig,
    #[serde(flatten)]
    pub extra: Extra,
}

// ── NaiveProxy（HTTP/2 CONNECT 隧道 + Basic Auth + 长度 padding）────────────
// 参见 https://github.com/klzgrad/naiveproxy
// 服务端只需实现协议本身：HTTP/2 CONNECT 隧道、Proxy-Authorization: Basic
// 认证、以及可选的首 8 次读写 padding；客户端侧的 Chrome TLS 指纹模拟
// （uTLS）与本服务端无关，本服务端的 TLS 层与其他协议一样使用 rustls。

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct NaiveproxyConfig {
    #[serde(default = "default_listen")]
    pub listen: String,
    pub port: u16,
    /// Proxy-Authorization: Basic 用户名/密码，至少配置一个。
    #[serde(default)]
    pub users: Vec<HttpAuthUser>,
    /// 协议本身跑在 HTTPS 之上；不配置证书字段时回退到自签证书。
    #[serde(flatten)]
    pub tls: StandardTlsConfig,
    #[serde(flatten)]
    pub masquerade: MasqueradeConfig,
    /// 是否启用首 8 次读写 padding（对等协商，双方都支持才生效）。
    /// 默认关闭：建议确认连通性正常后再手动开启。
    #[serde(default)]
    pub padding: bool,
    #[serde(flatten)]
    pub outbound: OutboundConfig,
    #[serde(flatten)]
    pub extra: Extra,
}

// ── VMess ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct VmessConfig {
    #[serde(default = "default_listen")]
    pub listen: String,
    pub port: u16,
    pub uuid: String,
    #[serde(flatten)]
    pub transport: TransportConfig,
    #[serde(flatten)]
    pub tls: StandardTlsConfig,
    #[serde(flatten)]
    pub outbound: OutboundConfig,
    #[serde(flatten)]
    pub extra: Extra,
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
    pub fn salt_len(&self) -> usize {
        self.key_len()
    }
    pub fn tag_len(&self) -> usize {
        16
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct ShadowsocksConfig {
    #[serde(default = "default_listen")]
    pub listen: String,
    pub port: u16,
    pub password: String,
    #[serde(default = "default_ss_cipher")]
    pub method: ShadowsocksCipher,
    #[serde(flatten)]
    pub transport: TransportConfig,
    #[serde(flatten)]
    pub tls: StandardTlsConfig,
    #[serde(flatten)]
    pub outbound: OutboundConfig,
    #[serde(flatten)]
    pub extra: Extra,
}

// ── AnyTLS ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct AnyTlsConfig {
    #[serde(default = "default_listen")]
    pub listen: String,
    pub port: u16,
    pub password: String,
    #[serde(flatten)]
    pub tls: StandardTlsConfig,
    pub padding_scheme: Option<String>,
    #[serde(flatten)]
    pub outbound: OutboundConfig,
    #[serde(flatten)]
    pub extra: Extra,
}

// ── ShadowQuic ───────────────────────────────────────────────────────────────

/// ShadowQuic 服务端配置（参考 shadowquic crate `ShadowQuicServerCfg`）。
///
/// 0-RTT QUIC + JLS SNI 伪装：未认证/不匹配的流量被透明转发到 `jls-upstream`
/// （伪装站），探测者看到的是一个正常的 HTTPS 站点；用户认证通过 JLS 协议层完成。
///
/// ```yaml
/// - name: sq-in
///   type: shadowquic
///   port: 443
///   jls-upstream: google.com:443   # 必须是真实 HTTPS 站点
///   server-name: google.com        # 留空则从 jls-upstream 推断
///   users:
///     - username: user1
///       password: pass1
/// ```
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct ShadowquicConfig {
    #[serde(default = "default_listen")]
    pub listen: String,
    pub port: u16,

    /// JLS 用户列表（username/password 必须与客户端一致）
    #[serde(default)]
    pub users: Vec<SocksUser>,

    /// JLS 伪装上游地址（host:port），未认证流量会被转发到此目标。
    pub jls_upstream: String,

    /// SNI 域名。留空则从 `jls-upstream` 的 host 部分推断，须与客户端一致。
    #[serde(default)]
    pub server_name: Option<String>,

    /// TLS ALPN，默认 ["h3"]，必须与客户端有交集
    #[serde(default = "default_sq_alpn")]
    pub alpn: Vec<String>,

    /// 启用 0-RTT 握手（默认 true）
    #[serde(default = "default_sq_zero_rtt")]
    pub zero_rtt: bool,

    /// 拥塞控制算法：`bbr`（默认）、`cubic`、`new-reno`、`brutal`
    #[serde(default = "default_sq_congestion_control")]
    pub congestion_control: String,

    /// 初始 MTU（≥1200，默认 1300）
    #[serde(default = "default_sq_initial_mtu")]
    pub initial_mtu: u16,

    /// 最小 MTU（必须小于 initial-mtu，≥1200，默认 1290）
    #[serde(default = "default_sq_min_mtu")]
    pub min_mtu: u16,

    /// 启用 QUIC GSO，默认 true
    #[serde(default = "default_sq_gso")]
    pub gso: bool,

    /// 启用 MTU 自动发现，默认 true
    #[serde(default = "default_sq_mtu_discovery")]
    pub mtu_discovery: bool,

    /// 启用 MTU 黑洞检测，默认 false
    #[serde(default)]
    pub blackhole_detection: bool,

    /// 是否允许 UDP6 中继，默认 false
    #[serde(default)]
    pub udp_relay_ipv6: bool,

    /// UDP 会话空闲超时，默认 30s
    #[serde(default = "default_sq_udp_timeout", with = "humantime_serde")]
    pub udp_timeout: Duration,

    #[serde(flatten)]
    pub outbound: OutboundConfig,
    #[serde(flatten)]
    pub extra: Extra,
}

fn default_sq_alpn() -> Vec<String> {
    vec!["h3".into()]
}
fn default_sq_zero_rtt() -> bool {
    true
}
fn default_sq_congestion_control() -> String {
    "bbr".into()
}
fn default_sq_initial_mtu() -> u16 {
    1300
}
fn default_sq_min_mtu() -> u16 {
    1290
}
fn default_sq_gso() -> bool {
    true
}
fn default_sq_mtu_discovery() -> bool {
    true
}
fn default_sq_udp_timeout() -> Duration {
    Duration::from_secs(30)
}

// ── Spectre ──────────────────────────────────────────────────────────────

/// Spectre 服务端入站配置（QUIC + JLS 伪装 + Brutal 拥塞控制）。
///
/// 协议来自 spectre-master（`src/server` + `src/protocol`）：认证失败的
/// QUIC 握手被 quinn-jls 透明转发到 `upstream`（必须是真实 HTTP/3 站点），
/// 探测者看到的是正常网站；通过 JLS 认证的客户端在控制流 AUTH 之后，
/// 每个代理目标开一条双向流（TCP Connect / UDP Associate），UDP 走
/// QUIC datagram + 分片。Brutal 目标速率取客户端 AUTH 帧声明的下载速率。
///
/// ```yaml
/// - name: sp-in
///   type: spectre
///   port: 4433
///   password: your-strong-password   # JLS 密钥，须与客户端一致
///   server-name: www.cloudflare.com  # SNI，须与客户端一致
///   upstream: www.cloudflare.com:443 # 未认证流量转发到此（真实站点）
/// ```
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct SpectreConfig {
    #[serde(default = "default_listen")]
    pub listen: String,
    pub port: u16,
    /// JLS 密钥（password）。与客户端完全一致。
    pub password: String,
    /// JLS 用户名（iv）。默认 "spectre"；留空则不校验用户名。
    #[serde(default)]
    pub username: Option<String>,
    /// JLS 伪装用的 SNI 域名，须与客户端一致，且应为 `upstream` 的 host。
    #[serde(default = "default_spectre_server_name")]
    pub server_name: String,
    /// 未认证/探测流量透明转发到的真实站点（host:port），须支持 HTTP/3。
    #[serde(default = "default_spectre_upstream")]
    pub upstream: String,
    /// Salamander 报文混淆 PSK（可选）。配置后每个外层 UDP 包都带
    /// 8 字节随机盐 + XOR 混淆，对抗被动 QUIC 指纹；须与客户端一致。
    #[serde(default)]
    pub obfs_psk: Option<String>,
    /// UDP 会话空闲超时（读任务无回包多久后回收会话）。
    #[serde(default = "default_spectre_udp_timeout", with = "humantime_serde")]
    pub udp_timeout: Duration,
    /// 是否中继 IPv6 UDP 目标（Direct 出站时才会建 v6 socket）。
    #[serde(default)]
    pub udp_relay_ipv6: bool,
    #[serde(flatten)]
    pub outbound: OutboundConfig,
    #[serde(flatten)]
    pub extra: Extra,
}

fn default_spectre_server_name() -> String {
    "www.cloudflare.com".into()
}
fn default_spectre_upstream() -> String {
    "www.cloudflare.com:443".into()
}
fn default_spectre_udp_timeout() -> Duration {
    Duration::from_secs(120)
}

// ── WireGuard ─────────────────────────────────────────────────────────────────

/// WireGuard 不支持 `outbound-*`（流量走内置虚拟网卡）。
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct WireGuardConfig {
    #[serde(default = "default_listen")]
    pub listen: String,
    pub port: u16,
    pub private_key: String,
    /// 服务端在隧道内的地址，如 ["10.0.0.1/24", "fd00::1/64"]
    #[serde(default)]
    pub server_address: Vec<String>,
    #[serde(default = "default_wg_mtu")]
    pub mtu: u16,
    pub peers: Vec<WireGuardPeerConfig>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct WireGuardPeerConfig {
    pub public_key: String,
    pub pre_shared_key: Option<String>,
    pub allowed_ips: Vec<String>,
    #[serde(default)]
    pub keepalive_interval: Option<u16>,
    #[serde(default)]
    pub dns: Vec<String>,
}

fn default_wg_mtu() -> u16 {
    1420
}
fn default_ss_cipher() -> ShadowsocksCipher {
    ShadowsocksCipher::Blake3Aes256Gcm
}

// ── Shared ────────────────────────────────────────────────────────────────────

/// 用户未配置 `up` / `down` 时使用的默认值。
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

fn default_log_level() -> String {
    "info".to_string()
}
/// Default listen address: dual-stack wildcard (`::`), reachable from external hosts.
/// Explicit `0.0.0.0` / `127.0.0.1` / specific IPs remain valid when set.
fn default_listen() -> String {
    "::".into()
}
fn default_transport_type() -> String {
    "tcp".to_string()
}
fn default_path() -> String {
    "/".to_string()
}

/// Resolve a filesystem path against `base_dir`.
/// Absolute paths and `file:` / `file://` prefixes are kept absolute;
/// relative paths join `base_dir` (config file directory / `-d`).
pub fn resolve_fs_path(path: &str, base_dir: &Path) -> String {
    let raw = path.trim();
    let stripped = raw
        .strip_prefix("file://")
        .or_else(|| raw.strip_prefix("file:"))
        .unwrap_or(raw);
    let p = Path::new(stripped);
    if p.is_absolute() {
        stripped.to_string()
    } else {
        base_dir.join(p).to_string_lossy().into_owned()
    }
}

fn resolve_opt_path(path: &mut Option<String>, base_dir: &Path) {
    if let Some(ref mut p) = path {
        *p = resolve_fs_path(p, base_dir);
    }
}

fn resolve_standard_tls(tls: &mut StandardTlsConfig, base: &Path) {
    resolve_opt_path(&mut tls.cert_path, base);
    resolve_opt_path(&mut tls.key_path, base);
}

impl Config {
    /// Resolve relative cert/key paths against `base_dir`.
    pub fn resolve_paths(&mut self, base_dir: &Path) {
        for node in &mut self.nodes {
            match &mut node.inner {
                NodeInner::Hysteria2(c) => resolve_standard_tls(&mut c.tls, base_dir),
                NodeInner::Vless(c) => resolve_standard_tls(&mut c.tls_files, base_dir),
                NodeInner::Vmess(c) => resolve_standard_tls(&mut c.tls, base_dir),
                NodeInner::Trojan(c) => resolve_standard_tls(&mut c.tls, base_dir),
                NodeInner::Shadowsocks(c) => resolve_standard_tls(&mut c.tls, base_dir),
                NodeInner::Tuic(c) => resolve_standard_tls(&mut c.tls, base_dir),
                NodeInner::Anytls(c) => resolve_standard_tls(&mut c.tls, base_dir),
                NodeInner::Http(c) => resolve_standard_tls(&mut c.tls, base_dir),
                NodeInner::Naiveproxy(c) => resolve_standard_tls(&mut c.tls, base_dir),
                NodeInner::Socks(_) | NodeInner::Wireguard(_) | NodeInner::Shadowquic(_) => {}
                NodeInner::Spectre(_) => {}
            }
        }
    }

    /// 校验配置并填充派生字段（如 VLESS 的 TLS 模式）。
    /// 须在 [`Config::resolve_paths`] 之后调用。
    fn finalize(&mut self) -> Result<()> {
        if !self.extra.is_empty() {
            bail!("unknown top-level field(s): {}", format_unknown(&self.extra));
        }
        for node in &mut self.nodes {
            let name = node.name.clone();
            node.finalize()
                .with_context(|| format!("node `{name}`"))?;
        }
        Ok(())
    }
}

impl NodeConfig {
    fn finalize(&mut self) -> Result<()> {
        let extra = self.inner.extra();
        if !extra.is_empty() {
            bail!("unknown field(s): {}", format_unknown(extra));
        }
        match &mut self.inner {
            NodeInner::Hysteria2(c) => {
                check_tls(&c.tls)?;
                check_outbound(&c.outbound)?;
                for (key, v) in [("up", &c.bandwidth.up), ("down", &c.bandwidth.down)] {
                    if let Some(s) = v {
                        if BandwidthConfig::parse_bps(s).is_none() {
                            bail!("invalid `{key}` bandwidth `{s}` (expected e.g. \"100 mbps\")");
                        }
                    }
                }
            }
            NodeInner::Vless(c) => {
                check_transport(&c.transport)?;
                check_tls(&c.tls_files)?;
                check_outbound(&c.outbound)?;
                c.tls = c.resolve_tls()?;
            }
            NodeInner::Vmess(c) => {
                check_transport(&c.transport)?;
                check_tls(&c.tls)?;
                check_outbound(&c.outbound)?;
            }
            NodeInner::Trojan(c) => {
                check_transport(&c.transport)?;
                check_tls(&c.tls)?;
                check_outbound(&c.outbound)?;
            }
            NodeInner::Shadowsocks(c) => {
                check_transport(&c.transport)?;
                check_tls(&c.tls)?;
                check_outbound(&c.outbound)?;
            }
            NodeInner::Tuic(c) => {
                check_tls(&c.tls)?;
                check_outbound(&c.outbound)?;
            }
            NodeInner::Anytls(c) => {
                check_tls(&c.tls)?;
                check_outbound(&c.outbound)?;
            }
            NodeInner::Http(c) => {
                check_tls(&c.tls)?;
                check_outbound(&c.outbound)?;
            }
            NodeInner::Naiveproxy(c) => {
                check_tls(&c.tls)?;
                check_outbound(&c.outbound)?;
            }
            NodeInner::Socks(c) => check_outbound(&c.outbound)?,
            NodeInner::Shadowquic(c) => check_outbound(&c.outbound)?,
            NodeInner::Spectre(c) => {
                check_outbound(&c.outbound)?;
                if c.password.trim().is_empty() {
                    bail!("`password` (JLS secret) must not be empty");
                }
                if let Some(psk) = &c.obfs_psk {
                    if psk.len() < crate::spectre::obfs::MIN_PSK_LEN {
                        bail!(
                            "`obfs-psk` must be at least {} bytes",
                            crate::spectre::obfs::MIN_PSK_LEN
                        );
                    }
                }
            }
            NodeInner::Wireguard(_) => {}
        }
        Ok(())
    }
}

fn check_tls(tls: &StandardTlsConfig) -> Result<()> {
    if tls.cert_path.is_some() != tls.key_path.is_some() {
        bail!("`cert` and `key` must be set together");
    }
    Ok(())
}

fn check_outbound(o: &OutboundConfig) -> Result<()> {
    if o.outbound_username.is_some() != o.outbound_password.is_some() {
        bail!("`outbound-username` and `outbound-password` must be set together");
    }
    if o.outbound_socks5.is_none() && o.outbound_username.is_some() {
        bail!("`outbound-username` / `outbound-password` require `outbound-socks5`");
    }
    Ok(())
}

fn check_transport(t: &TransportConfig) -> Result<()> {
    match t.kind.as_str() {
        "tcp" => {
            if t.path != "/"
                || t.host.is_some()
                || t.max_early_data != 0
                || t.early_data_header.is_some()
                || t.headers.is_some()
            {
                bail!(
                    "path / host / max-early-data / early-data-header / headers only apply to \
                     `transport: ws` or `xhttp`, but transport is `tcp` (forgot `transport: ws`?)"
                );
            }
        }
        "ws" => {}
        "xhttp" => {
            if t.max_early_data != 0 || t.early_data_header.is_some() || t.headers.is_some() {
                bail!("max-early-data / early-data-header / headers only apply to `transport: ws`");
            }
        }
        other => bail!("unknown transport `{other}` (expected tcp | ws | xhttp)"),
    }
    Ok(())
}

/// 把未知字段列成 "`a`, `b（提示）`"；对旧版嵌套写法给出迁移提示。
fn format_unknown(extra: &Extra) -> String {
    let mut keys: Vec<&String> = extra.keys().collect();
    keys.sort();
    keys.iter()
        .map(|k| match unknown_field_hint(k) {
            Some(h) => format!("`{k}` ({h})"),
            None => format!("`{k}`"),
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn unknown_field_hint(key: &str) -> Option<&'static str> {
    Some(match key {
        "tls" => "now flat: use cert / key / self-signed-domain (vless reality: reality-*)",
        "transport" => "now flat: transport: ws plus path / host",
        "outbound" => "now flat: outbound-socks5 / outbound-username / outbound-password",
        "auth" => "now flat: use `password`",
        "bandwidth" => "now flat: use `up` / `down`",
        "masquerade" => "now flat: use masquerade-url / masquerade-rewrite-host",
        "cert-path" => "renamed to `cert`",
        "key-path" => "renamed to `key`",
        "ws-path" | "xhttp-path" => "renamed to `path`",
        "ws-host" | "xhttp-host" => "renamed to `host`",
        "ws-max-early-data" => "renamed to `max-early-data`",
        "ws-early-data-header-name" => "renamed to `early-data-header`",
        "ws-headers" => "renamed to `headers`",
        _ => return None,
    })
}

/// Load YAML config. Relative cert/key paths resolve against `base_dir`
/// (or the config file's parent directory when `base_dir` is `None`).
pub fn load_with_base(path: &str, base_dir: Option<&Path>) -> Result<Config> {
    let path_buf = PathBuf::from(path);
    let derived_base = path_buf
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));
    let base = base_dir.unwrap_or(derived_base.as_path());

    let content = std::fs::read_to_string(&path_buf)
        .with_context(|| format!("cannot read config file: {path}"))?;
    parse(&content, base).with_context(|| format!("invalid config {path}"))
}

fn parse(content: &str, base: &Path) -> Result<Config> {
    let mut cfg: Config = serde_yaml::from_str(content)?;
    if let Some(dup) = cfg.check_duplicate_names() {
        bail!("duplicate node name `{dup}`");
    }
    for n in &cfg.nodes {
        if n.name.trim().is_empty() {
            bail!("node name must not be empty");
        }
    }
    cfg.resolve_paths(base);
    cfg.finalize()?;
    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_str(yaml: &str) -> Result<Config> {
        parse(yaml, Path::new("/base"))
    }

    fn err(yaml: &str) -> String {
        format!("{:#}", parse_str(yaml).unwrap_err())
    }

    #[test]
    fn hysteria2_flat() {
        let cfg = parse_str(
            r#"
nodes:
  - name: hy2
    type: hysteria2
    port: 443
    password: pw
    cert: certs/a.pem
    key: /abs/k.pem
    up: 300 mbps
    down: 50 mbps
    masquerade-url: https://example.com
    masquerade-rewrite-host: true
    outbound-socks5: 127.0.0.1:1080
    outbound-username: u
    outbound-password: p
"#,
        )
        .unwrap();
        let NodeInner::Hysteria2(c) = &cfg.nodes[0].inner else {
            panic!()
        };
        assert_eq!(c.listen, "::");
        assert_eq!(c.password, "pw");
        // 相对路径基于配置文件目录解析，绝对路径保持不变
        assert_eq!(c.tls.cert_path.as_deref(), Some("/base/certs/a.pem"));
        assert_eq!(c.tls.key_path.as_deref(), Some("/abs/k.pem"));
        assert_eq!(c.bandwidth.up_bps(), Some(300_000_000 / 8));
        assert_eq!(c.bandwidth.down_bps(), Some(50_000_000 / 8));
        assert_eq!(
            c.masquerade.masquerade_url.as_deref(),
            Some("https://example.com")
        );
        assert!(c.masquerade.masquerade_rewrite_host);
        assert_eq!(c.outbound.outbound_socks5.as_deref(), Some("127.0.0.1:1080"));
        assert_eq!(c.outbound.outbound_username.as_deref(), Some("u"));
    }

    #[test]
    fn hysteria2_minimal_defaults() {
        let cfg = parse_str(
            "nodes:\n  - {name: a, type: hysteria2, port: 443, password: x}\n",
        )
        .unwrap();
        let NodeInner::Hysteria2(c) = &cfg.nodes[0].inner else {
            panic!()
        };
        assert!(!c.tls.is_set());
        assert!(c.masquerade.masquerade_url.is_none());
        assert!(c.outbound.outbound_socks5.is_none());
    }

    #[test]
    fn vless_tls_modes() {
        let cfg = parse_str(
            r#"
nodes:
  - {name: plain, type: vless, port: 1, uuid: u}
  - {name: tls, type: vless, port: 2, uuid: u, cert: c.pem, key: k.pem}
  - {name: ss, type: vless, port: 3, uuid: u, self-signed-domain: a.com}
  - name: reality
    type: vless
    port: 4
    uuid: u
    reality-private-key: PK
    reality-short-ids: [deadbeef]
    reality-dest: www.microsoft.com:443
    reality-server-name: www.microsoft.com
"#,
        )
        .unwrap();
        let tls = |i: usize| match &cfg.nodes[i].inner {
            NodeInner::Vless(c) => c.tls.clone(),
            _ => panic!(),
        };
        assert!(tls(0).is_none());
        assert!(matches!(tls(1), Some(VlessTlsConfig::Tls { .. })));
        assert!(matches!(tls(2), Some(VlessTlsConfig::Tls { .. })));
        match tls(3) {
            Some(VlessTlsConfig::Reality(r)) => {
                assert_eq!(r.private_key, "PK");
                assert_eq!(r.short_ids, vec!["deadbeef"]);
                assert_eq!(r.max_time_diff, 90);
            }
            other => panic!("expected reality, got {other:?}"),
        }
    }

    #[test]
    fn vless_ws_transport() {
        let cfg = parse_str(
            r#"
nodes:
  - name: ws
    type: vless
    port: 443
    uuid: u
    transport: ws
    path: /vless
    host: a.com
    max-early-data: 2560
    early-data-header: Sec-WebSocket-Protocol
    headers: {User-Agent: x}
    cert: c.pem
    key: k.pem
"#,
        )
        .unwrap();
        let NodeInner::Vless(c) = &cfg.nodes[0].inner else {
            panic!()
        };
        assert_eq!(c.transport.kind, "ws");
        assert_eq!(c.transport.path, "/vless");
        assert_eq!(c.transport.host.as_deref(), Some("a.com"));
        assert_eq!(c.transport.max_early_data, 2560);
        assert_eq!(
            c.transport.early_data_header.as_deref(),
            Some("Sec-WebSocket-Protocol")
        );
        assert_eq!(c.transport.headers.as_ref().unwrap()["User-Agent"], "x");
    }

    #[test]
    fn other_protocols_flat() {
        let cfg = parse_str(
            r#"
nodes:
  - {name: vm, type: vmess, port: 1, uuid: u, transport: xhttp, path: /x, host: h}
  - {name: tj, type: trojan, port: 2, password: p, cert: c, key: k}
  - {name: ss, type: shadowsocks, port: 3, password: p, method: 2022-blake3-aes-128-gcm}
  - name: tu
    type: tuic
    port: 4
    users: [{uuid: 11111111-1111-1111-1111-111111111111, password: p}]
    heartbeat: 5s
  - {name: at, type: anytls, port: 5, password: p, padding-scheme: s}
  - {name: so, type: socks, port: 6, users: [{username: u, password: p}]}
  - {name: ht, type: http, port: 7, self-signed-domain: a.com}
  - name: nv
    type: naiveproxy
    port: 8
    users: [{username: u, password: p}]
    masquerade-url: https://example.com
    padding: true
  - name: sq
    type: shadowquic
    port: 9
    jls-upstream: google.com:443
    users: [{username: u, password: p}]
    congestion-control: cubic
  - name: sp
    type: spectre
    port: 10
    password: spectre-pw
  - name: wg
    type: wireguard
    port: 11
    private-key: K
    server-address: [10.0.0.1/24]
    peers: [{public-key: P, allowed-ips: [10.0.0.2/32]}]
"#,
        )
        .unwrap();
        assert_eq!(cfg.nodes.len(), 11);
        let NodeInner::Tuic(t) = &cfg.nodes[3].inner else {
            panic!()
        };
        assert_eq!(t.heartbeat, Duration::from_secs(5));
        assert_eq!(t.max_idle_time, Duration::from_secs(30));
        let NodeInner::Http(h) = &cfg.nodes[6].inner else {
            panic!()
        };
        assert!(h.tls.is_set());
        let NodeInner::Naiveproxy(n) = &cfg.nodes[7].inner else {
            panic!()
        };
        assert!(n.padding && n.masquerade.masquerade_url.is_some());
        let NodeInner::Shadowquic(q) = &cfg.nodes[8].inner else {
            panic!()
        };
        assert_eq!(q.congestion_control, "cubic");
        assert_eq!(q.alpn, vec!["h3"]);
        let NodeInner::Spectre(s) = &cfg.nodes[9].inner else {
            panic!()
        };
        assert_eq!(s.password, "spectre-pw");
        assert_eq!(s.server_name, "www.cloudflare.com");
        assert_eq!(s.upstream, "www.cloudflare.com:443");
        assert_eq!(s.udp_timeout, Duration::from_secs(120));
        assert!(s.username.is_none());
        assert!(s.obfs_psk.is_none());
    }

    #[test]
    fn spectre_config() {
        // 最小配置：只写 password，其余走默认
        let cfg = parse_str("nodes:\n  - {name: sp, type: spectre, port: 4433, password: pw}\n")
            .unwrap();
        let NodeInner::Spectre(s) = &cfg.nodes[0].inner else {
            panic!()
        };
        assert_eq!(s.listen, "::");
        assert_eq!(s.server_name, "www.cloudflare.com");
        assert_eq!(s.upstream, "www.cloudflare.com:443");
        assert_eq!(s.udp_timeout, Duration::from_secs(120));
        assert!(!s.udp_relay_ipv6);

        // 完整配置
        let cfg = parse_str(
            r#"
nodes:
  - name: sp-full
    type: spectre
    listen: "0.0.0.0"
    port: 4433
    password: pw
    username: spectre
    server-name: www.example.com
    upstream: www.example.com:443
    obfs-psk: "0123456789abcdef"
    udp-timeout: 60s
    udp-relay-ipv6: true
    outbound-bind-ipv4: 203.0.113.10
"#,
        )
        .unwrap();
        let NodeInner::Spectre(s) = &cfg.nodes[0].inner else {
            panic!()
        };
        assert_eq!(s.listen, "0.0.0.0");
        assert_eq!(s.username.as_deref(), Some("spectre"));
        assert_eq!(s.server_name, "www.example.com");
        assert_eq!(s.upstream, "www.example.com:443");
        assert_eq!(s.obfs_psk.as_deref(), Some("0123456789abcdef"));
        assert_eq!(s.udp_timeout, Duration::from_secs(60));
        assert!(s.udp_relay_ipv6);
        assert_eq!(
            s.outbound.outbound_bind_ipv4,
            Some("203.0.113.10".parse().unwrap())
        );

        // 链式 SOCKS5 出站
        let cfg = parse_str(
            "nodes:\n  - {name: sp, type: spectre, port: 1, password: p, outbound-socks5: '127.0.0.1:1080', outbound-username: u, outbound-password: w}\n",
        )
        .unwrap();
        let NodeInner::Spectre(s) = &cfg.nodes[0].inner else {
            panic!()
        };
        assert_eq!(
            s.outbound.outbound_socks5.as_deref(),
            Some("127.0.0.1:1080")
        );
    }

    #[test]
    fn rejects_invalid_spectre_config() {
        // password 必填
        assert!(parse_str("nodes:\n  - {name: sp, type: spectre, port: 1}\n").is_err());
        // password 不能为空串
        assert!(err("nodes:\n  - {name: sp, type: spectre, port: 1, password: '  '}\n")
            .contains("must not be empty"));
        // obfs-psk 至少 4 字节
        assert!(err("nodes:\n  - {name: sp, type: spectre, port: 1, password: p, obfs-psk: 'ab'}\n")
            .contains("obfs-psk"));
        // 出站认证须成对
        assert!(err(
            "nodes:\n  - {name: sp, type: spectre, port: 1, password: p, outbound-socks5: 'h:1', outbound-username: u}\n"
        )
        .contains("together"));
        // 未知字段报错
        assert!(err("nodes:\n  - {name: sp, type: spectre, port: 1, password: p, sni: x}\n")
            .contains("`sni`"));
    }

    #[test]
    fn rejects_old_nested_style_with_hint() {
        let e = err(
            r#"
nodes:
  - name: a
    type: trojan
    port: 443
    password: p
    tls:
      cert-path: c.pem
      key-path: k.pem
"#,
        );
        assert!(e.contains("node `a`") && e.contains("`tls`") && e.contains("now flat"), "{e}");

        let e = err(
            r#"
nodes:
  - {name: a, type: vless, port: 1, uuid: u, ws-path: /x}
"#,
        );
        assert!(e.contains("`ws-path`") && e.contains("renamed to `path`"), "{e}");

        // 旧版嵌套 transport 是 map，而新的 transport 是字符串
        assert!(parse_str(
            "nodes:\n  - {name: a, type: vless, port: 1, uuid: u, transport: {type: ws}}\n"
        )
        .is_err());
    }

    #[test]
    fn rejects_typos_and_top_level_unknown() {
        let e = err("nodes:\n  - {name: a, type: socks, port: 1, usres: []}\n");
        assert!(e.contains("`usres`"), "{e}");
        let e = err("node: []\n");
        assert!(e.contains("`node`"), "{e}");
    }

    #[test]
    fn rejects_inconsistent_fields() {
        // cert / key 必须成对
        assert!(err("nodes:\n  - {name: a, type: trojan, port: 1, password: p, cert: c}\n")
            .contains("together"));
        // path 等字段只对 ws / xhttp 有意义，tcp 下设置多半是忘了写 transport
        assert!(err("nodes:\n  - {name: a, type: vmess, port: 1, uuid: u, path: /x}\n")
            .contains("transport: ws"));
        assert!(err("nodes:\n  - {name: a, type: vmess, port: 1, uuid: u, transport: grpc}\n")
            .contains("unknown transport"));
        // 上游 SOCKS5 认证必须成对且依赖 outbound-socks5
        assert!(err(
            "nodes:\n  - {name: a, type: socks, port: 1, outbound-socks5: 'h:1', outbound-username: u}\n"
        )
        .contains("together"));
        assert!(err(
            "nodes:\n  - {name: a, type: socks, port: 1, outbound-username: u, outbound-password: p}\n"
        )
        .contains("require `outbound-socks5`"));
        // wireguard 不支持出站字段
        assert!(err(
            "nodes:\n  - {name: w, type: wireguard, port: 1, private-key: k, peers: [], outbound-socks5: 'h:1'}\n"
        )
        .contains("`outbound-socks5`"));
        // Reality 约束
        assert!(err(
            "nodes:\n  - {name: a, type: vless, port: 1, uuid: u, reality-dest: 'x:443'}\n"
        )
        .contains("reality-private-key"));
        assert!(err(
            "nodes:\n  - {name: a, type: vless, port: 1, uuid: u, reality-private-key: k, cert: c, key: k}\n"
        )
        .contains("cannot be combined"));
        assert!(err(
            "nodes:\n  - {name: a, type: vless, port: 1, uuid: u, reality-private-key: k}\n"
        )
        .contains("reality-short-ids"));
        // 带宽格式
        assert!(err(
            "nodes:\n  - {name: a, type: hysteria2, port: 1, password: p, up: fast}\n"
        )
        .contains("invalid `up`"));
        // 缺少必填字段
        assert!(parse_str("nodes:\n  - {name: a, type: hysteria2, port: 1}\n").is_err());
    }

    #[test]
    fn rejects_duplicate_and_empty_names() {
        assert!(err(
            "nodes:\n  - {name: a, type: socks, port: 1}\n  - {name: a, type: socks, port: 2}\n"
        )
        .contains("duplicate node name"));
        assert!(err("nodes:\n  - {name: ' ', type: socks, port: 1}\n").contains("must not be empty"));
    }

    /// 把 config.example.yaml 里所有被注释掉的示例块取消注释后整体解析，
    /// 保证模板里的每一个示例都是合法配置。
    #[test]
    fn example_file_blocks_are_valid() {
        let text = include_str!("../config.example.yaml");
        let mut out = String::new();
        let mut in_nodes = false;
        for line in text.lines() {
            if line.starts_with("nodes:") {
                in_nodes = true;
            }
            let t = line.strip_prefix("  # ");
            match t {
                // 示例块：`- name:` 行，或缩进 ≥ 2 的 `key:` / `- ` 行
                Some(rest)
                    if in_nodes
                        && (rest.starts_with("- name:")
                            || (rest.starts_with("  ")
                                && !rest.trim_start().starts_with('#')
                                && (rest.contains(": ") || rest.trim_end().ends_with(':') || rest.trim_start().starts_with("- ")))) =>
                {
                    out.push_str("  ");
                    out.push_str(rest);
                    out.push('\n');
                }
                _ => {
                    out.push_str(line);
                    out.push('\n');
                }
            }
        }
        // 同名节点（如 2-A..2-D 各自 name 不同）已保证唯一
        let cfg = parse_str(&out).unwrap_or_else(|e| panic!("{e:#}\n----\n{out}"));
        // 12 种协议 + vless 的 4 个变体 + demo
        assert!(cfg.nodes.len() >= 15, "got {} nodes", cfg.nodes.len());
    }
}

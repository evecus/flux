//! 链式出站代理（`[node.outbound]`）。
//!
//! 每个协议 node 可选配置一个上游 SOCKS5 出站：
//!
//! ```toml
//! [node.outbound]
//! type     = "socks5"
//! addr     = "127.0.0.1:1080"
//! username = "user"     # 可选
//! password = "pass"     # 可选
//! ```
//!
//! 不配置 `[node.outbound]`：该 node 所有出站走直连（原有行为不变，
//! `outbound_bind_ipv4` / `outbound_bind_ipv6` 依旧对直连生效）。
//!
//! 配置了 `[node.outbound]`：该 node 的 **TCP 与 UDP 出站流量都必须**
//! 经由这个 SOCKS5 服务器转发（TCP 用 CONNECT，UDP 用 UDP ASSOCIATE）。
//! 这是严格模式 —— 握手 / ASSOCIATE 失败就直接判定本次连接 / UDP 会话
//! 失败，绝不会静默回退成直连，避免流量意外绕过链式代理导致出口 IP 泄漏。

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Mutex as AsyncMutex;
use tracing::{debug, warn};

use crate::config::OutboundConfig;

use super::net::{self as direct, OutboundBind};

/// 统一出站配置：直连 or 链式 SOCKS5。
#[derive(Debug, Clone)]
pub enum Outbound {
    Direct(OutboundBind),
    Socks5(Arc<Socks5Config>),
}

#[derive(Debug, Clone)]
pub struct Socks5Config {
    pub addr: String,
    pub username: Option<String>,
    pub password: Option<String>,
}

impl Outbound {
    /// 根据协议 config 里的 `outbound_bind_ipv4/ipv6` + 可选 `outbound`
    /// 构造统一出站配置。各协议模块原先构造 `OutboundBind::new(...)`
    /// 的地方直接替换为本函数即可。
    pub fn new(
        bind_v4: Option<std::net::Ipv4Addr>,
        bind_v6: Option<std::net::Ipv6Addr>,
        outbound: &Option<OutboundConfig>,
    ) -> Self {
        match outbound {
            None => Outbound::Direct(OutboundBind::new(bind_v4, bind_v6)),
            Some(cfg) => Outbound::Socks5(Arc::new(Socks5Config {
                addr: cfg.addr().to_string(),
                username: cfg.username().cloned(),
                password: cfg.password().cloned(),
            })),
        }
    }
}

impl Default for Outbound {
    fn default() -> Self {
        Outbound::Direct(OutboundBind::default())
    }
}

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

// ── TCP ─────────────────────────────────────────────────────────────────────

/// 解析 `target`（"host:port"）并按 `outbound` 建立到目标的 TCP 连接。
/// - Direct：等价于原先的 `net::dial_tcp`。
/// - Socks5：经上游 SOCKS5 CONNECT 转发；握手失败直接返回错误（严格模式，
///   不回退直连）。
pub async fn dial_tcp(target: &str, outbound: &Outbound) -> io::Result<TcpStream> {
    match outbound {
        Outbound::Direct(bind) => direct::dial_tcp(target, *bind).await,
        Outbound::Socks5(cfg) => socks5_connect(cfg, target).await,
    }
}

/// 已解析好 `SocketAddr` 的场景。
pub async fn dial_tcp_addr(target: SocketAddr, outbound: &Outbound) -> io::Result<TcpStream> {
    match outbound {
        Outbound::Direct(bind) => direct::dial_tcp_addr(target, *bind).await,
        Outbound::Socks5(cfg) => socks5_connect(cfg, &target.to_string()).await,
    }
}

/// 带超时的 TCP 拨号。
pub async fn dial_tcp_timeout(
    target: &str,
    outbound: &Outbound,
    timeout: Duration,
) -> io::Result<TcpStream> {
    match tokio::time::timeout(timeout, dial_tcp(target, outbound)).await {
        Ok(res) => res,
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("connect {target} timeout"),
        )),
    }
}

async fn socks5_connect(cfg: &Socks5Config, target: &str) -> io::Result<TcpStream> {
    let target = target.to_string();
    let result = if let (Some(user), Some(pass)) = (&cfg.username, &cfg.password) {
        tokio::time::timeout(
            CONNECT_TIMEOUT,
            tokio_socks::tcp::Socks5Stream::connect_with_password(
                cfg.addr.as_str(),
                target.as_str(),
                user.as_str(),
                pass.as_str(),
            ),
        )
        .await
    } else {
        tokio::time::timeout(
            CONNECT_TIMEOUT,
            tokio_socks::tcp::Socks5Stream::connect(cfg.addr.as_str(), target.as_str()),
        )
        .await
    };

    match result {
        Ok(Ok(stream)) => Ok(stream.into_inner()),
        Ok(Err(e)) => Err(io::Error::other(format!(
            "上游 socks5({}) CONNECT {target} 失败: {e}",
            cfg.addr
        ))),
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("上游 socks5({}) CONNECT {target} 超时", cfg.addr),
        )),
    }
}

// ── UDP ─────────────────────────────────────────────────────────────────────
//
// 各协议（VLESS/Trojan/VMess 的 packetaddr relay、Hysteria2 的 UDP session）
// 原先都是直接持有一个裸 `tokio::net::UdpSocket`，用 `send_to(target, buf)` /
// `recv_from(&mut buf)` 收发。为了让这些调用点改动最小，这里提供一个同样
// 语义的 `UdpRelay` 封装：
// - Direct：内部就是裸 UdpSocket，等价于原来的 `net::bind_udp`。
// - Socks5：内部维护一条常驻 TCP 控制连接（UDP ASSOCIATE）+ 中转 UDP
//   socket，`send_to`/`recv_from` 自动做 SOCKS5 UDP 请求头的封装/解封装。
//   控制连接必须全程存活；连接失败或中途断开都视为该 UDP 会话失败
//   （严格模式，不回退直连）。

pub enum UdpRelay {
    Direct(UdpSocket),
    Socks5(Socks5UdpRelay),
}

impl UdpRelay {
    /// 建立一个 UDP 出站通道。
    /// - Direct：`v6` 决定未配置出口 IP 时使用哪个 unspecified 地址。
    /// - Socks5：忽略 `v6`（同一条 UDP ASSOCIATE 通道同时承载 v4/v6 目标）。
    pub async fn bind(outbound: &Outbound, v6: bool) -> io::Result<Self> {
        match outbound {
            Outbound::Direct(bind) => Ok(UdpRelay::Direct(direct::bind_udp(*bind, v6).await?)),
            Outbound::Socks5(cfg) => Ok(UdpRelay::Socks5(Socks5UdpRelay::associate(cfg).await?)),
        }
    }

    /// 向 `target` 发送一个 UDP 包。`target` 既可以是已解析的 `SocketAddr`
    /// 字符串，也可以是域名（SOCKS5 UDP 请求原生支持域名目标）。
    pub async fn send_to(&self, buf: &[u8], target: &str) -> io::Result<()> {
        match self {
            UdpRelay::Direct(sock) => {
                sock.send_to(buf, target).await?;
                Ok(())
            }
            UdpRelay::Socks5(relay) => relay.send_to(buf, target).await,
        }
    }

    /// 同上，但目标已是解析好的 `SocketAddr`。
    pub async fn send_to_addr(&self, buf: &[u8], target: SocketAddr) -> io::Result<()> {
        self.send_to(buf, &target.to_string()).await
    }

    /// 收一个 UDP 包，返回 (payload, 来源地址)。
    /// 对 Socks5 通道，来源地址是目标服务器的真实回包地址（已从 SOCKS5
    /// UDP 响应头解析出来）。
    pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        match self {
            UdpRelay::Direct(sock) => sock.recv_from(buf).await,
            UdpRelay::Socks5(relay) => relay.recv_from(buf).await,
        }
    }
}

/// 通过上游 SOCKS5 的 UDP ASSOCIATE 建立的中转通道。
///
/// 协议流程（RFC 1928）：
/// 1. 与 SOCKS5 服务器建立一条 TCP 控制连接，完成认证。
/// 2. 发送 UDP ASSOCIATE 请求（DST.ADDR/DST.PORT 填 0，表示客户端尚不
///    知道会从哪个本地地址发包）。
/// 3. 服务器返回一个 BND.ADDR:BND.PORT，之后所有 UDP 包都发到这个地址；
///    服务器用它转发到真实目标，并将目标的回包同样从这个地址转发回来。
/// 4. 每个 UDP 包都要用 SOCKS5 UDP request 头封装：
///    `[RSV(2)=0x0000][FRAG(1)=0x00][ATYP(1)][DST.ADDR][DST.PORT][DATA]`
/// 5. 控制连接必须保持打开，服务器才会维持这条 UDP 转发；控制连接一断，
///    中转立即失效。
pub struct Socks5UdpRelay {
    /// 控制连接：必须持有，drop 即断开，上游会关闭 UDP 转发。
    _ctrl: AsyncMutex<TcpStream>,
    udp: UdpSocket,
    relay_addr: SocketAddr,
}

const SOCKS5_VER: u8 = 0x05;
const SOCKS5_CMD_UDP_ASSOCIATE: u8 = 0x03;
const SOCKS5_ATYP_V4: u8 = 0x01;
const SOCKS5_ATYP_DOMAIN: u8 = 0x03;
const SOCKS5_ATYP_V6: u8 = 0x04;
const SOCKS5_METHOD_NOAUTH: u8 = 0x00;
const SOCKS5_METHOD_PASSWORD: u8 = 0x02;
const SOCKS5_METHOD_NO_ACCEPTABLE: u8 = 0xFF;

impl Socks5UdpRelay {
    pub async fn associate(cfg: &Socks5Config) -> io::Result<Self> {
        let mut ctrl = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(&cfg.addr))
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("上游 socks5({}) 连接超时", cfg.addr),
                )
            })??;

        socks5_handshake_auth(&mut ctrl, cfg).await.map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("上游 socks5({}) UDP ASSOCIATE 认证失败: {e}", cfg.addr),
            )
        })?;

        // ── 发送 UDP ASSOCIATE 请求（DST=0.0.0.0:0）──
        let req = [SOCKS5_VER, SOCKS5_CMD_UDP_ASSOCIATE, 0x00, SOCKS5_ATYP_V4, 0, 0, 0, 0, 0, 0];
        ctrl.write_all(&req).await?;

        let relay_addr = read_socks5_reply_addr(&mut ctrl).await.map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("上游 socks5({}) UDP ASSOCIATE 被拒绝: {e}", cfg.addr),
            )
        })?;

        debug!(
            "[outbound socks5] UDP ASSOCIATE via {} -> relay {relay_addr}",
            cfg.addr
        );

        // relay_addr 可能返回 0.0.0.0（部分实现意为"和控制连接同一 IP"），
        // 这种情况下退回控制连接对端的 IP。
        let relay_addr = if relay_addr.ip().is_unspecified() {
            let peer = ctrl.peer_addr()?;
            SocketAddr::new(peer.ip(), relay_addr.port())
        } else {
            relay_addr
        };

        let udp = UdpSocket::bind(if relay_addr.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        })
        .await?;
        udp.connect(relay_addr).await?;

        Ok(Self {
            _ctrl: AsyncMutex::new(ctrl),
            udp,
            relay_addr,
        })
    }

    pub async fn send_to(&self, payload: &[u8], target: &str) -> io::Result<()> {
        let packet = encode_udp_request(target, payload)?;
        self.udp.send(&packet).await?;
        Ok(())
    }

    pub async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let mut raw = vec![0u8; 65535];
        let n = self.udp.recv(&mut raw).await?;
        let (from, payload) = decode_udp_response(&raw[..n]).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("上游 socks5 UDP relay({}) 响应解析失败: {e}", self.relay_addr),
            )
        })?;
        let len = payload.len().min(buf.len());
        buf[..len].copy_from_slice(&payload[..len]);
        Ok((len, from))
    }
}

/// 完成 SOCKS5 认证协商（贪婪选择：有密码配置就用密码，否则用 NOAUTH）。
async fn socks5_handshake_auth(stream: &mut TcpStream, cfg: &Socks5Config) -> io::Result<()> {
    let use_password = cfg.username.is_some() && cfg.password.is_some();
    let methods: &[u8] = if use_password {
        &[SOCKS5_METHOD_NOAUTH, SOCKS5_METHOD_PASSWORD]
    } else {
        &[SOCKS5_METHOD_NOAUTH]
    };

    let mut greeting = Vec::with_capacity(2 + methods.len());
    greeting.push(SOCKS5_VER);
    greeting.push(methods.len() as u8);
    greeting.extend_from_slice(methods);
    stream.write_all(&greeting).await?;

    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await?;
    if resp[0] != SOCKS5_VER {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("bad SOCKS version in method reply: 0x{:02x}", resp[0]),
        ));
    }

    match resp[1] {
        SOCKS5_METHOD_NOAUTH => Ok(()),
        SOCKS5_METHOD_PASSWORD if use_password => {
            let user = cfg.username.as_deref().unwrap_or("");
            let pass = cfg.password.as_deref().unwrap_or("");
            let mut sub = Vec::with_capacity(3 + user.len() + pass.len());
            sub.push(0x01);
            sub.push(user.len() as u8);
            sub.extend_from_slice(user.as_bytes());
            sub.push(pass.len() as u8);
            sub.extend_from_slice(pass.as_bytes());
            stream.write_all(&sub).await?;

            let mut sub_resp = [0u8; 2];
            stream.read_exact(&mut sub_resp).await?;
            if sub_resp[1] != 0x00 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "socks5 username/password authentication rejected",
                ));
            }
            Ok(())
        }
        SOCKS5_METHOD_NO_ACCEPTABLE => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "socks5 server: no acceptable authentication method",
        )),
        other => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected socks5 auth method selected: 0x{other:02x}"),
        )),
    }
}

/// 读取 SOCKS5 CONNECT/UDP ASSOCIATE 回复，返回 BND.ADDR:BND.PORT。
async fn read_socks5_reply_addr(stream: &mut TcpStream) -> io::Result<SocketAddr> {
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    let (ver, rep, _rsv, atyp) = (head[0], head[1], head[2], head[3]);
    if ver != SOCKS5_VER {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("bad SOCKS version in reply: 0x{ver:02x}"),
        ));
    }
    if rep != 0x00 {
        return Err(io::Error::other(format!(
            "socks5 server rejected request, REP=0x{rep:02x}"
        )));
    }

    let ip = match atyp {
        SOCKS5_ATYP_V4 => {
            let mut b = [0u8; 4];
            stream.read_exact(&mut b).await?;
            std::net::IpAddr::V4(std::net::Ipv4Addr::from(b))
        }
        SOCKS5_ATYP_V6 => {
            let mut b = [0u8; 16];
            stream.read_exact(&mut b).await?;
            std::net::IpAddr::V6(std::net::Ipv6Addr::from(b))
        }
        SOCKS5_ATYP_DOMAIN => {
            let len = stream.read_u8().await? as usize;
            let mut b = vec![0u8; len];
            stream.read_exact(&mut b).await?;
            // BND.ADDR 极少是域名；退回解析失败当 unspecified 处理。
            let s = String::from_utf8_lossy(&b).to_string();
            let resolved = tokio::net::lookup_host((s.as_str(), 0))
                .await?
                .next()
                .map(|a| a.ip())
                .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
            resolved
        }
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported ATYP in socks5 reply: 0x{other:02x}"),
            ))
        }
    };

    let port = stream.read_u16().await?;
    Ok(SocketAddr::new(ip, port))
}

/// 编码一个 SOCKS5 UDP request 包：
/// `[RSV(2)][FRAG(1)][ATYP(1)][DST.ADDR][DST.PORT][DATA]`
/// `target` 可以是 "ip:port" 或 "domain:port"。
fn encode_udp_request(target: &str, payload: &[u8]) -> io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(10 + target.len() + payload.len());
    out.extend_from_slice(&[0x00, 0x00, 0x00]); // RSV(2) + FRAG(1)

    let (host, port) = split_host_port(target)?;

    if let Ok(v4) = host.parse::<std::net::Ipv4Addr>() {
        out.push(SOCKS5_ATYP_V4);
        out.extend_from_slice(&v4.octets());
    } else if let Ok(v6) = host.trim_start_matches('[').trim_end_matches(']').parse::<std::net::Ipv6Addr>() {
        out.push(SOCKS5_ATYP_V6);
        out.extend_from_slice(&v6.octets());
    } else {
        if host.len() > 255 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "domain name too long for SOCKS5 UDP request",
            ));
        }
        out.push(SOCKS5_ATYP_DOMAIN);
        out.push(host.len() as u8);
        out.extend_from_slice(host.as_bytes());
    }

    out.extend_from_slice(&port.to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// 解码一个 SOCKS5 UDP response 包，返回 (来源地址, payload)。
fn decode_udp_response(buf: &[u8]) -> io::Result<(SocketAddr, &[u8])> {
    if buf.len() < 4 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "socks5 UDP packet too short",
        ));
    }
    let frag = buf[2];
    if frag != 0x00 {
        // 分片包（FRAG != 0）：本实现不做重组，直接丢弃。
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "fragmented SOCKS5 UDP packet not supported",
        ));
    }
    let atyp = buf[3];
    let mut i = 4usize;
    let ip = match atyp {
        SOCKS5_ATYP_V4 => {
            if buf.len() < i + 4 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "truncated v4 addr"));
            }
            let ip = std::net::Ipv4Addr::new(buf[i], buf[i + 1], buf[i + 2], buf[i + 3]);
            i += 4;
            std::net::IpAddr::V4(ip)
        }
        SOCKS5_ATYP_V6 => {
            if buf.len() < i + 16 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "truncated v6 addr"));
            }
            let mut b = [0u8; 16];
            b.copy_from_slice(&buf[i..i + 16]);
            i += 16;
            std::net::IpAddr::V6(std::net::Ipv6Addr::from(b))
        }
        SOCKS5_ATYP_DOMAIN => {
            if buf.len() < i + 1 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "truncated domain len"));
            }
            let len = buf[i] as usize;
            i += 1;
            if buf.len() < i + len {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "truncated domain"));
            }
            i += len;
            // 域名来源地址不常见，退回 0.0.0.0，上层不依赖这个值做路由判断。
            std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
        }
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported ATYP in socks5 UDP response: 0x{other:02x}"),
            ))
        }
    };
    if buf.len() < i + 2 {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "truncated port"));
    }
    let port = u16::from_be_bytes([buf[i], buf[i + 1]]);
    i += 2;
    Ok((SocketAddr::new(ip, port), &buf[i..]))
}

fn split_host_port(target: &str) -> io::Result<(&str, u16)> {
    let idx = target.rfind(':').ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, format!("bad target '{target}': missing port"))
    })?;
    let host = &target[..idx];
    let port: u16 = target[idx + 1..]
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, format!("bad port in '{target}'")))?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    Ok((host, port))
}

#[allow(dead_code)]
fn log_udp_relay_error(addr: &str, e: &io::Error) {
    warn!("[outbound socks5] udp relay via {addr} error: {e}");
}
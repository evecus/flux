//! ShadowQuic 服务端入站。
//!
//! 基于 shadowquic crate 的 `ShadowQuicServer` 实现 0-RTT QUIC + JLS SNI 伪装代理。
//!
//! ## 协议概述
//! - 0-RTT QUIC：首包即数据，降低握手延迟
//! - JLS：SNI 伪装，TLS 握手呈现的是伪装域名，未认证流量透明转发到 `jls_upstream`
//! - TCP：通过 bi-stream 接收 SQConnect 请求，双向透传
//! - UDP：通过 associate 获取 (Sender, Receiver)，桥接到本地 UDP socket
//!   - over_stream=false：UDP over QUIC datagram（高效，推荐）
//!   - over_stream=true：UDP over QUIC uni-stream（兼容性更好）
//!
//! ## 实现方式
//! shadowquic crate 提供高层 `ShadowQuicServer`（实现 `Inbound` trait）：
//! - `init()` 启动后台 QUIC accept 循环
//! - `accept()` 返回 `ProxyRequest`（Tcp 或 Udp）
//!
//! 适配层负责将 `ProxyRequest` 桥接到 flux 的出站网络：
//! - TCP：用 `common::net::dial_tcp` 拨号（支持 outbound_bind），双向 copy
//! - UDP：创建本地 UDP socket（v4 + 可选 v6），在 session 和 socket 间转发

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket as StdUdpSocket},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result};
use bytes::Bytes;
use shadowquic::{
    Inbound, ProxyRequest,
    config::{AuthUser, CongestionControl, JlsUpstream, ShadowQuicServerCfg},
    shadowquic::inbound::ShadowQuicServer,
};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::{
    io::AsyncWriteExt,
    net::UdpSocket,
    sync::Mutex,
};
use tracing::{debug, info, warn};

use crate::{common::net::OutboundBind, config::ShadowquicConfig};

/// UDP 接收缓冲区大小
const UDP_BUF_SIZE: usize = 65535;

pub async fn run(cfg: Arc<ShadowquicConfig>) -> Result<()> {
    let sq_cfg = build_sq_server_cfg(&cfg)?;
    let bind_addr = sq_cfg.bind_addr;

    let mut server = ShadowQuicServer::new(sq_cfg)
        .await
        .map_err(|e| anyhow::anyhow!("shadowquic server create failed: {e}"))?;

    server
        .init()
        .await
        .map_err(|e| anyhow::anyhow!("shadowquic server init failed: {e}"))?;

    info!("[ShadowQuic] listening on {bind_addr}, users: {}", cfg.users.len());

    loop {
        match server.accept().await {
            Ok(ProxyRequest::Tcp(tcp)) => {
                let cfg = cfg.clone();
                let dst = tcp.dst.to_string();
                tokio::spawn(async move {
                    if let Err(e) = handle_tcp(tcp.stream, &dst, &cfg).await {
                        debug!("[ShadowQuic][TCP] {dst}: {e:#}");
                    }
                });
            }
            Ok(ProxyRequest::Udp(udp)) => {
                let cfg = cfg.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_udp(udp, &cfg).await {
                        debug!("[ShadowQuic][UDP] {e:#}");
                    }
                });
            }
            Err(e) => {
                warn!("[ShadowQuic] accept error: {e}");
                // 短暂休眠避免 busy loop
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

// ── TCP ──────────────────────────────────────────────────────────────────────

async fn handle_tcp(
    mut stream: shadowquic::AnyTcp,
    dst: &str,
    cfg: &ShadowquicConfig,
) -> Result<()> {
    let bind = OutboundBind::new(cfg.outbound_bind_ipv4, cfg.outbound_bind_ipv6);
    let mut upstream = crate::common::net::dial_tcp(dst, bind)
        .await
        .with_context(|| format!("dial tcp {dst}"))?;
    let _ = upstream.set_nodelay(true);

    debug!("[ShadowQuic][TCP] {dst}: connected, relaying");

    // 双向 copy：客户端 -> 上游 / 上游 -> 客户端
    let (mut client_r, mut client_w) = tokio::io::split(&mut stream);
    let (mut up_r, mut up_w) = upstream.split();

    let c2s = async {
        tokio::io::copy(&mut client_r, &mut up_w).await?;
        up_w.shutdown().await
    };
    let s2c = async {
        tokio::io::copy(&mut up_r, &mut client_w).await?;
        client_w.shutdown().await
    };

    tokio::try_join!(c2s, s2c)?;
    debug!("[ShadowQuic][TCP] {dst}: done");
    Ok(())
}

// ── UDP ──────────────────────────────────────────────────────────────────────

async fn handle_udp(
    udp_session: shadowquic::UdpSession,
    cfg: &ShadowquicConfig,
) -> Result<()> {
    // 创建 v4 + 可选 v6 UDP socket（支持 outbound_bind）
    let socket_v4 = create_udp_socket(cfg.outbound_bind_ipv4)
        .context("create udp v4 socket")?;
    let socket_v6 = if cfg.udp_relay_ipv6 {
        Some(create_udp_socket_v6(cfg.outbound_bind_ipv6)
            .context("create udp v6 socket")?)
    } else {
        None
    };

    let upstream = Arc::new(UdpPair {
        v4: UdpSocket::from_std(socket_v4)?,
        v6: socket_v6.map(|s| UdpSocket::from_std(s).ok()).flatten(),
    });

    // DNS 反向映射：resolved SocketAddr -> 原始 SocksAddr
    // 客户端可能用域名发 UDP（如 DNS 查询），socket 收到的回包源地址是 IP，
    // 需要映射回原始域名才能让客户端正确匹配。
    let dns_cache: Arc<Mutex<HashMap<SocketAddr, shadowquic::msgs::socks5::SocksAddr>>> =
        Arc::new(Mutex::new(HashMap::new()));

    let timeout = cfg.udp_timeout;

    // 任务 1：session.recv -> 本地 socket（客户端 -> 目标）
    let upstream_send = upstream.clone();
    let dns_cache_send = dns_cache.clone();
    let mut downstream_recv = udp_session.recv;
    let send_fut = async move {
        loop {
            let (data, dst_socks) = downstream_recv.recv_from().await?;
            // 解析 SocksAddr -> SocketAddr
            let dst_addr = match resolve_socks_addr(&dst_socks).await {
                Ok(a) => a,
                Err(e) => {
                    warn!("[ShadowQuic][UDP] resolve {} failed: {e}", dst_socks);
                    continue;
                }
            };
            // 缓存映射：resolved addr -> original socks addr
            dns_cache_send.lock().await.insert(dst_addr, dst_socks);
            // 发送到目标
            if let Err(e) = upstream_send.send_to(&data, dst_addr).await {
                warn!("[ShadowQuic][UDP] send to {dst_addr}: {e}");
            }
        }
        #[allow(unreachable_code)]
        Ok::<_, shadowquic::error::SError>(())
    };

    // 任务 2：本地 socket -> session.send（目标 -> 客户端）
    let downstream_send = udp_session.send.clone();
    let dns_cache_recv = dns_cache.clone();
    let recv_fut = async move {
        // 分别给 v4 和 v6 准备缓冲区，避免在 select! 中重复借用
        let mut buf_v4 = vec![0u8; UDP_BUF_SIZE];
        let mut buf_v6 = vec![0u8; UDP_BUF_SIZE];
        loop {
            let (len, from_addr) = if let Some(ref v6) = upstream.v6 {
                // 同时监听 v4 和 v6
                tokio::select! {
                    r = upstream.v4.recv_from(&mut buf_v4) => match r {
                        Ok((n, a)) => (n, a),
                        Err(e) => {
                            warn!("[ShadowQuic][UDP] recv v4: {e}");
                            continue;
                        }
                    },
                    r = v6.recv_from(&mut buf_v6) => match r {
                        Ok((n, a)) => (n, a),
                        Err(e) => {
                            warn!("[ShadowQuic][UDP] recv v6: {e}");
                            continue;
                        }
                    },
                }
            } else {
                match upstream.v4.recv_from(&mut buf_v4).await {
                    Ok((n, a)) => (n, a),
                    Err(e) => {
                        warn!("[ShadowQuic][UDP] recv: {e}");
                        continue;
                    }
                }
            };

            // 反向查找原始 SocksAddr
            let src_socks = {
                let cache = dns_cache_recv.lock().await;
                cache.get(&from_addr).cloned()
            };
            let src_socks = match src_socks {
                Some(s) => s,
                None => {
                    // 没有缓存映射，直接用 IP 地址构造 SocksAddr
                    from_addr.into()
                }
            };

            // 从对应的 buffer 中切片（select! 已分支返回，此处借用安全）
            let data = if from_addr.is_ipv4() {
                Bytes::copy_from_slice(&buf_v4[..len])
            } else {
                Bytes::copy_from_slice(&buf_v6[..len])
            };
            if let Err(e) = downstream_send.send_to(data, src_socks).await {
                debug!("[ShadowQuic][UDP] send back to client: {e}");
                break;
            }
        }
        #[allow(unreachable_code)]
        Ok::<_, shadowquic::error::SError>(())
    };

    // 带超时：任一方向空闲超时则结束
    tokio::pin!(send_fut);
    tokio::pin!(recv_fut);

    let result = tokio::time::timeout(timeout, async {
        tokio::select! {
            r = &mut send_fut => r,
            r = &mut recv_fut => r,
        }
    })
    .await;

    match result {
        Ok(Ok(())) => {}
        Ok(Err(e)) => debug!("[ShadowQuic][UDP] session ended: {e}"),
        Err(_) => debug!("[ShadowQuic][UDP] session idle timeout ({timeout:?})"),
    }

    Ok(())
}

// ── 辅助类型与函数 ────────────────────────────────────────────────────────────

/// 一对 UDP socket（v4 + 可选 v6），按目标地址族自动选择。
struct UdpPair {
    v4: UdpSocket,
    v6: Option<UdpSocket>,
}

impl UdpPair {
    async fn send_to(&self, data: &[u8], addr: SocketAddr) -> std::io::Result<()> {
        // IPv4-mapped IPv6 -> IPv4
        let addr = normalize_addr(addr);
        match addr {
            SocketAddr::V4(_) => self.v4.send_to(data, addr).await.map(|_| ()),
            SocketAddr::V6(_) => {
                if let Some(ref v6) = self.v6 {
                    v6.send_to(data, addr).await.map(|_| ())
                } else {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::Unsupported,
                        "IPv6 UDP relay disabled (set udp_relay_ipv6 = true)",
                    ))
                }
            }
        }
    }
}

/// IPv4-mapped IPv6 地址转换为 IPv4（与 TUIC UdpSession 一致）
fn normalize_addr(addr: SocketAddr) -> SocketAddr {
    if let SocketAddr::V6(v6) = addr {
        if let Some(v4) = v6.ip().to_ipv4_mapped() {
            return SocketAddr::new(IpAddr::V4(v4), v6.port());
        }
    }
    addr
}

/// 创建 IPv4 UDP socket 并绑定（端口由内核分配）。
fn create_udp_socket(bind_ip: Option<Ipv4Addr>) -> std::io::Result<StdUdpSocket> {
    let bind_addr = bind_ip.unwrap_or(Ipv4Addr::UNSPECIFIED);
    let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    s.set_nonblocking(true)?;
    s.bind(&SockAddr::from(SocketAddr::from((bind_addr, 0))))?;
    Ok(StdUdpSocket::from(s))
}

/// 创建 IPv6 UDP socket
fn create_udp_socket_v6(bind_ip: Option<Ipv6Addr>) -> std::io::Result<StdUdpSocket> {
    let bind_addr = bind_ip.unwrap_or(Ipv6Addr::UNSPECIFIED);
    let s = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    s.set_nonblocking(true)?;
    s.set_only_v6(true)?;
    s.bind(&SockAddr::from(SocketAddr::from((bind_addr, 0))))?;
    Ok(StdUdpSocket::from(s))
}

/// 将 shadowquic SocksAddr 解析为 SocketAddr
async fn resolve_socks_addr(
    socks: &shadowquic::msgs::socks5::SocksAddr,
) -> std::io::Result<SocketAddr> {
    use shadowquic::msgs::socks5::AddrOrDomain;

    match &socks.addr {
        AddrOrDomain::V4(octets) => Ok(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::from(*octets)),
            socks.port,
        )),
        AddrOrDomain::V6(octets) => Ok(SocketAddr::new(
            IpAddr::V6(Ipv6Addr::from(*octets)),
            socks.port,
        )),
        AddrOrDomain::Domain(var_vec) => {
            let host = std::str::from_utf8(&var_vec.contents)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?
                .to_string();
            let port = socks.port;
            // 使用 owned (String, u16) 元组避免借用生命周期问题
            let resolved = tokio::net::lookup_host((host.clone(), port))
                .await?
                .next()
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::AddrNotAvailable,
                        format!("DNS resolve failed for {host}:{port}"),
                    )
                })?;
            Ok(resolved)
        }
    }
}

/// 将 flux `ShadowquicConfig` 转换为 shadowquic crate `ShadowQuicServerCfg`。
fn build_sq_server_cfg(cfg: &ShadowquicConfig) -> Result<ShadowQuicServerCfg> {
    let bind_addr: SocketAddr = cfg
        .listen
        .parse()
        .with_context(|| format!("invalid listen address: {}", cfg.listen))?;

    let users: Vec<AuthUser> = cfg
        .users
        .iter()
        .map(|u| AuthUser {
            username: u.username.clone(),
            password: u.password.clone(),
        })
        .collect();

    let congestion_control = match cfg.congestion_control.as_str() {
        "cubic" => CongestionControl::Cubic,
        "new-reno" => CongestionControl::NewReno,
        "brutal" => CongestionControl::Brutal(Default::default()),
        _ => CongestionControl::Bbr,
    };

    // server_name：未配置则从 jls_upstream 的 host 部分推断
    let server_name = cfg.server_name.clone().or_else(|| {
        cfg.jls_upstream
            .split(':')
            .next()
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
    });

    Ok(ShadowQuicServerCfg {
        bind_addr,
        users,
        server_name,
        jls_upstream: JlsUpstream {
            addr: cfg.jls_upstream.clone(),
            rate_limit: u64::MAX, // 不限速
        },
        alpn: cfg.alpn.clone(),
        zero_rtt: cfg.zero_rtt,
        congestion_control,
        initial_mtu: cfg.initial_mtu,
        min_mtu: cfg.min_mtu,
        gso: cfg.gso,
        mtu_discovery: cfg.mtu_discovery,
        blackhole_detection: cfg.blackhole_detection,
    })
}

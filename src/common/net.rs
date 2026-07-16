//! 出站拨号工具：统一 TCP/UDP 出站逻辑，支持通过 `outbound_bind_ipv4` /
//! `outbound_bind_ipv6` 指定本地出口 IP（多 IP 服务器场景）。
//!
//! 规则（见 [`OutboundBind`]）：
//! - 两者都不配置：完全走系统默认路由，行为与不使用本模块时一致。
//! - 只配置了一个地址族：所有出站流量都必须从这个 IP 走；若目标解析
//!   结果里没有同地址族的候选，视为无法满足约束，拒绝本次连接（info
//!   日志，非 warn/error —— 这是纯 v4/v6 服务器上可预期的常见情况）。
//! - 两者都配置：按目标地址族自动选择对应的出口 IP。

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use tokio::net::{TcpSocket, TcpStream, UdpSocket};
use tracing::info;

/// 一对可选的出口 IP（IPv4 / IPv6），供各协议 config 直接持有并传入本模块。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct OutboundBind {
    pub v4: Option<Ipv4Addr>,
    pub v6: Option<Ipv6Addr>,
}

impl OutboundBind {
    pub fn new(v4: Option<Ipv4Addr>, v6: Option<Ipv6Addr>) -> Self {
        Self { v4, v6 }
    }

    /// 两者都未配置：完全不介入，走系统默认路由。
    fn is_unset(&self) -> bool {
        self.v4.is_none() && self.v6.is_none()
    }

    /// 按目标地址族选择应使用的出口 IP。
    /// 返回 `None` 表示该地址族没有配置对应出口 IP（调用方需要据此过滤候选地址）。
    fn pick_for(&self, target_is_v4: bool) -> Option<IpAddr> {
        if target_is_v4 {
            self.v4.map(IpAddr::V4)
        } else {
            self.v6.map(IpAddr::V6)
        }
    }
}

/// 解析 `target`（"host:port"）并按需绑定本地出口 IP 后建立 TCP 连接。
///
/// `target` 支持域名或 IP，内部通过 `tokio::net::lookup_host` 解析，
/// 与原先直接调用 `TcpStream::connect(&str)` 的行为保持一致。
pub async fn dial_tcp(target: &str, bind: OutboundBind) -> io::Result<TcpStream> {
    if bind.is_unset() {
        return TcpStream::connect(target).await;
    }

    let candidates: Vec<SocketAddr> = tokio::net::lookup_host(target).await?.collect();

    // 只保留：该候选地址的地址族在 bind 中配置了出口 IP 的那些。
    let matched: Vec<(SocketAddr, IpAddr)> = candidates
        .iter()
        .filter_map(|&addr| bind.pick_for(addr.is_ipv4()).map(|src| (addr, src)))
        .collect();

    if matched.is_empty() {
        // 目标解析结果里没有任何一个地址族匹配已配置的出口 IP：
        // 无法满足"必须从指定 IP 出站"的约束，拒绝本次连接。
        // 这是只配置了单一地址族出口、且目标恰好只有另一地址族记录时的
        // 常见、可预期情况，用 info 而非 warn。
        info!(
            "outbound_bind (v4={:?}, v6={:?}) 与目标 {target} 的解析结果中无可用地址族匹配，拒绝本次连接",
            bind.v4, bind.v6
        );
        return Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            format!("outbound_bind 与目标 {target} 无同地址族可用地址"),
        ));
    }

    let mut last_err: Option<io::Error> = None;
    for (addr, src_ip) in matched {
        match connect_from(addr, src_ip).await {
            Ok(stream) => return Ok(stream),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.expect("matched 非空时必有至少一次连接尝试"))
}

/// 已经解析好 `SocketAddr` 的场景（TUIC/AnyTLS 等直接拿到 SocketAddr 的情况）。
/// 这里没有候选地址列表可筛，若目标地址族没有配置对应出口 IP 则拒绝连接（info 日志）。
pub async fn dial_tcp_addr(target: SocketAddr, bind: OutboundBind) -> io::Result<TcpStream> {
    if bind.is_unset() {
        return TcpStream::connect(target).await;
    }

    match bind.pick_for(target.is_ipv4()) {
        Some(src_ip) => connect_from(target, src_ip).await,
        None => {
            info!(
                "outbound_bind (v4={:?}, v6={:?}) 未配置目标 {target} 所需的地址族，拒绝本次连接",
                bind.v4, bind.v6
            );
            Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                format!("outbound_bind 未配置目标 {target} 所需的地址族"),
            ))
        }
    }
}

async fn connect_from(target: SocketAddr, bind_ip: IpAddr) -> io::Result<TcpStream> {
    let socket = if bind_ip.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };

    socket.bind(SocketAddr::new(bind_ip, 0)).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("无法绑定出口 IP {bind_ip}: {e}（请确认该 IP 已配置在本机网卡上）"),
        )
    })?;

    socket.connect(target).await
}

/// 创建一个 UDP socket，按需绑定本地出口 IP（端口由内核分配）。
/// `v6` 决定在两个地址族都未配置时使用哪个 unspecified 地址
/// （`0.0.0.0:0` 或 `[::]:0`），以保持和原先调用方式一致。
pub async fn bind_udp(bind: OutboundBind, v6: bool) -> io::Result<UdpSocket> {
    let local = match (v6, bind.v4, bind.v6) {
        (false, Some(ip), _) => SocketAddr::new(IpAddr::V4(ip), 0),
        (true, _, Some(ip)) => SocketAddr::new(IpAddr::V6(ip), 0),
        (false, None, _) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        (true, _, None) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    let explicitly_bound = if v6 {
        bind.v6.is_some()
    } else {
        bind.v4.is_some()
    };
    UdpSocket::bind(local).await.map_err(|e| {
        if explicitly_bound {
            io::Error::new(
                e.kind(),
                format!("无法绑定出口 IP {local}: {e}（请确认该 IP 已配置在本机网卡上）"),
            )
        } else {
            e
        }
    })
}

/// 带超时的 TCP 拨号封装，返回值与 `dial_tcp` 一致，超时时返回
/// `io::ErrorKind::TimedOut`。
pub async fn dial_tcp_timeout(
    target: &str,
    bind: OutboundBind,
    timeout: Duration,
) -> io::Result<TcpStream> {
    match tokio::time::timeout(timeout, dial_tcp(target, bind)).await {
        Ok(res) => res,
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("connect {target} timeout"),
        )),
    }
}

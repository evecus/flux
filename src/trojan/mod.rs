//! Trojan inbound — 对齐 sing-box `transport/trojan`。
//!
//! ## 协议格式（与 sing-box / Xray 一致）
//!
//! ### 请求头（client → server）
//! ```text
//! [56-byte hex(SHA224(password))][CRLF][cmd(1)][ATYP(1)][addr][port(2)][CRLF][payload...]
//! ```
//!
//! ### 命令字节
//! - `1` = TCP
//! - `3` = UDP
//! - `0x7f` = Mux（未实现，拒绝）
//!
//! ### UDP-over-TCP 包格式（每个包）
//! ```text
//! [ATYP(1)][addr][port(2)][length(2 BE)][CRLF(2)][payload(length)]
//! ```
//! 注意：这与 VLESS packetaddr 格式 `[2B len][ATYP][addr][port][payload]` **不同**，
//! Trojan 的地址在前、长度在后，且有 CRLF 分隔。

use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::{bail, Result};
use sha2::{Digest, Sha224};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

use crate::common::net::{self as shared_net, OutboundBind};
use crate::common::tls::standard as shared_tls;
use crate::common::transport::websocket as shared_ws;
use crate::common::transport::xhttp::{XhttpConfig, XhttpServer};
use crate::config::TrojanConfig;

/// Trojan 命令字节（对齐 sing-box `transport/trojan/protocol.go`）：
/// - `CommandTCP = 1`
/// - `CommandUDP = 3`
/// - `CommandMux = 0x7f`
const CMD_TCP: u8 = 0x01;
const CMD_UDP: u8 = 0x03;
const CMD_MUX: u8 = 0x7f;

/// SHA224 hex 摘要长度 = 28 字节 → 56 hex 字符。
const KEY_LENGTH: usize = 56;

const TROJAN_UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const TROJAN_UDP_MAX_PACKET: usize = 65535;

pub async fn run(cfg: Arc<TrojanConfig>) -> Result<()> {
    let tls_acceptor = if let Some(t) = &cfg.tls {
        let sc = shared_tls::build(
            t.cert_path.as_deref(),
            t.key_path.as_deref(),
            t.self_signed_domain.as_deref(),
        )?;
        Some(Arc::new(TlsAcceptor::from(Arc::new(sc))))
    } else {
        None
    };
    let addr: SocketAddr = cfg.listen.parse()?;
    let listener = TcpListener::bind(addr).await?;
    info!(
        "[trojan] Listening on {addr} (transport={}, tls={})",
        cfg.transport.r#type,
        if tls_acceptor.is_some() { "yes" } else { "no" },
    );

    // ── xhttp：server 级别 session 表 ─────────────────────────────────────────
    if cfg.transport.r#type == "xhttp" {
        let xh_cfg = XhttpConfig {
            path: cfg.transport.xhttp_path.clone(),
            host: cfg.transport.xhttp_host.clone(),
        };
        let xhttp_server = XhttpServer::new(xh_cfg);
        let password = cfg.password.clone();
        let bind_ip = OutboundBind::new(cfg.outbound_bind_ipv4, cfg.outbound_bind_ipv6);

        let srv_feed = xhttp_server.clone();
        let tls2 = tls_acceptor.clone();
        tokio::spawn(async move {
            loop {
                let (stream, peer) = match listener.accept().await {
                    Ok(p) => p,
                    Err(e) => {
                        warn!("[trojan] accept error: {e}");
                        continue;
                    }
                };
                match &tls2 {
                    None => {
                        srv_feed.feed_plain(stream, peer);
                    }
                    Some(acc) => {
                        let acc = Arc::clone(acc);
                        let srv = srv_feed.clone();
                        tokio::spawn(async move {
                            match acc.accept(stream).await {
                                Ok(tls) => srv.feed_tls(tls, peer),
                                Err(e) => warn!("[trojan] {peer} TLS: {e}"),
                            }
                        });
                    }
                }
            }
        });

        loop {
            match xhttp_server.accept().await {
                None => {
                    warn!("[trojan] xhttp server closed");
                    break;
                }
                Some(xhs) => {
                    let pw = password.clone();
                    tokio::spawn(async move {
                        let peer: SocketAddr = "0.0.0.0:0".parse().unwrap();
                        let mut io: Box<dyn AsyncReadWrite> = Box::new(xhs);
                        if let Err(e) = process(&mut *io, peer, &pw, bind_ip).await {
                            warn!("[trojan] {peer}: {e:#}");
                        }
                    });
                }
            }
        }
        return Ok(());
    }

    // ── 其他 transport ────────────────────────────────────────────────────────
    loop {
        let (stream, peer) = listener.accept().await?;
        let cfg2 = cfg.clone();
        let acc = tls_acceptor.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(stream, peer, &cfg2, acc).await {
                warn!("[trojan] {peer}: {e:#}")
            }
        });
    }
}

async fn handle(
    stream: TcpStream,
    peer: SocketAddr,
    cfg: &TrojanConfig,
    tls_acceptor: Option<Arc<TlsAcceptor>>,
) -> Result<()> {
    let transport = cfg.transport.r#type.as_str();

    let mut io: Box<dyn AsyncReadWrite> = match (transport, tls_acceptor) {
        ("tcp", None) => Box::new(stream),
        ("tcp", Some(acc)) => Box::new(acc.accept(stream).await?),
        ("ws", None) => Box::new(
            shared_ws::accept_plain(stream, &shared_ws::opts_from_transport(&cfg.transport))
                .await?,
        ),
        ("ws", Some(acc)) => {
            let tls = acc.accept(stream).await?;
            Box::new(
                shared_ws::accept_tls(tls, &shared_ws::opts_from_transport(&cfg.transport)).await?,
            )
        }
        _ => bail!("trojan: unknown transport"),
    };
    process(
        &mut *io,
        peer,
        &cfg.password,
        OutboundBind::new(cfg.outbound_bind_ipv4, cfg.outbound_bind_ipv6),
    )
    .await
}

async fn process<S: AsyncRead + AsyncWrite + Unpin + ?Sized>(
    io: &mut S,
    peer: SocketAddr,
    password: &str,
    bind_ip: OutboundBind,
) -> Result<()> {
    let (cmd, target) = decode_trojan(io, password).await?;
    match cmd {
        CMD_TCP => {
            info!("[trojan] {peer} -> {target} (tcp)");
            let outbound = shared_net::dial_tcp(&target, bind_ip).await?;
            relay_tcp(io, outbound, peer, &target).await
        }
        CMD_UDP => {
            info!("[trojan] {peer} -> {target} (udp)");
            relay_udp(io, peer, bind_ip).await
        }
        CMD_MUX => {
            warn!("[trojan] {peer} mux not implemented");
            bail!("trojan: mux not implemented")
        }
        other => bail!("trojan: unsupported cmd {other:#x}"),
    }
}

trait AsyncReadWrite: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncReadWrite for T {}

/// 解析 Trojan 请求头。
///
/// 对齐 sing-box `trojan.Service.NewConnection`：
///   1. 读取恰好 56 字节 key（SHA224 hex），与期望值比较
///   2. 跳过 2 字节 CRLF
///   3. 读取 1 字节 cmd
///   4. 读取 SOCKS5 地址（ATYP + addr + port）
///   5. 跳过 2 字节 CRLF
///
/// 返回 `(cmd, "host:port")`。
async fn decode_trojan<S: AsyncRead + Unpin + ?Sized>(
    s: &mut S,
    password: &str,
) -> Result<(u8, String)> {
    // Step 1: 读取 56 字节 key
    let mut key = [0u8; KEY_LENGTH];
    s.read_exact(&mut key).await?;
    let expected = hex::encode(Sha224::digest(password.as_bytes()));
    if key != expected.as_bytes() {
        bail!("trojan: invalid password");
    }

    // Step 2: 跳过 CRLF
    let mut crlf = [0u8; 2];
    s.read_exact(&mut crlf).await?;
    if crlf != *b"\r\n" {
        bail!("trojan: expected CRLF after key");
    }

    // Step 3: 读取 cmd
    let cmd = s.read_u8().await?;
    if cmd != CMD_TCP && cmd != CMD_UDP && cmd != CMD_MUX {
        bail!("trojan: unsupported cmd {cmd:#x}");
    }

    // Step 4: 读取 SOCKS5 地址
    let atyp = s.read_u8().await?;
    let host = match atyp {
        1 => {
            let mut b = [0; 4];
            s.read_exact(&mut b).await?;
            std::net::Ipv4Addr::from(b).to_string()
        }
        3 => {
            let l = s.read_u8().await? as usize;
            let mut b = vec![0; l];
            s.read_exact(&mut b).await?;
            String::from_utf8(b)?
        }
        4 => {
            let mut b = [0; 16];
            s.read_exact(&mut b).await?;
            format!("[{}]", std::net::Ipv6Addr::from(b))
        }
        _ => bail!("trojan: bad atyp {atyp:#x}"),
    };
    let port = s.read_u16().await?;

    // Step 5: 跳过 CRLF
    s.read_exact(&mut crlf).await?;
    if crlf != *b"\r\n" {
        bail!("trojan: expected CRLF after address");
    }

    Ok((cmd, format!("{host}:{port}")))
}

// ── TCP relay ─────────────────────────────────────────────────────────────────

async fn relay_tcp<S: AsyncRead + AsyncWrite + Unpin + ?Sized>(
    inbound: &mut S,
    outbound: TcpStream,
    peer: SocketAddr,
    target: &str,
) -> Result<()> {
    let (mut or, mut ow) = outbound.into_split();
    let (mut ir, mut iw) = tokio::io::split(inbound);
    let t = target.to_string();
    let a = async {
        match tokio::io::copy(&mut ir, &mut ow).await {
            Ok(n) => debug!("[trojan] {peer}→{t} uplink {n}B"),
            Err(e) => debug!("[trojan] {peer}→{t} uplink: {e}"),
        }
        let _ = ow.shutdown().await;
    };
    let t2 = target.to_string();
    let b = async {
        match tokio::io::copy(&mut or, &mut iw).await {
            Ok(n) => debug!("[trojan] {t2}→{peer} downlink {n}B"),
            Err(e) => debug!("[trojan] {t2}→{peer} downlink: {e}"),
        }
        let _ = iw.shutdown().await;
    };
    tokio::join!(a, b);
    debug!("[trojan] relay closed: {peer} ↔ {target}");
    Ok(())
}

// ── UDP relay (Trojan-native packet format) ───────────────────────────────────
//
// Trojan UDP-over-TCP 包格式（对齐 sing-box `transport/trojan/protocol.go`）：
//
//   读（uplink, client → server）:
//     [ATYP(1)][addr][port(2)][length(2 BE)][CRLF(2)][payload(length)]
//
//   写（downlink, server → client）:
//     [ATYP(1)][addr][port(2)][length(2 BE)][CRLF(2)][payload]
//
// ATYP 支持：
//   0x01 = IPv4（4 字节）
//   0x03 = 域名（1 字节长度 + 域名）
//   0x04 = IPv6（16 字节）
//
// 与 VLESS packetaddr 格式 `[2B len][ATYP][addr][port][payload]` 完全不同：
// Trojan 地址在前、长度在后，且有 CRLF 分隔。

async fn relay_udp<S: AsyncRead + AsyncWrite + Unpin + ?Sized>(
    io: &mut S,
    peer: SocketAddr,
    bind_ip: OutboundBind,
) -> Result<()> {
    let socket_v4 = shared_net::bind_udp(bind_ip, false).await?;
    let socket_v6 = shared_net::bind_udp(bind_ip, true).await.ok();

    let (mut in_r, mut in_w) = tokio::io::split(io);

    // 上行：从流读 trojan UDP 包 → 解析地址 → send_to
    let uplink = async {
        loop {
            let (target, payload) = match read_trojan_packet(&mut in_r).await {
                Ok(t) => t,
                Err(e) => {
                    debug!("[trojan] {peer} udp uplink read end: {e}");
                    return;
                }
            };
            let sock = match target {
                SocketAddr::V4(_) => &socket_v4,
                SocketAddr::V6(_) => match &socket_v6 {
                    Some(s) => s,
                    None => {
                        debug!("[trojan] {peer} udp drop v6 target {target} (no v6 socket)");
                        continue;
                    }
                },
            };
            if let Err(e) = sock.send_to(&payload, target).await {
                debug!("[trojan] {peer} udp send_to {target}: {e}");
            }
        }
    };

    // 下行：recv_from → 编码 trojan UDP 包 → 写回流
    let downlink = async {
        loop {
            let (from, payload) = match &socket_v6 {
                Some(v6) => tokio::select! {
                    r = recv_one(&socket_v4) => match r { Ok(v) => v, Err(e) => { debug!("[trojan] {peer} udp recv v4: {e}"); return; } },
                    r = recv_one(v6)         => match r { Ok(v) => v, Err(e) => { debug!("[trojan] {peer} udp recv v6: {e}"); return; } },
                },
                None => match recv_one(&socket_v4).await {
                    Ok(v) => v,
                    Err(e) => {
                        debug!("[trojan] {peer} udp recv v4: {e}");
                        return;
                    }
                },
            };
            if let Err(e) = write_trojan_packet(&mut in_w, from, &payload).await {
                debug!("[trojan] {peer} udp write_packet: {e}");
                return;
            }
        }
    };

    let idle = tokio::time::sleep(TROJAN_UDP_IDLE_TIMEOUT);
    tokio::select! {
        _ = uplink => debug!("[trojan] {peer} udp uplink closed"),
        _ = downlink => debug!("[trojan] {peer} udp downlink closed"),
        _ = idle => debug!("[trojan] {peer} udp idle timeout"),
    }
    Ok(())
}

/// 从流中读取一个 trojan UDP 包，返回 (目标地址, 负载)。
///
/// 包格式：`[ATYP][addr][port][length(2 BE)][CRLF][payload]`
///
/// 域名 ATYP (3) 通过 `tokio::net::lookup_host` 解析为 IP。
async fn read_trojan_packet<R: AsyncRead + Unpin>(r: &mut R) -> Result<(SocketAddr, Vec<u8>)> {
    let atyp = r.read_u8().await?;
    let host = match atyp {
        1 => {
            let mut b = [0; 4];
            r.read_exact(&mut b).await?;
            std::net::Ipv4Addr::from(b).to_string()
        }
        3 => {
            let l = r.read_u8().await? as usize;
            let mut b = vec![0; l];
            r.read_exact(&mut b).await?;
            String::from_utf8(b)?
        }
        4 => {
            let mut b = [0; 16];
            r.read_exact(&mut b).await?;
            std::net::Ipv6Addr::from(b).to_string()
        }
        _ => bail!("trojan udp: bad atyp {atyp:#x}"),
    };
    let port = r.read_u16().await?;
    let target_str = format!("{host}:{port}");

    let length = r.read_u16().await? as usize;
    if length > TROJAN_UDP_MAX_PACKET {
        bail!("trojan udp: packet too large ({length})");
    }

    let mut crlf = [0u8; 2];
    r.read_exact(&mut crlf).await?;
    if crlf != *b"\r\n" {
        bail!("trojan udp: expected CRLF before payload");
    }

    let mut payload = vec![0u8; length];
    r.read_exact(&mut payload).await?;

    // 域名需要解析为 SocketAddr；IP 地址直接构造。
    let target: SocketAddr = if atyp == 1 || atyp == 4 {
        target_str
            .parse()
            .map_err(|e| anyhow::anyhow!("trojan udp: bad addr {target_str}: {e}"))?
    } else {
        // 域名：lookup_host 可能返回多个地址，取第一个可用
        match tokio::net::lookup_host(&target_str).await?.next() {
            Some(addr) => addr,
            None => bail!("trojan udp: failed to resolve {target_str}"),
        }
    };

    Ok((target, payload))
}

/// 向流中写入一个 trojan UDP 包。
///
/// 包格式：`[ATYP][addr][port][length(2 BE)][CRLF][payload]`
///
/// `from` 是 recv_from 得到的 SocketAddr，始终是 IP 地址。
async fn write_trojan_packet<W: AsyncWrite + Unpin>(
    w: &mut W,
    from: SocketAddr,
    payload: &[u8],
) -> Result<()> {
    let len = payload.len();
    if len > 0xFFFF {
        bail!("trojan udp: packet too large ({len})");
    }

    // 写 ATYP + addr + port
    match from {
        SocketAddr::V4(v4) => {
            w.write_all(&[0x01]).await?;
            w.write_all(&v4.ip().octets()).await?;
            w.write_all(&v4.port().to_be_bytes()).await?;
        }
        SocketAddr::V6(v6) => {
            w.write_all(&[0x04]).await?;
            w.write_all(&v6.ip().octets()).await?;
            w.write_all(&v6.port().to_be_bytes()).await?;
        }
    }

    // 写 length(2 BE) + CRLF
    w.write_all(&(len as u16).to_be_bytes()).await?;
    w.write_all(b"\r\n").await?;

    // 写 payload
    w.write_all(payload).await?;
    w.flush().await?;
    Ok(())
}

/// 从 UdpSocket 接收一个包，返回 (来源地址, 负载)。
async fn recv_one(sock: &UdpSocket) -> std::io::Result<(SocketAddr, Vec<u8>)> {
    let mut buf = vec![0u8; TROJAN_UDP_MAX_PACKET];
    let (n, from) = sock.recv_from(&mut buf).await?;
    buf.truncate(n);
    Ok((from, buf))
}

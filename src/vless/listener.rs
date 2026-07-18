//! VLESS listener — supports TCP, WS, and XHTTP transports with optional TLS/Reality.
//! TCP 流量走 `process_vless_stream`；UDP 流量（cmd=0x02，packetaddr）
//! 走 `relay_udp`，在双栈 `UdpSocket` 上转发。

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

use crate::common::net::{self as shared_net, OutboundBind};
use crate::common::tls::standard as shared_tls;
use crate::common::transport::websocket as shared_ws;
use crate::common::transport::xhttp::{XhttpConfig, XhttpServer};
use crate::config::{VlessConfig, VlessTlsConfig};
use crate::vless::protocol::{decode_request, encode_response, parse_uuid, CMD_TCP, CMD_UDP};
use crate::vless::tls::reality as vless_reality;

pub async fn run(cfg: Arc<VlessConfig>) -> Result<()> {
    let uuid_bytes =
        parse_uuid(&cfg.uuid).map_err(|e| anyhow::anyhow!("vless: invalid UUID in config: {e}"))?;

    let tls_acceptor: Option<Arc<TlsAcceptor>> = match &cfg.tls {
        None => None,
        Some(VlessTlsConfig::Tls { standard: tls_cfg }) => {
            let sc = shared_tls::build(
                tls_cfg.cert_path.as_deref(),
                tls_cfg.key_path.as_deref(),
                tls_cfg.self_signed_domain.as_deref(),
            )?;
            Some(Arc::new(TlsAcceptor::from(Arc::new(sc))))
        }
        Some(VlessTlsConfig::Reality(reality_cfg)) => {
            let sc = vless_reality::build(reality_cfg)?;
            Some(Arc::new(TlsAcceptor::from(Arc::new(sc))))
        }
    };

    let tls_label = match &cfg.tls {
        None => "none",
        Some(VlessTlsConfig::Tls { .. }) => "tls",
        Some(VlessTlsConfig::Reality(_)) => "reality",
    };

    let addr: SocketAddr = cfg.listen.parse()?;
    let listener = TcpListener::bind(addr).await?;
    info!(
        "[vless] Listening on {addr} (transport={}, tls={tls_label})",
        cfg.transport.r#type,
    );

    // ── xhttp：server 级别，跨 TCP 连接共享 session 表 ────────────────────────
    if cfg.transport.r#type == "xhttp" {
        let xh_cfg = XhttpConfig {
            path: cfg.transport.xhttp_path.clone(),
            host: cfg.transport.xhttp_host.clone(),
        };
        let xhttp_server = XhttpServer::new(xh_cfg);

        // 任务1：接受 TCP 连接，feed 给 xhttp_server
        let xhttp_server_feed = xhttp_server.clone();
        let tls_acceptor2 = tls_acceptor.clone();
        let cfg2 = Arc::clone(&cfg);
        tokio::spawn(async move {
            loop {
                let (stream, peer) = match listener.accept().await {
                    Ok(p) => p,
                    Err(e) => {
                        warn!("[vless] accept error: {e}");
                        continue;
                    }
                };
                debug!("[vless] New connection from {peer}");
                match &cfg2.tls {
                    None => {
                        debug!("[vless] {peer} → XHTTP");
                        xhttp_server_feed.feed_plain(stream, peer);
                    }
                    Some(VlessTlsConfig::Tls { .. }) => {
                        debug!("[vless] {peer} → XHTTP+TLS");
                        let acceptor = match &tls_acceptor2 {
                            Some(a) => Arc::clone(a),
                            None => {
                                warn!("[vless] TLS acceptor missing");
                                continue;
                            }
                        };
                        let srv = xhttp_server_feed.clone();
                        tokio::spawn(async move {
                            match acceptor.accept(stream).await {
                                Ok(tls_stream) => srv.feed_tls(tls_stream, peer),
                                Err(e) => warn!("[vless] {peer} TLS handshake failed: {e}"),
                            }
                        });
                    }
                    Some(VlessTlsConfig::Reality(reality_cfg)) => {
                        debug!("[vless] {peer} → XHTTP+Reality");
                        let reality_cfg = reality_cfg.clone();
                        let srv = xhttp_server_feed.clone();
                        tokio::spawn(async move {
                            match vless_reality::accept(stream, peer, &reality_cfg).await {
                                Ok(reality_stream) => srv.feed_tls(reality_stream, peer),
                                Err(e) => warn!("[vless] {peer} Reality handshake failed: {e}"),
                            }
                        });
                    }
                }
            }
        });

        // 任务2：从 xhttp_server.accept() 取完整逻辑连接，交给 process_vless_stream
        loop {
            match xhttp_server.accept().await {
                None => {
                    warn!("[vless] xhttp server channel closed");
                    break;
                }
                Some(xhs) => {
                    let bind_ip = OutboundBind::new(cfg.outbound_bind_ipv4, cfg.outbound_bind_ipv6);
                    tokio::spawn(async move {
                        // peer 信息在 xhttp 层，这里用占位符
                        let peer: SocketAddr = "0.0.0.0:0".parse().unwrap();
                        if let Err(e) = process_vless_stream(xhs, peer, uuid_bytes, bind_ip).await {
                            warn!("[vless] xhttp stream error: {e:#}");
                        }
                    });
                }
            }
        }
        return Ok(());
    }

    // ── 其他 transport：per-TCP-connection ────────────────────────────────────
    loop {
        let (stream, peer) = listener.accept().await?;
        let cfg2 = Arc::clone(&cfg);
        let acceptor = tls_acceptor.clone();

        tokio::spawn(async move {
            debug!("[vless] New connection from {peer}");
            if let Err(e) = handle_conn(stream, peer, &cfg2, uuid_bytes, acceptor).await {
                warn!("[vless] Connection from {peer} error: {e:#}");
            }
        });
    }
}

async fn handle_conn(
    stream: TcpStream,
    peer: SocketAddr,
    cfg: &VlessConfig,
    uuid_bytes: [u8; 16],
    tls_acceptor: Option<Arc<TlsAcceptor>>,
) -> Result<()> {
    let transport_type = cfg.transport.r#type.as_str();
    let ws_path = cfg.transport.ws_path.as_str();
    let ws_host = cfg.transport.ws_host.as_deref();
    let bind_ip = OutboundBind::new(cfg.outbound_bind_ipv4, cfg.outbound_bind_ipv6);

    match (transport_type, &cfg.tls) {
        // ── TCP, no TLS ───────────────────────────────────────────────────
        ("tcp", None) => {
            debug!("[vless] {peer} → plain TCP");
            process_vless_stream(stream, peer, uuid_bytes, bind_ip).await
        }
        // ── TCP + standard TLS ────────────────────────────────────────────
        ("tcp", Some(VlessTlsConfig::Tls { .. })) => {
            debug!("[vless] {peer} → TCP+TLS");
            let acceptor =
                tls_acceptor.ok_or_else(|| anyhow::anyhow!("[vless] TLS acceptor missing"))?;
            let tls_stream = acceptor
                .accept(stream)
                .await
                .map_err(|e| anyhow::anyhow!("vless TLS handshake failed: {e}"))?;
            process_vless_stream(tls_stream, peer, uuid_bytes, bind_ip).await
        }
        // ── TCP + Reality ─────────────────────────────────────────────────
        ("tcp", Some(VlessTlsConfig::Reality(reality_cfg))) => {
            debug!("[vless] {peer} → TCP+Reality");
            let reality_stream = vless_reality::accept(stream, peer, reality_cfg).await?;
            process_vless_stream(reality_stream, peer, uuid_bytes, bind_ip).await
        }
        // ── WS, no TLS ────────────────────────────────────────────────────
        ("ws", None) => {
            debug!("[vless] {peer} → WS");
            let ws = shared_ws::accept_plain(stream, ws_path, ws_host).await?;
            process_vless_stream(ws, peer, uuid_bytes, bind_ip).await
        }
        // ── WS + standard TLS ─────────────────────────────────────────────
        ("ws", Some(VlessTlsConfig::Tls { .. })) => {
            debug!("[vless] {peer} → WS+TLS");
            let acceptor =
                tls_acceptor.ok_or_else(|| anyhow::anyhow!("[vless] TLS acceptor missing"))?;
            let tls_stream = acceptor
                .accept(stream)
                .await
                .map_err(|e| anyhow::anyhow!("vless WS+TLS handshake failed: {e}"))?;
            let ws = shared_ws::accept_tls(tls_stream, ws_path, ws_host).await?;
            process_vless_stream(ws, peer, uuid_bytes, bind_ip).await
        }
        // ── WS + Reality ──────────────────────────────────────────────────
        ("ws", Some(VlessTlsConfig::Reality(reality_cfg))) => {
            debug!("[vless] {peer} → WS+Reality");
            let reality_stream = vless_reality::accept(stream, peer, reality_cfg).await?;
            let ws = shared_ws::accept_tls(reality_stream, ws_path, ws_host).await?;
            process_vless_stream(ws, peer, uuid_bytes, bind_ip).await
        }
        (other, _) => anyhow::bail!("vless: unknown transport type '{other}'"),
    }
}

async fn process_vless_stream<S>(
    mut stream: S,
    peer: SocketAddr,
    uuid_bytes: [u8; 16],
    bind_ip: OutboundBind,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request = decode_request(&mut stream, &uuid_bytes)
        .await
        .map_err(|e| {
            warn!("[vless] {peer} header decode failed: {e}");
            e
        })?;

    match request.command {
        CMD_TCP => {
            info!("[vless] {peer} → {} (tcp)", request.target);
            relay_tcp(stream, peer, &request.target, bind_ip).await
        }
        CMD_UDP => {
            info!("[vless] {peer} → {} (udp)", request.target);
            relay_udp(stream, peer, bind_ip).await
        }
        other => anyhow::bail!("vless: unsupported command {other:#x}"),
    }
}

async fn relay_tcp<S>(
    mut stream: S,
    peer: SocketAddr,
    target: &str,
    bind_ip: OutboundBind,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let outbound = match shared_net::dial_tcp_timeout(
        target,
        bind_ip,
        std::time::Duration::from_secs(10),
    )
    .await
    {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
            warn!("[vless] {peer} connect {target} timeout");
            anyhow::bail!("connect timeout");
        }
        Err(e) => {
            warn!("[vless] {peer} connect {target} failed: {e}");
            return Err(e.into());
        }
    };

    encode_response(&mut stream).await?;

    relay(stream, outbound, peer, target).await
}

async fn relay<S>(inbound: S, outbound: TcpStream, peer: SocketAddr, target: &str) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut out_r, mut out_w) = outbound.into_split();
    let (mut in_r, mut in_w) = tokio::io::split(inbound);
    let target_str = target.to_string();

    let uplink = async {
        match tokio::io::copy(&mut in_r, &mut out_w).await {
            Ok(n) => debug!("[vless] {peer}→{target_str} uplink {n}B"),
            Err(e) => debug!("[vless] {peer}→{target_str} uplink: {e}"),
        }
        let _ = out_w.shutdown().await;
    };

    let target_str2 = target.to_string();
    let downlink = async {
        match tokio::io::copy(&mut out_r, &mut in_w).await {
            Ok(n) => debug!("[vless] {target_str2}→{peer} downlink {n}B"),
            Err(e) => debug!("[vless] {target_str2}→{peer} downlink: {e}"),
        }
        let _ = in_w.shutdown().await;
    };

    tokio::join!(uplink, downlink);
    debug!("[vless] relay closed: {peer} ↔ {target}");
    Ok(())
}

// ── UDP relay (VLESS cmd=0x02, packetaddr) ────────────────────────────────────
//
// 一个 VLESS UDP 流可承载去往多个目标的包（典型场景：DNS over UDP + QUIC + 等）。
// 出站用一对 socket（v4 / v6）覆盖两个地址族；socket 由 OutboundBind 配置。
//
// 包格式（packetaddr，对齐 Xray `packetaddr/packetaddr.go`）：
//   [2B length BE] [1B ATYP] [addr] [2B port BE] [payload]
//
// VLESS 在写响应头后委托给共享的 `packetaddr_relay`。

async fn relay_udp<S>(stream: S, peer: SocketAddr, bind_ip: OutboundBind) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // VLESS UDP 响应头与 TCP 相同（version + addon_len）。
    let mut stream = stream;
    encode_response(&mut stream).await?;
    // 剩余 packetaddr 帧的转发逻辑与 Trojan / VMess(sec=none) 共用。
    crate::vless::protocol::packetaddr_relay(stream, peer, bind_ip).await
}

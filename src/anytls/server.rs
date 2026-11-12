//! AnyTLS server.
//!
//! Protocol (server side):
//!   1. Accept TLS connection.
//!   2. Auth packet: sha256(password)[32] | padding0_len[2 BE] | padding0[N].
//!   3. Session loop: multiplex streams. For each stream, read its SOCKS5
//!      destination, then relay UDP-over-TCP (UoT magic host) or plain TCP.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Result};
use bytes::{Buf, BufMut, BytesMut};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

use crate::common::outbound::{self as shared_net, Outbound, UdpRelay};
use crate::common::tls::standard as shared_tls;
use crate::config::AnyTlsConfig;

use super::padding::SharedPadding;
use super::session::{run_server_session, StreamConn};
use super::uot::{self as uot_codec, UotAddr, MAX_PACKET_LEN};

/// v2 客户端对 `sid >= 2` 的流有 3 秒 SYNACK 超时（官方
/// `util.NewDeadlineWatcher`），超时会直接关掉整条 session。出站建立必须
/// 留足网络 RTT 余量，因此拨号上限压到 2.5 秒，而不能用原来的 10 秒。
const DIAL_TIMEOUT: Duration = Duration::from_millis(2500);

pub async fn run(cfg: Arc<AnyTlsConfig>) -> Result<()> {
    // Build SHA-256 hash of password once at startup.
    let password_hash: Arc<[u8; 32]> = Arc::new({
        let mut h = Sha256::new();
        h.update(cfg.password.as_bytes());
        h.finalize().into()
    });

    // TLS is mandatory for AnyTLS.
    let tls_cfg = shared_tls::build(
        cfg.tls.cert_path.as_deref(),
        cfg.tls.key_path.as_deref(),
        cfg.tls.self_signed_domain.as_deref(),
    )?;
    let tls_acceptor = Arc::new(TlsAcceptor::from(Arc::new(tls_cfg)));

    // Padding scheme.
    let padding = Arc::new(SharedPadding::new_default());
    if let Some(ref scheme_str) = cfg.padding_scheme {
        if !padding.update(scheme_str.as_bytes()) {
            bail!("[anytls] invalid padding_scheme in config");
        }
    }

    let addr: SocketAddr = crate::config::join_listen_addr(&cfg.listen, cfg.port)?;
    let listener = TcpListener::bind(addr).await?;
    info!("[anytls] listening on {addr}");

    let outbound = Outbound::new(&cfg.outbound);

    loop {
        let (stream, peer) = listener.accept().await?;
        let acc = Arc::clone(&tls_acceptor);
        let pw_hash = Arc::clone(&password_hash);
        let pad = Arc::clone(&padding);
        let outbound = outbound.clone();

        tokio::spawn(async move {
            debug!("[anytls] new connection from {peer}");
            if let Err(e) = handle_conn(stream, peer, acc, pw_hash, pad, outbound).await {
                warn!("[anytls] {peer}: {e:#}");
            }
        });
    }
}

async fn handle_conn(
    stream: TcpStream,
    peer: SocketAddr,
    acceptor: Arc<TlsAcceptor>,
    password_hash: Arc<[u8; 32]>,
    padding: Arc<SharedPadding>,
    outbound: Outbound,
) -> Result<()> {
    let mut conn = acceptor.accept(stream).await?;

    // ── Authentication ──────────────────────────────────────────────────────
    // Format: sha256(password)[32] | padding0_len[2 BE u16] | padding0[N]
    let mut auth_buf = [0u8; 34];
    conn.read_exact(&mut auth_buf).await?;

    if &auth_buf[..32] != password_hash.as_ref() {
        debug!("[anytls] {peer}: auth failed");
        return Ok(());
    }

    let padding0_len = u16::from_be_bytes([auth_buf[32], auth_buf[33]]) as usize;
    if padding0_len > 0 {
        let mut discard = vec![0u8; padding0_len];
        conn.read_exact(&mut discard).await?;
    }

    info!("[anytls] {peer} authenticated");

    // ── Session loop ────────────────────────────────────────────────────────
    let pad_clone = (*padding).clone();
    run_server_session(conn, pad_clone, move |stream_conn| {
        let outbound = outbound.clone();
        async move {
            if let Err(e) = handle_stream(stream_conn, peer, outbound).await {
                debug!("[anytls] stream error {peer}: {e:#}");
            }
        }
    })
    .await?;

    debug!("[anytls] session closed: {peer}");
    Ok(())
}

/// 按 stream 的 SOCKS5 目标分流：UoT magic host 走 UDP，其余走 TCP。
async fn handle_stream(mut stream: StreamConn, peer: SocketAddr, outbound: Outbound) -> Result<()> {
    let target = read_socks5_addr(&mut stream).await?;
    let sid = stream.stream_id;

    if let Some(version) = uot_codec::classify_target(&target) {
        info!("[anytls] {peer} → UDP/UoT v{version} ({target}, stream {sid})");
        return handle_uot_stream(stream, peer, sid, version, outbound).await;
    }

    info!("[anytls] {peer} → {target} (stream {sid})");
    handle_tcp_stream(stream, peer, sid, &target, outbound).await
}

// ── TCP ──────────────────────────────────────────────────────────────────────

async fn handle_tcp_stream(
    stream: StreamConn,
    peer: SocketAddr,
    sid: u32,
    target: &str,
    outbound: Outbound,
) -> Result<()> {
    let upstream = match shared_net::dial_tcp_timeout(target, &outbound, DIAL_TIMEOUT).await {
        Ok(s) => {
            // 拨号成功，发 SYNACK（对齐 sing-anytls Stream.HandshakeSuccess）
            stream.handshake_success().await;
            s
        }
        Err(e) => {
            // 拨号失败，发 SYNACK 带错误信息（对齐 Stream.HandshakeFailure）
            let err_msg = format!("connect {target} failed: {e}");
            stream.handshake_failure(&err_msg).await;
            return Err(anyhow::anyhow!(err_msg));
        }
    };

    let (mut out_r, mut out_w) = upstream.into_split();
    // 读半与写半各自独占，绝不能用一把 Mutex 把 StreamConn 包起来：
    // 那样 uplink 在 `read().await` 等客户端数据时会一直持锁，downlink
    // 拿不到锁，请求-响应型流量（HTTP / DoT / TLS 握手）会直接卡死。
    let (mut stream_r, stream_w) = stream.into_split();
    let t1 = target.to_string();
    let t2 = target.to_string();

    // Uplink: AnyTLS stream → upstream TCP
    let uplink = async move {
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            let n = match stream_r.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            if out_w.write_all(&buf[..n]).await.is_err() {
                break;
            }
        }
        let _ = out_w.shutdown().await;
        debug!("[anytls] uplink done {peer}→{t1} stream={sid}");
    };

    // Downlink: upstream TCP → AnyTLS stream
    let downlink = async move {
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            let n = match out_r.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            if stream_w.write(&buf[..n]).await.is_err() {
                break;
            }
        }
        // Send FIN to notify client this stream is done.
        let _ = stream_w.close().await;
        debug!("[anytls] downlink done {t2}→{peer} stream={sid}");
    };

    // 任一方向结束就收敛。原来的 join! 会等两个方向都结束，上游若忽略
    // 半关闭（不主动 close），本任务会永久挂起并泄漏 streams 表项。
    tokio::select! {
        _ = uplink => {}
        _ = downlink => {}
    }
    Ok(())
}

// ── UDP (UoT v2 / legacy v1) ────────────────────────────────────────────────

/// 一条 UoT stream 就是一个 UDP 会话：请求头协商 isConnect / 固定目标，
/// 之后在字节流上按 `[地址?][LEN][DATA]` 复用多个 datagram。
async fn handle_uot_stream(
    mut stream: StreamConn,
    peer: SocketAddr,
    sid: u32,
    version: u8,
    outbound: Outbound,
) -> Result<()> {
    // 1) 读请求头。UoT 是字节流，请求头可能被拆到多个 PSH 帧里，因此用
    //    累加缓冲做增量解析；v1 没有请求头，parse_request 会立即返回且不消耗字节。
    let mut acc = BytesMut::new();
    let mut tmp = vec![0u8; 32 * 1024];
    let (req, consumed) = loop {
        if let Some(v) = uot_codec::parse_request(&acc, version)? {
            break v;
        }
        let n = stream.read(&mut tmp).await?;
        if n == 0 {
            bail!("[anytls] uot v{version}: stream closed before request header");
        }
        acc.put_slice(&tmp[..n]);
    };
    acc.advance(consumed);
    let is_connect = req.is_connect;

    // 2) 建 UDP 出站通道。复用项目统一的 UdpRelay（直连 / 链式 SOCKS5
    //    UDP ASSOCIATE），因此 UDP 同样遵守 outbound-bind-* 与
    //    outbound-socks5 配置，不会绕过链式出口。
    let relay = match UdpRelay::bind(&outbound, req.bind_ipv6()).await {
        Ok(r) => {
            // 对齐官方 proxyOutboundUoT：ListenPacket 成功后才 ReportHandshakeSuccess
            stream.handshake_success().await;
            r
        }
        Err(e) => {
            let err_msg = format!("bind udp relay failed: {e}");
            stream.handshake_failure(&err_msg).await;
            return Err(anyhow::anyhow!(err_msg));
        }
    };
    let relay = Arc::new(relay);

    debug!(
        "[anytls] uot v{version} is_connect={is_connect} dest={:?} peer={peer} stream={sid}",
        req.destination
    );

    let (mut reader, writer) = stream.into_split();
    let relay_up = Arc::clone(&relay);
    let relay_down = Arc::clone(&relay);

    // 上行：AnyTLS stream → UDP。先把累加缓冲里可能已经完整的数据包发掉，
    // 再继续读流；一次 read 可能含多个包，也可能只含半个包。
    let uplink = async move {
        loop {
            loop {
                match uot_codec::parse_packet(&acc, &req) {
                    Ok(Some((target, data, used))) => {
                        acc.advance(used);
                        if let Err(e) = relay_up.send_to(&data, &target.to_target()).await {
                            debug!("[anytls] uot uplink send failed: {e}");
                            return;
                        }
                    }
                    Ok(None) => break,
                    Err(e) => {
                        debug!("[anytls] uot uplink parse error: {e}");
                        return;
                    }
                }
            }
            let n = match reader.read(&mut tmp).await {
                Ok(0) | Err(_) => return,
                Ok(n) => n,
            };
            acc.put_slice(&tmp[..n]);
        }
    };

    // 下行：UDP → AnyTLS stream。connectionless 模式必须回带来源地址；
    // connect 模式不带地址（客户端已固定目标）。
    let downlink = async move {
        let mut buf = vec![0u8; MAX_PACKET_LEN];
        loop {
            let (n, src) = match relay_down.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(e) => {
                    debug!("[anytls] uot downlink recv failed: {e}");
                    break;
                }
            };
            let src_uot = UotAddr::from_socket(src);
            let src_ref = if is_connect { None } else { Some(&src_uot) };
            let packet = match uot_codec::encode_packet(src_ref, &buf[..n]) {
                Ok(p) => p,
                Err(e) => {
                    debug!("[anytls] uot encode reply failed: {e}");
                    break;
                }
            };
            if writer.write(&packet).await.is_err() {
                break;
            }
        }
        let _ = writer.close().await;
        debug!("[anytls] uot downlink done peer={peer} stream={sid}");
    };

    // 任一方向结束即收敛。这里**刻意不加** trojan/vless 那种 UDP 空闲超时：
    // AnyTLS 的一条 UoT stream 是客户端长期持有的 UDP 会话（ant 的
    // AnyTlsUdpSession 全程复用同一条流），空闲是常态；超时会误杀会话，
    // 而客户端不会重建流。对齐官方 anytls-go `CopyPacketConn`：生命周期
    // 由 stream 关闭 / session 结束决定。
    tokio::select! {
        _ = uplink => {}
        _ = downlink => {}
    }
    Ok(())
}

/// Read a SOCKS5-format address (RFC 1928 §5) from a StreamConn.
/// Format: ATYP(1) | ADDR(N) | PORT(2 BE u16)
async fn read_socks5_addr(stream: &mut StreamConn) -> Result<String> {
    let mut atyp = [0u8; 1];
    stream.read_exact_from(&mut atyp).await?;

    let host = match atyp[0] {
        0x01 => {
            let mut b = [0u8; 4];
            stream.read_exact_from(&mut b).await?;
            Ipv4Addr::from(b).to_string()
        }
        0x03 => {
            let mut lb = [0u8; 1];
            stream.read_exact_from(&mut lb).await?;
            let mut b = vec![0u8; lb[0] as usize];
            stream.read_exact_from(&mut b).await?;
            String::from_utf8(b)?
        }
        0x04 => {
            let mut b = [0u8; 16];
            stream.read_exact_from(&mut b).await?;
            format!("[{}]", Ipv6Addr::from(b))
        }
        t => bail!("anytls: unknown ATYP {t:#x}"),
    };

    let mut pb = [0u8; 2];
    stream.read_exact_from(&mut pb).await?;
    let port = u16::from_be_bytes(pb);
    Ok(format!("{host}:{port}"))
}

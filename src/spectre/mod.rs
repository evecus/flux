//! Spectre 协议服务端入站。
//!
//! 从 spectre-master `src/server/mod.rs` + `src/protocol/*` 移植并适配到
//! flux 的节点框架：
//!
//! * **协议不变**：QUIC + JLS（`quinn-jls` / `rustls-jls`）承载，认证
//!   失败的握手被透明转发到伪装站点；控制流 AUTH 之后，每个代理目标一条
//!   双向流（TCP Connect / UDP Associate / Padding），UDP 走 QUIC
//!   datagram + 分片重组。与 spectre 客户端线兼容。
//! * **出站统一走 flux**：TCP 用 `common::outbound::dial_tcp`、UDP 会话用
//!   `common::outbound::UdpRelay`，因此支持 `outbound-bind-ipv4/6` 指定
//!   出口 IP 与 `outbound-socks5` 链式出站（严格模式，失败不回退直连）。
//! * **UDP 会话读模型改进**：每会话一个长连接读任务推送回包（见
//!   [`udp`] 模块文档），替代上游的“轮询几个包”模型。
//!
//! ## 配置示例
//!
//! ```yaml
//! nodes:
//!   - name: sp-in
//!     type: spectre
//!     port: 4433
//!     password: your-strong-password
//!     server-name: www.cloudflare.com
//!     upstream: www.cloudflare.com:443
//! ```

mod brutal;
/// Salamander 混淆原语。`MIN_PSK_LEN` 供 config 加载期校验 `obfs-psk`。
pub mod obfs;
mod obfs_socket;
mod protocol;
mod relay;
mod udp;

use std::net::SocketAddr;
use std::sync::atomic::AtomicU16;
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use bytes::Bytes;
use quinn_jls as quinn;
use rustls_jls as rustls;
use rustls::jls::JlsServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tracing::{debug, info, warn};

use crate::common::outbound::{self, Outbound};
use crate::config::SpectreConfig;
use crate::spectre::brutal::BrutalHandle;
use crate::spectre::obfs_socket::ObfsRuntime;
use crate::spectre::protocol::{
    secure_eq, AuthRequest, AuthResponse, Command, PaddingFrame, ProtocolError,
    TcpConnectRequest, TcpConnectResponse,
};
use crate::spectre::udp::{FragmentReassembler, SessionCtx, SessionTable};

/// 单帧最大字节数（AUTH / TCP Connect / Padding 的 u16 padding 上限 +
/// 固定字段，64 KiB 足够覆盖协议声明的最大值）。
const MAX_FRAME_BYTES: usize = 64 * 1024;

// ── 入口 ──────────────────────────────────────────────────────────────────

pub async fn run(cfg: Arc<SpectreConfig>) -> Result<()> {
    let username = cfg.username.clone().unwrap_or_else(|| "spectre".into());
    let password = cfg.password.clone();
    let upstream = cfg.upstream.clone();
    let server_name = cfg.server_name.clone();

    let (cert, key) = generate_self_signed_cert(&server_name)?;
    let mut server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .context("failed to build tls ServerConfig")?;
    // 看起来像浏览器：只要 "h3"。自定义 ALPN 会出现在 QUIC Initial 包里，
    // 而任何人都能解密它。
    server_crypto.alpn_protocols = vec![b"h3".to_vec()];
    // JLS：共享秘密藏在 ClientHello.random / ServerHello.random 里。
    //   * 认证通过 → 正常 Spectre 会话。上面的证书永不被客户端校验，
    //     自签即可。
    //   * 认证失败 → quinn-jls 把原始 QUIC 包转发给 `upstream`，探测者
    //     看到的是真实站点及其真实证书。
    // `server_name` 同时是客户端必须发送的 SNI；其他 SNI 一律算认证
    // 失败并被转发。
    server_crypto.jls_config = JlsServerConfig::new(
        password.clone(),
        username.clone(),
        Some(upstream.clone()),
        Some(server_name.clone()),
    )
    .into();

    let quic_server_crypto = quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
        .context("QuicServerConfig")?;
    // 基础配置（Brutal 关）。每个连接会拿到自己的一份、带独立速率句柄的
    // 副本，认证后再设置速率。
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_server_crypto));
    server_config.transport_config(make_transport(BrutalHandle::new(0)));
    let base_config = Arc::new(server_config);

    let listen: SocketAddr = crate::config::join_listen_addr(&cfg.listen, cfg.port)?;
    let socket = brutal::bind_udp(listen).context("bind udp socket")?;
    let base_runtime =
        quinn::default_runtime().ok_or_else(|| anyhow!("no async runtime found"))?;
    let runtime: Arc<dyn quinn::Runtime> = match &cfg.obfs_psk {
        Some(psk) => Arc::new(ObfsRuntime::new(base_runtime, psk.clone().into_bytes())),
        None => base_runtime,
    };
    let endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some((*base_config).clone()),
        socket,
        runtime,
    )?;
    info!(
        "[spectre] listening on {listen} (JLS), sni={server_name}, upstream={upstream}, obfs={}",
        if cfg.obfs_psk.is_some() { "on" } else { "off" },
    );

    while let Some(incoming) = endpoint.accept().await {
        let base_config = Arc::clone(&base_config);
        let cfg = Arc::clone(&cfg);
        tokio::spawn(async move {
            if let Err(e) = handle_connection(incoming, base_config, cfg).await {
                debug!("[spectre] connection error: {e:#}");
            }
        });
    }
    Ok(())
}

/// 所有连接共享的传输配置：流数量上限、datagram 缓冲、大流控窗口，
/// 以及绑定到 `handle` 的 Brutal 控制器。
fn make_transport(handle: BrutalHandle) -> Arc<quinn::TransportConfig> {
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(4096u32.into());
    transport.datagram_receive_buffer_size(Some(2 * 1024 * 1024));
    transport.datagram_send_buffer_size(2 * 1024 * 1024);
    brutal::tune_transport(&mut transport, handle);
    Arc::new(transport)
}

// ── 每连接处理 ────────────────────────────────────────────────────────────

async fn handle_connection(
    incoming: quinn::Incoming,
    base_config: Arc<quinn::ServerConfig>,
    cfg: Arc<SpectreConfig>,
) -> Result<()> {
    // 每连接独立配置，从而有独立的 Brutal 速率句柄。
    let rate = BrutalHandle::new(0);
    let mut conn_config = (*base_config).clone();
    conn_config.transport_config(make_transport(rate.clone()));
    let conn = incoming
        .accept_with(Arc::new(conn_config))
        .context("accept connection")?
        .await
        .context("handshake failed")?;
    let remote = conn.remote_address();
    // 认证失败的 JLS 握手到不了这里（已被转发去伪装站点）；这是 JLS 万一
    // 被禁用时的安全网。
    if conn.is_jls() != Some(true) {
        warn!("[spectre] non-JLS connection from {remote}, closing");
        conn.close(0u32.into(), b"");
        return Ok(());
    }
    info!(
        "[spectre] new connection from {remote} (JLS user={:?})",
        conn.jls_chosen_user()
    );

    // ── 控制流 AUTH ──────────────────────────────────────────────────────
    let (mut send, mut recv) = conn.accept_bi().await.context("accept auth stream")?;
    let auth_req = read_auth(&mut recv).await?;
    let username = cfg.username.clone().unwrap_or_else(|| "spectre".into());
    let user_ok = username.is_empty() || secure_eq(&auth_req.username, &username);
    let pass_ok = secure_eq(&auth_req.password, &cfg.password);
    if !(user_ok && pass_ok) {
        warn!("[spectre] auth failed from {remote}");
        let resp = AuthResponse::err("invalid credentials");
        send.write_all(&resp.encode()).await?;
        let _ = send.finish();
        return Ok(());
    }

    info!(
        "[spectre] auth ok from {remote}, client rx={} tx={}",
        auth_req.rx_bps, auth_req.tx_bps
    );
    // 回声速率：服务端发往客户端 ≈ 客户端的 rx，反之亦然。
    let resp = AuthResponse::ok(auth_req.rx_bps, auth_req.tx_bps);
    send.write_all(&resp.encode()).await?;
    let _ = send.finish();

    // 服务端→客户端流量即客户端下载：按客户端声明的 rx 发送。0 = 保持
    // BBR 退路。客户端自己的上传速率由客户端控制器执行。
    rate.set(auth_req.rx_bps);

    // ── 每连接状态 ───────────────────────────────────────────────────────
    let outbound = Outbound::new(&cfg.outbound);
    let sessions: SessionTable = udp::new_session_table();
    let packet_id = Arc::new(AtomicU16::new(1));
    let mut reasm = FragmentReassembler::new();
    let udp_timeout = cfg.udp_timeout;
    let udp_relay_ipv6 = cfg.udp_relay_ipv6;

    loop {
        tokio::select! {
            bi = conn.accept_bi() => {
                match bi {
                    Ok((s, r)) => {
                        let outbound = outbound.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_proxy_stream(s, r, outbound).await {
                                debug!("[spectre] proxy stream error: {e:#}");
                            }
                        });
                    }
                    Err(e) => {
                        info!("[spectre] connection closed: {e}");
                        break;
                    }
                }
            }
            dgram = conn.read_datagram() => {
                match dgram {
                    Ok(data) => {
                        let ctx = SessionCtx {
                            outbound: &outbound,
                            v6: udp_relay_ipv6,
                            conn: conn.clone(),
                            packet_id: Arc::clone(&packet_id),
                            idle: udp_timeout,
                        };
                        if let Err(e) = handle_udp_datagram(
                            data,
                            &mut reasm,
                            &sessions,
                            &ctx,
                        ).await {
                            debug!("[spectre] udp datagram error: {e:#}");
                        }
                    }
                    Err(_) => break,
                }
            }
        }
    }
    Ok(())
}

/// 读控制流上的 AUTH 帧。循环读到可完整解码（帧可能被 QUIC 分包），
/// 超出 [`MAX_FRAME_BYTES`] 判协议错误。
async fn read_auth(recv: &mut quinn::RecvStream) -> Result<AuthRequest> {
    let mut cmd = [0u8; 1];
    recv.read_exact(&mut cmd)
        .await
        .context("read auth cmd")?;
    if Command::try_from(cmd[0]).ok() != Some(Command::Auth) {
        bail!("expected AUTH, got {:#04x}", cmd[0]);
    }
    read_frame(recv, MAX_FRAME_BYTES, |buf| AuthRequest::decode(buf)).await
}

/// 从 QUIC 流读入一个完整帧：循环读直到 `decode` 成功（`BufferTooShort`
/// 表示还没收全，继续读），超过 `max_bytes` 判错。
async fn read_frame<T>(
    recv: &mut quinn::RecvStream,
    max_bytes: usize,
    decode: impl Fn(&mut &[u8]) -> Result<T, ProtocolError>,
) -> Result<T> {
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    loop {
        if buf.len() > max_bytes {
            bail!("frame too large (>{max_bytes} bytes)");
        }
        let mut tmp = [0u8; 4096];
        let n = recv
            .read(&mut tmp)
            .await
            .context("read frame")?
            .ok_or_else(|| anyhow!("stream closed mid-frame"))?;
        buf.extend_from_slice(&tmp[..n]);
        let mut cur = &buf[..];
        match decode(&mut cur) {
            Ok(v) => return Ok(v),
            Err(ProtocolError::BufferTooShort) => continue,
            Err(e) => return Err(e.into()),
        }
    }
}

// ── 代理流 ────────────────────────────────────────────────────────────────

async fn handle_proxy_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    outbound: Outbound,
) -> Result<()> {
    let mut header = [0u8; 1];
    if recv.read_exact(&mut header).await.is_err() {
        return Ok(());
    }
    let cmd = Command::try_from(header[0])?;

    match cmd {
        Command::TcpConnect => {
            let req: TcpConnectRequest =
                read_frame(&mut recv, MAX_FRAME_BYTES, |buf| TcpConnectRequest::decode(buf))
                    .await?;
            let target = req.address.to_socket_addr_string();
            info!("[spectre] TCP CONNECT {target}");

            match outbound::dial_tcp(&target, &outbound).await {
                Ok(tcp) => {
                    let resp = TcpConnectResponse::ok();
                    send.write_all(&resp.encode()).await?;

                    let _ = tcp.set_nodelay(true);
                    let (tcp_r, tcp_w) = tcp.into_split();
                    // 速率由 QUIC 拥塞控制负责，这里是朴素的全双工字节中继。
                    if let Err(e) = relay::relay(recv, send, tcp_r, tcp_w).await {
                        info!("[spectre] relay ended: {e}");
                    }
                }
                Err(e) => {
                    let resp = TcpConnectResponse::err(format!("connect failed: {e}"));
                    send.write_all(&resp.encode()).await?;
                    let _ = send.finish();
                }
            }
        }
        Command::UdpAssociate => {
            // 控制流保留；实际数据走 datagram。
            info!("[spectre] UDP ASSOCIATE control stream opened");
            let resp = TcpConnectResponse::ok(); // 轻量复用状态帧
            let _ = send.write_all(&resp.encode()).await;
            // 流保持打开直到客户端关闭
            let mut sink = vec![0u8; 256];
            while let Ok(Some(n)) = recv.read(&mut sink).await {
                if n == 0 {
                    break;
                }
            }
            let _ = send.finish();
        }
        Command::Padding => {
            // 客户端侧的 keepalive / 掩护流量（见 `PaddingFrame`）。读取并
            // 丢弃该帧；不需要响应内容，但仍回一个随机长度的 padding，
            // 使该流在大小/方向上不易与真实的短请求应答区分。
            let _frame: PaddingFrame =
                read_frame(&mut recv, MAX_FRAME_BYTES, |buf| PaddingFrame::decode(buf)).await?;
            let reply = PaddingFrame::random();
            let _ = send.write_all(&reply.encode()).await;
            let _ = send.finish();
        }
        _ => {
            warn!("[spectre] unsupported command {cmd:?}");
            let _ = send.finish();
        }
    }
    Ok(())
}

// ── UDP datagram ─────────────────────────────────────────────────────────

async fn handle_udp_datagram(
    data: Bytes,
    reasm: &mut FragmentReassembler,
    sessions: &SessionTable,
    ctx: &SessionCtx<'_>,
) -> Result<()> {
    let Some((session_id, address, payload)) = reasm.push(data)? else {
        return Ok(()); // 分片未收全
    };

    // 首次建会话时 spawn 长连接读任务；回包由该任务推回客户端。
    let sock = udp::get_or_create_session(sessions, session_id, ctx).await?;
    let dest = udp::resolve_address(&address).await?;
    sock.send_to_addr(&payload, dest).await?;
    Ok(())
}

// ── 证书 ─────────────────────────────────────────────────────────────────

fn generate_self_signed_cert(
    server_name: &str,
) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
    // JLS 客户端从不校验它，探测者也永远看不到它（被转发去真实站点），
    // 一次性自签证书足够。
    let cert = rcgen::generate_simple_self_signed(vec![server_name.to_string()])?;
    let cert_der = CertificateDer::from(cert.cert);
    let key_der = PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into());
    Ok((cert_der, key_der))
}

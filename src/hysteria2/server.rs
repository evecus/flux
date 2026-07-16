//! Hysteria2 QUIC server
//!
//! 连接架构（与官方 hysteria2 一致）：
//!
//!   ┌─────────────────────────────────────────┐
//!   │           quinn::Connection              │
//!   │                                          │
//!   │   H3 循环 (h3::server::Connection)       │
//!   │     POST /auth on host "hysteria"        │  ← auth 握手
//!   │     其他任何 HTTP/3 请求                  │  ← masquerade（v2rayN 延迟测试）
//!   │                                          │
//!   │   QUIC 循环 (conn.accept_bi)             │
//!   │     frame type 0x401                     │  ← TCP proxy
//!   │                                          │
//!   │   Datagram 循环 (conn.read_datagram)     │  ← UDP proxy
//!   └─────────────────────────────────────────┘
//!
//! auth 完成后，H3 循环和 QUIC 循环并发运行，共享同一个 quinn::Connection。
//! H3 只消费 SETTINGS/HEADERS 帧开头的流；TCP 流以 varint 0x401 开头，
//! 不是合法 H3 帧，quinn 层直接拿走，两者不会互相抢流。
//!
//! 注意：h3-quinn 对"非 H3 格式"的流的处理行为取决于版本。
//! 在 h3 0.0.8 + h3-quinn 0.0.10 下，H3 connection 内部只通过
//! accept_bi 拿它感兴趣的流，0x401 开头的流因为第一个字节不是合法
//! H3 frame type 会被 H3 层 reset（QUIC stream error），导致 TCP
//! 代理请求丢失。
//!
//! 解决方案：auth 完成后不再把 H3 connection 留在循环里消费新流，
//! 只用它处理已有的 masquerade 请求。新进来的 bidi stream 全部通过
//! quinn::Connection::accept_bi 在 quic_tcp_loop 中处理，由我们自己
//! 判断是 0x401 TCP 流还是 H3 stream（以 H3 SETTINGS frame type 开头）。

use anyhow::Result;
use bytes::Bytes;
use hyper::http;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, info, warn};

use crate::common::net::OutboundBind;
use crate::config::{AuthConfig, Hysteria2Config};
use crate::hysteria2::auth::{gen_padding, read_tcp_request};
use crate::hysteria2::congestion::BrutalFactory;
use crate::hysteria2::proxy::{handle_tcp_stream, handle_udp_session, parse_udp_frame, UdpFrame};
use crate::hysteria2::tls::build_hy2_tls;
// ── 协议常量 ───────────────────────────────────────────────────────────────────
const AUTH_HOST: &str = "hysteria";
const AUTH_PATH: &str = "/auth";
const FRAME_TYPE_TCP: u64 = 0x401;

// H3 SETTINGS frame type（RFC 9114 §7.2.3）
// bidi stream 以此字节开头说明是 H3 控制流/请求流，不是我们的 TCP 代理流
const H3_FRAME_SETTINGS: u64 = 0x4;
// H3 HEADERS frame type
const H3_FRAME_HEADERS: u64 = 0x1;

// ── QUIC 传输参数 ──────────────────────────────────────────────────────────────
const STREAM_RECEIVE_WINDOW: u32 = 8 * 1024 * 1024;
const CONN_RECEIVE_WINDOW: u32 = 20 * 1024 * 1024;
const MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_INCOMING_STREAMS: u32 = 1024;

type SessionMap = Arc<Mutex<HashMap<u32, mpsc::Sender<UdpFrame>>>>;

// ── 入口 ───────────────────────────────────────────────────────────────────────

pub async fn run(cfg: Arc<Hysteria2Config>) -> Result<()> {
    let tls_config = build_hy2_tls(&cfg.tls)?;

    // up_bps()/down_bps() 始终返回 Some：未在配置文件中显式设置时，
    // 使用 BandwidthConfig 内置的保守默认值，而不是回退到 CUBIC。
    let brutal_bps = cfg.bandwidth.up_bps();
    let bps = brutal_bps.expect("up_bps() always returns Some");
    if cfg.bandwidth.up.is_some() {
        info!(
            "[hy2] Congestion: Brutal @ {} Mbps upload (configured)",
            bps * 8 / 1_000_000
        );
    } else {
        info!(
            "[hy2] Congestion: Brutal @ {} Mbps upload (default, [node.bandwidth] not set — configure it for best performance)",
            bps * 8 / 1_000_000
        );
    }

    let mut transport = quinn::TransportConfig::default();
    transport
        .max_concurrent_bidi_streams(MAX_INCOMING_STREAMS.into())
        .stream_receive_window(STREAM_RECEIVE_WINDOW.into())
        .receive_window(CONN_RECEIVE_WINDOW.into())
        .max_idle_timeout(Some(MAX_IDLE_TIMEOUT.try_into()?))
        .keep_alive_interval(Some(Duration::from_secs(10)));

    if let Some(bps) = brutal_bps {
        transport.congestion_controller_factory(BrutalFactory::new(bps));
    }

    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)?,
    ));
    server_config.transport_config(Arc::new(transport));

    let addr: SocketAddr = cfg.listen.parse()?;
    let endpoint = quinn::Endpoint::server(server_config, addr)?;
    info!("[hy2] Listening on {}", endpoint.local_addr()?);

    while let Some(incoming) = endpoint.accept().await {
        let cfg2 = Arc::clone(&cfg);
        tokio::spawn(async move {
            if let Err(e) = handle_connection(incoming, cfg2).await {
                debug!("[hy2] Connection ended: {e:#}");
            }
        });
    }

    Ok(())
}

// ── 连接处理 ───────────────────────────────────────────────────────────────────

async fn handle_connection(incoming: quinn::Incoming, cfg: Arc<Hysteria2Config>) -> Result<()> {
    let conn = incoming.await?;
    let peer = conn.remote_address();
    info!("[hy2] New connection from {peer}");

    // 建立 H3 连接（交换 SETTINGS 帧）
    let h3_quinn_conn = h3_quinn::Connection::new(conn.clone());
    let mut h3 = h3::server::Connection::new(h3_quinn_conn).await?;

    // ── 阶段一：等待 auth ──────────────────────────────────────────────────────
    loop {
        match h3.accept().await {
            Ok(Some(resolver)) => {
                let (req, stream) = match resolver.resolve_request().await {
                    Ok(v) => v,
                    Err(e) => {
                        debug!("[hy2] {peer} resolve_request: {e}");
                        continue;
                    }
                };

                let is_auth = req.method() == http::Method::POST
                    && req.uri().host().unwrap_or("") == AUTH_HOST
                    && req.uri().path() == AUTH_PATH;

                if is_auth {
                    let auth_val = req
                        .headers()
                        .get("Hysteria-Auth")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_string();

                    let ok = match &cfg.auth {
                        AuthConfig::Password { password } => auth_val == *password,
                        AuthConfig::None => true,
                    };

                    if ok {
                        // 计算 cc-rx：告知客户端服务端接收带宽（下行速率，bps）。
                        // down_bps() 始终返回 Some：显式配置了 [node.bandwidth].down 则用该值，
                        // 否则回退到 BandwidthConfig 内置的保守默认值（不会再是 0/不限制）。
                        let cc_rx = cfg
                            .bandwidth
                            .down_bps()
                            .map(|bps| format!("{}", bps))
                            .unwrap_or_else(|| "0".to_string());

                        send_auth_ok(stream, &cc_rx).await?;
                        info!("[hy2] Auth OK: {peer}");
                        break; // 进入阶段二
                    } else {
                        warn!("[hy2] Auth failed from {peer}");
                        let _ = send_auth_fail(stream).await;
                        conn.close(quinn::VarInt::from_u32(1), b"auth failed");
                        return Ok(());
                    }
                } else {
                    // 未认证的普通 HTTP 请求 → masquerade
                    let masq_cfg = Arc::clone(&cfg);
                    tokio::spawn(masquerade(req, stream, masq_cfg));
                }
            }
            Ok(None) => {
                debug!("[hy2] {peer} closed before auth");
                return Ok(());
            }
            Err(e) => {
                debug!("[hy2] {peer} H3 error before auth: {e}");
                return Ok(());
            }
        }
    }

    // ── 阶段二：auth 通过，三个循环并发跑 ────────────────────────────────────
    //
    // 重要变化：auth 后不再单独跑 h3_loop，因为 h3_loop 内部调用
    // h3.accept()，其底层是 h3_quinn 对 conn.accept_bi() 的包装。
    // 这会和下面 quic_tcp_loop 里的 conn.accept_bi() 竞争同一批 bidi stream，
    // 导致 TCP 代理流被 H3 层先拿走并因解析失败而 reset。
    //
    // 正确做法：auth 后所有 bidi stream 都由 quic_tcp_loop 统一接收，
    // 在 handle_tcp_bidi 里通过读第一个 varint 区分 TCP 流（0x401）和
    // 其他类型（H3 masquerade 请求等），对非 TCP 流直接 reset 或忽略。
    // masquerade 请求在 auth 前已由 H3 loop 处理，auth 后正常客户端
    // 不会再发普通 H3 请求，可以安全忽略。

    let session_map: SessionMap = Arc::new(Mutex::new(HashMap::new()));
    let bind_ip = OutboundBind::new(cfg.outbound_bind_ipv4, cfg.outbound_bind_ipv6);

    // 循环 A：QUIC 层——统一接收 bidi stream，处理 TCP 代理流
    let tcp_task = {
        let conn2 = conn.clone();
        tokio::spawn(async move {
            quic_tcp_loop(conn2, peer, bind_ip).await;
        })
    };

    // 循环 B：Datagram 层——处理 UDP 代理
    let udp_task = {
        let conn2 = conn.clone();
        let smap = Arc::clone(&session_map);
        tokio::spawn(async move {
            datagram_loop(conn2, smap, bind_ip).await;
        })
    };

    // 任意一个循环结束就关闭连接
    tokio::select! {
        _ = tcp_task => {},
        _ = udp_task => {},
    }

    info!("[hy2] Connection closed: {peer}");
    conn.close(quinn::VarInt::from_u32(0), b"");
    Ok(())
}

// ── QUIC TCP 循环 ──────────────────────────────────────────────────────────────

async fn quic_tcp_loop(conn: quinn::Connection, peer: SocketAddr, bind_ip: OutboundBind) {
    loop {
        let (send, recv) = match conn.accept_bi().await {
            Ok(s) => s,
            Err(e) => {
                debug!("[hy2] {peer} accept_bi ended: {e}");
                break;
            }
        };

        tokio::spawn(async move {
            if let Err(e) = handle_tcp_bidi(send, recv, peer, bind_ip).await {
                debug!("[hy2] {peer} TCP stream: {e}");
            }
        });
    }
}

async fn handle_tcp_bidi(
    send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    peer: SocketAddr,
    bind_ip: OutboundBind,
) -> Result<()> {
    let frame_type = read_varint(&mut recv).await?;

    match frame_type {
        FRAME_TYPE_TCP => {
            // 正常 TCP 代理流
            let target = read_tcp_request(&mut recv).await?;
            info!("[hy2] {peer} → {target}");
            handle_tcp_stream(send, recv, target, bind_ip).await
        }
        H3_FRAME_SETTINGS | H3_FRAME_HEADERS => {
            // H3 控制流/请求流误入（正常不应发生，auth 后客户端不发 masquerade）
            // 静默忽略，不 reset，避免影响连接
            debug!("[hy2] {peer} got H3 frame type {frame_type:#x} after auth, ignoring");
            Ok(())
        }
        other => {
            debug!("[hy2] {peer} unknown frame type {other:#x}, ignoring");
            Ok(())
        }
    }
}

// ── Datagram 循环：UDP ────────────────────────────────────────────────────────

async fn datagram_loop(conn: quinn::Connection, session_map: SessionMap, bind_ip: OutboundBind) {
    loop {
        let datagram = match conn.read_datagram().await {
            Ok(d) => d,
            Err(e) => {
                debug!("[hy2] datagram loop ended: {e}");
                break;
            }
        };

        let frame = match parse_udp_frame(datagram) {
            Ok(f) => f,
            Err(e) => {
                warn!("[hy2] bad UDP frame: {e}");
                continue;
            }
        };

        let session_id = frame.session_id;
        let maybe_tx = session_map.lock().await.get(&session_id).cloned();

        if let Some(tx) = maybe_tx {
            if tx.send(frame).await.is_err() {
                session_map.lock().await.remove(&session_id);
            }
        } else {
            let (tx, rx) = mpsc::channel::<UdpFrame>(256);
            session_map.lock().await.insert(session_id, tx);

            let conn2 = conn.clone();
            let smap2 = Arc::clone(&session_map);

            tokio::spawn(async move {
                let send_fn: Arc<dyn Fn(Bytes) -> Result<()> + Send + Sync> =
                    Arc::new(move |pkt: Bytes| {
                        conn2.send_datagram(pkt)?;
                        Ok(())
                    });

                if let Err(e) = handle_udp_session(session_id, frame, rx, send_fn, bind_ip).await {
                    debug!("[hy2] UDP session {session_id}: {e}");
                }

                smap2.lock().await.remove(&session_id);
            });
        }
    }
}

// ── Masquerade ────────────────────────────────────────────────────────────────

/// 伪装响应：headers + body 分开持有，便于通过 H3 stream 分两步发送。
struct MasqResponse {
    headers: http::Response<()>,
    body: Bytes,
}

async fn masquerade<S>(
    req: http::Request<()>,
    mut stream: h3::server::RequestStream<S, Bytes>,
    cfg: Arc<Hysteria2Config>,
) where
    S: h3::quic::BidiStream<Bytes>,
{
    let resp = match cfg.masquerade.r#type.as_str() {
        "proxy" => {
            if let Some(proxy_cfg) = &cfg.masquerade.proxy {
                masquerade_proxy(req, &proxy_cfg.url, proxy_cfg.rewrite_host).await
            } else {
                masquerade_404()
            }
        }
        _ => masquerade_404(),
    };

    // send_response 只发 headers frame
    let _ = stream.send_response(resp.headers).await;
    // send_data 发 body frame（空 body 时跳过，避免发空 DATA frame）
    if !resp.body.is_empty() {
        let _ = stream.send_data(resp.body).await;
    }
    let _ = stream.finish().await;
}

fn masquerade_404() -> MasqResponse {
    let body = Bytes::from_static(b"<html><body><h1>404 Not Found</h1></body></html>");
    let headers = http::Response::builder()
        .status(404u16)
        .header("server", "nginx/1.24.0")
        .header("content-type", "text/html; charset=utf-8")
        .header("content-length", body.len().to_string())
        .body(())
        .unwrap();
    MasqResponse { headers, body }
}

async fn masquerade_proxy(
    req: http::Request<()>,
    target_base: &str,
    rewrite_host: bool,
) -> MasqResponse {
    use http_body_util::{BodyExt, Empty};
    use hyper::body::Bytes as HBytes;
    use hyper::header::{CONTENT_LENGTH, CONTENT_TYPE, HOST, LOCATION, TRANSFER_ENCODING};
    use hyper_util::client::legacy::Client;
    use hyper_util::rt::TokioExecutor;

    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/");
    let target_url = format!("{}{}", target_base.trim_end_matches('/'), path_and_query);

    let target_uri: hyper::Uri = match target_url.parse() {
        Ok(u) => u,
        Err(_) => return masquerade_404(),
    };

    let mut builder = hyper::Request::builder()
        .method(req.method())
        .uri(target_uri.clone());

    // 透传请求头，rewrite_host 时替换 Host
    for (name, value) in req.headers() {
        if name == HOST && rewrite_host {
            continue;
        }
        builder = builder.header(name, value);
    }
    if rewrite_host {
        if let Some(host) = target_uri.host() {
            let host_val = match target_uri.port_u16() {
                Some(port) => format!("{host}:{port}"),
                None => host.to_string(),
            };
            builder = builder.header(HOST, host_val);
        }
    }

    let outgoing_req = match builder.body(Empty::<HBytes>::new()) {
        Ok(r) => r,
        Err(_) => return masquerade_404(),
    };

    let client: Client<_, Empty<HBytes>> = Client::builder(TokioExecutor::new()).build_http();

    let proxy_resp = match client.request(outgoing_req).await {
        Ok(r) => r,
        Err(e) => {
            warn!("[hy2] masquerade proxy error: {e}");
            return masquerade_502();
        }
    };

    let status = proxy_resp.status();
    let upstream_headers = proxy_resp.headers().clone();

    // 重定向：透传 Location，body 为空
    if status.is_redirection() {
        let mut resp_builder = http::Response::builder().status(status);
        if let Some(loc) = upstream_headers.get(LOCATION) {
            resp_builder = resp_builder.header(LOCATION, loc);
        }
        let headers = resp_builder
            .body(())
            .unwrap_or_else(|_| masquerade_404().headers);
        return MasqResponse {
            headers,
            body: Bytes::new(),
        };
    }

    // 读取上游 body
    let body_bytes = match proxy_resp.into_body().collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(e) => {
            warn!("[hy2] masquerade body read error: {e}");
            return masquerade_502();
        }
    };

    // 构造响应头：透传 Content-Type / Content-Encoding，
    // Content-Length 用实际 body 长度重新计算（上游可能是 chunked）。
    // 过滤掉 Transfer-Encoding：H3 不用 chunked，长度由 DATA frame 决定。
    let mut resp_builder = http::Response::builder().status(status);
    for (name, value) in &upstream_headers {
        if name == TRANSFER_ENCODING || name == CONTENT_LENGTH {
            continue; // 重新算
        }
        resp_builder = resp_builder.header(name, value);
    }
    // 如果上游没有 Content-Type，补一个通用类型避免浏览器乱猜
    if !upstream_headers.contains_key(CONTENT_TYPE) {
        resp_builder = resp_builder.header(CONTENT_TYPE, "application/octet-stream");
    }
    resp_builder = resp_builder.header(CONTENT_LENGTH, body_bytes.len().to_string());

    let headers = resp_builder
        .body(())
        .unwrap_or_else(|_| masquerade_404().headers);
    MasqResponse {
        headers,
        body: body_bytes,
    }
}

fn masquerade_502() -> MasqResponse {
    let body = Bytes::from_static(b"<html><body><h1>502 Bad Gateway</h1></body></html>");
    let headers = http::Response::builder()
        .status(502u16)
        .header("server", "nginx/1.24.0")
        .header("content-type", "text/html; charset=utf-8")
        .header("content-length", body.len().to_string())
        .body(())
        .unwrap();
    MasqResponse { headers, body }
}

// ── Auth 响应 ─────────────────────────────────────────────────────────────────

async fn send_auth_ok<S>(mut stream: h3::server::RequestStream<S, Bytes>, cc_rx: &str) -> Result<()>
where
    S: h3::quic::BidiStream<Bytes>,
{
    // hysteria-cc-rx：告知客户端服务端下行接收带宽（bytes/sec）。
    // 部分客户端（如 sing-box outbound）会用这个值协商 Brutal 拥塞控制的目标速率。
    // 值来自 BandwidthConfig::down_bps()：显式配置了 down 就用配置值，
    // 否则回退到内置默认值（不再是 "0"/不限制，因为默认也走 Brutal）。
    let resp = http::Response::builder()
        .status(233u16)
        .header("hysteria-udp", "true")
        .header("hysteria-cc-rx", cc_rx)
        .header("hysteria-padding", gen_padding(256, 2048))
        .body(())?;
    stream.send_response(resp).await?;
    stream.finish().await?;
    Ok(())
}

async fn send_auth_fail<S>(mut stream: h3::server::RequestStream<S, Bytes>) -> Result<()>
where
    S: h3::quic::BidiStream<Bytes>,
{
    let resp = http::Response::builder()
        .status(403u16)
        .header("hysteria-padding", gen_padding(64, 256))
        .body(())?;
    stream.send_response(resp).await?;
    stream.finish().await?;
    Ok(())
}

// ── varint 读取（QUIC 格式）────────────────────────────────────────────────────

async fn read_varint(recv: &mut quinn::RecvStream) -> Result<u64> {
    let first = recv.read_u8().await?;
    let len = 1usize << (first >> 6);
    let mut val = (first & 0x3f) as u64;
    for _ in 1..len {
        val = (val << 8) | recv.read_u8().await? as u64;
    }
    Ok(val)
}

//! NaiveProxy 入站。
//! 协议参考：<https://github.com/klzgrad/naiveproxy>
//!
//! 服务端需要实现的核心协议是：
//!   1. TLS（ALPN 同时声明 h2 / http1.1，与真实 Chrome / Caddy 行为一致）
//!   2. HTTP/2 CONNECT 隧道：`:method = CONNECT`，`:authority = host:port`，
//!      建连成功后整个 stream 的 DATA 帧就是原始隧道字节流（HTTP/2 的
//!      CONNECT 语义本身就是双向字节流，不像 HTTP/1.1 CONNECT 需要 upgrade）。
//!   3. `Proxy-Authorization: Basic base64(user:pass)` 鉴权。
//!   4. 未认证 / 非 CONNECT 请求走 masquerade（反代到真实网站或返回 404），
//!      而不是直接报错，用于抵御主动探测（同 Caddy forwardproxy 的
//!      application fronting 思路）。
//!   5. 可选：首 8 次读写的长度 padding（详见 `padding` 子模块），双方
//!      通过 CONNECT 请求/响应里是否存在 `padding` 头协商是否启用。
//!
//! 客户端侧的 Chrome TLS 指纹模拟（uTLS）是 naiveproxy client 自己的事，
//! 和本服务端无关；本服务端的 TLS 层与其他协议一样用 rustls 标准实现。
//!
//! 已知限制：本实现只处理 h2（HTTP/2）连接；如果客户端 TLS 握手协商到了
//! http/1.1（说明对方不是走 naiveproxy 协议，多半是浏览器访问或探测），
//! 会退化为一个极简的 HTTP/1.1 服务器，只用来提供 masquerade 内容。

mod padding;

use std::{net::SocketAddr, sync::Arc};

use anyhow::{bail, Context, Result};
use base64::Engine;
use bytes::Bytes;
use futures_util::future::poll_fn;
use h2::server::SendResponse;
use h2::{RecvStream, SendStream};
use http::{Method, Request, Response, StatusCode};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

use crate::common::net::{self as shared_net, OutboundBind};
use crate::common::tls::standard as shared_tls;
use crate::config::NaiveproxyConfig;

const PADDING_HEADER: &str = "padding";

pub async fn run(cfg: Arc<NaiveproxyConfig>) -> Result<()> {
    let sc = shared_tls::build(
        cfg.tls.cert_path.as_deref(),
        cfg.tls.key_path.as_deref(),
        cfg.tls.self_signed_domain.as_deref(),
    )?;
    let tls_acceptor = TlsAcceptor::from(Arc::new(sc));

    let addr: SocketAddr = cfg.listen.parse()?;
    let listener = TcpListener::bind(addr).await?;
    info!(
        "[naiveproxy] Listening on {addr} (users={}, padding={})",
        cfg.users.len(),
        cfg.padding,
    );

    loop {
        let (stream, peer) = listener.accept().await?;
        let cfg2 = cfg.clone();
        let acc = tls_acceptor.clone();
        tokio::spawn(async move {
            let tls = match acc.accept(stream).await {
                Ok(t) => t,
                Err(e) => {
                    debug!("[naiveproxy] {peer} TLS handshake failed: {e}");
                    return;
                }
            };
            let alpn = tls.get_ref().1.alpn_protocol().map(|p| p.to_vec());
            let result = match alpn.as_deref() {
                Some(b"h2") | None => handle_h2(tls, peer, cfg2).await,
                _ => handle_h1_masquerade_only(tls, peer, cfg2).await,
            };
            if let Err(e) = result {
                debug!("[naiveproxy] {peer}: {e:#}");
            }
        });
    }
}

// ── HTTP/2 主路径 ────────────────────────────────────────────────────────────

async fn handle_h2<S>(tls: S, peer: SocketAddr, cfg: Arc<NaiveproxyConfig>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut h2 = h2::server::handshake(tls).await.context("h2 handshake")?;

    while let Some(result) = h2.accept().await {
        let (request, respond) = result.context("h2 accept")?;
        let cfg2 = cfg.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_request(request, respond, peer, cfg2).await {
                debug!("[naiveproxy] {peer} stream error: {e:#}");
            }
        });
    }
    Ok(())
}

async fn handle_request(
    request: Request<RecvStream>,
    mut respond: SendResponse<Bytes>,
    peer: SocketAddr,
    cfg: Arc<NaiveproxyConfig>,
) -> Result<()> {
    let authed = check_basic_auth(request.headers().get("proxy-authorization"), &cfg);

    if !authed || request.method() != Method::CONNECT {
        // 未认证、或不是 CONNECT（比如探测者直接用浏览器访问）—— 走 masquerade。
        return serve_masquerade(request, respond, &cfg).await;
    }

    // ── 合法 CONNECT：建立隧道 ────────────────────────────────────────────────
    let target = match request.uri().authority() {
        Some(a) => a.to_string(),
        None => {
            let resp = Response::builder().status(StatusCode::BAD_REQUEST).body(()).unwrap();
            let _ = respond.send_response(resp, true);
            bail!("CONNECT request without :authority from {peer}");
        }
    };

    let client_wants_padding = cfg.padding && request.headers().contains_key(PADDING_HEADER);

    let bind_ip = OutboundBind::new(cfg.outbound_bind_ipv4, cfg.outbound_bind_ipv6);
    let outbound = match shared_net::dial_tcp(&target, bind_ip).await {
        Ok(s) => s,
        Err(e) => {
            let resp = Response::builder().status(StatusCode::BAD_GATEWAY).body(()).unwrap();
            let _ = respond.send_response(resp, true);
            bail!("CONNECT {target} failed: {e}");
        }
    };

    let mut resp_builder = Response::builder().status(StatusCode::OK);
    if client_wants_padding {
        resp_builder = resp_builder.header(PADDING_HEADER, padding::random_padding_value(30, 62));
    }
    let response = resp_builder.body(()).unwrap();

    let send_stream = respond
        .send_response(response, false)
        .context("send CONNECT response")?;

    info!("[naiveproxy] {peer} CONNECT {target} (padding={client_wants_padding})");

    let recv_stream = request.into_body();
    let (outbound_r, outbound_w) = outbound.into_split();

    if client_wants_padding {
        padding::relay_padded(recv_stream, send_stream, outbound_r, outbound_w).await
    } else {
        relay_plain(recv_stream, send_stream, outbound_r, outbound_w).await
    }
}

/// 无 padding 的直通隧道：h2 stream <-> TCP，双向 splice。
async fn relay_plain(
    mut recv: RecvStream,
    mut send: SendStream<Bytes>,
    mut outbound_r: tokio::net::tcp::OwnedReadHalf,
    mut outbound_w: tokio::net::tcp::OwnedWriteHalf,
) -> Result<()> {
    let up = async move {
        // RecvStream::data() 在产出数据的同时会自动释放接收窗口容量，
        // 不需要手动调用 flow_control().release_capacity()。
        while let Some(chunk) = recv.data().await {
            let chunk = match chunk {
                Ok(c) => c,
                Err(_) => break,
            };
            if outbound_w.write_all(&chunk).await.is_err() {
                break;
            }
        }
        let _ = outbound_w.shutdown().await;
    };

    let down = async move {
        let mut buf = [0u8; 16 * 1024];
        loop {
            let n = match outbound_r.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            if send_backpressured(&mut send, Bytes::copy_from_slice(&buf[..n]))
                .await
                .is_err()
            {
                break;
            }
        }
        let _ = send.send_data(Bytes::new(), true);
    };

    tokio::join!(up, down);
    debug!("[naiveproxy] tunnel closed");
    Ok(())
}

/// 带流控背压地把一段数据写进 h2 SendStream：先 reserve_capacity，
/// 再等 poll_capacity 分配到窗口后才 send_data，避免无限制在内存里堆积。
pub(crate) async fn send_backpressured(send: &mut SendStream<Bytes>, mut data: Bytes) -> Result<(), h2::Error> {
    while !data.is_empty() {
        send.reserve_capacity(data.len());
        let cap = match poll_fn(|cx| send.poll_capacity(cx)).await {
            Some(Ok(cap)) => cap,
            Some(Err(e)) => return Err(e),
            None => return Ok(()), // 对端已关闭流
        };
        let cap = cap.min(data.len()).max(1);
        let chunk = data.split_to(cap);
        send.send_data(chunk, false)?;
    }
    Ok(())
}

// ── Basic Auth ───────────────────────────────────────────────────────────────

fn check_basic_auth(header: Option<&http::HeaderValue>, cfg: &NaiveproxyConfig) -> bool {
    if cfg.users.is_empty() {
        return false; // naiveproxy 必须配置至少一个用户，没配就一律视为未认证（全部走 masquerade）
    }
    let Some(header) = header.and_then(|v| v.to_str().ok()) else { return false };
    let Some(b64) = header.strip_prefix("Basic ") else { return false };
    let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(b64.trim()) else {
        return false;
    };
    let Ok(decoded) = String::from_utf8(decoded) else { return false };
    let Some((user, pass)) = decoded.split_once(':') else { return false };
    cfg.users.iter().any(|u| u.username == user && u.password == pass)
}

// ── Masquerade（h2 版本）────────────────────────────────────────────────────

async fn serve_masquerade(
    request: Request<RecvStream>,
    mut respond: SendResponse<Bytes>,
    cfg: &NaiveproxyConfig,
) -> Result<()> {
    let resp = match &cfg.masquerade {
        Some(m) => masquerade_proxy(&request, &m.url, m.rewrite_host).await,
        None => masquerade_404(),
    };

    let (parts, body) = resp.into_parts();
    let response = Response::from_parts(parts, ());
    let end_of_stream = body.is_empty();
    let mut send_stream = respond
        .send_response(response, end_of_stream)
        .context("send masquerade response")?;
    if !body.is_empty() {
        let _ = send_stream.send_data(body, true);
    }
    Ok(())
}

struct MasqResponse {
    parts: http::response::Parts,
    body: Bytes,
}

impl MasqResponse {
    fn into_parts(self) -> (http::response::Parts, Bytes) {
        (self.parts, self.body)
    }
}

fn masquerade_404() -> MasqResponse {
    let body = Bytes::from_static(b"<html><body><h1>404 Not Found</h1></body></html>");
    let resp = Response::builder()
        .status(404u16)
        .header("server", "nginx/1.24.0")
        .header("content-type", "text/html; charset=utf-8")
        .header("content-length", body.len().to_string())
        .body(())
        .unwrap();
    let (parts, _) = resp.into_parts();
    MasqResponse { parts, body }
}

fn masquerade_502() -> MasqResponse {
    let body = Bytes::from_static(b"<html><body><h1>502 Bad Gateway</h1></body></html>");
    let resp = Response::builder()
        .status(502u16)
        .header("server", "nginx/1.24.0")
        .header("content-type", "text/html; charset=utf-8")
        .header("content-length", body.len().to_string())
        .body(())
        .unwrap();
    let (parts, _) = resp.into_parts();
    MasqResponse { parts, body }
}

async fn masquerade_proxy(req: &Request<RecvStream>, target_base: &str, rewrite_host: bool) -> MasqResponse {
    use http_body_util::{BodyExt, Empty};
    use hyper::body::Bytes as HBytes;
    use hyper::header::{CONTENT_LENGTH, CONTENT_TYPE, HOST, LOCATION, TRANSFER_ENCODING};
    use hyper_util::client::legacy::Client;
    use hyper_util::rt::TokioExecutor;

    let path_and_query = req.uri().path_and_query().map(|p| p.as_str()).unwrap_or("/");
    let target_url = format!("{}{}", target_base.trim_end_matches('/'), path_and_query);

    let target_uri: hyper::Uri = match target_url.parse() {
        Ok(u) => u,
        Err(_) => return masquerade_404(),
    };

    let mut builder = hyper::Request::builder().method(req.method().clone()).uri(target_uri.clone());
    for (name, value) in req.headers() {
        if name == HOST && rewrite_host {
            continue;
        }
        builder = builder.header(name.clone(), value.clone());
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
            warn!("[naiveproxy] masquerade proxy error: {e}");
            return masquerade_502();
        }
    };

    let status = proxy_resp.status();
    let upstream_headers = proxy_resp.headers().clone();

    if status.is_redirection() {
        let mut resp_builder = http::Response::builder().status(status);
        if let Some(loc) = upstream_headers.get(LOCATION) {
            resp_builder = resp_builder.header(LOCATION, loc.clone());
        }
        return match resp_builder.body(()) {
            Ok(resp) => {
                let (parts, _) = resp.into_parts();
                MasqResponse { parts, body: Bytes::new() }
            }
            Err(_) => masquerade_404(),
        };
    }

    let body_bytes = match proxy_resp.into_body().collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(e) => {
            warn!("[naiveproxy] masquerade body read error: {e}");
            return masquerade_502();
        }
    };

    let mut resp_builder = http::Response::builder().status(status);
    for (name, value) in &upstream_headers {
        if name == TRANSFER_ENCODING || name == CONTENT_LENGTH {
            continue;
        }
        resp_builder = resp_builder.header(name.clone(), value.clone());
    }
    if !upstream_headers.contains_key(CONTENT_TYPE) {
        resp_builder = resp_builder.header(CONTENT_TYPE, "application/octet-stream");
    }
    resp_builder = resp_builder.header(CONTENT_LENGTH, body_bytes.len().to_string());

    match resp_builder.body(()) {
        Ok(resp) => {
            let (parts, _) = resp.into_parts();
            MasqResponse { parts, body: body_bytes }
        }
        Err(_) => masquerade_404(),
    }
}

// ── 非 h2（http/1.1）连接：仅提供 masquerade，不支持隧道 ─────────────────────
//
// naiveproxy 客户端总是走 h2；这里出现的是浏览器直接访问、或不支持/未协商
// h2 的探测流量。给这类流量一个看起来正常的网站响应即可，不需要完整实现
// HTTP/1.1 keep-alive 等特性。

async fn handle_h1_masquerade_only<S>(mut stream: S, peer: SocketAddr, _cfg: Arc<NaiveproxyConfig>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    // 只读第一行 + headers，不关心 body，回一个 masquerade 响应后关闭连接。
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 1024];
    loop {
        let n = stream.read(&mut tmp).await.unwrap_or(0);
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() > 16 * 1024 {
            break;
        }
    }
    debug!("[naiveproxy] {peer} non-h2 connection, serving masquerade only");

    // 注：h1 兜底路径目前只返回一个静态 404，不会真正反代到
    // `[node.masquerade.proxy].url`（那部分逻辑只在 h2 路径里实现）。
    // naiveproxy 客户端总是走 h2，这里覆盖的是浏览器/探测器等非法访问，
    // 一个安静的 404 已经足够满足"看起来不像代理"的基本要求。
    let resp = masquerade_404_h1();
    let _ = stream.write_all(&resp).await;
    let _ = stream.shutdown().await;
    Ok(())
}

fn masquerade_404_h1() -> Vec<u8> {
    let body = b"<html><body><h1>404 Not Found</h1></body></html>";
    format!(
        "HTTP/1.1 404 Not Found\r\nServer: nginx/1.24.0\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes()
    .into_iter()
    .chain(body.iter().copied())
    .collect()
}

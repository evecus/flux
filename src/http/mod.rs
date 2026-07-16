//! HTTP 代理入站（标准 HTTP/1.1 CONNECT 代理，RFC 9110 §9.3.6）。
//!
//! 支持两种使用方式：
//!   1. `CONNECT host:port HTTP/1.1`            — 建立隧道，之后透传任意协议（最常见，浏览器/客户端访问 https 网站走这个）
//!   2. `GET http://host/path HTTP/1.1`         — 绝对 URI 形式的普通 HTTP 转发（老式 HTTP 代理用法）
//!
//! 可选：
//!   - `[node.tls]`：给 HTTP CONNECT 包一层 TLS（即 HTTPS 代理，客户端需要用支持
//!     HTTPS 代理的软件，如 v2rayN / Clash.Meta 的 http 出站 + tls）。
//!   - `[node.users]`：配置后要求 `Proxy-Authorization: Basic base64(user:pass)`。

use std::{net::SocketAddr, sync::Arc};

use anyhow::{bail, Context, Result};
use base64::Engine;
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info};

use crate::common::net::{self as shared_net, OutboundBind};
use crate::common::tls::standard as shared_tls;
use crate::config::HttpConfig;

const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_HEADER_LINES: usize = 128;

pub async fn run(cfg: Arc<HttpConfig>) -> Result<()> {
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
        "[http] Listening on {addr} (tls={}, auth={})",
        if tls_acceptor.is_some() { "yes" } else { "no" },
        if cfg.users.is_empty() { "none" } else { "basic" },
    );

    loop {
        let (stream, peer) = listener.accept().await?;
        let cfg2 = cfg.clone();
        let acc = tls_acceptor.clone();
        tokio::spawn(async move {
            let result = match acc {
                None => handle(stream, peer, &cfg2).await,
                Some(acc) => match acc.accept(stream).await {
                    Ok(tls) => handle(tls, peer, &cfg2).await,
                    Err(e) => {
                        debug!("[http] {peer} TLS handshake failed: {e}");
                        return;
                    }
                },
            };
            if let Err(e) = result {
                debug!("[http] {peer}: {e:#}");
            }
        });
    }
}

async fn handle<S>(stream: S, peer: SocketAddr, cfg: &HttpConfig) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut reader = BufReader::new(stream);
    let (request_line, headers) = read_headers(&mut reader).await?;

    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let target_raw = parts.next().unwrap_or("").to_string();
    let version = parts.next().unwrap_or("HTTP/1.1").to_string();

    if method.is_empty() || target_raw.is_empty() {
        bail!("malformed request line: {request_line:?}");
    }

    // ── 鉴权 ──────────────────────────────────────────────────────────────────
    if !cfg.users.is_empty() {
        let auth_header = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("proxy-authorization"))
            .map(|(_, v)| v.as_str());

        if !check_basic_auth(auth_header, cfg) {
            let mut w = reader.into_inner();
            let body = b"Proxy Authentication Required";
            let resp = format!(
                "HTTP/1.1 407 Proxy Authentication Required\r\n\
                 Proxy-Authenticate: Basic realm=\"flux\"\r\n\
                 Content-Length: {}\r\n\
                 Connection: close\r\n\r\n",
                body.len()
            );
            let _ = w.write_all(resp.as_bytes()).await;
            let _ = w.write_all(body).await;
            let _ = w.shutdown().await;
            bail!("auth failed from {peer}");
        }
    }

    let bind_ip = OutboundBind::new(cfg.outbound_bind_ipv4, cfg.outbound_bind_ipv6);

    if method.eq_ignore_ascii_case("CONNECT") {
        // CONNECT host:port HTTP/1.1 —— target 本身就是 "host:port"
        let target = normalize_connect_target(&target_raw)?;
        let outbound = match shared_net::dial_tcp(&target, bind_ip).await {
            Ok(s) => s,
            Err(e) => {
                let mut w = reader.into_inner();
                let _ = w
                    .write_all(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
                    .await;
                bail!("CONNECT {target} failed: {e}");
            }
        };
        // BufReader 内部缓冲区里可能已经读入了紧跟在 CONNECT 请求头之后的数据
        // （比如客户端把 CONNECT 请求和 TLS ClientHello 粘在同一个 TCP 包里发送）。
        // into_inner() 会直接丢弃这部分缓冲，必须先取出来，隧道建立后原样转发。
        let leftover = reader.buffer().to_vec();
        let mut w_stream = reader.into_inner();
        w_stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        info!("[http] {peer} CONNECT {target}");
        relay(w_stream, outbound, leftover).await?;
        return Ok(());
    }

    // ── 普通方法（GET/POST/...），绝对 URI 转发 ─────────────────────────────────
    let (target, path_and_query) = parse_absolute_uri(&target_raw)?;

    let outbound = match shared_net::dial_tcp(&target, bind_ip).await {
        Ok(s) => s,
        Err(e) => {
            let mut w = reader.into_inner();
            let _ = w
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
                .await;
            bail!("{method} {target} failed: {e}");
        }
    };
    info!("[http] {peer} {method} {target}");

    let (or, mut ow) = outbound.into_split();

    // 把请求行改写成 origin-form（去掉绝对 URI 里的 scheme://host 部分）
    // 再把已读到的 headers 原样透传给上游，之后把剩余的连接数据（可能含请求体）
    // 直接做双向 splice，交给上游自己按 Content-Length / chunked 处理。
    let rewritten_line = format!("{method} {path_and_query} {version}\r\n");
    ow.write_all(rewritten_line.as_bytes()).await?;
    for (k, v) in &headers {
        // Proxy-* 头是给代理自己看的，不透传给上游
        if k.eq_ignore_ascii_case("proxy-authorization") || k.eq_ignore_ascii_case("proxy-connection") {
            continue;
        }
        ow.write_all(format!("{k}: {v}\r\n").as_bytes()).await?;
    }
    ow.write_all(b"\r\n").await?;

    // 同上：请求体（POST body 等）可能已经被 BufReader 提前读入内部缓冲区，
    // 必须先取出并原样写给上游，再继续做活体转发，否则请求体开头会丢字节。
    let leftover = reader.buffer().to_vec();
    if !leftover.is_empty() {
        ow.write_all(&leftover).await?;
    }
    let inbound = reader.into_inner();
    relay_halves(inbound, or, ow).await
}

/// 读取请求行 + headers（直到空行），返回 (request_line, [(header_name, header_value)]).
/// 消耗掉的字节不含 body —— body（如果有）留在底层流里，由后续转发逻辑处理。
async fn read_headers<S: AsyncRead + Unpin>(
    reader: &mut BufReader<S>,
) -> Result<(String, Vec<(String, String)>)> {
    use tokio::io::AsyncBufReadExt;

    let mut total = 0usize;
    let mut request_line = String::new();
    reader
        .read_line(&mut request_line)
        .await
        .context("read request line")?;
    total += request_line.len();
    let request_line = request_line.trim_end().to_string();
    if request_line.is_empty() {
        bail!("empty request line");
    }

    let mut headers = Vec::new();
    loop {
        if headers.len() > MAX_HEADER_LINES || total > MAX_HEADER_BYTES {
            bail!("header too large");
        }
        let mut line = String::new();
        let n = reader.read_line(&mut line).await.context("read header line")?;
        if n == 0 {
            bail!("connection closed while reading headers");
        }
        total += n;
        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            break;
        }
        if let Some((k, v)) = trimmed.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }

    Ok((request_line, headers))
}

fn check_basic_auth(header: Option<&str>, cfg: &HttpConfig) -> bool {
    let Some(header) = header else { return false };
    let Some(b64) = header.strip_prefix("Basic ") else { return false };
    let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(b64.trim()) else {
        return false;
    };
    let Ok(decoded) = String::from_utf8(decoded) else { return false };
    let Some((user, pass)) = decoded.split_once(':') else { return false };
    cfg.users.iter().any(|u| u.username == user && u.password == pass)
}

/// `CONNECT` 的 target 应形如 `host:port`；补默认端口保险起见做个基本校验。
fn normalize_connect_target(raw: &str) -> Result<String> {
    if raw.rsplit_once(':').is_none() {
        bail!("CONNECT target missing port: {raw:?}");
    }
    Ok(raw.to_string())
}

/// 把 `http://host[:port]/path?query` 拆成 (`host:port`, `/path?query`)。
/// 也兼容只给了 origin-form（`/path`）+ Host 头的老式写法调用方在外层已处理不到，
/// 这里只处理绝对 URI 形式（标准代理请求的写法）。
fn parse_absolute_uri(raw: &str) -> Result<(String, String)> {
    let rest = raw
        .strip_prefix("http://")
        .ok_or_else(|| anyhow::anyhow!("only absolute http:// URIs are supported as a plain proxy: {raw:?}"))?;

    let (authority, path_and_query) = match rest.find('/') {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => (rest, "/"),
    };

    let target = if authority.contains(':') {
        authority.to_string()
    } else {
        format!("{authority}:80")
    };

    Ok((target, path_and_query.to_string()))
}

async fn relay<S>(inbound: S, outbound: TcpStream, leftover: Vec<u8>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut ir, mut iw) = tokio::io::split(inbound);
    let (mut or, mut ow) = outbound.into_split();
    if !leftover.is_empty() {
        ow.write_all(&leftover).await?;
    }
    let a = async {
        let _ = tokio::io::copy(&mut ir, &mut ow).await;
        let _ = ow.shutdown().await;
    };
    let b = async {
        let _ = tokio::io::copy(&mut or, &mut iw).await;
        let _ = iw.shutdown().await;
    };
    tokio::join!(a, b);
    debug!("[http] connection closed");
    Ok(())
}

async fn relay_halves<S>(
    inbound: S,
    mut or: tokio::net::tcp::OwnedReadHalf,
    mut ow: tokio::net::tcp::OwnedWriteHalf,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut ir, mut iw) = tokio::io::split(inbound);
    let a = async {
        let _ = tokio::io::copy(&mut ir, &mut ow).await;
        let _ = ow.shutdown().await;
    };
    let b = async {
        let _ = tokio::io::copy(&mut or, &mut iw).await;
        let _ = iw.shutdown().await;
    };
    tokio::join!(a, b);
    debug!("[http] connection closed");
    Ok(())
}

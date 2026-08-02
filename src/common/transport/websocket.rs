//! WebSocket transport (shared by VLESS / VMess / Trojan / Shadowsocks).
//!
//! 对齐 sing-box `transport/v2raywebsocket`：
//!   • 路径自动补 `/` 前缀
//!   • 0-RTT 早期数据（path-based base64url 或 header-based，如 Sec-WebSocket-Protocol）
//!   • 自定义 HTTP 头校验
//!
//! Wire format: payload is carried in Binary WebSocket frames.

use anyhow::Result;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL_NO_PAD, Engine as _};
use bytes::BytesMut;
use futures_util::{Sink, Stream};
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{accept_hdr_async, WebSocketStream};
use tracing::debug;

// ── Accept options ───────────────────────────────────────────────────────────

/// WebSocket 接受选项。对齐 sing-box V2RayWebsocketOptions。
pub struct WsAcceptOptions {
    /// 期望的 URL 路径（不含 query string）。自动补 `/` 前缀。
    pub path: String,
    /// 可选 Host 头校验。
    pub host: Option<String>,
    /// 早期数据最大字节数。0 = 不启用。
    pub max_early_data: u32,
    /// 早期数据 HTTP 头名。None = 路径模式（base64url 追加到 path 末尾）。
    pub early_data_header_name: Option<String>,
    /// 自定义 HTTP 头（仅做存在性 / 值校验；None = 不校验）。
    pub headers: Option<HashMap<String, String>>,
}

impl WsAcceptOptions {
    #[allow(dead_code)]
    pub fn new(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            host: None,
            max_early_data: 0,
            early_data_header_name: None,
            headers: None,
        }
    }
}

/// 从 TransportConfig 构建 WsAcceptOptions。
pub fn opts_from_transport(t: &crate::config::TransportConfig) -> WsAcceptOptions {
    WsAcceptOptions {
        path: t.ws_path.clone(),
        host: t.ws_host.clone(),
        max_early_data: t.ws_max_early_data,
        early_data_header_name: t.ws_early_data_header_name.clone(),
        headers: t.ws_headers.clone(),
    }
}

// ── Public accept functions ──────────────────────────────────────────────────

/// Accept a WebSocket upgrade on a plain TcpStream (no TLS).
#[allow(clippy::result_large_err)]
pub async fn accept_plain(
    stream: TcpStream,
    opts: &WsAcceptOptions,
) -> Result<WsStream<TcpStream>> {
    do_upgrade(stream, opts).await
}

/// Accept a WebSocket upgrade on a TLS stream.
pub async fn accept_tls<S>(stream: S, opts: &WsAcceptOptions) -> Result<WsStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    do_upgrade(stream, opts).await
}

#[allow(clippy::result_large_err)]
async fn do_upgrade<S>(stream: S, opts: &WsAcceptOptions) -> Result<WsStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // 对齐 sing-box：路径自动补 '/' 前缀
    let expected_path = if opts.path.starts_with('/') {
        opts.path.clone()
    } else {
        format!("/{}", opts.path)
    };

    let host = opts.host.clone();
    let max_early_data = opts.max_early_data;
    let early_data_header = opts.early_data_header_name.clone();
    let custom_headers = opts.headers.clone();
    let path_for_check = expected_path.clone();

    // accept_hdr_async 的 callback 是 Fn（不可变捕获），无法直接写闭包外变量。
    // 用 Arc<Mutex<Option<Vec<u8>>>> 提供内部可变性来捕获 early data。
    let early_data_slot: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
    let early_data_slot_cb = Arc::clone(&early_data_slot);

    let ws = accept_hdr_async(stream, move |req: &Request, resp: Response| {
        // ── 校验 Host 头 ──────────────────────────────────────────────────
        if let Some(ref expected) = host {
            let req_host = req
                .headers()
                .get("host")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            if req_host != expected.as_str() {
                debug!("[ws] rejected host: {req_host} (expected {expected})");
                return Err(Response::builder().status(400).body(None).unwrap());
            }
        }

        // ── 提取早期数据 + 路径校验 ───────────────────────────────────────
        //
        // 对齐 sing-box v2raywebsocket/server.go ServeHTTP:
        //   1. max_early_data > 0 且 early_data_header_name == "":
        //      早期数据以 base64url 追加到 URL path 末尾 → 前缀匹配。
        //   2. early_data_header_name != "":
        //      早期数据从指定 HTTP 头读取（base64url）→ 严格 path 匹配。
        //   3. max_early_data == 0: 无早期数据 → 严格 path 匹配。
        let early_data: Vec<u8> = if max_early_data > 0 {
            if let Some(ref hdr_name) = early_data_header {
                // 模式 2：header-based early data，严格 path 匹配
                let req_path = req.uri().path();
                if req_path != path_for_check.as_str() {
                    debug!("[ws] rejected path: {req_path} (expected {path_for_check})");
                    return Err(Response::builder().status(404).body(None).unwrap());
                }
                req.headers()
                    .get(hdr_name.as_str())
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| {
                        if s.is_empty() {
                            None
                        } else {
                            BASE64_URL_NO_PAD.decode(s).ok()
                        }
                    })
                    .unwrap_or_default()
            } else {
                // 模式 1：path-based early data，前缀匹配
                let req_uri = req.uri().path();
                if !req_uri.starts_with(path_for_check.as_str()) {
                    debug!("[ws] rejected path: {req_uri} (expected prefix {path_for_check})");
                    return Err(Response::builder().status(404).body(None).unwrap());
                }
                let ed_str = &req_uri[path_for_check.len()..];
                if ed_str.is_empty() {
                    Vec::new()
                } else {
                    BASE64_URL_NO_PAD.decode(ed_str).unwrap_or_else(|e| {
                        debug!("[ws] early data base64 decode error: {e}");
                        Vec::new()
                    })
                }
            }
        } else {
            // 模式 3：无早期数据，严格 path 匹配
            let req_path = req.uri().path();
            if req_path != path_for_check.as_str() {
                debug!("[ws] rejected path: {req_path} (expected {path_for_check})");
                return Err(Response::builder().status(404).body(None).unwrap());
            }
            Vec::new()
        };

        // ── 校验自定义头（可选）──────────────────────────────────────────
        if let Some(ref hdrs) = custom_headers {
            for (k, v) in hdrs {
                if let Some(rv) = req.headers().get(k.as_str()) {
                    if rv.to_str().map(|s| s != v.as_str()).unwrap_or(true) {
                        debug!("[ws] custom header mismatch: {k}");
                    }
                }
            }
        }

        debug!(
            "[ws] accepted: path={} early_data={} bytes",
            req.uri().path(),
            early_data.len()
        );

        // 将 early data 存入共享 slot，握手完成后取回
        *early_data_slot_cb.lock().unwrap() = Some(early_data);

        Ok(resp)
    })
    .await?;

    // 取回 callback 中提取的 early data
    let early_data = early_data_slot.lock().unwrap().take().unwrap_or_default();

    Ok(WsStream::with_early_data(ws, early_data))
}

// ── WsStream: AsyncRead + AsyncWrite wrapper ──────────────────────────────────
//
// WebSocket is message-framed; VLESS/VMess/Trojan are byte streams. We:
//   • poll incoming Binary/Text frames into a BytesMut ring buffer (read side)
//   • send outgoing bytes as Binary frames (write side)
//   • early data is pre-loaded into read_buf so it's returned first

pub struct WsStream<S> {
    inner: WebSocketStream<S>,
    /// Buffered bytes from a partially-consumed WebSocket frame or early data
    read_buf: BytesMut,
}

impl<S> WsStream<S> {
    #[allow(dead_code)]
    pub fn new(ws: WebSocketStream<S>) -> Self {
        Self {
            inner: ws,
            read_buf: BytesMut::with_capacity(65536),
        }
    }

    /// Create a WsStream with early data pre-loaded into the read buffer.
    /// The early data will be returned first on the next read, before any
    /// WebSocket frames are polled.
    pub fn with_early_data(ws: WebSocketStream<S>, early_data: Vec<u8>) -> Self {
        let cap = 65536.max(early_data.len());
        let mut read_buf = BytesMut::with_capacity(cap);
        if !early_data.is_empty() {
            read_buf.extend_from_slice(&early_data);
        }
        Self {
            inner: ws,
            read_buf,
        }
    }
}

impl<S> AsyncRead for WsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        // Drain any carry-over bytes from a previous large frame or early data
        if !this.read_buf.is_empty() {
            let n = this.read_buf.len().min(buf.remaining());
            buf.put_slice(&this.read_buf[..n]);
            let _ = this.read_buf.split_to(n);
            return Poll::Ready(Ok(()));
        }

        // Poll for the next WebSocket message
        loop {
            match Pin::new(&mut this.inner).poll_next(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => return Poll::Ready(Ok(())), // EOF / connection closed
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::ConnectionReset,
                        e.to_string(),
                    )))
                }
                Poll::Ready(Some(Ok(msg))) => {
                    let data: Vec<u8> = match msg {
                        Message::Binary(v) => v,
                        Message::Text(s) => s.into_bytes(),
                        // Control frames — skip and keep polling
                        Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => continue,
                        Message::Close(_) => return Poll::Ready(Ok(())),
                    };

                    if data.is_empty() {
                        continue;
                    }

                    let n = data.len().min(buf.remaining());
                    buf.put_slice(&data[..n]);
                    // Buffer the rest if the frame was larger than the read buffer
                    if n < data.len() {
                        this.read_buf.extend_from_slice(&data[n..]);
                    }
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

impl<S> AsyncWrite for WsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();

        // Check the sink has capacity before sending
        match Pin::new(&mut this.inner).poll_ready(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    e.to_string(),
                )))
            }
            Poll::Ready(Ok(())) => {}
        }

        // Send as Binary frame
        let msg = Message::Binary(buf.to_vec());
        if let Err(e) = Pin::new(&mut this.inner).start_send(msg) {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                e.to_string(),
            )));
        }

        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner)
            .poll_flush(cx)
            .map_err(|e| std::io::Error::other(e.to_string()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner)
            .poll_close(cx)
            .map_err(|e| std::io::Error::other(e.to_string()))
    }
}

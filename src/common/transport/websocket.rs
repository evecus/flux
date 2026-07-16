//! WebSocket transport for VLESS.
//!
//! Performs the HTTP/1.1 Upgrade handshake and wraps the resulting
//! WebSocketStream as an AsyncRead + AsyncWrite byte stream.
//!
//! Wire format: VLESS data is carried in Binary WebSocket frames,
//! matching Xray's ws transport implementation.

use anyhow::Result;
use bytes::BytesMut;
use futures_util::{Sink, Stream};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{accept_hdr_async, WebSocketStream};
use tracing::debug;

// ── Public accept functions ───────────────────────────────────────────────────

/// Accept a WebSocket upgrade on a plain TcpStream (no TLS).
#[allow(clippy::result_large_err)]
pub async fn accept_plain(
    stream: TcpStream,
    expected_path: &str,
    expected_host: Option<&str>,
) -> Result<WsStream<TcpStream>> {
    let ws = do_upgrade(stream, expected_path, expected_host).await?;
    Ok(WsStream::new(ws))
}

/// Accept a WebSocket upgrade on a TLS stream.
pub async fn accept_tls<S>(
    stream: S,
    expected_path: &str,
    expected_host: Option<&str>,
) -> Result<WsStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let ws = do_upgrade(stream, expected_path, expected_host).await?;
    Ok(WsStream::new(ws))
}

#[allow(clippy::result_large_err)]
async fn do_upgrade<S>(
    stream: S,
    expected_path: &str,
    expected_host: Option<&str>,
) -> Result<WebSocketStream<S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let path = expected_path.to_string();
    let host = expected_host.map(|h| h.to_string());
    let ws = accept_hdr_async(stream, move |req: &Request, resp: Response| {
        // Validate Host header if configured
        if let Some(ref expected) = host {
            let req_host = req
                .headers()
                .get("host")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            if req_host != expected.as_str() {
                debug!("[vless/ws] rejected host: {req_host} (expected {expected})");
                return Err(Response::builder().status(400).body(None).unwrap());
            }
        }
        // Validate path
        let req_path = req.uri().path();
        if req_path != path.as_str() {
            debug!("[vless/ws] rejected path: {req_path} (expected {path})");
            return Err(Response::builder().status(404).body(None).unwrap());
        }
        debug!("[vless/ws] accepted: host_ok path={req_path}");
        Ok(resp)
    })
    .await?;
    Ok(ws)
}

// ── WsStream: AsyncRead + AsyncWrite wrapper ──────────────────────────────────
//
// WebSocket is message-framed; VLESS is a byte stream. We:
//   • poll incoming Binary/Text frames into a BytesMut ring buffer (read side)
//   • send outgoing bytes as Binary frames (write side)
//
// This matches Xray's websocket.connection implementation.

pub struct WsStream<S> {
    inner: WebSocketStream<S>,
    /// Buffered bytes from a partially-consumed WebSocket frame
    read_buf: BytesMut,
}

impl<S> WsStream<S> {
    pub fn new(ws: WebSocketStream<S>) -> Self {
        Self {
            inner: ws,
            read_buf: BytesMut::with_capacity(65536),
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

        // Drain any carry-over bytes from a previous large frame
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
                        // tungstenite 0.20: Binary(Vec<u8>), Text(String)
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

        // Send as Binary frame — matches Xray ws transport
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

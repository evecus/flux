//! XHTTP over HTTP/3（QUIC）监听 — 对齐 Xray `transport/internet/splithttp/hub.go`
//! 的 `isH3` 分支。
//!
//! Xray 中 XHTTP 的同一个 HTTP handler 同时跑在 h1/h2（TCP）与 h3（QUIC）上：
//! 当 TLS `NextProtos == ["h3"]` 时，splithttp 启动 `http3.Server` 监听 UDP，
//! 请求处理路径与 TCP 版完全一致（GET downlink / POST packet-up /
//! stream-up / stream-one），session 表仍然跨连接共享。
//!
//! flux 的实现：quinn Endpoint + h3 server。每条 QUIC 双向流承载一个 HTTP/3
//! 请求：请求 body 从 QUIC stream 泵入 channel，构造出与 hyper 兼容的
//! `http_body::Body`，复用 `xhttp.rs` 的全部 session 管理与 handler 逻辑；
//! 响应 body 帧逐个写回 QUIC stream。

use anyhow::Result;
use bytes::{Buf, Bytes};
use http_body_util::BodyExt;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::sync::mpsc;
use tracing::{debug, info};

use super::xhttp::XhttpServer;

/// 由 rustls ServerConfig 构建 quinn UDP Endpoint（ALPN 强制为 `["h3"]`）。
///
/// 与 hysteria2 相同的构建方式：`QuicServerConfig::try_from(rustls config)`。
/// TLS 配置可直接复用各协议已有的 cert/key 构建（shared_tls::build 等），
/// ALPN 在这里统一覆盖为 h3。
pub fn build_h3_endpoint(mut tls: rustls::ServerConfig, addr: SocketAddr) -> Result<quinn::Endpoint> {
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls)?,
    ));
    Ok(quinn::Endpoint::server(server_config, addr)?)
}

/// H3 服务器主循环：接受 QUIC 连接，每条双向流解析为一个 HTTP 请求，
/// 交给 `XhttpServer::handle_request`（与 TCP 版共用 session 表）。
pub async fn serve_h3(endpoint: quinn::Endpoint, server: XhttpServer) -> Result<()> {
    let local = endpoint.local_addr()?;
    info!("[xhttp-h3] Listening on {local} (HTTP/3 over QUIC, alpn=h3)");

    loop {
        let Some(incoming) = endpoint.accept().await else {
            break;
        };
        let conn = match incoming.await {
            Ok(c) => c,
            Err(e) => {
                debug!("[xhttp-h3] QUIC handshake failed: {e}");
                continue;
            }
        };
        let peer = conn.remote_address();
        debug!("[xhttp-h3] new QUIC connection from {peer}");
        let server = server.clone();
        tokio::spawn(async move {
            let h3_quinn = h3_quinn::Connection::new(conn);
            let mut h3_conn = match h3::server::Connection::new(h3_quinn).await {
                Ok(c) => c,
                Err(e) => {
                    debug!("[xhttp-h3] {peer} h3 setup failed: {e}");
                    return;
                }
            };
            loop {
                match h3_conn.accept().await {
                    Ok(Some(resolver)) => {
                        let (req, stream) = match resolver.resolve_request().await {
                            Ok(v) => v,
                            Err(e) => {
                                debug!("[xhttp-h3] {peer} resolve_request: {e}");
                                continue;
                            }
                        };
                        let srv = server.clone();
                        tokio::spawn(handle_request_h3(req, stream, srv, peer));
                    }
                    Ok(None) => break,
                    Err(e) => {
                        debug!("[xhttp-h3] {peer} h3 accept: {e}");
                        break;
                    }
                }
            }
        });
    }

    Ok(())
}

/// 处理一条 H3 请求：
///   请求 body：QUIC stream → channel → `http_body::Body`
///   响应 body：`ResponseBody` 帧 → QUIC stream
async fn handle_request_h3<S>(
    mut req: http::Request<()>,
    stream: h3::server::RequestStream<S, Bytes>,
    server: XhttpServer,
    peer: SocketAddr,
) where
    S: h3::quic::BidiStream<Bytes>,
    // split 后两端分别进入独立任务（pump task / 本任务），要求 Send + 'static
    S::SendStream: Send + 'static,
    S::RecvStream: Send + 'static,
{
    // HTTP/3 没有 Host header（authority 在 :authority 伪头里）。
    // 把 :authority 注入 Host，供 XhttpServer 的 host 严格校验使用
    // （对齐 Xray：Go 的 http3 服务端会把 Request.Host 设为 :authority）。
    if req.headers().get(hyper::header::HOST).is_none() {
        if let Some(auth) = req.uri().authority() {
            if let Ok(v) = hyper::header::HeaderValue::from_str(auth.as_str()) {
                req.headers_mut().insert(hyper::header::HOST, v);
            }
        }
    }

    // split() 分离收发两端：接收端泵请求 body，发送端写响应。
    let (mut send_stream, mut recv_stream) = stream.split();

    // 请求 body 泵：QUIC stream → channel。
    // handle_get / handle_post（hyper 版）也是逐帧读 body，这里保持一致的
    // 异步流式语义：stream-up POST 在响应返回后仍持续接收上行数据。
    let (body_tx, body_rx) = mpsc::channel::<Bytes>(64);
    tokio::spawn(async move {
        loop {
            // h3 0.0.8 的 recv_data 返回 `Result<Option<impl Buf>, StreamError>`，
            // 用 copy_to_bytes 转成 Bytes 再入队（Buf 消费一次即取走全部数据）。
            match recv_stream.recv_data().await {
                Ok(Some(mut data)) => {
                    let chunk = data.copy_to_bytes(data.remaining());
                    if body_tx.send(chunk).await.is_err() {
                        // XhttpServer 已丢弃读端（session 结束），停止接收。
                        break;
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    debug!("[xhttp-h3] {peer} recv body: {e}");
                    break;
                }
            }
        }
    });

    let (parts, ()) = req.into_parts();
    let req = http::Request::from_parts(parts, H3RequestBody { rx: body_rx });

    // 与 TCP 版完全相同的处理路径（host 校验 / 路径解析 / session 管理 / CORS）
    let resp = server.handle_request(req, peer).await;
    let (parts, body) = resp.into_parts();
    let mut body = body;
    let resp = http::Response::from_parts(parts, ());

    if let Err(e) = send_stream.send_response(resp).await {
        debug!("[xhttp-h3] {peer} send_response: {e}");
        return;
    }
    // 响应 body 帧 → QUIC stream。downlink GET（ResponseBody::Stream）会持续
    // 等待 down_rx；XhttpStream 写端关闭后 rx 返回 None，循环结束并发送 finish。
    while let Some(frame) = body.frame().await {
        match frame {
            Ok(f) => {
                if let Ok(data) = f.into_data() {
                    if let Err(e) = send_stream.send_data(data).await {
                        debug!("[xhttp-h3] {peer} send body: {e}");
                        return;
                    }
                }
            }
            Err(e) => {
                // ResponseBody 的 Error 是 Infallible，此处仅防御
                debug!("[xhttp-h3] {peer} body error: {e}");
                break;
            }
        }
    }
    let _ = send_stream.finish().await;
}

/// 从 channel 读取数据的请求 body（由 QUIC stream 泵填充）。
/// 实现与 xhttp.rs 的 `ResponseBody` 对称：单向 channel → poll_frame。
struct H3RequestBody {
    rx: mpsc::Receiver<Bytes>,
}

impl http_body::Body for H3RequestBody {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        match self.get_mut().rx.poll_recv(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Ready(Some(d)) => Poll::Ready(Some(Ok(http_body::Frame::data(d)))),
        }
    }
}

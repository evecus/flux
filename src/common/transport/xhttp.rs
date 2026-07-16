//! XHTTP (SplitHTTP) transport — server 级别 session 管理。
//!
//! ## 架构
//!
//! Xray packet-up 模式下，一个逻辑连接 = 多个独立 TCP 连接：
//!   GET  /<base>/<sessionId>        → downlink（长连接流式响应）
//!   POST /<base>/<sessionId>/<seq>  → packet-up（每包一个短连接）
//!   POST /<base>/<sessionId>        → stream-up（长连接流式上行）
//!   GET  /<base>                    → stream-one（上下行同一连接）
//!
//! 因此 session 表必须跨 TCP 连接共享。
//!
//! ## 使用方式
//!
//! ```rust
//! // 1. 启动时创建 server（含共享 session 表）
//! let xhttp_server = XhttpServer::new(cfg);
//!
//! // 2. 每个 TCP 连接调用 feed_plain / feed_tls（立即返回）
//! xhttp_server.feed_plain(tcp_stream, peer);
//!
//! // 3. accept() 等待下一个完整逻辑连接（GET 已到达）
//! let stream: XhttpStream = xhttp_server.accept().await.unwrap();
//! ```
//!
//! ## Session 内部结构
//!
//! 创建时分配：
//!   up_tx / up_rx   — POST 写入，XhttpStream 读端消费
//!   down_tx / down_rx — XhttpStream 写端写入，GET response body 消费
//!
//! Session 在 map 里只保留 { up_tx, down_tx, get_arrived }。
//! up_rx 和 down_rx 在 GET 到达时一次性取出，构造 XhttpStream 推入 ready_tx。
//! POST 到达时只需要 up_tx（随时可拿到）。

use anyhow::Result;
use bytes::{Buf, BytesMut};
use http_body_util::BodyExt;
use hyper::{Method, Request, Response, StatusCode};
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, Mutex, Notify};
use tokio_util::sync::PollSender;
use tracing::{debug, warn};

// ── Config ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct XhttpConfig {
    pub path: String,
    pub host: Option<String>,
}

impl Default for XhttpConfig {
    fn default() -> Self {
        Self {
            path: "/".to_string(),
            host: None,
        }
    }
}

impl XhttpConfig {
    pub fn normalized_path(&self) -> String {
        let p = self.path.trim_end_matches('/');
        let p = if p.starts_with('/') {
            p.to_string()
        } else {
            format!("/{p}")
        };
        format!("{p}/")
    }
}

// ── 上行数据包 ─────────────────────────────────────────────────────────────────

enum UploadPacket {
    Chunk(bytes::Bytes),
    Packet { seq: u64, data: bytes::Bytes },
    Eof,
}

// ── Session ───────────────────────────────────────────────────────────────────

struct Session {
    /// POST handler 写上行数据
    up_tx: mpsc::Sender<UploadPacket>,
    /// GET handler 到达时取走，构造 XhttpStream 的读端
    up_rx: Option<mpsc::Receiver<UploadPacket>>,
    /// XhttpStream 写端写下行数据
    down_tx: mpsc::Sender<bytes::Bytes>,
    /// GET handler 到达时取走，作为 response body
    down_rx: Option<mpsc::Receiver<bytes::Bytes>>,
    /// GET 到达通知（供 TTL 任务监听）
    get_arrived: Arc<Notify>,
}

// ── XhttpServer ───────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct XhttpServer {
    inner: Arc<ServerInner>,
}

struct ServerInner {
    cfg: XhttpConfig,
    sessions: Mutex<HashMap<String, Arc<Mutex<Session>>>>,
    ready_tx: mpsc::Sender<XhttpStream>,
    ready_rx: Mutex<mpsc::Receiver<XhttpStream>>,
}

impl XhttpServer {
    pub fn new(cfg: XhttpConfig) -> Self {
        let (ready_tx, ready_rx) = mpsc::channel(64);
        Self {
            inner: Arc::new(ServerInner {
                cfg,
                sessions: Mutex::new(HashMap::new()),
                ready_tx,
                ready_rx: Mutex::new(ready_rx),
            }),
        }
    }

    /// 等待下一个完整的 xhttp 逻辑连接就绪，返回 XhttpStream。
    pub async fn accept(&self) -> Option<XhttpStream> {
        self.inner.ready_rx.lock().await.recv().await
    }

    /// 把一个明文 TCP 流交给 hyper（立即返回，不阻塞）。
    pub fn feed_plain(&self, stream: tokio::net::TcpStream, peer: SocketAddr) {
        let inner = Arc::clone(&self.inner);
        tokio::spawn(async move {
            serve_conn(hyper_util::rt::TokioIo::new(stream), peer, inner).await;
        });
    }

    /// 把一个已完成 TLS/Reality 握手的流交给 hyper（立即返回，不阻塞）。
    pub fn feed_tls<S>(&self, stream: S, peer: SocketAddr)
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let inner = Arc::clone(&self.inner);
        tokio::spawn(async move {
            serve_conn(hyper_util::rt::TokioIo::new(stream), peer, inner).await;
        });
    }
}

// ── hyper 连接 ────────────────────────────────────────────────────────────────

async fn serve_conn<IO>(io: IO, peer: SocketAddr, inner: Arc<ServerInner>)
where
    IO: hyper::rt::Read + hyper::rt::Write + Send + Unpin + 'static,
{
    let svc = hyper::service::service_fn(move |req: Request<hyper::body::Incoming>| {
        let inner = Arc::clone(&inner);
        async move {
            let resp = handle_request(req, &inner, peer).await;
            Ok::<_, std::convert::Infallible>(resp)
        }
    });
    if let Err(e) =
        hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
            .serve_connection(io, svc)
            .await
    {
        debug!("[xhttp] {peer} conn closed: {e}");
    }
}

// ── Session 管理 ───────────────────────────────────────────────────────────────

async fn get_or_create_session(inner: &Arc<ServerInner>, session_id: &str) -> Arc<Mutex<Session>> {
    let mut map = inner.sessions.lock().await;
    if let Some(s) = map.get(session_id) {
        return Arc::clone(s);
    }

    let (up_tx, up_rx) = mpsc::channel::<UploadPacket>(64);
    let (down_tx, down_rx) = mpsc::channel::<bytes::Bytes>(64);
    let get_arrived = Arc::new(Notify::new());

    let session = Arc::new(Mutex::new(Session {
        up_tx,
        up_rx: Some(up_rx),
        down_tx,
        down_rx: Some(down_rx),
        get_arrived: Arc::clone(&get_arrived),
    }));
    map.insert(session_id.to_string(), Arc::clone(&session));

    // TTL：30s 内 GET 未到则清理；GET 到达后再等 300s（连接存活期）再清理
    let inner2 = Arc::clone(inner);
    let sid = session_id.to_string();
    tokio::spawn(async move {
        let get_timed_out = tokio::time::timeout(Duration::from_secs(30), get_arrived.notified())
            .await
            .is_err();

        if get_timed_out {
            // GET 30s 内未到，直接清理
            debug!("[xhttp] session {sid} TTL expired (no GET)");
            let mut map = inner2.sessions.lock().await;
            if let Some(s) = map.remove(&sid) {
                let s = s.lock().await;
                let _ = s.up_tx.send(UploadPacket::Eof).await;
            }
        } else {
            // GET 已到达，再等 300s 后清理（正常连接早已结束，这只是防内存泄漏的兜底）
            tokio::time::sleep(Duration::from_secs(300)).await;
            debug!("[xhttp] session {sid} cleaned up after connection lifetime");
            inner2.sessions.lock().await.remove(&sid);
        }
    });

    session
}

// ── 路径解析 ───────────────────────────────────────────────────────────────────

fn parse_path(req_path: &str, base_path: &str) -> Option<(Option<String>, Option<String>)> {
    let base_no_slash = base_path.trim_end_matches('/');

    let rest = if req_path == base_no_slash || req_path == base_path {
        ""
    } else {
        let s = req_path.strip_prefix(base_path)?;
        s.trim_start_matches('/')
    };

    if rest.is_empty() {
        return Some((None, None));
    }

    let mut parts = rest.splitn(2, '/');
    let session_id = parts.next().filter(|s| !s.is_empty()).map(str::to_string);
    let seq = parts.next().filter(|s| !s.is_empty()).map(str::to_string);
    Some((session_id, seq))
}

// ── HTTP 请求处理 ──────────────────────────────────────────────────────────────

async fn handle_request(
    req: Request<hyper::body::Incoming>,
    inner: &Arc<ServerInner>,
    peer: SocketAddr,
) -> Response<ResponseBody> {
    if let Some(expected) = &inner.cfg.host {
        let req_host = req
            .headers()
            .get("host")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if req_host != expected.as_str() {
            warn!("[xhttp] {peer} bad host: {req_host} != {expected}");
            return plain(StatusCode::NOT_FOUND);
        }
    }

    if *req.method() == Method::OPTIONS {
        return cors_ok();
    }

    let base_path = inner.cfg.normalized_path();
    let req_path = req.uri().path().to_string();

    let (session_id, seq_str) = match parse_path(&req_path, &base_path) {
        Some(p) => p,
        None => {
            warn!("[xhttp] {peer} bad path: {req_path} (base={base_path})");
            return plain(StatusCode::NOT_FOUND);
        }
    };

    debug!(
        "[xhttp] {peer} {} session={session_id:?} seq={seq_str:?}",
        req.method()
    );

    let is_downlink = *req.method() == Method::GET && seq_str.is_none();
    if is_downlink {
        handle_get(req, inner, session_id.as_deref(), peer).await
    } else {
        handle_post(req, inner, session_id.as_deref(), seq_str.as_deref(), peer).await
    }
}

/// GET handler：downlink 或 stream-one
async fn handle_get(
    req: Request<hyper::body::Incoming>,
    inner: &Arc<ServerInner>,
    session_id: Option<&str>,
    peer: SocketAddr,
) -> Response<ResponseBody> {
    // ── stream-one：无 sessionId ────────────────────────────────────────────
    if session_id.is_none() {
        let (up_tx, up_rx) = mpsc::channel::<UploadPacket>(64);
        let (down_tx, down_rx) = mpsc::channel::<bytes::Bytes>(64);

        let mut body = req.into_body();
        tokio::spawn(async move {
            loop {
                match body.frame().await {
                    None => break,
                    Some(Ok(frame)) => {
                        if let Ok(data) = frame.into_data() {
                            if up_tx.send(UploadPacket::Chunk(data)).await.is_err() {
                                break;
                            }
                        }
                    }
                    Some(Err(e)) => {
                        debug!("[xhttp] {peer} stream-one up: {e}");
                        break;
                    }
                }
            }
            let _ = up_tx.send(UploadPacket::Eof).await;
        });

        let xhs = XhttpStream::new(up_rx, down_tx);
        let _ = inner.ready_tx.send(xhs).await;

        return downlink_response(down_rx);
    }

    // ── stream-down：有 sessionId ───────────────────────────────────────────
    let sid = session_id.unwrap();
    let session_arc = get_or_create_session(inner, sid).await;
    let mut session = session_arc.lock().await;

    let up_rx = match session.up_rx.take() {
        Some(r) => r,
        None => {
            warn!("[xhttp] {peer} duplicate GET for session {sid}");
            return plain(StatusCode::CONFLICT);
        }
    };
    let down_rx = match session.down_rx.take() {
        Some(r) => r,
        None => {
            warn!("[xhttp] {peer} down_rx already taken for session {sid}");
            return plain(StatusCode::CONFLICT);
        }
    };
    let down_tx = session.down_tx.clone();

    // 通知 TTL 任务：GET 已到达
    session.get_arrived.notify_one();
    drop(session);
    // 不从 map 移除 session！up_tx 留在 session 里，后续 POST 仍可通过 map 拿到。
    // session 的清理由 TTL 任务负责（GET 到达后 TTL 会延长到连接超时）。

    // 构造 XhttpStream，推入 ready_tx
    let xhs = XhttpStream::new(up_rx, down_tx);
    let _ = inner.ready_tx.send(xhs).await;

    downlink_response(down_rx)
}

/// POST/PUT handler：接收上行数据
async fn handle_post(
    req: Request<hyper::body::Incoming>,
    inner: &Arc<ServerInner>,
    session_id: Option<&str>,
    seq_str: Option<&str>,
    peer: SocketAddr,
) -> Response<ResponseBody> {
    let up_tx = if let Some(sid) = session_id {
        let session_arc = get_or_create_session(inner, sid).await;
        let up_tx = session_arc.lock().await.up_tx.clone();
        up_tx
    } else {
        // POST 无 sessionId 不常见，忽略
        warn!("[xhttp] {peer} POST without sessionId");
        return plain(StatusCode::BAD_REQUEST);
    };

    match seq_str {
        None => {
            // stream-up
            let mut body = req.into_body();
            tokio::spawn(async move {
                loop {
                    match body.frame().await {
                        None => break,
                        Some(Ok(frame)) => {
                            if let Ok(data) = frame.into_data() {
                                if up_tx.send(UploadPacket::Chunk(data)).await.is_err() {
                                    break;
                                }
                            }
                        }
                        Some(Err(e)) => {
                            debug!("[xhttp] {peer} stream-up: {e}");
                            break;
                        }
                    }
                }
            });
        }
        Some(s) => {
            // packet-up: collect the body synchronously before returning 200 OK.
            // If we spawn and return immediately, hyper may process the next pipelined
            // request before the body is fully read, corrupting HTTP/1.1 framing.
            let seq: u64 = match s.parse() {
                Ok(n) => n,
                Err(_) => {
                    warn!("[xhttp] {peer} invalid seq: {s}");
                    return plain(StatusCode::BAD_REQUEST);
                }
            };
            let body = req.into_body();
            match body.collect().await {
                Ok(c) => {
                    let _ = up_tx
                        .send(UploadPacket::Packet {
                            seq,
                            data: c.to_bytes(),
                        })
                        .await;
                }
                Err(e) => debug!("[xhttp] {peer} packet-up collect: {e}"),
            }
        }
    }

    plain(StatusCode::OK)
}

fn downlink_response(down_rx: mpsc::Receiver<bytes::Bytes>) -> Response<ResponseBody> {
    Response::builder()
        .status(StatusCode::OK)
        // text/event-stream makes nginx and CDN middleboxes disable buffering,
        // matching Xray's hub.go behavior (NoSSEHeader=false by default)
        .header("Content-Type", "text/event-stream")
        .header("Cache-Control", "no-store")
        .header("Access-Control-Allow-Origin", "*")
        .header("X-Accel-Buffering", "no")
        .body(ResponseBody::Stream(down_rx))
        .unwrap()
}

fn plain(code: StatusCode) -> Response<ResponseBody> {
    Response::builder()
        .status(code)
        .header("Access-Control-Allow-Origin", "*")
        .body(ResponseBody::Empty)
        .unwrap()
}

fn cors_ok() -> Response<ResponseBody> {
    Response::builder()
        .status(StatusCode::OK)
        .header("Access-Control-Allow-Origin", "*")
        .header("Access-Control-Allow-Methods", "GET, POST, PUT, OPTIONS")
        .header("Access-Control-Allow-Headers", "Content-Type")
        .body(ResponseBody::Empty)
        .unwrap()
}

// ── Response body ─────────────────────────────────────────────────────────────

enum ResponseBody {
    Empty,
    Stream(mpsc::Receiver<bytes::Bytes>),
}

impl http_body::Body for ResponseBody {
    type Data = bytes::Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        match self.get_mut() {
            ResponseBody::Empty => Poll::Ready(None),
            ResponseBody::Stream(rx) => match rx.poll_recv(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(None) => Poll::Ready(None),
                Poll::Ready(Some(d)) => Poll::Ready(Some(Ok(http_body::Frame::data(d)))),
            },
        }
    }
}

// ── XhttpStream ───────────────────────────────────────────────────────────────

struct PktQueue {
    heap: BinaryHeap<Reverse<PktEntry>>,
    next_seq: u64,
    leftover: BytesMut,
}

#[derive(Eq, PartialEq)]
struct PktEntry {
    seq: u64,
    data: bytes::Bytes,
}

impl Ord for PktEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.seq.cmp(&other.seq)
    }
}
impl PartialOrd for PktEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

pub struct XhttpStream {
    up_rx: mpsc::Receiver<UploadPacket>,
    pkt_queue: PktQueue,
    stream_buf: BytesMut,
    eof: bool,
    down_tx: PollSender<bytes::Bytes>,
}

impl XhttpStream {
    fn new(up_rx: mpsc::Receiver<UploadPacket>, down_tx: mpsc::Sender<bytes::Bytes>) -> Self {
        Self {
            up_rx,
            pkt_queue: PktQueue {
                heap: BinaryHeap::new(),
                next_seq: 0,
                leftover: BytesMut::new(),
            },
            stream_buf: BytesMut::new(),
            eof: false,
            down_tx: PollSender::new(down_tx),
        }
    }
}

impl AsyncRead for XhttpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        loop {
            if !this.pkt_queue.leftover.is_empty() {
                let n = this.pkt_queue.leftover.len().min(buf.remaining());
                buf.put_slice(&this.pkt_queue.leftover[..n]);
                this.pkt_queue.leftover.advance(n);
                return Poll::Ready(Ok(()));
            }
            if !this.stream_buf.is_empty() {
                let n = this.stream_buf.len().min(buf.remaining());
                buf.put_slice(&this.stream_buf[..n]);
                this.stream_buf.advance(n);
                return Poll::Ready(Ok(()));
            }
            if let Some(Reverse(top)) = this.pkt_queue.heap.peek() {
                if top.seq == this.pkt_queue.next_seq {
                    let Reverse(entry) = this.pkt_queue.heap.pop().unwrap();
                    let n = entry.data.len().min(buf.remaining());
                    buf.put_slice(&entry.data[..n]);
                    if n < entry.data.len() {
                        this.pkt_queue.leftover.extend_from_slice(&entry.data[n..]);
                    }
                    this.pkt_queue.next_seq += 1;
                    return Poll::Ready(Ok(()));
                }
            }
            if this.eof {
                return Poll::Ready(Ok(()));
            }
            match this.up_rx.poll_recv(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => {
                    this.eof = true;
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Some(pkt)) => match pkt {
                    UploadPacket::Chunk(data) => {
                        let n = data.len().min(buf.remaining());
                        buf.put_slice(&data[..n]);
                        if n < data.len() {
                            this.stream_buf.extend_from_slice(&data[n..]);
                        }
                        return Poll::Ready(Ok(()));
                    }
                    UploadPacket::Packet { seq, data } => {
                        this.pkt_queue.heap.push(Reverse(PktEntry { seq, data }));
                    }
                    UploadPacket::Eof => {
                        this.eof = true;
                        return Poll::Ready(Ok(()));
                    }
                },
            }
        }
    }
}

impl AsyncWrite for XhttpStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        match this.down_tx.poll_reserve(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(_)) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "xhttp downlink closed",
            ))),
            Poll::Ready(Ok(())) => {
                match this.down_tx.send_item(bytes::Bytes::copy_from_slice(buf)) {
                    Ok(()) => Poll::Ready(Ok(buf.len())),
                    Err(_) => Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "xhttp downlink closed",
                    ))),
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

// ── 单元测试 ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_path() {
        let base = "/vless/";
        assert_eq!(parse_path("/vless", base), Some((None, None)));
        assert_eq!(parse_path("/vless/", base), Some((None, None)));

        let sid = "550e8400-e29b-41d4-a716-446655440000";
        assert_eq!(
            parse_path(&format!("/vless/{sid}"), base),
            Some((Some(sid.into()), None))
        );
        assert_eq!(
            parse_path(&format!("/vless/{sid}/42"), base),
            Some((Some(sid.into()), Some("42".into())))
        );
        assert_eq!(parse_path("/other", base), None);
    }
}

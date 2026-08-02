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
    /// 对齐 Xray `Config.GetNormalizedPath`（`splithttp/config.go`）：
    ///   - 空或非 `/` 开头 → 前补 `/`
    ///   - 末尾保证有 `/`（便于 `parse_path` 切 sessionId/seq）
    ///
    /// 修复：原实现对 `/` 会产出 `//`（`trim_end_matches('/')` 把 `/` 削成空串，
    /// 再 format 出 `//`），导致默认配置下所有请求都被 404。
    pub fn normalized_path(&self) -> String {
        let mut p = self.path.trim_end_matches('/').to_string();
        if !p.starts_with('/') {
            p.insert(0, '/');
        }
        if p.is_empty() {
            // path 全部由 `/` 组成（如 `/`、`//`），trim 后为空，规范化为 `/`
            p.push('/');
        }
        if !p.ends_with('/') {
            p.push('/');
        }
        p
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
    /// XhttpStream 写端写下行数据。
    /// GET handler 到达时取走（`take`，不再 clone）：这是修复下行流挂死的关键 ——
    /// 只有当所有 `down_tx` 都被释放后，`down_rx` 才会返回 `None`，GET 响应才会结束。
    /// 之前是 `clone`，导致 session 里永远保留一个 sender，`down_rx` 永远不返回 `None`，
    /// 下行连接会挂死到 1 小时 TTL 才被清理。
    down_tx: Option<mpsc::Sender<bytes::Bytes>>,
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

    // channel 容量：packet-up 模式下客户端每个 chunk 发一个 POST，
    // 高并发（如视频流）时会快速产生大量 Packet。容量太小会导致
    // up_tx.send() 阻塞，hyper 连接被占用，影响吞吐。
    // 512 足够缓冲突发流量，又不至于占用过多内存。
    let (up_tx, up_rx) = mpsc::channel::<UploadPacket>(512);
    let (down_tx, down_rx) = mpsc::channel::<bytes::Bytes>(512);
    let get_arrived = Arc::new(Notify::new());

    let session = Arc::new(Mutex::new(Session {
        up_tx,
        up_rx: Some(up_rx),
        down_tx: Some(down_tx),
        down_rx: Some(down_rx),
        get_arrived: Arc::clone(&get_arrived),
    }));
    map.insert(session_id.to_string(), Arc::clone(&session));

    // TTL：30s 内 GET 未到则清理。
    // 注意：GET 到达后不再在这里清理 —— GET 响应流结束时由
    // `ResponseBody::Stream` 的 cleanup 回调负责移除 session（对齐 Xray
    // hub.go 的 `defer h.sessions.Delete(sessionId)`）。
    let inner2 = Arc::clone(inner);
    let sid = session_id.to_string();
    tokio::spawn(async move {
        let get_timed_out = tokio::time::timeout(Duration::from_secs(30), get_arrived.notified())
            .await
            .is_err();

        if get_timed_out {
            // GET 30s 内未到，直接清理
            debug!("[xhttp] session {sid} TTL expired (no GET)");
            if let Some(s) = inner2.sessions.lock().await.remove(&sid) {
                let s = s.lock().await;
                let _ = s.up_tx.send(UploadPacket::Eof).await;
            }
        }
        // GET 已到达的情况不在这里处理 —— 由 ResponseBody 的 cleanup 回调负责。
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

/// 对齐 Xray `internet.IsValidHTTPHost`（`transport/internet/internet.go`）：
///   - 大小写不敏感
///   - 若 request host 含 `:`（即带端口），仅比较 host 部分
fn is_valid_http_host(request: &str, config: &str) -> bool {
    let r = request.to_lowercase();
    let c = config.to_lowercase();
    if let Some((h, _)) = r.rsplit_once(':') {
        // 注意：IPv6 字面量形如 `[::1]:443`，rsplit_once(':') 取到最后一个 `:`
        // 对 `[::1]:443` → ("[::1]", "443")，h="[::1]" 与配置 `[::1]` 比较仍正确。
        h == c
    } else {
        r == c
    }
}

async fn handle_request(
    req: Request<hyper::body::Incoming>,
    inner: &Arc<ServerInner>,
    peer: SocketAddr,
) -> Response<ResponseBody> {
    // 提前取 Origin，用于按 Xray `WriteResponseHeader` 的逻辑回写 CORS。
    let origin = req
        .headers()
        .get("origin")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    if let Some(expected) = &inner.cfg.host {
        let req_host = req
            .headers()
            .get("host")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !is_valid_http_host(req_host, expected) {
            warn!("[xhttp] {peer} bad host: {req_host} != {expected}");
            return plain_with_cors(StatusCode::NOT_FOUND, origin.as_deref());
        }
    }

    if *req.method() == Method::OPTIONS {
        return cors_ok(origin.as_deref());
    }

    let base_path = inner.cfg.normalized_path();
    let req_path = req.uri().path().to_string();

    let (session_id, seq_str) = match parse_path(&req_path, &base_path) {
        Some(p) => p,
        None => {
            warn!("[xhttp] {peer} bad path: {req_path} (base={base_path})");
            return plain_with_cors(StatusCode::NOT_FOUND, origin.as_deref());
        }
    };

    debug!(
        "[xhttp] {peer} {} session={session_id:?} seq={seq_str:?}",
        req.method()
    );

    let is_downlink = *req.method() == Method::GET && seq_str.is_none();
    if is_downlink {
        handle_get(req, inner, session_id.as_deref(), peer, origin).await
    } else {
        handle_post(
            req,
            inner,
            session_id.as_deref(),
            seq_str.as_deref(),
            peer,
            origin,
        )
        .await
    }
}

/// GET handler：downlink 或 stream-one
async fn handle_get(
    req: Request<hyper::body::Incoming>,
    inner: &Arc<ServerInner>,
    session_id: Option<&str>,
    peer: SocketAddr,
    origin: Option<String>,
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

        // stream-one 无 session，无需 cleanup
        return downlink_response(down_rx, origin.as_deref(), None);
    }

    // ── stream-down：有 sessionId ───────────────────────────────────────────
    let sid = session_id.unwrap();
    let session_arc = get_or_create_session(inner, sid).await;
    let mut session = session_arc.lock().await;

    let up_rx = match session.up_rx.take() {
        Some(r) => r,
        None => {
            warn!("[xhttp] {peer} duplicate GET for session {sid}");
            return plain_with_cors(StatusCode::CONFLICT, origin.as_deref());
        }
    };
    let down_rx = match session.down_rx.take() {
        Some(r) => r,
        None => {
            warn!("[xhttp] {peer} down_rx already taken for session {sid}");
            return plain_with_cors(StatusCode::CONFLICT, origin.as_deref());
        }
    };
    // 关键修复：take（不是 clone）。这样当 XhttpStream 释放 down_tx 后，
    // channel 的所有 sender 都消失，down_rx 才会返回 None，GET 响应才能正常结束。
    let down_tx = match session.down_tx.take() {
        Some(t) => t,
        None => {
            warn!("[xhttp] {peer} down_tx already taken for session {sid}");
            return plain_with_cors(StatusCode::CONFLICT, origin.as_deref());
        }
    };

    // 通知 TTL 任务：GET 已到达（TTL 任务不再做清理，交给 cleanup 回调）
    session.get_arrived.notify_one();
    drop(session);
    // 不从 map 移除 session！up_tx 留在 session 里，后续 POST 仍可通过 map 拿到。
    // session 的清理在 GET 响应流结束时由 cleanup 回调执行（对齐 Xray
    // hub.go 的 `defer h.sessions.Delete(sessionId)`）。

    // 构造 XhttpStream，推入 ready_tx
    let xhs = XhttpStream::new(up_rx, down_tx);
    let _ = inner.ready_tx.send(xhs).await;

    // cleanup：GET 响应流结束（down_rx 返回 None）时移除 session。
    // 此时 XhttpStream 已被 drop（down_tx 释放），后续 POST 会发现 session 不存在
    // 而创建新 session（客户端应已感知连接断开）。
    let inner_clone = Arc::clone(inner);
    let sid_owned = sid.to_string();
    let cleanup: Option<Box<dyn FnOnce() + Send + 'static>> = Some(Box::new(move || {
        tokio::spawn(async move {
            if let Some(s) = inner_clone.sessions.lock().await.remove(&sid_owned) {
                debug!("[xhttp] session removed on GET response end");
                // 关闭 up_tx，让 XhttpStream::poll_read（如果还在读）感知 EOF
                let _ = s.lock().await.up_tx.send(UploadPacket::Eof).await;
            }
        });
    }));

    downlink_response(down_rx, origin.as_deref(), cleanup)
}

/// POST/PUT handler：接收上行数据
async fn handle_post(
    req: Request<hyper::body::Incoming>,
    inner: &Arc<ServerInner>,
    session_id: Option<&str>,
    seq_str: Option<&str>,
    peer: SocketAddr,
    origin: Option<String>,
) -> Response<ResponseBody> {
    let up_tx = if let Some(sid) = session_id {
        let session_arc = get_or_create_session(inner, sid).await;
        let up_tx = session_arc.lock().await.up_tx.clone();
        up_tx
    } else {
        // POST 无 sessionId 不常见，忽略
        warn!("[xhttp] {peer} POST without sessionId");
        return plain_with_cors(StatusCode::BAD_REQUEST, origin.as_deref());
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
                // body 读完或出错时发送 Eof，让 XhttpStream::poll_read 能感知上行结束
                let _ = up_tx.send(UploadPacket::Eof).await;
            });
            // 对齐 Xray hub.go：stream-up 响应也设置 X-Accel-Buffering / Cache-Control
            return stream_up_response(origin.as_deref());
        }
        Some(s) => {
            // packet-up: collect the body synchronously before returning 200 OK.
            // If we spawn and return immediately, hyper may process the next pipelined
            // request before the body is fully read, corrupting HTTP/1.1 framing.
            let seq: u64 = match s.parse() {
                Ok(n) => n,
                Err(_) => {
                    warn!("[xhttp] {peer} invalid seq: {s}");
                    return plain_with_cors(StatusCode::BAD_REQUEST, origin.as_deref());
                }
            };
            let body = req.into_body();
            let had_body = match body.collect().await {
                Ok(c) => {
                    let bytes = c.to_bytes();
                    let had = !bytes.is_empty();
                    let _ = up_tx.send(UploadPacket::Packet { seq, data: bytes }).await;
                    had
                }
                Err(e) => {
                    debug!("[xhttp] {peer} packet-up collect: {e}");
                    return plain_with_cors(StatusCode::BAD_REQUEST, origin.as_deref());
                }
            };
            // 对齐 Xray hub.go：无 body 的 POST 默认会被中间件缓存，需显式 no-store
            if !had_body {
                return packet_up_response_no_body(origin.as_deref());
            }
        }
    }

    plain_with_cors(StatusCode::OK, origin.as_deref())
}

/// 对齐 Xray `Config.WriteResponseHeader`（`splithttp/config.go`）：
///   - 无 Origin → `Access-Control-Allow-Origin: *`
///   - 有 Origin → 回写该 Origin（浏览器 credentials 模式必需）
fn cors_origin_header(
    builder: http::response::Builder,
    origin: Option<&str>,
) -> http::response::Builder {
    match origin {
        Some(o) => builder
            .header("Access-Control-Allow-Origin", o)
            .header("Access-Control-Allow-Credentials", "true")
            .header("Vary", "Origin"),
        None => builder.header("Access-Control-Allow-Origin", "*"),
    }
}

fn downlink_response(
    down_rx: mpsc::Receiver<bytes::Bytes>,
    origin: Option<&str>,
    cleanup: Option<Box<dyn FnOnce() + Send + 'static>>,
) -> Response<ResponseBody> {
    let builder = Response::builder()
        .status(StatusCode::OK)
        // text/event-stream makes nginx and CDN middleboxes disable buffering,
        // matching Xray's hub.go behavior (NoSSEHeader=false by default)
        .header("Content-Type", "text/event-stream")
        .header("Cache-Control", "no-store")
        .header("X-Accel-Buffering", "no");
    let builder = cors_origin_header(builder, origin);
    builder
        .body(ResponseBody::Stream {
            rx: down_rx,
            cleanup,
        })
        .unwrap()
}

/// stream-up 响应：对齐 Xray hub.go，设置 X-Accel-Buffering / Cache-Control
fn stream_up_response(origin: Option<&str>) -> Response<ResponseBody> {
    let builder = Response::builder()
        .status(StatusCode::OK)
        .header("X-Accel-Buffering", "no")
        .header("Cache-Control", "no-store");
    let builder = cors_origin_header(builder, origin);
    builder.body(ResponseBody::Empty).unwrap()
}

/// packet-up 无 body 响应：对齐 Xray hub.go `len(bodyPayload) == 0` 分支，
/// 显式设置 Cache-Control: no-store 防止中间件缓存无 body 的 POST 响应。
fn packet_up_response_no_body(origin: Option<&str>) -> Response<ResponseBody> {
    let builder = Response::builder()
        .status(StatusCode::OK)
        .header("Cache-Control", "no-store");
    let builder = cors_origin_header(builder, origin);
    builder.body(ResponseBody::Empty).unwrap()
}

fn plain_with_cors(code: StatusCode, origin: Option<&str>) -> Response<ResponseBody> {
    let builder = Response::builder().status(code);
    let builder = cors_origin_header(builder, origin);
    builder.body(ResponseBody::Empty).unwrap()
}

fn cors_ok(origin: Option<&str>) -> Response<ResponseBody> {
    let builder = Response::builder().status(StatusCode::OK);
    let builder = cors_origin_header(builder, origin);
    // 对齐 Xray WriteResponseHeader：回显客户端请求的 Methods/Headers，
    // 缺省时用 `*`。
    builder
        .header("Access-Control-Allow-Methods", "GET, POST, PUT, OPTIONS")
        .header("Access-Control-Allow-Headers", "Content-Type")
        .body(ResponseBody::Empty)
        .unwrap()
}

// ── Response body ─────────────────────────────────────────────────────────────

enum ResponseBody {
    Empty,
    Stream {
        rx: mpsc::Receiver<bytes::Bytes>,
        /// 响应流结束（poll_frame 返回 None）时执行一次，用于清理 session。
        /// 对齐 Xray hub.go 的 `defer h.sessions.Delete(sessionId)`。
        cleanup: Option<Box<dyn FnOnce() + Send + 'static>>,
    },
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
            ResponseBody::Stream { rx, cleanup } => match rx.poll_recv(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(None) => {
                    // 响应流结束：触发 cleanup（移除 session），对齐 Xray hub.go
                    if let Some(c) = cleanup.take() {
                        c();
                    }
                    Poll::Ready(None)
                }
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

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // 关闭下行 channel：close() 释放 PollSender 持有的 down_tx。
        // 由于 handle_get 现在用 take()（不再 clone），session 里已无 down_tx，
        // down_tx 全部释放后 down_rx 收到 None → GET 响应流结束
        // → ResponseBody::Stream 的 cleanup 回调移除 session（对齐 Xray hub.go
        // 的 `defer h.sessions.Delete(sessionId)`）。
        // 不关闭的话，远程目标已断开但 GET 响应流永远不结束，
        // 客户端的 relay downlink 永远读不到 EOF → 连接挂死。
        self.down_tx.close();
        Poll::Ready(Ok(()))
    }
}

// ── 单元测试 ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalized_path() {
        // 默认 `/` 不能被规范化成 `//`（原 bug）
        assert_eq!(XhttpConfig::default().normalized_path(), "/");
        // 空 path
        assert_eq!(
            XhttpConfig {
                path: "".into(),
                host: None,
            }
            .normalized_path(),
            "/"
        );
        // 普通 path
        assert_eq!(
            XhttpConfig {
                path: "/vless".into(),
                host: None,
            }
            .normalized_path(),
            "/vless/"
        );
        // 多余尾斜杠
        assert_eq!(
            XhttpConfig {
                path: "/vless//".into(),
                host: None,
            }
            .normalized_path(),
            "/vless/"
        );
        // 无前导斜杠
        assert_eq!(
            XhttpConfig {
                path: "vless".into(),
                host: None,
            }
            .normalized_path(),
            "/vless/"
        );
    }

    #[test]
    fn test_parse_path() {
        // 默认 base `/`（修复后）
        assert_eq!(parse_path("/", "/"), Some((None, None)));
        assert_eq!(parse_path("/sid", "/"), Some((Some("sid".into()), None)));
        assert_eq!(
            parse_path("/sid/42", "/"),
            Some((Some("sid".into()), Some("42".into())))
        );

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

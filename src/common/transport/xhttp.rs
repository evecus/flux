//! XHTTP (SplitHTTP) transport — server 级别 session 管理。
//!
//! ## 架构
//!
//! Xray packet-up 模式下，一个逻辑连接 = 多个独立 TCP 连接：
//!   GET  /<base>/<sessionId>        → downlink（长连接流式响应）
//!   POST /<base>/<sessionId>/<seq>  → packet-up（每包一个短连接）
//!   POST /<base>/<sessionId>        → stream-up（长连接流式上行）
//!   GET/POST /<base>                → stream-one（上下行同一连接）
//!
//! 因此 session 表必须跨 TCP 连接共享。
//!
//! ## 对齐 Xray `transport/internet/splithttp`（hub.go / upload_queue.go /
//! xpadding.go / config.go）与 shoes `src/xhttp`（server.rs / wire.rs）：
//!
//!   1. 所有响应带随机长度（100–1000）的 `X-Padding` 头（两参考实现的默认行为）。
//!   2. 请求 padding 校验：`Referer`（优先）或请求 URL query 中的 `x_padding`
//!      必须存在且长度在 100–1000，否则 400（Xray `IsPaddingValid` / shoes
//!      `classify` 一致；当前版本 Xray 客户端恒发送 padding）。
//!   3. `mode`（auto / packet-up / stream-up / stream-one）强制：不匹配的请求
//!      形态直接 400（Xray hub.go 分支校验）。
//!   4. OPTIONS 仅作 CORS 预检处理，回显 `Access-Control-Request-Method/Headers`
//!      （缺省 `*`，Xray `WriteResponseHeader`）。
//!   5. stream-up 与 packet-up 在同一 session 内互斥：重复 stream-up 或混合
//!      使用一律 409（Xray `uploadQueue.Push` 的 reader CAS 语义）。
//!   6. packet-up body 大小上限 `scMaxEachPostBytes`（默认 1MB）→ 413。
//!   7. 乱序 packet 重排缓冲上限：缺失 seq 等待期间堆积超过上限 → 拆除连接
//!      （Xray "packet queue is too large"）。
//!   8. session 关闭后保留 30s tombstone，迟到的 GET/POST 直接 409 而不是
//!      重建 zombie session（shoes `Entry::Closed` 语义）。
//!   9. stream-up 保活：客户端带 `Referer` 时按 Xray 默认 `scStreamUpServerSecs`
//!      （20–80s 随机间隔）向响应 body 周期写入 `X` padding，防止中间盒断开。
//!   10. session id 合法性：≤256 字符且仅 `[A-Za-z0-9_-]`（shoes `classify`）。
//!
//! ## Session 内部结构
//!
//! 创建时分配：
//!   up_tx / up_rx   — POST 写入，XhttpStream 读端消费
//!   down_tx / down_rx — XhttpStream 写端写入，GET response body 消费
//!
//! Session 在 map 里只保留 { up_tx, down_tx, get_arrived, upload }。
//! up_rx 和 down_rx 在 GET 到达时一次性取出，构造 XhttpStream 推入 ready_tx。
//! POST 到达时只需要 up_tx（随时可拿到）。

use anyhow::Result;
use bytes::{Buf, BytesMut};
use http_body_util::BodyExt;
use hyper::{HeaderMap, Method, Request, Response, StatusCode};
use rand::Rng;
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

// ── 常量（对齐 Xray GetNormalized* 默认值）────────────────────────────────────

/// `X-Padding` 响应头长度范围（Xray `GetNormalizedXPaddingBytes` 默认 100–1000）。
const X_PADDING_MIN: usize = 100;
const X_PADDING_MAX: usize = 1000;
/// 请求 padding 合法长度范围（同上）。
const PADDING_VALID_MIN: usize = X_PADDING_MIN;
const PADDING_VALID_MAX: usize = X_PADDING_MAX;

/// packet-up 单个 POST body 上限（Xray `scMaxEachPostBytes` 默认 To=1,000,000）。
/// 超限返回 413 Payload Too Large，提示客户端调整分片大小。
const SC_MAX_EACH_POST_BYTES: usize = 1_000_000;

/// session 乱序 packet 重排缓冲上限（Xray `scMaxBufferedPosts`；
/// 同时也是上行 channel 容量）。缺失 seq 等待期间堆积超过上限即拆除连接。
const SC_MAX_BUFFERED_POSTS: usize = 512;

/// 未收到 GET 的 session 存活 TTL；session 关闭后的 tombstone 存活时间。
const SESSION_TTL: Duration = Duration::from_secs(30);

/// stream-up 保活间隔范围（Xray `scStreamUpServerSecs` 默认 20–80s）。
const STREAM_UP_KEEPALIVE_SECS: (u64, u64) = (20, 80);

// ── Config ────────────────────────────────────────────────────────────────────

/// XHTTP 模式（Xray `mode` 字段）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum XhttpMode {
    /// 接受所有请求形态（默认）。
    #[default]
    Auto,
    /// 仅 packet-up（`/<sid>/<seq>` POST/GET）。
    PacketUp,
    /// 仅 stream-up（`/<sid>` POST）与 stream-one。
    StreamUp,
    /// 仅 stream-one（无 sessionId）。
    StreamOne,
}

impl XhttpMode {
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "" | "auto" => Some(Self::Auto),
            "packet-up" => Some(Self::PacketUp),
            "stream-up" => Some(Self::StreamUp),
            "stream-one" => Some(Self::StreamOne),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct XhttpConfig {
    pub path: String,
    pub host: Option<String>,
    pub mode: XhttpMode,
    /// true = 下行响应不设置 `Content-Type: text/event-stream`
    /// （Xray `NoSSEHeader`；默认 false = 设置，便于中间盒关闭缓冲）。
    pub no_sse_header: bool,
}

impl Default for XhttpConfig {
    fn default() -> Self {
        Self {
            path: "/".to_string(),
            host: None,
            mode: XhttpMode::Auto,
            no_sse_header: false,
        }
    }
}

impl XhttpConfig {
    /// 从统一 TransportConfig 构造（配置校验已在 config::check_transport 完成）。
    pub fn from_transport(t: &crate::config::TransportConfig) -> Self {
        Self {
            path: t.path.clone(),
            host: t.host.clone(),
            mode: t.mode.as_deref().and_then(XhttpMode::parse).unwrap_or_default(),
            no_sse_header: t.no_sse_header,
        }
    }

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

/// session 上行形态（对齐 shoes `Upload`）：
/// stream-up 与 packet-up 互斥，先到者得，后到者 409。
#[derive(Debug, PartialEq)]
enum UploadState {
    Unclaimed,
    Packet,
    Stream,
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
    /// 上行形态：stream-up / packet-up 互斥
    upload: UploadState,
}

/// session 表条目（对齐 shoes `Entry`）：
/// 关闭后保留 tombstone，迟到的 GET/POST 直接 409 而不是重建 zombie session。
enum SessionEntry {
    Live(Arc<Mutex<Session>>),
    Closed,
}

// ── XhttpServer ───────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct XhttpServer {
    inner: Arc<ServerInner>,
}

struct ServerInner {
    cfg: XhttpConfig,
    sessions: Mutex<HashMap<String, SessionEntry>>,
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

    /// 处理一条 HTTP 请求（供 hyper TCP 路径与 HTTP/3 路径共用）。
    ///
    /// 请求 body 泛型化：hyper 路径是 `hyper::body::Incoming`，H3 路径是
    /// 从 QUIC stream 泵入 channel 的自定义 body（见 `xhttp_h3::H3RequestBody`）。
    /// 对齐 Xray `hub.go`：同一个 HTTP handler 同时服务 h1/h2（TCP）与 h3（QUIC）。
    pub async fn handle_request<B>(&self, req: Request<B>, peer: SocketAddr) -> Response<ResponseBody>
    where
        B: http_body::Body<Data = bytes::Bytes> + Unpin + Send + 'static,
        B::Error: std::error::Error + Send + Sync + 'static,
    {
        handle_request(req, &self.inner, peer).await
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

/// 取活 session；已关闭（tombstone）→ 409；不存在 → 创建。
async fn get_or_create_session(
    inner: &Arc<ServerInner>,
    session_id: &str,
) -> Result<Arc<Mutex<Session>>, StatusCode> {
    let mut map = inner.sessions.lock().await;
    match map.get(session_id) {
        Some(SessionEntry::Live(s)) => return Ok(Arc::clone(s)),
        // 关闭后的 session 不允许复活：客户端必须用新 session id 重连。
        // （对齐 shoes：Xray 原版会静默重建 zombie session，掩盖连接已死的事实。）
        Some(SessionEntry::Closed) => return Err(StatusCode::CONFLICT),
        None => {}
    }

    // channel 容量：packet-up 模式下客户端每个 chunk 发一个 POST，
    // 高并发（如视频流）时会快速产生大量 Packet。容量太小会导致
    // up_tx.send() 阻塞，hyper 连接被占用，影响吞吐。
    let (up_tx, up_rx) = mpsc::channel::<UploadPacket>(SC_MAX_BUFFERED_POSTS);
    let (down_tx, down_rx) = mpsc::channel::<bytes::Bytes>(SC_MAX_BUFFERED_POSTS);
    let get_arrived = Arc::new(Notify::new());

    let session = Arc::new(Mutex::new(Session {
        up_tx,
        up_rx: Some(up_rx),
        down_tx: Some(down_tx),
        down_rx: Some(down_rx),
        get_arrived: Arc::clone(&get_arrived),
        upload: UploadState::Unclaimed,
    }));
    map.insert(
        session_id.to_string(),
        SessionEntry::Live(Arc::clone(&session)),
    );
    drop(map);

    // TTL：30s 内 GET 未到则关闭（tombstone + 关闭上行）。
    // GET 到达后由 GET 响应流结束时的 cleanup 回调负责关闭
    // （对齐 Xray hub.go 的 `defer h.sessions.Delete(sessionId)`）。
    let inner2 = Arc::clone(inner);
    let sid = session_id.to_string();
    let session_ttl = Arc::clone(&session);
    tokio::spawn(async move {
        let get_timed_out =
            tokio::time::timeout(SESSION_TTL, get_arrived.notified()).await.is_err();
        if get_timed_out {
            debug!("[xhttp] session {sid} TTL expired (no GET)");
            close_session(&inner2, &sid, &session_ttl).await;
        }
    });

    Ok(session)
}

/// 关闭 session：仅当 map 仍指向该 Arc 时（防止误关新建的同名 session），
/// 置为 tombstone、关闭上行，并安排 30s 后回收 tombstone。
async fn close_session(inner: &Arc<ServerInner>, sid: &str, session: &Arc<Mutex<Session>>) {
    let mut map = inner.sessions.lock().await;
    if !matches!(map.get(sid), Some(SessionEntry::Live(cur)) if Arc::ptr_eq(cur, session)) {
        return;
    }
    map.insert(sid.to_string(), SessionEntry::Closed);
    drop(map);

    let _ = session.lock().await.up_tx.send(UploadPacket::Eof).await;

    let inner2 = Arc::clone(inner);
    let sid2 = sid.to_string();
    tokio::spawn(async move {
        tokio::time::sleep(SESSION_TTL).await;
        let mut map = inner2.sessions.lock().await;
        if matches!(map.get(&sid2), Some(SessionEntry::Closed)) {
            map.remove(&sid2);
        }
    });
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

// ── padding / session id 校验 ──────────────────────────────────────────────────

/// 最小 percent-decode（`%XX` → 字节；非法序列原样保留）。
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        // 需要 % + 两个完整 hex 位
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(h), Some(l)) = (hi, lo) {
                out.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// 从 query string 取参数（做 percent-decode；不处理 `+`→空格，
/// padding 值恒为 token 字符，无空格）。
fn query_param(query: &str, key: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        if percent_decode(k) == key {
            Some(percent_decode(v))
        } else {
            None
        }
    })
}

/// 提取请求 padding（对齐 Xray `ExtractXPaddingFromRequest` 非 obfs 分支 /
/// shoes `classify`）：有 `Referer` 时只看 Referer URL 的 query，否则看请求
/// 自身 query，取 `x_padding` 参数。返回 None = 未携带 padding。
fn extract_request_padding(req: &Request<impl http_body::Body>) -> Option<String> {
    let referer = req
        .headers()
        .get("referer")
        .and_then(|v| v.to_str().ok())
        .filter(|v| !v.is_empty());

    let query = match referer {
        Some(r) => r.split_once('?').map(|(_, q)| q),
        None => req.uri().query(),
    };
    query.and_then(|q| query_param(q, "x_padding"))
}

/// 对齐 Xray `IsPaddingValid` / shoes `classify`：padding 必须存在且长度在
/// 默认范围内（100–1000），否则请求非法。
fn padding_is_valid(padding: &str) -> bool {
    !padding.is_empty()
        && padding.len() >= PADDING_VALID_MIN
        && padding.len() <= PADDING_VALID_MAX
}

/// session id 合法性（对齐 shoes `classify`）：非空、≤256 字符且仅
/// `[A-Za-z0-9_-]`。
fn valid_session_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 256
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
}

fn rand_range_u64(min: u64, max: u64) -> u64 {
    rand::thread_rng().gen_range(min..=max)
}

fn rand_padding_len() -> usize {
    rand::thread_rng().gen_range(X_PADDING_MIN..=X_PADDING_MAX) as usize
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

async fn handle_request<B>(
    req: Request<B>,
    inner: &Arc<ServerInner>,
    peer: SocketAddr,
) -> Response<ResponseBody>
where
    B: http_body::Body<Data = bytes::Bytes> + Unpin + Send + 'static,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    // 提前取 Origin，用于按 Xray `WriteResponseHeader` 的逻辑回写 CORS。
    let origin = req
        .headers()
        .get("origin")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    // 每个请求生成一次 X-Padding 值，所有响应（含错误响应）统一携带
    // （对齐 Xray：ApplyXPaddingToResponse 在所有校验之前调用）。
    let pad = rand_padding_len();

    if let Some(expected) = &inner.cfg.host {
        let req_host = req
            .headers()
            .get("host")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !is_valid_http_host(req_host, expected) {
            warn!("[xhttp] {peer} bad host: {req_host} != {expected}");
            return plain_with_cors(StatusCode::NOT_FOUND, origin.as_deref(), pad);
        }
    }

    // OPTIONS 一律按 CORS 预检处理：回显请求的 Method/Headers（缺省 `*`，
    // 对齐 Xray WriteResponseHeader 与 shoes）。
    if *req.method() == Method::OPTIONS {
        return cors_ok(origin.as_deref(), req.headers(), pad);
    }

    let base_path = inner.cfg.normalized_path();
    let req_path = req.uri().path().to_string();

    let (session_id, seq_str) = match parse_path(&req_path, &base_path) {
        Some(p) => p,
        None => {
            warn!("[xhttp] {peer} bad path: {req_path} (base={base_path})");
            return plain_with_cors(StatusCode::NOT_FOUND, origin.as_deref(), pad);
        }
    };

    debug!(
        "[xhttp] {peer} {} session={session_id:?} seq={seq_str:?}",
        req.method()
    );

    // ── padding 校验（对齐 Xray / shoes：缺失或长度出界 → 400）───────────────
    let padding = extract_request_padding(&req).unwrap_or_default();
    if !padding_is_valid(&padding) {
        debug!(
            "[xhttp] {peer} invalid padding (len={})",
            padding.len()
        );
        return plain_with_cors(StatusCode::BAD_REQUEST, origin.as_deref(), pad);
    }

    // ── session id 合法性 ─────────────────────────────────────────────────────
    if let Some(sid) = &session_id {
        if !valid_session_id(sid) {
            return plain_with_cors(StatusCode::BAD_REQUEST, origin.as_deref(), pad);
        }
    }

    // ── mode 强制 + 方法分类（对齐 Xray hub.go 分支）─────────────────────────
    let mode = inner.cfg.mode;
    let method = req.method().clone();

    match (&session_id, &seq_str) {
        // stream-one：无 sessionId。Xray：mode 为 packet-up 时拒绝 stream-one。
        (None, _) => {
            if !matches!(mode, XhttpMode::Auto | XhttpMode::StreamOne | XhttpMode::StreamUp) {
                debug!("[xhttp] {peer} stream-one mode is not allowed (mode={mode:?})");
                return plain_with_cors(StatusCode::BAD_REQUEST, origin.as_deref(), pad);
            }
            if method != Method::GET && method != Method::POST {
                return plain_with_cors(StatusCode::METHOD_NOT_ALLOWED, origin.as_deref(), pad);
            }
            handle_stream_one(req, inner, peer, origin, pad).await
        }
        // stream-down：GET /<sid>
        (Some(_), None) if method == Method::GET => {
            handle_get(req, inner, session_id.as_deref(), peer, origin, pad).await
        }
        // packet-up：/<sid>/<seq>（POST 或 GET，对齐 shoes；其余方法 405）
        (Some(_), Some(_)) => {
            if !matches!(mode, XhttpMode::Auto | XhttpMode::PacketUp) {
                debug!("[xhttp] {peer} packet-up mode is not allowed (mode={mode:?})");
                return plain_with_cors(StatusCode::BAD_REQUEST, origin.as_deref(), pad);
            }
            if method != Method::POST && method != Method::GET {
                return plain_with_cors(StatusCode::METHOD_NOT_ALLOWED, origin.as_deref(), pad);
            }
            handle_packet(
                req,
                inner,
                session_id.as_deref(),
                seq_str.as_deref(),
                peer,
                origin,
                pad,
            )
            .await
        }
        // stream-up：POST /<sid>（其余方法 405）
        (Some(_), None) => {
            if !matches!(mode, XhttpMode::Auto | XhttpMode::StreamUp) {
                debug!("[xhttp] {peer} stream-up mode is not allowed (mode={mode:?})");
                return plain_with_cors(StatusCode::BAD_REQUEST, origin.as_deref(), pad);
            }
            if method != Method::POST {
                return plain_with_cors(StatusCode::METHOD_NOT_ALLOWED, origin.as_deref(), pad);
            }
            handle_stream_up(req, inner, session_id.as_deref(), peer, origin, pad).await
        }
    }
}

/// stream-one：无 sessionId，上下行同一连接。无 session 表参与。
async fn handle_stream_one<B>(
    req: Request<B>,
    inner: &Arc<ServerInner>,
    peer: SocketAddr,
    origin: Option<String>,
    pad: usize,
) -> Response<ResponseBody>
where
    B: http_body::Body<Data = bytes::Bytes> + Unpin + Send + 'static,
    B::Error: std::error::Error + Send + Sync + 'static,
{
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
    downlink_response(down_rx, origin.as_deref(), pad, inner.cfg.no_sse_header, None)
}

/// GET handler：stream-down（有 sessionId）
#[allow(clippy::too_many_arguments)]
async fn handle_get<B>(
    _req: Request<B>,
    inner: &Arc<ServerInner>,
    session_id: Option<&str>,
    peer: SocketAddr,
    origin: Option<String>,
    pad: usize,
) -> Response<ResponseBody>
where
    B: http_body::Body<Data = bytes::Bytes> + Unpin + Send + 'static,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    let sid = session_id.unwrap_or_default();
    let session_arc = match get_or_create_session(inner, sid).await {
        Ok(s) => s,
        Err(code) => {
            warn!("[xhttp] {peer} GET for closed session {sid}");
            return plain_with_cors(code, origin.as_deref(), pad);
        }
    };
    let mut session = session_arc.lock().await;

    let up_rx = match session.up_rx.take() {
        Some(r) => r,
        None => {
            warn!("[xhttp] {peer} duplicate GET for session {sid}");
            return plain_with_cors(StatusCode::CONFLICT, origin.as_deref(), pad);
        }
    };
    let down_rx = match session.down_rx.take() {
        Some(r) => r,
        None => {
            warn!("[xhttp] {peer} down_rx already taken for session {sid}");
            return plain_with_cors(StatusCode::CONFLICT, origin.as_deref(), pad);
        }
    };
    // 关键修复：take（不是 clone）。这样当 XhttpStream 释放 down_tx 后，
    // channel 的所有 sender 都消失，down_rx 才会返回 None，GET 响应才能正常结束。
    let down_tx = match session.down_tx.take() {
        Some(t) => t,
        None => {
            warn!("[xhttp] {peer} down_tx already taken for session {sid}");
            return plain_with_cors(StatusCode::CONFLICT, origin.as_deref(), pad);
        }
    };

    // 通知 TTL 任务：GET 已到达（TTL 任务不再做清理，交给 cleanup 回调）
    session.get_arrived.notify_one();
    drop(session);
    // 不从 map 移除 session！up_tx 留在 session 里，后续 POST 仍可通过 map 拿到。
    // session 的关闭在 GET 响应流结束时由 cleanup 回调执行（对齐 Xray
    // hub.go 的 `defer h.sessions.Delete(sessionId)`；关闭后保留 tombstone）。

    // 构造 XhttpStream，推入 ready_tx
    let xhs = XhttpStream::new(up_rx, down_tx);
    let _ = inner.ready_tx.send(xhs).await;

    // cleanup：GET 响应流结束（down_rx 返回 None）时关闭 session（tombstone）。
    // 此时 XhttpStream 已被 drop（down_tx 释放），后续 POST 会得到 409
    // （客户端应感知连接断开并以新 session id 重连）。
    let inner_clone = Arc::clone(inner);
    let sid_owned = sid.to_string();
    let session_clone = Arc::clone(&session_arc);
    let cleanup: Option<Box<dyn FnOnce() + Send + 'static>> = Some(Box::new(move || {
        tokio::spawn(async move {
            debug!("[xhttp] session {sid_owned} closed on GET response end");
            close_session(&inner_clone, &sid_owned, &session_clone).await;
        });
    }));

    downlink_response(
        down_rx,
        origin.as_deref(),
        pad,
        inner.cfg.no_sse_header,
        cleanup,
    )
}

/// stream-up：POST /<sid>，长连接流式上行。
/// 同一 session 内 stream-up 与 packet-up 互斥；重复 stream-up → 409。
#[allow(clippy::too_many_arguments)]
async fn handle_stream_up<B>(
    req: Request<B>,
    inner: &Arc<ServerInner>,
    session_id: Option<&str>,
    peer: SocketAddr,
    origin: Option<String>,
    pad: usize,
) -> Response<ResponseBody>
where
    B: http_body::Body<Data = bytes::Bytes> + Unpin + Send + 'static,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    let sid = session_id.unwrap_or_default();
    let session_arc = match get_or_create_session(inner, sid).await {
        Ok(s) => s,
        Err(code) => {
            warn!("[xhttp] {peer} stream-up for closed session {sid}");
            return plain_with_cors(code, origin.as_deref(), pad);
        }
    };

    let up_tx = {
        let mut session = session_arc.lock().await;
        // 对齐 Xray uploadQueue 的 reader CAS：上行形态互斥，重复/混合 409
        if session.upload != UploadState::Unclaimed {
            warn!("[xhttp] {peer} session {sid} upload already claimed ({:?})", session.upload);
            return plain_with_cors(StatusCode::CONFLICT, origin.as_deref(), pad);
        }
        session.upload = UploadState::Stream;
        session.up_tx.clone()
    };

    let has_referer = req
        .headers()
        .get("referer")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| !v.is_empty());

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

    // stream-up 保活（对齐 Xray hub.go scStreamUpServerSecs / shoes）：
    // 客户端带 Referer（当前 Xray 客户端恒带，padding 即在其中）时，
    // 按 20–80s 随机间隔向响应 body 写入 'X' padding，防止 CDN/中间盒
    // 因长时间无响应数据而断开连接。响应流在客户端断开时自然终止
    // （body 被 drop → channel send 失败 → 保活任务退出）。
    if has_referer {
        let (pad_tx, pad_rx) = mpsc::channel::<bytes::Bytes>(8);
        tokio::spawn(async move {
            loop {
                let secs = rand_range_u64(STREAM_UP_KEEPALIVE_SECS.0, STREAM_UP_KEEPALIVE_SECS.1);
                tokio::time::sleep(Duration::from_secs(secs)).await;
                let chunk = vec![b'X'; rand_padding_len()];
                if pad_tx.send(bytes::Bytes::from(chunk)).await.is_err() {
                    break;
                }
            }
        });
        return streaming_up_response_with_keepalive(pad_rx, origin.as_deref(), pad);
    }

    // 对齐 Xray hub.go：stream-up 响应也设置 X-Accel-Buffering / Cache-Control
    stream_up_response(origin.as_deref(), pad)
}

/// packet-up：POST/PUT /<sid>/<seq>，每包一个短连接。
#[allow(clippy::too_many_arguments)]
async fn handle_packet<B>(
    req: Request<B>,
    inner: &Arc<ServerInner>,
    session_id: Option<&str>,
    seq_str: Option<&str>,
    peer: SocketAddr,
    origin: Option<String>,
    pad: usize,
) -> Response<ResponseBody>
where
    B: http_body::Body<Data = bytes::Bytes> + Unpin + Send + 'static,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    let sid = session_id.unwrap_or_default();
    let seq: u64 = match seq_str.unwrap_or_default().parse() {
        Ok(n) => n,
        Err(_) => {
            warn!("[xhttp] {peer} invalid seq: {:?}", seq_str);
            return plain_with_cors(StatusCode::BAD_REQUEST, origin.as_deref(), pad);
        }
    };

    let session_arc = match get_or_create_session(inner, sid).await {
        Ok(s) => s,
        Err(code) => {
            warn!("[xhttp] {peer} packet for closed session {sid}");
            return plain_with_cors(code, origin.as_deref(), pad);
        }
    };

    let up_tx = {
        let mut session = session_arc.lock().await;
        // 对齐 shoes：stream-up 已声明的 session 不接受 packet（互斥）
        if session.upload == UploadState::Stream {
            warn!("[xhttp] {peer} session {sid} already in stream-up mode");
            return plain_with_cors(StatusCode::CONFLICT, origin.as_deref(), pad);
        }
        session.upload = UploadState::Packet;
        session.up_tx.clone()
    };

    // packet-up: collect the body synchronously before returning 200 OK.
    // If we spawn and return immediately, hyper may process the next pipelined
    // request before the body is fully read, corrupting HTTP/1.1 framing.
    //
    // scMaxEachPostBytes（对齐 Xray）：先看 Content-Length 提前拒绝（413），
    // 收完后兜底再查一次，防 chunked 绕过。
    if let Some(cl) = req
        .headers()
        .get(hyper::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok())
    {
        if cl > SC_MAX_EACH_POST_BYTES {
            warn!("[xhttp] {peer} upload too large (content-length={cl})");
            return plain_with_cors(StatusCode::PAYLOAD_TOO_LARGE, origin.as_deref(), pad);
        }
    }

    let body = req.into_body();
    let collected = body.collect().await;
    let data = match collected {
        Ok(c) => c.to_bytes(),
        Err(e) => {
            debug!("[xhttp] {peer} packet-up collect: {e}");
            return plain_with_cors(StatusCode::BAD_REQUEST, origin.as_deref(), pad);
        }
    };
    if data.len() > SC_MAX_EACH_POST_BYTES {
        warn!("[xhttp] {peer} upload too large (len={})", data.len());
        return plain_with_cors(StatusCode::PAYLOAD_TOO_LARGE, origin.as_deref(), pad);
    }
    let had_body = !data.is_empty();
    let _ = up_tx
        .send(UploadPacket::Packet { seq, data })
        .await;

    // 对齐 Xray hub.go：无 body 的 POST 默认会被中间件缓存，需显式 no-store
    if !had_body {
        return packet_up_response_no_body(origin.as_deref(), pad);
    }

    plain_with_cors(StatusCode::OK, origin.as_deref(), pad)
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

/// X-Padding 头：随机长度 'X'（对齐 Xray ApplyXPaddingToResponse / shoes）。
fn padding_header(
    builder: http::response::Builder,
    pad: usize,
) -> http::response::Builder {
    builder.header("X-Padding", "X".repeat(pad))
}

fn downlink_response(
    down_rx: mpsc::Receiver<bytes::Bytes>,
    origin: Option<&str>,
    pad: usize,
    no_sse_header: bool,
    cleanup: Option<Box<dyn FnOnce() + Send + 'static>>,
) -> Response<ResponseBody> {
    let builder = Response::builder()
        .status(StatusCode::OK)
        // text/event-stream makes nginx and CDN middleboxes disable buffering,
        // matching Xray's hub.go behavior (NoSSEHeader=false by default)
        .header("Cache-Control", "no-store")
        .header("X-Accel-Buffering", "no");
    let builder = if no_sse_header {
        builder
    } else {
        builder.header("Content-Type", "text/event-stream")
    };
    let builder = padding_header(cors_origin_header(builder, origin), pad);
    builder
        .body(ResponseBody::Stream { rx: down_rx, cleanup })
        .unwrap()
}

/// stream-up 响应：对齐 Xray hub.go，设置 X-Accel-Buffering / Cache-Control
fn stream_up_response(origin: Option<&str>, pad: usize) -> Response<ResponseBody> {
    let builder = Response::builder()
        .status(StatusCode::OK)
        .header("X-Accel-Buffering", "no")
        .header("Cache-Control", "no-store");
    let builder = padding_header(cors_origin_header(builder, origin), pad);
    builder.body(ResponseBody::Empty).unwrap()
}

/// stream-up + 保活：响应 body 为独立的 padding 流（20–80s 随机间隔写 'X'）。
fn streaming_up_response_with_keepalive(
    pad_rx: mpsc::Receiver<bytes::Bytes>,
    origin: Option<&str>,
    pad: usize,
) -> Response<ResponseBody> {
    let builder = Response::builder()
        .status(StatusCode::OK)
        .header("X-Accel-Buffering", "no")
        .header("Cache-Control", "no-store");
    let builder = padding_header(cors_origin_header(builder, origin), pad);
    builder
        .body(ResponseBody::Stream { rx: pad_rx, cleanup: None })
        .unwrap()
}

/// packet-up 无 body 响应：对齐 Xray hub.go `len(bodyPayload) == 0` 分支，
/// 显式设置 Cache-Control: no-store 防止中间件缓存无 body 的 POST 响应。
fn packet_up_response_no_body(origin: Option<&str>, pad: usize) -> Response<ResponseBody> {
    let builder = Response::builder()
        .status(StatusCode::OK)
        .header("Cache-Control", "no-store");
    let builder = padding_header(cors_origin_header(builder, origin), pad);
    builder.body(ResponseBody::Empty).unwrap()
}

fn plain_with_cors(code: StatusCode, origin: Option<&str>, pad: usize) -> Response<ResponseBody> {
    let builder = Response::builder().status(code);
    let builder = padding_header(cors_origin_header(builder, origin), pad);
    builder.body(ResponseBody::Empty).unwrap()
}

fn cors_ok(
    origin: Option<&str>,
    req_headers: &HeaderMap,
    pad: usize,
) -> Response<ResponseBody> {
    let builder = Response::builder().status(StatusCode::OK);
    let builder = padding_header(cors_origin_header(builder, origin), pad);
    // 对齐 Xray WriteResponseHeader / shoes：回显客户端请求的
    // Access-Control-Request-Method / -Headers，缺省时用 `*`。
    let echo = |name: &str| -> http::header::HeaderValue {
        req_headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .filter(|v| !v.is_empty())
            .and_then(|v| http::header::HeaderValue::from_str(v).ok())
            .unwrap_or(http::header::HeaderValue::from_static("*"))
    };
    builder
        .header("Access-Control-Allow-Methods", echo("access-control-request-method"))
        .header("Access-Control-Allow-Headers", echo("access-control-request-headers"))
        .body(ResponseBody::Empty)
        .unwrap()
}

// ── Response body ─────────────────────────────────────────────────────────────

/// 响应 body：hyper（TCP h1/h2）与 HTTP/3 两条路径共用。
/// `Empty` 为无 body 响应；`Stream` 是 session 的下行 channel
/// （downlink GET）或 stream-up 保活 padding 流。
pub(crate) enum ResponseBody {
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
                    // 响应流结束：触发 cleanup（关闭 session），对齐 Xray hub.go
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
                // 缺失 seq 等待期间堆积超过重排缓冲上限 → 拆除连接
                // （对齐 Xray upload_queue.Read 的 "packet queue is too large"：
                //  无界等待会让僵尸 session 永久占用内存）。
                if this.pkt_queue.heap.len() > SC_MAX_BUFFERED_POSTS {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::ConnectionReset,
                        "xhttp packet queue is too large",
                    )));
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
        // → ResponseBody::Stream 的 cleanup 回调关闭 session（tombstone，
        // 对齐 Xray hub.go 的 `defer h.sessions.Delete(sessionId)` + shoes）。
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

    fn cfg(path: &str) -> XhttpConfig {
        XhttpConfig {
            path: path.into(),
            ..Default::default()
        }
    }

    #[test]
    fn test_xhttp_mode_parse() {
        assert_eq!(XhttpMode::parse("auto"), Some(XhttpMode::Auto));
        assert_eq!(XhttpMode::parse(""), Some(XhttpMode::Auto));
        assert_eq!(XhttpMode::parse("packet-up"), Some(XhttpMode::PacketUp));
        assert_eq!(XhttpMode::parse("stream-up"), Some(XhttpMode::StreamUp));
        assert_eq!(XhttpMode::parse("stream-one"), Some(XhttpMode::StreamOne));
        assert_eq!(XhttpMode::parse("AUTO"), Some(XhttpMode::Auto));
        assert_eq!(XhttpMode::parse("bad"), None);
    }

    #[test]
    fn test_normalized_path() {
        // 默认 `/` 不能被规范化成 `//`（原 bug）
        assert_eq!(XhttpConfig::default().normalized_path(), "/");
        // 空 path
        assert_eq!(cfg("").normalized_path(), "/");
        // 普通 path
        assert_eq!(cfg("/vless").normalized_path(), "/vless/");
        // 多余尾斜杠
        assert_eq!(cfg("/vless//").normalized_path(), "/vless/");
        // 无前导斜杠
        assert_eq!(cfg("vless").normalized_path(), "/vless/");
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

    #[test]
    fn test_percent_decode_and_query_param() {
        assert_eq!(percent_decode("plain"), "plain");
        assert_eq!(percent_decode("a%20b"), "a b");
        assert_eq!(percent_decode("%2F%2F"), "//");
        // 非法序列原样保留
        assert_eq!(percent_decode("%G1"), "%G1");
        assert_eq!(percent_decode("x%"), "x%");

        assert_eq!(
            query_param("a=1&x_padding=XXXX&b=2", "x_padding"),
            Some("XXXX".into())
        );
        assert_eq!(query_param("a=1&b=2", "x_padding"), None);
        assert_eq!(query_param("x_padding=%41%42%43", "x_padding"), Some("ABC".into()));
        // 前缀相似的 key 不误匹配
        assert_eq!(query_param("x_padding2=zz", "x_padding"), None);
    }

    #[test]
    fn test_padding_is_valid() {
        assert!(!padding_is_valid(""));
        assert!(!padding_is_valid(&"X".repeat(99)));
        assert!(padding_is_valid(&"X".repeat(100)));
        assert!(padding_is_valid(&"X".repeat(1000)));
        assert!(!padding_is_valid(&"X".repeat(1001)));
    }

    #[test]
    fn test_valid_session_id() {
        assert!(valid_session_id("550e8400-e29b-41d4-a716-446655440000"));
        assert!(valid_session_id("abc_DEF-123"));
        assert!(!valid_session_id(""));
        assert!(!valid_session_id("a/b"));
        assert!(!valid_session_id("a b"));
        assert!(!valid_session_id(&"a".repeat(257)));
        assert!(valid_session_id(&"a".repeat(256)));
    }

    #[test]
    fn test_padding_header_length_range() {
        for _ in 0..50 {
            let n = rand_padding_len();
            assert!((X_PADDING_MIN..=X_PADDING_MAX).contains(&n));
        }
    }
}

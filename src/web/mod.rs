//! Web 面板：hyper 1.x 手写路由 + 登录页 + HttpOnly Cookie 会话。
//!
//! 仅 `-d` 面板模式启动本模块。登录凭据为「用户名 + PBKDF2 密码哈希」，
//! 存于加密数据库；面板端口同样存库，修改后监听器自动重绑定。
//! 节点增删改通过 NodeManager 热重载：写数据库 + 停旧启新，立即生效。

use anyhow::{Context, Result};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::header::{CONTENT_TYPE, COOKIE, LOCATION, SET_COOKIE};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::convert::Infallible;
use std::net::IpAddr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::watch::Receiver;

use crate::config;
use crate::crypto;
use crate::node_manager::NodeManager;
use crate::stats::{self, Stats};

const LOGIN_HTML: &str = include_str!("login.html");
const INDEX_HTML: &str = include_str!("index.html");
const SESSION_TTL_MS: u64 = 24 * 3600 * 1000;

// ── 登录防爆破 ──────────────────────────────────────────────────────────────
// 三层防护：
//  1. 单 IP：15 分钟窗口内失败 MAX_FAILS 次即锁定；锁定时长随累犯翻倍
//     （15 分钟 → 30 分钟 → … 上限 24 小时），24 小时无失败后才清零。
//  2. 全局：10 分钟内全站失败达 GLOBAL_MAX_FAILS 次（分布式 / 换 IP 爆破）即进入
//     全局冷却，期间只允许「近期成功登录过的 IP」尝试，其余一律拒绝。
//  3. 并发：同一时刻最多 LOGIN_CONCURRENCY 个 PBKDF2 校验，且放在 blocking 线程池，
//     防止用大量登录请求拖垮 CPU / 异步工作线程。
const MAX_FAILS: u32 = 5;
const FAIL_WINDOW_MS: u64 = 15 * 60 * 1000;
const BASE_LOCK_MS: u64 = 15 * 60 * 1000;
const MAX_LOCK_MS: u64 = 24 * 3600 * 1000;
const STRIKE_MEMORY_MS: u64 = 24 * 3600 * 1000;
const GLOBAL_WINDOW_MS: u64 = 10 * 60 * 1000;
const GLOBAL_MAX_FAILS: usize = 60;
const GLOBAL_LOCK_MS: u64 = 5 * 60 * 1000;
const TRUSTED_TTL_MS: u64 = 30 * 24 * 3600 * 1000;
const MAX_TRACKED_IPS: usize = 50_000;
const LOGIN_CONCURRENCY: usize = 2;
/// 登录请求体上限；其余已鉴权接口 2 MiB。
const LOGIN_BODY_LIMIT: usize = 4 * 1024;
const API_BODY_LIMIT: usize = 2 * 1024 * 1024;
const BODY_READ_TIMEOUT: Duration = Duration::from_secs(15);
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);

type Resp = Response<Full<Bytes>>;

#[derive(Default, Clone, Copy)]
struct IpState {
    fails: u32,
    window_start: u64,
    locked_until: u64,
    /// 累计被锁定次数（决定下次锁多久）。
    strikes: u32,
    last_seen: u64,
}

/// 登录失败跟踪（内存态，重启即清零）。
#[derive(Default)]
struct LoginGuard {
    ips: HashMap<String, IpState>,
    global_fails: VecDeque<u64>,
    global_locked_until: u64,
    /// 近期成功登录过的 IP → 时间；全局冷却期间仍允许其尝试。
    trusted: HashMap<String, u64>,
}

impl LoginGuard {
    /// 允许尝试返回 Ok(())；否则 Err(剩余毫秒数)。
    fn check(&self, ip: &str) -> Result<(), u64> {
        let now = stats::now_ms();
        if let Some(st) = self.ips.get(ip) {
            if now < st.locked_until {
                return Err(st.locked_until - now);
            }
        }
        if now < self.global_locked_until && !self.trusted.contains_key(ip) {
            return Err(self.global_locked_until - now);
        }
        Ok(())
    }

    /// 记录一次失败。返回 Err(剩余锁定毫秒数) 表示本次已触发该 IP 的锁定。
    fn record_failure(&mut self, ip: &str) -> Result<(), u64> {
        let now = stats::now_ms();

        // 全局滑动窗口
        self.global_fails.push_back(now);
        while self.global_fails.front().is_some_and(|t| now.saturating_sub(*t) > GLOBAL_WINDOW_MS) {
            self.global_fails.pop_front();
        }
        if self.global_fails.len() >= GLOBAL_MAX_FAILS && now >= self.global_locked_until {
            self.global_locked_until = now + GLOBAL_LOCK_MS;
            tracing::warn!(
                "[web] 全局登录失败 {} 次/{} 分钟，疑似分布式爆破，进入 {} 分钟全局冷却",
                self.global_fails.len(),
                GLOBAL_WINDOW_MS / 60_000,
                GLOBAL_LOCK_MS / 60_000
            );
        }

        // 清理过期条目，防止表无限增长（含 IPv6 海量来源）。
        self.ips.retain(|_, st| now < st.locked_until || now.saturating_sub(st.last_seen) <= STRIKE_MEMORY_MS);
        self.trusted.retain(|_, t| now.saturating_sub(*t) <= TRUSTED_TTL_MS);
        if self.ips.len() >= MAX_TRACKED_IPS {
            self.ips.retain(|_, st| now < st.locked_until);
        }

        let st = self.ips.entry(ip.to_string()).or_default();
        st.last_seen = now;
        if now.saturating_sub(st.window_start) > FAIL_WINDOW_MS {
            st.fails = 0;
            st.window_start = now;
        }
        st.fails = st.fails.saturating_add(1);
        if st.fails >= MAX_FAILS {
            let lock = (BASE_LOCK_MS << st.strikes.min(7)).min(MAX_LOCK_MS);
            st.strikes = st.strikes.saturating_add(1);
            st.fails = 0;
            st.locked_until = now + lock;
            return Err(lock);
        }
        Ok(())
    }

    fn record_success(&mut self, ip: &str) {
        self.ips.remove(ip);
        if self.trusted.len() < MAX_TRACKED_IPS {
            self.trusted.insert(ip.to_string(), stats::now_ms());
        }
    }
}

pub struct WebState {
    /// token → 过期时间（Unix ms）
    sessions: Mutex<HashMap<String, u64>>,
    /// 登录防爆破状态（per-IP）
    guard: Mutex<LoginGuard>,
    /// 限制并发的 PBKDF2 校验数量。
    login_sem: Arc<tokio::sync::Semaphore>,
    stats: Arc<Stats>,
    manager: Arc<NodeManager>,
    /// 面板端口更新通道：写入新端口后监听器自动重绑定。
    port_tx: Arc<tokio::sync::watch::Sender<u16>>,
}

impl WebState {
    pub fn new(
        stats: Arc<Stats>,
        manager: Arc<NodeManager>,
        port_tx: tokio::sync::watch::Sender<u16>,
    ) -> Arc<Self> {
        Arc::new(Self {
            sessions: Mutex::new(HashMap::new()),
            guard: Mutex::new(LoginGuard::default()),
            login_sem: Arc::new(tokio::sync::Semaphore::new(LOGIN_CONCURRENCY)),
            stats,
            manager,
            port_tx: Arc::new(port_tx),
        })
    }
}

/// 面板主循环。端口被修改（port_rx 收到新值）时 drop 监听器并重新绑定，
/// 进行中的连接在各自任务里自然结束。
pub async fn run(host: String, port_rx: Receiver<u16>, state: Arc<WebState>) -> Result<()> {
    let mut port = *port_rx.borrow();
    loop {
        let bind = format!("{host}:{port}");
        let listener = TcpListener::bind(&bind)
            .await
            .with_context(|| format!("web: cannot bind {bind}"))?;
        tracing::info!("[web] 面板已启动: http://{bind}");

        let mut rebind = port_rx.clone();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let (stream, peer) = accepted?;
                    let state = Arc::clone(&state);
                    tokio::spawn(async move {
                        let io = TokioIo::new(stream);
                        let svc = service_fn(move |req: Request<Incoming>| {
                            let state = Arc::clone(&state);
                            let peer_ip = peer.ip();
                            async move {
                                let mut resp = match handle(req, state, peer_ip).await {
                                    Ok(r) => r,
                                    Err(e) => {
                                        // 详情只进日志，不回显给客户端（避免泄露内部路径 / 结构）。
                                        tracing::warn!("[web] request error: {e:#}");
                                        json_resp(StatusCode::INTERNAL_SERVER_ERROR, json!({"error": format!("{e:#}")}))
                                    }
                                };
                                security_headers(&mut resp);
                                Ok::<_, Infallible>(resp)
                            }
                        });
                        let mut builder = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
                        // slowloris 防护：限时读完请求头。
                        builder
                            .http1()
                            .timer(TokioTimer::new())
                            .header_read_timeout(HEADER_READ_TIMEOUT);
                        let _ = builder.serve_connection(io, svc).await;
                    });
                }
                _ = rebind.changed() => {
                    port = *rebind.borrow();
                    break;
                }
            }
        }
        drop(listener);
    }
}

/// 解析限流/审计用的客户端 IP。
/// 默认使用 TCP 直连地址；仅当设置环境变量 `FLUX_TRUST_PROXY=1`（面板位于
/// 始终覆盖 X-Forwarded-For 的可信反代之后）时才信任该请求头，否则攻击者
/// 可伪造 XFF 绕过登录锁定。
fn trust_proxy() -> bool {
    std::env::var("FLUX_TRUST_PROXY")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// 跨站请求防护（在 SameSite=Lax 之外再加一层）：
/// 状态变更方法若带 `Origin`，其主机必须与请求的 Host 一致；`Sec-Fetch-Site: cross-site` 一律拒绝。
/// 不带 Origin 的非浏览器客户端（curl 等）不受影响，它们本来也拿不到受害者的 cookie。
fn same_origin_ok(req: &Request<Incoming>) -> bool {
    if matches!(*req.method(), hyper::Method::GET | hyper::Method::HEAD | hyper::Method::OPTIONS) {
        return true;
    }
    let h = req.headers();
    if h.get("sec-fetch-site").and_then(|v| v.to_str().ok()) == Some("cross-site") {
        return false;
    }
    let Some(origin) = h.get("origin").and_then(|v| v.to_str().ok()) else {
        return true;
    };
    if origin == "null" {
        return false;
    }
    let origin_host = origin.split_once("://").map(|x| x.1).unwrap_or(origin);
    let fwd = if trust_proxy() {
        h.get("x-forwarded-host").and_then(|v| v.to_str().ok()).and_then(|v| v.split(',').next())
    } else {
        None
    };
    let host = fwd.or_else(|| h.get(hyper::header::HOST).and_then(|v| v.to_str().ok()));
    host.is_some_and(|host| host.trim().eq_ignore_ascii_case(origin_host))
}

/// 统一附加安全响应头。
fn security_headers(resp: &mut Resp) {
    let h = resp.headers_mut();
    for (k, v) in [
        ("X-Content-Type-Options", "nosniff"),
        ("X-Frame-Options", "DENY"),
        ("Referrer-Policy", "no-referrer"),
        ("Content-Security-Policy", "frame-ancestors 'none'; base-uri 'self'; object-src 'none'"),
        ("Cross-Origin-Opener-Policy", "same-origin"),
        ("Cache-Control", "no-store"),
    ] {
        h.insert(k, v.parse().unwrap());
    }
}

/// 限长、限时地读取请求体。
async fn read_body(req: Request<Incoming>, limit: usize) -> std::result::Result<Bytes, Resp> {
    match tokio::time::timeout(BODY_READ_TIMEOUT, Limited::new(req, limit).collect()).await {
        Ok(Ok(c)) => Ok(c.to_bytes()),
        Ok(Err(_)) => Err(json_resp(StatusCode::PAYLOAD_TOO_LARGE, json!({"error": "请求体过大或读取失败"}))),
        Err(_) => Err(json_resp(StatusCode::REQUEST_TIMEOUT, json!({"error": "请求超时"}))),
    }
}

fn client_ip(req: &Request<Incoming>, peer: IpAddr) -> String {
    if trust_proxy() {
        if let Some(xff) = req.headers().get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            if let Some(first) = xff.split(',').next() {
                let t = first.trim();
                if !t.is_empty() {
                    return t.to_string();
                }
            }
        }
    }
    peer.to_string()
}

async fn handle(req: Request<Incoming>, state: Arc<WebState>, peer_ip: IpAddr) -> Result<Resp> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let query = req.uri().query().unwrap_or("").to_string();
    let cookie = req
        .headers()
        .get(COOKIE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    // 限流键与来源校验必须在 collect（消耗 req）之前解析。
    let client_ip = client_ip(&req, peer_ip);
    if !same_origin_ok(&req) {
        tracing::warn!("[web] cross-origin request rejected from {client_ip}: {method} {path}");
        return Ok(json_resp(StatusCode::FORBIDDEN, json!({"error": "forbidden"})));
    }

    // ── 无需鉴权的路由 ──────────────────────────────────────────────────────
    if path == "/login" && method == hyper::Method::GET {
        return Ok(html(StatusCode::OK, LOGIN_HTML, None));
    }
    if path == "/api/login" && method == hyper::Method::POST {
        let body = match read_body(req, LOGIN_BODY_LIMIT).await {
            Ok(b) => b,
            Err(r) => return Ok(r),
        };
        return handle_login(&state, &body, &client_ip).await;
    }

    // 先鉴权再读请求体：未登录者无法让服务器缓冲任意大的数据。
    if !is_authed(&state, &cookie) {
        if path.starts_with("/api/") {
            return Ok(json_resp(
                StatusCode::UNAUTHORIZED,
                json!({"error": "unauthorized"}),
            ));
        }
        return Ok(redirect("/login"));
    }
    let body = match read_body(req, API_BODY_LIMIT).await {
        Ok(b) => b,
        Err(r) => return Ok(r),
    };

    // ── 已鉴权路由 ──────────────────────────────────────────────────────────
    match (method.as_str(), path.as_str()) {
        ("GET", "/") => Ok(html(StatusCode::OK, INDEX_HTML, None)),
        ("POST", "/api/logout") => handle_logout(&state, &cookie),
        ("GET", "/api/summary") => api_summary(&state).await,
        ("GET", "/api/nodes") => api_nodes(&state),
        ("GET", "/api/nodes/detail") => api_nodes_detail(&state),
        ("GET", "/api/traffic") => api_traffic(&state, &query).await,
        ("GET", "/api/connections") => api_connections(&state, &query).await,
        ("GET", "/api/ips") => api_ips(&state, &query).await,
        ("POST", "/api/data/clear") => api_clear(&body).await,

        // ── 节点管理（热重载）─────────────────────────────────────────────
        ("POST", "/api/nodes") => api_node_add(&state, &body).await,
        ("PUT", "/api/nodes") => api_node_update(&state, &body).await,
        ("DELETE", "/api/nodes") => api_node_delete(&state, &query).await,
        ("POST", "/api/nodes/quick") => api_node_quick(&state, &body).await,

        // ── SSL 证书（ACME）────────────────────────────────────────────────
        ("GET", "/api/certs") => api_certs(&state),
        ("POST", "/api/certs") => api_cert_create(&state, &body).await,
        ("POST", "/api/certs/issue") => api_cert_issue(&state, &body).await,
        ("POST", "/api/certs/upload") => api_cert_upload(&state, &query, &body).await,
        ("DELETE", "/api/certs") => api_cert_delete(&state, &query).await,

        // ── 随机凭据生成 & 分享链接导出 ────────────────────────────────
        ("GET", "/api/gen") => api_gen(&state, &query),
        ("GET", "/api/server-ip") => api_server_ip(),
        ("GET", "/api/port-check") => api_port_check(&state, &query),
        ("POST", "/api/export") => api_export(&state, &body),

        // ── 设置 ─────────────────────────────────────────────────────────
        ("GET", "/api/settings") => api_settings_get(&state),
        ("POST", "/api/settings") => api_settings_post(&state, &client_ip, &body).await,

        _ => Ok(json_resp(StatusCode::NOT_FOUND, json!({"error": "not found"}))),
    }
}

// ── 会话 ────────────────────────────────────────────────────────────────────

fn session_token(cookie: &str) -> Option<&str> {
    cookie
        .split(';')
        .map(|s| s.trim())
        .find_map(|s| s.strip_prefix("flux_session="))
        .filter(|s| !s.is_empty())
}

fn is_authed(state: &WebState, cookie: &str) -> bool {
    let Some(token) = session_token(cookie) else { return false };
    let now = stats::now_ms();
    let mut sessions = state.sessions.lock().unwrap();
    sessions.retain(|_, exp| *exp > now);
    sessions.contains_key(token)
}

/// 用于「用户名不存在 / 未设置密码」时仍执行一次完整 PBKDF2，消除计时差异。
fn dummy_hash() -> &'static str {
    static H: OnceLock<String> = OnceLock::new();
    H.get_or_init(|| crypto::hash_password("flux-dummy-password").unwrap_or_default())
}

fn locked_resp(remain_ms: u64, prefix: &str) -> Resp {
    let mins = remain_ms.div_ceil(60_000).max(1);
    json_resp(
        StatusCode::TOO_MANY_REQUESTS,
        json!({"ok": false, "error": format!("{prefix}，请约 {mins} 分钟后再试")}),
    )
}

/// 在 blocking 线程里校验密码（及可选的用户名），受并发信号量约束。
/// 返回 `Ok(None)` 表示排队超时（服务繁忙）。
async fn verify_credentials(
    state: &Arc<WebState>,
    user: Option<String>,
    pass: String,
) -> Result<Option<bool>> {
    let permit = match tokio::time::timeout(
        Duration::from_secs(5),
        Arc::clone(&state.login_sem).acquire_owned(),
    )
    .await
    {
        Ok(Ok(p)) => p,
        _ => return Ok(None),
    };
    let manager = Arc::clone(&state.manager);
    let ok = tokio::task::spawn_blocking(move || -> Result<bool> {
        // 每次都从数据库读取最新凭据：设置页与 `flux set-user/set-password`
        // （另一个进程）的修改都能立即生效。
        let s = manager.panel_settings()?;
        let hash = if s.pass_hash.is_empty() { dummy_hash() } else { s.pass_hash.as_str() };
        // 无论用户名是否匹配，都完整执行 PBKDF2，且不使用短路 &&。
        let pw_ok = crypto::verify_password(&pass, hash) && !s.pass_hash.is_empty();
        let user_ok = user.map_or(true, |u| ct_eq(u.as_bytes(), s.user.as_bytes()));
        Ok(pw_ok & user_ok)
    })
    .await??;
    drop(permit);
    Ok(Some(ok))
}

async fn handle_login(state: &Arc<WebState>, body: &[u8], ip: &str) -> Result<Resp> {
    // 防爆破：锁定期间直接拒绝，不进入密码校验。
    {
        let guard = state.guard.lock().unwrap();
        if let Err(remain_ms) = guard.check(ip) {
            tracing::warn!("[web] login blocked (lockout) from {ip}");
            return Ok(locked_resp(remain_ms, "失败次数过多，登录已被暂时锁定"));
        }
    }

    let v: Value = serde_json::from_slice(body).unwrap_or_default();
    let u = v.get("u").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let p = v.get("p").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let Some(ok) = verify_credentials(state, Some(u), p).await? else {
        return Ok(json_resp(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"ok": false, "error": "服务繁忙，请稍后再试"}),
        ));
    };
    if !ok {
        let verdict = state.guard.lock().unwrap().record_failure(ip);
        tracing::warn!("[web] login failed from {ip}");
        return match verdict {
            Err(remain_ms) => Ok(locked_resp(
                remain_ms,
                &format!("用户名或密码错误。连续失败 {MAX_FAILS} 次，已锁定"),
            )),
            Ok(()) => Ok(json_resp(
                StatusCode::UNAUTHORIZED,
                json!({"ok": false, "error": "用户名或密码错误"}),
            )),
        };
    }
    state.guard.lock().unwrap().record_success(ip);
    tracing::info!("[web] login ok from {ip}");

    let mut raw = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut raw);
    let token = hex::encode(raw);
    state
        .sessions
        .lock()
        .unwrap()
        .insert(token.clone(), stats::now_ms() + SESSION_TTL_MS);

    let cookie = format!(
        "flux_session={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={}{}",
        SESSION_TTL_MS / 1000,
        // HTTPS 部署（如反代终结 TLS）时可设 FLUX_SECURE_COOKIE=1 启用 Secure。
        if secure_cookie() { "; Secure" } else { "" },
    );
    tracing::info!("[web] login ok from {ip}");
    Ok(html(
        StatusCode::OK,
        "{\"ok\":true}",
        Some((CONTENT_TYPE, "application/json; charset=utf-8")),
    )
    .with_cookie(&cookie))
}

/// HTTPS 部署时给会话 cookie 加 `Secure` 属性（默认关闭，兼容纯 HTTP 面板）。
fn secure_cookie() -> bool {
    std::env::var("FLUX_SECURE_COOKIE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn handle_logout(state: &WebState, cookie: &str) -> Result<Resp> {
    if let Some(token) = session_token(cookie) {
        state.sessions.lock().unwrap().remove(token);
    }
    Ok(Resp::new(Full::new(Bytes::from("{\"ok\":true}"))).with_cookie(&format!(
        "flux_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0{}",
        if secure_cookie() { "; Secure" } else { "" },
    )))
}

/// 常数时间字节串比较：长度不等也走完全部循环，不提前返回，
/// 避免通过响应时间差异推断用户名/Token 长度。
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = (a.len() ^ b.len()) as u64;
    let n = a.len().max(b.len());
    for i in 0..n {
        let x = a.get(i).copied().unwrap_or(0u8) as u64;
        let y = b.get(i).copied().unwrap_or(0u8) as u64;
        diff |= x ^ y;
    }
    diff == 0
}

// ── 只读 API ────────────────────────────────────────────────────────────────

async fn api_summary(state: &Arc<WebState>) -> Result<Resp> {
    let s = &state.stats;
    let snapshot = s.nodes.read().unwrap().clone();
    let nodes_online = snapshot
        .iter()
        .filter(|n| n.active.load(Ordering::Relaxed) > 0)
        .count();
    let active_conn: i64 = snapshot
        .iter()
        .map(|n| n.active.load(Ordering::Relaxed).max(0))
        .sum();
    let now_bucket = stats::hour_bucket(stats::now_ms());
    let db = Arc::clone(&s.db);
    let (ips, last24_up, last24_down) = tokio::task::spawn_blocking(move || {
        let (u, d) = db.sum_hours(now_bucket.saturating_sub(24))?;
        Ok::<_, anyhow::Error>((db.ip_count()?, u, d))
    })
    .await??;

    Ok(json_resp(
        StatusCode::OK,
        json!({
            "started_ms": s.started_ms,
            "nodes_total": snapshot.len(),
            "nodes_online": nodes_online,
            "active_conn": active_conn,
            "total_up": s.total_up.load(Ordering::Relaxed),
            "total_down": s.total_down.load(Ordering::Relaxed),
            "total_conns": s.total_conns.load(Ordering::Relaxed),
            "last24_up": last24_up,
            "last24_down": last24_down,
            "unique_ips": ips,
        }),
    ))
}

fn api_nodes(state: &Arc<WebState>) -> Result<Resp> {
    let snapshot = state.stats.nodes.read().unwrap().clone();
    let list: Vec<Value> = snapshot
        .iter()
        .map(|n| {
            let active = n.active.load(Ordering::Relaxed).max(0);
            json!({
                "name": n.info.name,
                "proto": n.info.proto,
                "listen": n.info.listen,
                "port": n.info.port,
                "active": active,
                "online": active > 0,
                "total_conn": n.total_conn.load(Ordering::Relaxed),
                "last_conn_ms": n.last_conn_ms.load(Ordering::Relaxed),
                "up": n.up.load(Ordering::Relaxed),
                "down": n.down.load(Ordering::Relaxed),
            })
        })
        .collect();
    Ok(json_resp(StatusCode::OK, json!(list)))
}

fn api_nodes_detail(state: &Arc<WebState>) -> Result<Resp> {
    Ok(json_resp(StatusCode::OK, json!(state.manager.list_details())))
}

async fn api_traffic(state: &Arc<WebState>, query: &str) -> Result<Resp> {
    let range = query_param(query, "range").unwrap_or_else(|| "24h".to_string());
    let db = Arc::clone(&state.stats.db);
    let range_for_task = range.clone();
    let points = tokio::task::spawn_blocking(move || -> Result<Vec<stats::db::SeriesPoint>> {
        match range_for_task.as_str() {
            "month" => db.month_series(),
            "30d" => db.hour_series(stats::hour_bucket(stats::now_ms()).saturating_sub(720)),
            _ => db.hour_series(stats::hour_bucket(stats::now_ms()).saturating_sub(24)),
        }
    })
    .await??;
    Ok(json_resp(StatusCode::OK, json!({ "range": range, "points": points })))
}

async fn api_connections(state: &Arc<WebState>, query: &str) -> Result<Resp> {
    let limit = query_param(query, "limit")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(50)
        .min(500);
    let db = Arc::clone(&state.stats.db);
    let rows = tokio::task::spawn_blocking(move || db.list_connections(limit)).await??;
    Ok(json_resp(StatusCode::OK, json!(rows)))
}

async fn api_ips(state: &Arc<WebState>, query: &str) -> Result<Resp> {
    let limit = query_param(query, "limit")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(100)
        .min(1000);
    let db = Arc::clone(&state.stats.db);
    let rows = tokio::task::spawn_blocking(move || db.list_ips(limit)).await??;
    Ok(json_resp(StatusCode::OK, json!(rows)))
}

async fn api_clear(body: &[u8]) -> Result<Resp> {
    let v: Value = serde_json::from_slice(body).unwrap_or_default();
    let all = v.get("all").and_then(|x| x.as_bool()).unwrap_or(false);
    let month = if all {
        None
    } else {
        v.get("month")
            .and_then(|x| x.as_u64())
            .map(|x| x as u32)
            .context("missing `month`")?
            .into()
    };
    stats::clear_data(month).await?;
    Ok(json_resp(StatusCode::OK, json!({"ok": true})))
}

// ── 节点管理 API ────────────────────────────────────────────────────────────

async fn api_node_add(state: &Arc<WebState>, body: &[u8]) -> Result<Resp> {
    let v: Value = serde_json::from_slice(body).context("invalid json")?;
    match state.manager.add_node(v).await {
        Ok(r) => Ok(json_resp(StatusCode::OK, r)),
        Err(e) => Ok(json_resp(StatusCode::BAD_REQUEST, json!({"error": format!("{e:#}")}))),
    }
}

async fn api_node_update(state: &Arc<WebState>, body: &[u8]) -> Result<Resp> {
    let mut v: Value = serde_json::from_slice(body).context("invalid json")?;
    let old_name = v.get("_old_name").and_then(|x| x.as_str())
        .context("missing `_old_name`")?.to_string();
    // `_old_name` 只是路由辅助字段，不能进入节点配置（否则被判为未知字段）。
    if let Some(obj) = v.as_object_mut() {
        obj.remove("_old_name");
    }
    match state.manager.update_node(&old_name, v).await {
        Ok(r) => Ok(json_resp(StatusCode::OK, r)),
        Err(e) => Ok(json_resp(StatusCode::BAD_REQUEST, json!({"error": format!("{e:#}")}))),
    }
}

async fn api_node_delete(state: &Arc<WebState>, query: &str) -> Result<Resp> {
    let name = query_param(query, "name").context("missing `name`")?;
    match state.manager.delete_node(&name).await {
        Ok(r) => Ok(json_resp(StatusCode::OK, r)),
        Err(e) => Ok(json_resp(StatusCode::BAD_REQUEST, json!({"error": format!("{e:#}")}))),
    }
}

// ── SSL 证书 API ────────────────────────────────────────────────────────────

fn api_certs(state: &Arc<WebState>) -> Result<Resp> {
    match state.manager.list_certs() {
        Ok(list) => Ok(json_resp(StatusCode::OK, json!(list))),
        Err(e) => Ok(json_resp(StatusCode::INTERNAL_SERVER_ERROR, json!({"error": format!("{e:#}")}))),
    }
}

/// 新建证书记录并启动后台申请（DNS 传播 + ACME 轮询约需 1~2 分钟，
/// 前端轮询 GET /api/certs 观察状态）。
/// body = { domains: [..] | "domain,domain", email, cf-token, zone-id?, auto-renew }
async fn api_cert_create(state: &Arc<WebState>, body: &[u8]) -> Result<Resp> {
    let v: Value = serde_json::from_slice(body).context("invalid json")?;
    let domains: Vec<String> = match v.get("domains") {
        Some(Value::Array(a)) => a
            .iter()
            .filter_map(|x| x.as_str())
            .map(|s| s.to_string())
            .collect(),
        Some(Value::String(s)) => s
            .split(',')
            .map(|x| x.trim().to_string())
            .filter(|x| !x.is_empty())
            .collect(),
        _ => Vec::new(),
    };
    let email = v.get("email").and_then(|x| x.as_str()).unwrap_or("");
    let token = v.get("cf-token").and_then(|x| x.as_str()).unwrap_or("");
    let zone = v.get("zone-id").and_then(|x| x.as_str()).unwrap_or("");
    let auto_renew = v.get("auto-renew").and_then(|x| x.as_bool()).unwrap_or(true);
    match state.manager.create_cert(domains, email, token, zone, auto_renew) {
        Ok(id) => Ok(json_resp(StatusCode::OK, json!({"ok": true, "id": id}))),
        Err(e) => Ok(json_resp(StatusCode::BAD_REQUEST, json!({"error": format!("{e:#}")}))),
    }
}

/// 上传证书压缩包：body = zip 原始字节（Content-Type: application/octet-stream）。
/// 可选 `?id=<已上传证书 id>` 表示替换更新（节点引用保持不变并热重载）。
async fn api_cert_upload(state: &Arc<WebState>, query: &str, body: &[u8]) -> Result<Resp> {
    if body.is_empty() {
        return Ok(json_resp(StatusCode::BAD_REQUEST, json!({"error": "未收到文件"})));
    }
    let replace = query_param(query, "id");
    match state.manager.import_cert(body, replace.as_deref()) {
        Ok(id) => Ok(json_resp(StatusCode::OK, json!({"ok": true, "id": id}))),
        Err(e) => Ok(json_resp(StatusCode::BAD_REQUEST, json!({"error": format!("{e:#}")}))),
    }
}

/// 重新申请/续签：body = { id }
async fn api_cert_issue(state: &Arc<WebState>, body: &[u8]) -> Result<Resp> {
    let v: Value = serde_json::from_slice(body).context("invalid json")?;
    let id = v.get("id").and_then(|x| x.as_str()).context("missing `id`")?;
    match state.manager.reissue_cert(id) {
        Ok(()) => Ok(json_resp(StatusCode::OK, json!({"ok": true}))),
        Err(e) => Ok(json_resp(StatusCode::BAD_REQUEST, json!({"error": format!("{e:#}")}))),
    }
}

/// 删除证书：query = ?id=
async fn api_cert_delete(state: &Arc<WebState>, query: &str) -> Result<Resp> {
    let id = query_param(query, "id").context("missing `id`")?;
    match state.manager.delete_cert(&id) {
        Ok(()) => Ok(json_resp(StatusCode::OK, json!({"ok": true}))),
        Err(e) => Ok(json_resp(StatusCode::BAD_REQUEST, json!({"error": format!("{e:#}")}))),
    }
}

// ── 随机凭据生成 & 分享链接导出 ──────────────────────────────────────────────
fn api_gen(_state: &Arc<WebState>, query: &str) -> Result<Resp> {
    let kind = query_param(query, "kind").unwrap_or_default();
    let result = match kind.as_str() {
        "uuid" => json!({ "value": config::gen_uuid() }),
        "password" => json!({ "value": config::gen_password(16) }),
        "ss" => json!({ "value": config::gen_ss_password() }),
        "shortid" => {
            let (_, sid) = config::gen_reality();
            json!({ "value": sid })
        }
        "reality-key" => {
            let (priv_key, sid) = config::gen_reality();
            json!({ "value": priv_key, "extra": sid })
        }
        "wg-key" => {
            let priv_key = config::gen_wireguard_private();
            let pub_key = config::wireguard_public_key(&priv_key)?;
            json!({ "value": priv_key, "extra": pub_key })
        }
        "wgpub" => {
            // 为 peer 生成一个随机的合法 X25519 公钥。
            let priv_key = config::gen_wireguard_private();
            let pub_key = config::wireguard_public_key(&priv_key)?;
            json!({ "value": pub_key })
        }
        "domain" => json!({ "value": config::random_self_signed_domain() }),
        other => {
            return Ok(json_resp(
                StatusCode::BAD_REQUEST,
                json!({"error": format!("unknown gen kind `{other}`")}),
            ))
        }
    };
    Ok(json_resp(StatusCode::OK, result))
}

/// 检测服务器对外 IP：`GET /api/server-ip` → { "ip": "..." }
/// 优先级：公网 IPv4 → 公网 IPv6 → 内网 IPv4 → 内网 IPv6。
fn api_server_ip() -> Result<Resp> {
    let ip = config::detect_server_ip();
    Ok(json_resp(
        StatusCode::OK,
        json!({ "ip": ip }),
    ))
}

/// 端口占用预检（保存节点前调用）：`GET /api/port-check?port=443&type=vless&exclude=name`
/// 返回 `{ "ok": true }` 或 `{ "ok": false, "error": "..." }`。
/// 按协议传输层区分 TCP/UDP：同一端口的 TCP 与 UDP 互不冲突。
fn api_port_check(state: &Arc<WebState>, query: &str) -> Result<Resp> {
    let port = match query_param(query, "port").and_then(|s| s.parse::<u16>().ok()) {
        Some(p) if p != 0 => p,
        _ => {
            return Ok(json_resp(
                StatusCode::BAD_REQUEST,
                json!({ "ok": false, "error": "请填写有效端口（1-65535）" }),
            ))
        }
    };
    let kind = query_param(query, "type").unwrap_or_default();
    let Some(layer) = config::layer_of_type(&kind) else {
        return Ok(json_resp(
            StatusCode::BAD_REQUEST,
            json!({ "ok": false, "error": format!("未知协议 `{kind}`") }),
        ));
    };
    let exclude = query_param(query, "exclude").filter(|s| !s.is_empty());
    // 用一个临时占位名仅为满足接口签名（错误信息里的 name 不会被前端使用）。
    let check_name = exclude.as_deref().unwrap_or("该节点");
    match state
        .manager
        .check_port_available(check_name, port, layer, exclude.as_deref())
    {
        Ok(()) => Ok(json_resp(StatusCode::OK, json!({ "ok": true }))),
        Err(e) => Ok(json_resp(
            StatusCode::OK,
            json!({ "ok": false, "error": format!("{e:#}") }),
        )),
    }
}

/// 导出分享链接：`POST /api/export` body = { name, host }
/// 按节点原始声明拼出客户端通用 URI；host 为客户端连接的对外域名/IP。
fn api_export(state: &Arc<WebState>, body: &[u8]) -> Result<Resp> {
    let v: Value = serde_json::from_slice(body).context("invalid json")?;
    let name = v.get("name").and_then(|x| x.as_str()).context("missing `name`")?;
    let host = v.get("host").and_then(|x| x.as_str()).unwrap_or("");
    let details = state.manager.list_details();
    let mut node = details
        .iter()
        .find(|n| n.get("name").and_then(|x| x.as_str()) == Some(name))
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("node `{name}` not found"))?;
    // cert-ref 引用的证书：解析出 cert-domain（分享链接的 SNI）。
    let _ = state.manager.resolve_cert_ref(&mut node);
    match crate::share_link::build(&node, host) {
        Ok(link) => Ok(json_resp(StatusCode::OK, json!({ "link": link }))),
        Err(e) => Ok(json_resp(
            StatusCode::BAD_REQUEST,
            json!({"error": format!("{e:#}")}),
        )),
    }
}

/// 一键配置：body = { protocols: [{ type, transport?, tls?, ... }], port? }
/// 为每个选中的协议生成带随机凭据的节点并立即部署。
async fn api_node_quick(state: &Arc<WebState>, body: &[u8]) -> Result<Resp> {
    let v: Value = serde_json::from_slice(body).context("invalid json")?;
    let protocols = v.get("protocols").and_then(|x| x.as_array())
        .context("missing `protocols` array")?;
    let base_port = v.get("port").and_then(|x| x.as_u64()).unwrap_or(443) as u16;

    // 按传输层分别维护"已占用端口"：配置里已用的 + 本轮刚分配的。
    // 这样 TCP 层占用不阻碍 UDP 节点使用同一端口，反之亦然。
    let mut used_tcp = state.manager.used_ports_by_layer(config::NetLayer::Tcp);
    let mut used_udp = state.manager.used_ports_by_layer(config::NetLayer::Udp);
    let mut next_port = base_port;
    let mut created = Vec::new();
    let mut errors = Vec::new();

    for p in protocols.iter() {
        let kind = p.get("type").and_then(|x| x.as_str()).unwrap_or("");
        let transport = p.get("transport").and_then(|x| x.as_str()).unwrap_or("tcp");
        let tls = p.get("tls").and_then(|x| x.as_str()).unwrap_or("selfsigned");
        let layer = config::layer_of_type(kind).unwrap_or(config::NetLayer::Tcp);
        // 找一个该传输层上真正空闲的端口：跳过配置已用、系统该层已占用、本轮已分配。
        let mut candidate = next_port;
        loop {
            if candidate == 0 || candidate == u16::MAX {
                candidate = 1024;
            }
            let used = match layer {
                config::NetLayer::Tcp => &used_tcp,
                config::NetLayer::Udp => &used_udp,
            };
            if !used.contains(&candidate)
                && !crate::node_manager::NodeManager::port_in_use_layer(candidate, layer)
            {
                break;
            }
            candidate = candidate.saturating_add(1);
        }
        // 本轮分配占位，避免后续同层协议选到同一端口。
        match layer {
            config::NetLayer::Tcp => {
                used_tcp.insert(candidate);
            }
            config::NetLayer::Udp => {
                used_udp.insert(candidate);
            }
        }
        next_port = candidate.saturating_add(1);
        let name = format!("{kind}-{candidate}");
        let node = match generate_quick_node(&name, kind, candidate, transport, tls) {
            Ok(n) => n,
            Err(e) => {
                errors.push(format!("{kind}: {e:#}"));
                continue;
            }
        };
        match state.manager.add_node(node).await {
            Ok(_) => created.push(name),
            Err(e) => errors.push(format!("{kind}: {e:#}")),
        }
    }

    Ok(json_resp(StatusCode::OK, json!({
        "ok": errors.is_empty(),
        "created": created,
        "errors": errors,
    })))
}

// ── 设置 API ────────────────────────────────────────────────────────────────

fn api_settings_get(state: &Arc<WebState>) -> Result<Resp> {
    let s = state.manager.panel_settings()?;
    Ok(json_resp(StatusCode::OK, json!({
        "user": s.user,
        "port": s.port,
    })))
}

/// 设置页保存：`u`（用户名）、`p`（新密码，留空不改）、`port`（面板端口）。
/// 任意修改成功后清除全部会话；端口变化时通知监听器重绑定。
async fn api_settings_post(state: &Arc<WebState>, ip: &str, body: &[u8]) -> Result<Resp> {
    let v: Value = serde_json::from_slice(body).context("invalid json")?;

    // 修改任何设置都必须提供当前密码：会话被盗（XSS / 共用电脑）也无法直接改密码锁死管理员。
    // 失败同样计入防爆破。
    {
        let guard = state.guard.lock().unwrap();
        if let Err(remain_ms) = guard.check(ip) {
            return Ok(locked_resp(remain_ms, "失败次数过多，已被暂时锁定"));
        }
    }
    let cur = v.get("cur").and_then(|x| x.as_str()).unwrap_or("").to_string();
    match verify_credentials(state, None, cur).await? {
        Some(true) => {}
        Some(false) => {
            let verdict = state.guard.lock().unwrap().record_failure(ip);
            tracing::warn!("[web] settings: wrong current password from {ip}");
            return Ok(match verdict {
                Err(remain_ms) => locked_resp(remain_ms, "当前密码错误次数过多，已被暂时锁定"),
                Ok(()) => json_resp(StatusCode::FORBIDDEN, json!({"error": "当前密码不正确"})),
            });
        }
        None => {
            return Ok(json_resp(
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"error": "服务繁忙，请稍后再试"}),
            ))
        }
    }

    if let Some(u) = v.get("u").and_then(|x| x.as_str()).filter(|s| !s.is_empty()) {
        state.manager.set_user(u)?;
    }
    if let Some(p) = v.get("p").and_then(|x| x.as_str()).filter(|s| !s.is_empty()) {
        state.manager.set_password(p)?;
    }
    let mut port_changed = false;
    if let Some(port) = v.get("port").and_then(|x| x.as_u64()) {
        let port = u16::try_from(port).map_err(|_| anyhow::anyhow!("端口超出范围（1-65535）"))?;
        let new_port = state.manager.set_port(port)?;
        if new_port != *state.port_tx.borrow() {
            state
                .port_tx
                .send(new_port)
                .map_err(|_| anyhow::anyhow!("web listener stopped"))?;
            port_changed = true;
        }
    }

    // 有改动即让所有会话失效，强制重新登录。
    state.sessions.lock().unwrap().clear();
    Ok(json_resp(
        StatusCode::OK,
        json!({"ok": true, "relogin": true, "port_changed": port_changed}),
    ))
}

// ── 一键配置节点生成器 ──────────────────────────────────────────────────────

/// 依据协议类型生成一份完整的节点 JSON（kebab-case 字段），凭据随机。
/// tls: "none" | "selfsigned"（默认，随机大厂域名自签）| "reality"（仅 vless）。
fn generate_quick_node(
    name: &str,
    kind: &str,
    port: u16,
    transport: &str,
    tls: &str,
) -> Result<Value> {
    // 无序 map 即可；serde_json 序列化后由 serde_yaml 一致处理。
    let mut n = json!({ "name": name, "type": kind, "port": port });
    let obj = n.as_object_mut().unwrap();

    // 自签证书：随机大厂域名，让程序自动生成证书（绝不空着 TLS）。
    let self_signed = || config::random_self_signed_domain();
    let tls_mode = if tls == "reality" && kind == "vless" { "reality" } else { tls };

    match kind {
        "hysteria2" => {
            obj.insert("password".into(), json!(config::gen_password(16)));
            if tls_mode != "none" {
                obj.insert("self-signed-domain".into(), json!(self_signed()));
            }
        }
        "vless" => {
            obj.insert("uuid".into(), json!(config::gen_uuid()));
            obj.insert("transport".into(), json!(transport));
            if tls_mode == "reality" {
                let (priv_key, sid) = config::gen_reality();
                let domain = self_signed();
                obj.insert("reality-private-key".into(), json!(priv_key));
                obj.insert("reality-short-ids".into(), json!([sid]));
                obj.insert("reality-dest".into(), json!(format!("{domain}:443")));
                obj.insert("reality-server-name".into(), json!(domain));
            } else if tls_mode != "none" {
                obj.insert("self-signed-domain".into(), json!(self_signed()));
            }
        }
        "vmess" => {
            obj.insert("uuid".into(), json!(config::gen_uuid()));
            obj.insert("transport".into(), json!(transport));
            if tls_mode != "none" {
                obj.insert("self-signed-domain".into(), json!(self_signed()));
            }
        }
        "trojan" => {
            obj.insert("password".into(), json!(config::gen_password(16)));
            obj.insert("transport".into(), json!(transport));
            if tls_mode != "none" {
                obj.insert("self-signed-domain".into(), json!(self_signed()));
            }
        }
        "shadowsocks" => {
            obj.insert("password".into(), json!(config::gen_ss_password()));
            obj.insert("method".into(), json!("2022-blake3-aes-256-gcm"));
            obj.insert("transport".into(), json!(transport));
            if tls_mode != "none" {
                obj.insert("self-signed-domain".into(), json!(self_signed()));
            }
        }
        "tuic" => {
            obj.insert("users".into(), json!([{
                "uuid": config::gen_uuid(),
                "password": config::gen_password(16),
            }]));
            if tls_mode != "none" {
                obj.insert("self-signed-domain".into(), json!(self_signed()));
            }
        }
        "anytls" => {
            obj.insert("password".into(), json!(config::gen_password(16)));
            if tls_mode != "none" {
                obj.insert("self-signed-domain".into(), json!(self_signed()));
            }
        }
        "socks" => {
            obj.insert("users".into(), json!([{
                "username": config::gen_password(8),
                "password": config::gen_password(16),
            }]));
        }
        "http" => {
            obj.insert("users".into(), json!([{
                "username": config::gen_password(8),
                "password": config::gen_password(16),
            }]));
            if tls_mode != "none" {
                obj.insert("self-signed-domain".into(), json!(self_signed()));
            }
        }
        "naiveproxy" => {
            obj.insert("users".into(), json!([{
                "username": config::gen_password(8),
                "password": config::gen_password(16),
            }]));
            obj.insert("self-signed-domain".into(), json!(self_signed()));
        }
        "shadowquic" => {
            let domain = self_signed();
            obj.insert("jls-upstream".into(), json!(format!("{domain}:443")));
            obj.insert("server-name".into(), json!(domain));
            obj.insert("users".into(), json!([{
                "username": config::gen_password(8),
                "password": config::gen_password(16),
            }]));
        }
        "spectre" => {
            let domain = self_signed();
            obj.insert("password".into(), json!(config::gen_password(16)));
            obj.insert("server-name".into(), json!(domain));
            obj.insert("upstream".into(), json!(format!("{domain}:443")));
        }
        "wireguard" => {
            obj.insert("private-key".into(), json!(config::gen_wireguard_private()));
            obj.insert("server-address".into(), json!(["10.0.0.1/24"]));
            obj.insert("mtu".into(), json!(1420));
            obj.insert("peers".into(), json!([]));
        }
        other => anyhow::bail!("unknown protocol `{other}`"),
    }
    Ok(n)
}

// ── 响应工具 ────────────────────────────────────────────────────────────────

trait WithCookie {
    fn with_cookie(self, value: &str) -> Self;
}
impl WithCookie for Resp {
    fn with_cookie(mut self, value: &str) -> Self {
        self.headers_mut().insert(SET_COOKIE, value.parse().unwrap());
        self
    }
}

fn html(status: StatusCode, body: &str, content_type: Option<(hyper::header::HeaderName, &str)>) -> Resp {
    let (name, value) = content_type.unwrap_or((CONTENT_TYPE, "text/html; charset=utf-8"));
    Response::builder()
        .status(status)
        .header(name, value)
        .header("Cache-Control", "no-store")
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap()
}

fn json_resp<T: Serialize>(status: StatusCode, value: T) -> Resp {
    let body = serde_json::to_string(&value).unwrap_or_else(|_| "{}".to_string());
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/json; charset=utf-8")
        .header("Cache-Control", "no-store")
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

fn redirect(location: &str) -> Resp {
    Response::builder()
        .status(StatusCode::FOUND)
        .header(LOCATION, location)
        .header("Cache-Control", "no-store")
        .body(Full::new(Bytes::new()))
        .unwrap()
}

fn query_param(query: &str, key: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=')?;
        (k == key).then(|| v.to_string())
    })
}

#[cfg(test)]
mod guard_tests {
    use super::*;

    #[test]
    fn per_ip_lock_escalates() {
        let mut g = LoginGuard::default();
        for _ in 0..MAX_FAILS - 1 {
            assert!(g.record_failure("1.1.1.1").is_ok());
        }
        assert_eq!(g.record_failure("1.1.1.1"), Err(BASE_LOCK_MS));
        assert!(g.check("1.1.1.1").is_err());
        assert!(g.check("2.2.2.2").is_ok());
        // 模拟锁定到期后再次失败：锁定时长翻倍
        g.ips.get_mut("1.1.1.1").unwrap().locked_until = 0;
        for _ in 0..MAX_FAILS - 1 {
            assert!(g.record_failure("1.1.1.1").is_ok());
        }
        assert_eq!(g.record_failure("1.1.1.1"), Err(BASE_LOCK_MS * 2));
    }

    #[test]
    fn global_lock_exempts_trusted_ips() {
        let mut g = LoginGuard::default();
        g.record_success("9.9.9.9");
        for i in 0..GLOBAL_MAX_FAILS {
            let _ = g.record_failure(&format!("10.0.{}.{}", i / 250, i % 250));
        }
        assert!(g.check("8.8.8.8").is_err(), "陌生 IP 应被全局冷却拒绝");
        assert!(g.check("9.9.9.9").is_ok(), "近期成功登录过的 IP 不受影响");
    }
}

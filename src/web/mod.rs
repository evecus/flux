//! Web 面板：hyper 1.x 手写路由 + 登录页 + HttpOnly Cookie 会话。
//!
//! 只有 `web: true` 时本模块才会被启动。所有页面与 API 都要求会话，
//! 未登录访问 `/` 会 302 到 `/login`，未登录调用 API 返回 401。

use anyhow::{Context, Result};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::{CONTENT_TYPE, COOKIE, LOCATION, SET_COOKIE};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde::Serialize;
use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;

use crate::stats::{self, Stats};

const LOGIN_HTML: &str = include_str!("login.html");
const INDEX_HTML: &str = include_str!("index.html");
const SESSION_TTL_MS: u64 = 24 * 3600 * 1000;

type Resp = Response<Full<Bytes>>;

struct WebState {
    user: String,
    pass: String,
    /// token → 过期时间（Unix ms）
    sessions: Mutex<HashMap<String, u64>>,
    stats: Arc<Stats>,
}

pub async fn run(bind: &str, user: String, pass: String, stats: Arc<Stats>) -> Result<()> {
    let listener = TcpListener::bind(bind)
        .await
        .with_context(|| format!("web: cannot bind {bind}"))?;
    tracing::info!("[web] 面板已启动: http://{bind}");

    let state = Arc::new(WebState {
        user,
        pass,
        sessions: Mutex::new(HashMap::new()),
        stats,
    });

    loop {
        let (stream, _peer) = listener.accept().await?;
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let svc = service_fn(move |req: Request<Incoming>| {
                let state = Arc::clone(&state);
                async move {
                    let resp = match handle(req, state).await {
                        Ok(r) => r,
                        Err(e) => {
                            tracing::warn!("[web] request error: {e:#}");
                            json_resp(StatusCode::INTERNAL_SERVER_ERROR, serde_json::json!({"error": "internal error"}))
                        }
                    };
                    Ok::<_, Infallible>(resp)
                }
            });
            let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                .serve_connection(io, svc)
                .await;
        });
    }
}

async fn handle(req: Request<Incoming>, state: Arc<WebState>) -> Result<Resp> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let query = req.uri().query().unwrap_or("").to_string();
    let cookie = req
        .headers()
        .get(COOKIE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let body = req.collect().await?.to_bytes();

    // ── 无需鉴权的路由 ──────────────────────────────────────────────────────
    if path == "/login" && method == hyper::Method::GET {
        return Ok(html(StatusCode::OK, LOGIN_HTML, None));
    }
    if path == "/api/login" && method == hyper::Method::POST {
        return handle_login(&state, &body);
    }

    if !is_authed(&state, &cookie) {
        if path.starts_with("/api/") {
            return Ok(json_resp(
                StatusCode::UNAUTHORIZED,
                serde_json::json!({"error": "unauthorized"}),
            ));
        }
        return Ok(redirect("/login"));
    }

    // ── 已鉴权路由 ──────────────────────────────────────────────────────────
    match (method.as_str(), path.as_str()) {
        ("GET", "/") => Ok(html(StatusCode::OK, INDEX_HTML, None)),
        ("POST", "/api/logout") => handle_logout(&state, &cookie),
        ("GET", "/api/summary") => api_summary(&state).await,
        ("GET", "/api/nodes") => api_nodes(&state),
        ("GET", "/api/traffic") => api_traffic(&state, &query).await,
        ("GET", "/api/connections") => api_connections(&state, &query).await,
        ("GET", "/api/ips") => api_ips(&state, &query).await,
        ("POST", "/api/data/clear") => api_clear(&body).await,
        _ => Ok(json_resp(StatusCode::NOT_FOUND, serde_json::json!({"error": "not found"}))),
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

fn handle_login(state: &WebState, body: &[u8]) -> Result<Resp> {
    let v: serde_json::Value = serde_json::from_slice(body).unwrap_or_default();
    let u = v.get("u").and_then(|x| x.as_str()).unwrap_or("");
    let p = v.get("p").and_then(|x| x.as_str()).unwrap_or("");
    if !ct_eq(u.as_bytes(), state.user.as_bytes()) || !ct_eq(p.as_bytes(), state.pass.as_bytes()) {
        return Ok(json_resp(StatusCode::UNAUTHORIZED, serde_json::json!({"ok": false, "error": "用户名或密码错误"})));
    }

    let mut raw = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut raw);
    let token = hex::encode(raw);
    state
        .sessions
        .lock()
        .unwrap()
        .insert(token.clone(), stats::now_ms() + SESSION_TTL_MS);

    let cookie = format!(
        "flux_session={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={}",
        SESSION_TTL_MS / 1000
    );
    Ok(html(
        StatusCode::OK,
        "{\"ok\":true}",
        Some((CONTENT_TYPE, "application/json; charset=utf-8")),
    )
    .with_cookie(&cookie))
}

fn handle_logout(state: &WebState, cookie: &str) -> Result<Resp> {
    if let Some(token) = session_token(cookie) {
        state.sessions.lock().unwrap().remove(token);
    }
    Ok(Resp::new(Full::new(Bytes::from("{\"ok\":true}"))).with_cookie(
        "flux_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0",
    ))
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ── API ─────────────────────────────────────────────────────────────────────

async fn api_summary(state: &Arc<WebState>) -> Result<Resp> {
    let s = &state.stats;
    let nodes_online = s
        .nodes
        .iter()
        .filter(|n| n.active.load(Ordering::Relaxed) > 0)
        .count();
    let active_conn: i64 = s
        .nodes
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
        serde_json::json!({
            "started_ms": s.started_ms,
            "nodes_total": s.nodes.len(),
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
    let list: Vec<serde_json::Value> = state
        .stats
        .nodes
        .iter()
        .map(|n| {
            let active = n.active.load(Ordering::Relaxed).max(0);
            serde_json::json!({
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
    Ok(json_resp(StatusCode::OK, serde_json::json!(list)))
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
    Ok(json_resp(StatusCode::OK, serde_json::json!({ "range": range, "points": points })))
}

async fn api_connections(state: &Arc<WebState>, query: &str) -> Result<Resp> {
    let limit = query_param(query, "limit")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(50)
        .min(500);
    let db = Arc::clone(&state.stats.db);
    let rows = tokio::task::spawn_blocking(move || db.list_connections(limit)).await??;
    Ok(json_resp(StatusCode::OK, serde_json::json!(rows)))
}

async fn api_ips(state: &Arc<WebState>, query: &str) -> Result<Resp> {
    let limit = query_param(query, "limit")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(100)
        .min(1000);
    let db = Arc::clone(&state.stats.db);
    let rows = tokio::task::spawn_blocking(move || db.list_ips(limit)).await??;
    Ok(json_resp(StatusCode::OK, serde_json::json!(rows)))
}

async fn api_clear(body: &[u8]) -> Result<Resp> {
    let v: serde_json::Value = serde_json::from_slice(body).unwrap_or_default();
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
    Ok(json_resp(StatusCode::OK, serde_json::json!({"ok": true})))
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

//! 全局统计收集器。
//!
//! 设计要点：
//! * 只有 `web: true` 时才会调用 [`init`]，未初始化时所有埋点函数直接返回，
//!   热路径上仅一次 `OnceLock::get()`，不触碰磁盘、不分配堆内存。
//! * 节点通过 `(协议, listen, port)` 定位，避免改动 13 个协议的配置结构体。
//! * 连接用 RAII guard 维护「活跃连接数」，Arc 引用归零时上报一条连接记录。
//! * 流量只累加到无锁原子计数器，由后台任务定时批量落盘（redb 是同步 API）。

pub mod db;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;

static STATS: OnceLock<Arc<Stats>> = OnceLock::new();

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

pub fn hour_bucket(ms: u64) -> u64 {
    ms / 3_600_000
}

/// Unix 毫秒 → `YYYYMM`（纯整数算法，避免引入 chrono）。
pub fn month_bucket(ms: u64) -> u32 {
    let days = (ms / 1000 / 86400) as i64;
    let (year, month, _) = civil_from_days(days);
    (year as u32) * 100 + month
}

/// Howard Hinnant 的 civil_from_days（UTC）。
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    (y + if m <= 2 { 1 } else { 0 }, m as u32, d as u32)
}

// ── 数据结构 ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct NodeInfo {
    pub name: String,
    pub proto: String,
    pub listen: String,
    pub port: u16,
}

pub struct NodeRuntime {
    pub info: NodeInfo,
    pub active: AtomicI64,
    pub total_conn: AtomicU64,
    pub up: AtomicU64,
    pub down: AtomicU64,
    pub last_conn_ms: AtomicU64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnRecord {
    pub ts_ms: u64,
    pub node: String,
    pub proto: String,
    pub ip: String,
    pub target: String,
    pub duration_ms: u64,
}

pub struct Stats {
    pub nodes: Vec<NodeRuntime>,
    pub started_ms: u64,
    pub db: Arc<db::Db>,
    pub total_up: AtomicU64,
    pub total_down: AtomicU64,
    pub total_conns: AtomicU64,
    /// 客户端 SocketAddr → 目标地址（协议解析出来后补写）。
    target_map: Mutex<HashMap<SocketAddr, String>>,
    conn_tx: mpsc::UnboundedSender<ConnRecord>,
}

impl Stats {
    fn find_node(&self, proto: &str, listen: &str, port: u16) -> Option<usize> {
        self.nodes
            .iter()
            .position(|n| {
                n.info.proto == proto && n.info.listen == listen && n.info.port == port
            })
            // 容错：协议类型相同即归属，最后兜底到第一个节点，保证流量不丢。
            .or_else(|| self.nodes.iter().position(|n| n.info.proto == proto))
            .or_else(|| (!self.nodes.is_empty()).then_some(0))
    }
}

/// 仅当 web 启用时调用。会创建/打开 redb 文件并启动后台刷盘任务。
pub fn init(db_path: &Path, nodes: Vec<NodeInfo>) -> Result<Arc<Stats>> {
    let db = Arc::new(db::Db::open(db_path)?);
    let (up, down, conns) = db.load_totals()?;

    let runtime = nodes
        .into_iter()
        .map(|info| NodeRuntime {
            info,
            active: AtomicI64::new(0),
            total_conn: AtomicU64::new(0),
            up: AtomicU64::new(0),
            down: AtomicU64::new(0),
            last_conn_ms: AtomicU64::new(0),
        })
        .collect();

    let (conn_tx, conn_rx) = mpsc::unbounded_channel();
    let stats = Arc::new(Stats {
        nodes: runtime,
        started_ms: now_ms(),
        db,
        total_up: AtomicU64::new(up),
        total_down: AtomicU64::new(down),
        total_conns: AtomicU64::new(conns),
        target_map: Mutex::new(HashMap::new()),
        conn_tx,
    });

    STATS
        .set(Arc::clone(&stats))
        .map_err(|_| anyhow::anyhow!("stats already initialized"))?;

    let s = Arc::clone(&stats);
    tokio::spawn(async move { flush_loop(s, conn_rx).await });
    Ok(stats)
}

pub fn get() -> Option<&'static Arc<Stats>> {
    STATS.get()
}

// ── 埋点 API ────────────────────────────────────────────────────────────────

struct ConnShared {
    stats: Arc<Stats>,
    idx: usize,
    peer: SocketAddr,
    ip: String,
    start_ms: u64,
}

impl Drop for ConnShared {
    fn drop(&mut self) {
        let stats = &self.stats;
        stats.nodes[self.idx].active.fetch_sub(1, Ordering::Relaxed);
        let target = stats
            .target_map
            .lock()
            .unwrap()
            .remove(&self.peer)
            .unwrap_or_default();
        let rec = ConnRecord {
            ts_ms: self.start_ms,
            node: stats.nodes[self.idx].info.name.clone(),
            proto: stats.nodes[self.idx].info.proto.clone(),
            ip: self.ip.clone(),
            target,
            duration_ms: now_ms().saturating_sub(self.start_ms),
        };
        let _ = stats.conn_tx.send(rec);
    }
}

/// 连接/会话建立时调用，返回 `(节点索引, guard)`。
/// guard 需覆盖整个连接生命周期，可 `clone()` 到多个并发任务里，
/// 最后一个释放时才记一条连接记录。
pub fn open(
    proto: &str,
    listen: &str,
    port: u16,
    peer: SocketAddr,
    target: &str,
) -> (Option<usize>, Option<ConnGuard>) {
    let Some(stats) = STATS.get() else { return (None, None) };
    let Some(idx) = stats.find_node(proto, listen, port) else { return (None, None) };
    let stats = Arc::clone(stats);
    let ts = now_ms();
    let n = &stats.nodes[idx];
    n.active.fetch_add(1, Ordering::Relaxed);
    n.total_conn.fetch_add(1, Ordering::Relaxed);
    n.last_conn_ms.store(ts, Ordering::Relaxed);
    stats.target_map.lock().unwrap().insert(peer, target.to_string());

    let guard = ConnGuard(Arc::new(ConnShared {
        stats,
        idx,
        peer,
        ip: peer.ip().to_string(),
        start_ms: ts,
    }));
    (Some(idx), Some(guard))
}

/// 协议解析出目标地址后补写，无需把 guard 传进深层函数。
pub fn set_target_peer(peer: SocketAddr, target: &str) {
    let Some(stats) = STATS.get() else { return };
    if let Some(slot) = stats.target_map.lock().unwrap().get_mut(&peer) {
        *slot = target.to_string();
    }
}

/// 没有 `cfg` 的场景（QUIC 连接 / WireGuard 会话）按协议名归属节点。
/// 同协议多节点时会归到第一个，其余情况与 [`open`] 等价。
pub fn open_peer(proto: &str, peer: SocketAddr, target: &str) -> Option<ConnGuard> {
    open(proto, "", 0, peer, target).1
}

/// 传输层拿不到真实客户端地址时（xhttp 复用连接 / shadowquic）使用唯一伪地址，
/// 保证 peer_map 不冲突；记录中的 IP 会显示为占位地址。
pub fn open_anon(proto: &str) -> Option<ConnGuard> {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let port = 20000u16.wrapping_add((seq % 40000) as u16);
    let peer = SocketAddr::from(([0, 0, 0, 0], port));
    open(proto, "", 0, peer, "").1
}

/// 兜底：拿不到 peer / cfg 的深层收发循环（如 WireGuard 协议栈）按协议名累加。
pub fn traffic_proto(proto: &str, up: u64, down: u64) {
    let Some(stats) = STATS.get() else { return };
    let idx = stats
        .nodes
        .iter()
        .position(|n| n.info.proto == proto)
        .or_else(|| (!stats.nodes.is_empty()).then_some(0));
    if let Some(i) = idx {
        add_traffic(stats, i, up, down);
    }
}

fn add_traffic(stats: &Arc<Stats>, idx: usize, up: u64, down: u64) {
    if up == 0 && down == 0 {
        return;
    }
    let n = &stats.nodes[idx];
    if up > 0 {
        n.up.fetch_add(up, Ordering::Relaxed);
        stats.total_up.fetch_add(up, Ordering::Relaxed);
    }
    if down > 0 {
        n.down.fetch_add(down, Ordering::Relaxed);
        stats.total_down.fetch_add(down, Ordering::Relaxed);
    }
}

/// RAII 句柄：存活期间代表一个活跃连接，最后一个句柄释放时写一条连接记录。
#[derive(Clone)]
pub struct ConnGuard(#[allow(dead_code)] Arc<ConnShared>);

// ── 后台刷盘 ────────────────────────────────────────────────────────────────

const FLUSH_INTERVAL: Duration = Duration::from_secs(5);

async fn flush_loop(stats: Arc<Stats>, mut rx: mpsc::UnboundedReceiver<ConnRecord>) {
    let mut last_up = vec![0u64; stats.nodes.len()];
    let mut last_down = vec![0u64; stats.nodes.len()];
    let mut ticker = tokio::time::interval(FLUSH_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        ticker.tick().await;

        let mut records = Vec::new();
        while let Ok(r) = rx.try_recv() {
            records.push(r);
        }
        if records.len() >= 4096 {
            // 防止极端情况下单批过大
            records.truncate(4096);
        }

        let mut deltas: Vec<(String, u64, u64)> = Vec::with_capacity(stats.nodes.len());
        for (i, n) in stats.nodes.iter().enumerate() {
            let up = n.up.load(Ordering::Relaxed);
            let down = n.down.load(Ordering::Relaxed);
            let du = up.saturating_sub(last_up[i]);
            let dd = down.saturating_sub(last_down[i]);
            last_up[i] = up;
            last_down[i] = down;
            if du > 0 || dd > 0 {
                deltas.push((n.info.name.clone(), du, dd));
            }
        }

        if deltas.is_empty() && records.is_empty() {
            continue;
        }
        if !records.is_empty() {
            stats
                .total_conns
                .fetch_add(records.len() as u64, Ordering::Relaxed);
        }

        let s = Arc::clone(&stats);
        let result = tokio::task::spawn_blocking(move || s.db.flush(&deltas, &records)).await;
        match result {
            Ok(Err(e)) => tracing::warn!("[stats] 数据库写入失败: {e:#}"),
            Err(e) => tracing::warn!("[stats] 刷盘任务异常: {e}"),
            _ => {}
        }
    }
}

/// 手动清理（不自动过期、不自动清理）。`month = Some(YYYYMM)` 只清该月。
/// 清理后从数据库重新载入累计值并同步到内存计数器，避免面板仍显示旧总量。
pub async fn clear_data(month: Option<u32>) -> Result<()> {
    let stats = Arc::clone(get().context("stats not enabled")?);
    let db = Arc::clone(&stats.db);
    let (up, down, conns) = tokio::task::spawn_blocking(move || -> Result<(u64, u64, u64)> {
        db.clear(month)?;
        db.load_totals()
    })
    .await
    .context("clear task failed")??;
    stats.total_up.store(up, Ordering::Relaxed);
    stats.total_down.store(down, Ordering::Relaxed);
    stats.total_conns.store(conns, Ordering::Relaxed);
    Ok(())
}

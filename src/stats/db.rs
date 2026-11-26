//! SQLite（rusqlite）持久化层（全量加密）。
//!
//! - 所有表值经 [`MasterKey`] AES-256-GCM 加密后落盘。
//! - IP 表键 = HMAC(ip)、HOUR/MONTH 表键中的节点名 = HMAC(name)，
//!   明文不进键；hmac → 节点名映射保存在 META（值加密）。
//! - 节点配置存储在 `nodes` 表（键 = 节点名，值 = 加密 JSON），
//!   面板模式的节点增删改直接读写该表。
//! - 面板设置（用户名 / 密码哈希 / 端口）存 META。
//!
//! 使用 WAL 模式 + `busy_timeout`：服务运行期间，`flux set-user` 等子命令
//! 也能另开进程安全写库（redb 为单进程独占锁，这正是换成 SQLite 的原因）。
//! 连接由 `Mutex` 串行化，所有数据库操作都由调用方放到 `spawn_blocking` 中执行；
//! 写入统一走 [`Db::flush`] 的单个写事务。
//! 数据**不会自动过期、不会自动清理**，只能由面板的「清理数据」触发 [`Db::clear`]。

use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use crate::crypto::MasterKey;
use super::{hour_bucket, month_bucket, now_ms, ConnRecord};

const CONN: &str = "conn";
const HOUR: &str = "hour";
const MONTH: &str = "month";
const IP: &str = "ip";
const META: &str = "meta";
const NODES: &str = "nodes";
/// 面板申请的 ACME 证书记录（值加密 JSON，与节点同级敏感数据）。
const CERTS: &str = "certs";

/// 面板设置（存 META，首次启动为默认值）。
#[derive(Debug, Clone, Serialize)]
pub struct PanelSettings {
    pub user: String,
    /// PBKDF2-HMAC-SHA256 哈希（`salt$hash`），不存明文。
    pub pass_hash: String,
    pub port: u16,
}

impl Default for PanelSettings {
    fn default() -> Self {
        Self {
            user: "admin".into(),
            // 空哈希永远校验失败；真正的初始密码由 `ensure_panel_credentials` 随机生成。
            pass_hash: String::new(),
            port: 9080,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IpAgg {
    /// 客户端 IP 明文（随值一起加密存储；键为 HMAC）。
    pub ip: String,
    pub first_ms: u64,
    pub last_ms: u64,
    pub count: u64,
    pub up: u64,
    pub down: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct SeriesPoint {
    /// `{bucket}|{node}`；bucket 为小时序号或 YYYYMM。
    pub key: String,
    pub up: u64,
    pub down: u64,
    pub conns: u64,
}


pub struct Db {
    conn: Mutex<Connection>,
    key: MasterKey,
}

impl Db {
    pub fn open(path: &Path, key: MasterKey) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("cannot create db dir: {}", parent.display()))?;
        }
        let conn = Connection::open(path)
            .with_context(|| format!("cannot open sqlite: {}", path.display()))?;
        // 先设置 busy_timeout：set-* 子命令与运行中的服务可能同时写库，
        // 遇到写锁时等待而不是立刻报 "database is locked"。
        conn.busy_timeout(Duration::from_secs(10))?;
        // WAL：读写互不阻塞，且允许多个进程访问同一个库文件。
        let _mode: String = conn.query_row("PRAGMA journal_mode = WAL", [], |r| r.get(0))?;
        conn.execute_batch("PRAGMA synchronous = NORMAL;")?;
        conn.execute_batch(&format!(
            "CREATE TABLE IF NOT EXISTS {CONN}  (k INTEGER PRIMARY KEY, v BLOB NOT NULL);
             CREATE TABLE IF NOT EXISTS {HOUR}  (k TEXT PRIMARY KEY, v BLOB NOT NULL) WITHOUT ROWID;
             CREATE TABLE IF NOT EXISTS {MONTH} (k TEXT PRIMARY KEY, v BLOB NOT NULL) WITHOUT ROWID;
             CREATE TABLE IF NOT EXISTS {IP}    (k TEXT PRIMARY KEY, v BLOB NOT NULL) WITHOUT ROWID;
             CREATE TABLE IF NOT EXISTS {META}  (k TEXT PRIMARY KEY, v BLOB NOT NULL) WITHOUT ROWID;
             CREATE TABLE IF NOT EXISTS {NODES} (k TEXT PRIMARY KEY, v BLOB NOT NULL) WITHOUT ROWID;
             CREATE TABLE IF NOT EXISTS {CERTS} (k TEXT PRIMARY KEY, v BLOB NOT NULL) WITHOUT ROWID;"
        ))?;
        tracing::info!("[stats] 数据库（已加密）: {}", path.display());
        Ok(Self { conn: Mutex::new(conn), key })
    }

    fn lock(&self) -> MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// 写事务：`IMMEDIATE` 在开始时就取写锁，配合 busy_timeout 可靠地排队。
    fn begin<'a>(conn: &'a mut Connection) -> Result<Transaction<'a>> {
        Ok(conn.transaction_with_behavior(TransactionBehavior::Immediate)?)
    }

    // ── 值加解密辅助 ────────────────────────────────────────────────────────

    fn seal(&self, plain: &[u8]) -> Result<Vec<u8>> {
        self.key.seal(plain)
    }

    fn open_val(&self, blob: &[u8]) -> Result<Vec<u8>> {
        self.key.open(blob)
    }

    // ── 面板设置 ────────────────────────────────────────────────────────────

    pub fn panel_settings(&self) -> Result<PanelSettings> {
        let conn = self.lock();
        let get = |k: &str| -> Option<String> {
            kv_get(&conn, META, k)
                .ok()
                .flatten()
                .and_then(|b| self.open_val(&b).ok())
                .and_then(|v| String::from_utf8(v).ok())
        };
        let user = get("panel_user").filter(|s| !s.is_empty());
        let pass_hash = get("panel_pass").filter(|s| !s.is_empty());
        let port = get("panel_port").and_then(|s| s.parse::<u16>().ok());
        Ok(match (user, pass_hash, port) {
            (Some(user), Some(pass_hash), Some(port)) => PanelSettings { user, pass_hash, port },
            (user, pass_hash, port) => {
                let d = PanelSettings::default();
                PanelSettings {
                    user: user.unwrap_or(d.user),
                    pass_hash: pass_hash.unwrap_or(d.pass_hash),
                    port: port.unwrap_or(d.port),
                }
            }
        })
    }

    /// 首次启动（或缺少凭据）时生成随机初始密码并写库，返回 `Some(明文密码)`，
    /// 仅此一次展示给管理员；不再使用公开已知的 admin/admin。
    pub fn ensure_panel_credentials(&self) -> Result<Option<String>> {
        let s = self.panel_settings()?;
        if !s.pass_hash.is_empty() {
            let conn = self.lock();
            if kv_get(&conn, META, "panel_user")?.is_none() {
                drop(conn);
                self.set_panel_user(&s.user)?;
            }
            return Ok(None);
        }
        let pw = crate::config::gen_password(16);
        let hash = crate::crypto::hash_password(&pw)?;
        self.set_panel_pass_hash(&hash)?;
        self.set_panel_user(&s.user)?;
        Ok(Some(pw))
    }

    fn write_meta(&self, k: &str, v: &str) -> Result<()> {
        let enc = self.seal(v.as_bytes())?;
        let conn = self.lock();
        kv_put(&conn, META, k, &enc)
    }

    pub fn set_panel_user(&self, user: &str) -> Result<()> {
        self.write_meta("panel_user", user)
    }

    pub fn set_panel_pass_hash(&self, hash: &str) -> Result<()> {
        self.write_meta("panel_pass", hash)
    }

    pub fn set_panel_port(&self, port: u16) -> Result<()> {
        self.write_meta("panel_port", &port.to_string())
    }

    // ── 节点存储（面板模式真源）────────────────────────────────────────────

    /// 登记节点名映射（hmac → name），供 HOUR/MONTH 系列反查显示名。
    pub fn register_node_name(&self, name: &str) -> Result<()> {
        let h = self.key.key_hash(name);
        let mut conn = self.lock();
        let tx = Self::begin(&mut conn)?;
        let mut map = self.node_names_in(&tx)?;
        if map.contains_key(&h) {
            return Ok(());
        }
        map.insert(h, name.to_string());
        let enc = self.seal(&serde_json::to_vec(&map)?)?;
        kv_put(&tx, META, "node_names", &enc)?;
        tx.commit()?;
        Ok(())
    }

    fn node_names_in(&self, c: &Connection) -> Result<std::collections::HashMap<String, String>> {
        match kv_get(c, META, "node_names")? {
            Some(b) => Ok(serde_json::from_slice(&self.open_val(&b)?).unwrap_or_default()),
            None => Ok(Default::default()),
        }
    }

    /// 只读获取 hmac → 节点名映射。
    fn node_names(&self) -> Result<std::collections::HashMap<String, String>> {
        let conn = self.lock();
        self.node_names_in(&conn)
    }

    fn list_json(&self, table: &str) -> Result<Vec<(String, serde_json::Value)>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(&format!("SELECT k, v FROM {table} ORDER BY k"))?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?)))?;
        let mut out = Vec::new();
        for row in rows {
            let (k, v) = row?;
            let val: serde_json::Value =
                serde_json::from_slice(&self.open_val(&v)?).unwrap_or_default();
            out.push((k, val));
        }
        Ok(out)
    }

    fn get_json(&self, table: &str, k: &str) -> Result<Option<serde_json::Value>> {
        let conn = self.lock();
        match kv_get(&conn, table, k)? {
            Some(b) => Ok(Some(serde_json::from_slice(&self.open_val(&b)?).unwrap_or_default())),
            None => Ok(None),
        }
    }

    fn put_json(&self, table: &str, k: &str, value: &serde_json::Value) -> Result<()> {
        let enc = self.seal(&serde_json::to_vec(value)?)?;
        let conn = self.lock();
        kv_put(&conn, table, k, &enc)
    }

    fn delete_key(&self, table: &str, k: &str) -> Result<()> {
        let conn = self.lock();
        conn.execute(&format!("DELETE FROM {table} WHERE k = ?1"), params![k])?;
        Ok(())
    }

    pub fn list_nodes(&self) -> Result<Vec<(String, serde_json::Value)>> {
        self.list_json(NODES)
    }

    pub fn get_node(&self, name: &str) -> Result<Option<serde_json::Value>> {
        self.get_json(NODES, name)
    }

    pub fn put_node(&self, name: &str, value: &serde_json::Value) -> Result<()> {
        self.put_json(NODES, name, value)
    }

    pub fn delete_node(&self, name: &str) -> Result<()> {
        self.delete_key(NODES, name)
    }

    // ── ACME 证书记录（面板 SSL 证书页）────────────────────────────────────

    pub fn list_certs(&self) -> Result<Vec<(String, serde_json::Value)>> {
        self.list_json(CERTS)
    }

    pub fn get_cert(&self, id: &str) -> Result<Option<serde_json::Value>> {
        self.get_json(CERTS, id)
    }

    pub fn put_cert(&self, id: &str, value: &serde_json::Value) -> Result<()> {
        self.put_json(CERTS, id, value)
    }

    pub fn delete_cert(&self, id: &str) -> Result<()> {
        self.delete_key(CERTS, id)
    }

    // ── 统计 ────────────────────────────────────────────────────────────────

    pub fn load_totals(&self) -> Result<(u64, u64, u64)> {
        let conn = self.lock();
        Ok((
            self.read_u64(&conn, "total_up")?,
            self.read_u64(&conn, "total_down")?,
            self.read_u64(&conn, "total_conns")?,
        ))
    }

    /// 一批增量 + 一批连接记录，单个写事务完成。
    /// `deltas` 为 `(节点名, 上行增量, 下行增量)`。
    pub fn flush(&self, deltas: &[(String, u64, u64)], records: &[ConnRecord]) -> Result<()> {
        let now = now_ms();
        let hour = hour_bucket(now);
        let month = month_bucket(now);

        // 键中的节点名用 HMAC 替换；映射表登记放在 flush 中的 META 块统一处理。
        let hmacs: Vec<String> = deltas.iter().map(|(n, _, _)| self.key.key_hash(n)).collect();

        let mut conn = self.lock();
        let tx = Self::begin(&mut conn)?;

        for ((_, du, dd), h) in deltas.iter().zip(&hmacs) {
            bump(&self.key, &tx, HOUR, &format!("{hour}|{h}"), *du, *dd, 0)?;
            bump(&self.key, &tx, MONTH, &format!("{month}|{h}"), *du, *dd, 0)?;
        }

        // 保证映射表含全部节点（包含本轮无流量的），供 series 反查名称。
        {
            let mut map = self.node_names_in(&tx).unwrap_or_default();
            let mut changed = false;
            for ((node, _, _), h) in deltas.iter().zip(&hmacs) {
                if !map.contains_key(h) {
                    map.insert(h.clone(), node.to_string());
                    changed = true;
                }
            }
            if changed {
                let enc = self.seal(&serde_json::to_vec(&map)?)?;
                kv_put(&tx, META, "node_names", &enc)?;
            }
        }

        {
            let mut stmt = tx.prepare_cached(&format!("INSERT INTO {CONN}(k, v) VALUES (?1, ?2)"))?;
            for rec in records {
                let enc = self.seal(&serde_json::to_vec(rec)?)?;
                stmt.execute(params![next_conn_id() as i64, enc])?;
            }
        }

        for rec in records {
            if rec.ip.is_empty() {
                continue;
            }
            let key = self.key.key_hash(&rec.ip);
            let old = kv_get(&tx, IP, &key)?.unwrap_or_default();
            let mut agg: IpAgg = serde_json::from_slice(&self.open_val(&old).unwrap_or_default())
                .unwrap_or_default();
            if agg.first_ms == 0 || rec.ts_ms < agg.first_ms {
                agg.first_ms = rec.ts_ms;
            }
            agg.last_ms = agg.last_ms.max(rec.ts_ms);
            agg.count += 1;
            agg.ip = rec.ip.clone();
            let enc = self.seal(&serde_json::to_vec(&agg)?)?;
            kv_put(&tx, IP, &key, &enc)?;
        }

        {
            let du: u64 = deltas.iter().map(|x| x.1).sum();
            let dd: u64 = deltas.iter().map(|x| x.2).sum();
            let up = self.read_u64(&tx, "total_up")?.saturating_add(du);
            let down = self.read_u64(&tx, "total_down")?.saturating_add(dd);
            let conns = self.read_u64(&tx, "total_conns")?.saturating_add(records.len() as u64);
            self.write_u64(&tx, "total_up", up)?;
            self.write_u64(&tx, "total_down", down)?;
            self.write_u64(&tx, "total_conns", conns)?;
        }

        tx.commit()?;
        Ok(())
    }

    pub fn ip_count(&self) -> Result<usize> {
        let conn = self.lock();
        let n: i64 = conn.query_row(&format!("SELECT COUNT(*) FROM {IP}"), [], |r| r.get(0))?;
        Ok(n as usize)
    }

    /// 汇总 `from_bucket`（含）之后所有小时桶的上下行流量。
    pub fn sum_hours(&self, from_bucket: u64) -> Result<(u64, u64)> {
        let conn = self.lock();
        let mut stmt = conn.prepare(&format!("SELECT k, v FROM {HOUR}"))?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?)))?;
        let mut up = 0u64;
        let mut down = 0u64;
        for row in rows {
            let (k, v) = row?;
            let bucket = k.split('|').next().and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
            if bucket < from_bucket {
                continue;
            }
            let (u, d, _) = self.decode_triple(&v)?;
            up += u;
            down += d;
        }
        Ok((up, down))
    }

    pub fn list_connections(&self, limit: usize) -> Result<Vec<ConnRecord>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(&format!("SELECT v FROM {CONN} ORDER BY k DESC LIMIT ?1"))?;
        let rows = stmt.query_map(params![limit as i64], |r| r.get::<_, Vec<u8>>(0))?;
        let mut out = Vec::new();
        for row in rows {
            let v = row?;
            if let Ok(r) = serde_json::from_slice(&self.open_val(&v)?) {
                out.push(r);
            }
        }
        Ok(out)
    }

    pub fn list_ips(&self, limit: usize) -> Result<Vec<(String, IpAgg)>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(&format!("SELECT v FROM {IP}"))?;
        let rows = stmt.query_map([], |r| r.get::<_, Vec<u8>>(0))?;
        let mut out = Vec::new();
        for row in rows {
            let v = row?;
            let agg: IpAgg = serde_json::from_slice(&self.open_val(&v)?).unwrap_or_default();
            out.push((agg.ip.clone(), agg));
        }
        out.sort_by(|a, b| b.1.last_ms.cmp(&a.1.last_ms));
        out.truncate(limit);
        Ok(out)
    }

    /// 小时桶序列（近 `hours` 小时内的所有点，键中的 hmac 已还原为节点名）。
    pub fn hour_series(&self, from_bucket: u64) -> Result<Vec<SeriesPoint>> {
        let map = self.node_names()?;
        let conn = self.lock();
        let mut stmt = conn.prepare(&format!("SELECT k, v FROM {HOUR} ORDER BY k"))?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?)))?;
        let mut out = Vec::new();
        for row in rows {
            let (key, v) = row?;
            let mut parts = key.split('|');
            let bucket = parts.next().and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
            let h = parts.next().unwrap_or("");
            if bucket < from_bucket {
                continue;
            }
            let (u, d, c) = self.decode_triple(&v)?;
            out.push(SeriesPoint {
                key: format!("{bucket}|{}", map.get(h).map(|s| s.as_str()).unwrap_or(h)),
                up: u,
                down: d,
                conns: c,
            });
        }
        Ok(out)
    }

    pub fn month_series(&self) -> Result<Vec<SeriesPoint>> {
        let map = self.node_names()?;
        let conn = self.lock();
        let mut stmt = conn.prepare(&format!("SELECT k, v FROM {MONTH} ORDER BY k"))?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?)))?;
        let mut out = Vec::new();
        for row in rows {
            let (key, v) = row?;
            let mut parts = key.split('|');
            let bucket = parts.next().unwrap_or("").to_string();
            let h = parts.next().unwrap_or("").to_string();
            let (u, d, c) = self.decode_triple(&v)?;
            out.push(SeriesPoint {
                key: format!("{bucket}|{}", map.get(&h).map(|s| s.as_str()).unwrap_or(&h)),
                up: u,
                down: d,
                conns: c,
            });
        }
        Ok(out)
    }

    /// `None` = 清空全部；`Some(YYYYMM)` = 只清该月的流量与连接记录。
    pub fn clear(&self, month: Option<u32>) -> Result<()> {
        let mut conn = self.lock();
        let tx = Self::begin(&mut conn)?;

        let mut removed_up = 0u64;
        let mut removed_down = 0u64;
        let mut removed_conns = 0u64;

        // ── MONTH ────────────────────────────────────────────────────────────
        {
            let rows = kv_all(&tx, MONTH)?;
            for (key, v) in rows {
                let m = key.split('|').next().and_then(|s| s.parse::<u32>().ok());
                let hit = match month {
                    None => true,
                    Some(mm) => m == Some(mm),
                };
                if hit {
                    let (u, d, _) = self.decode_triple(&v)?;
                    removed_up += u;
                    removed_down += d;
                    tx.execute(&format!("DELETE FROM {MONTH} WHERE k = ?1"), params![key])?;
                }
            }
        }

        // ── HOUR ─────────────────────────────────────────────────────────────
        match month {
            None => {
                tx.execute(&format!("DELETE FROM {HOUR}"), [])?;
            }
            Some(mm) => {
                for (key, _) in kv_all(&tx, HOUR)? {
                    let bucket = key.split('|').next().and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
                    if month_bucket(bucket.saturating_mul(3_600_000)) == mm {
                        tx.execute(&format!("DELETE FROM {HOUR} WHERE k = ?1"), params![key])?;
                    }
                }
            }
        }

        // ── CONN ─────────────────────────────────────────────────────────────
        match month {
            None => {
                removed_conns += tx.execute(&format!("DELETE FROM {CONN}"), [])? as u64;
            }
            Some(mm) => {
                let rows: Vec<(i64, Vec<u8>)> = {
                    let mut stmt = tx.prepare(&format!("SELECT k, v FROM {CONN}"))?;
                    let it = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
                    it.collect::<std::result::Result<_, _>>()?
                };
                for (id, v) in rows {
                    let rec: Option<ConnRecord> =
                        serde_json::from_slice(&self.open_val(&v).unwrap_or_default()).ok();
                    if rec.map(|r| month_bucket(r.ts_ms) == mm).unwrap_or(false) {
                        tx.execute(&format!("DELETE FROM {CONN} WHERE k = ?1"), params![id])?;
                        removed_conns += 1;
                    }
                }
            }
        }

        // ── IP（仅在清空全部时重置；按月清理保留历史 IP 聚合）─────────────────
        if month.is_none() {
            tx.execute(&format!("DELETE FROM {IP}"), [])?;
        }

        // ── META ─────────────────────────────────────────────────────────────
        if month.is_none() {
            self.write_u64(&tx, "total_up", 0)?;
            self.write_u64(&tx, "total_down", 0)?;
            self.write_u64(&tx, "total_conns", 0)?;
        } else {
            let up = self.read_u64(&tx, "total_up")?.saturating_sub(removed_up);
            let down = self.read_u64(&tx, "total_down")?.saturating_sub(removed_down);
            let conns = self.read_u64(&tx, "total_conns")?.saturating_sub(removed_conns);
            self.write_u64(&tx, "total_up", up)?;
            self.write_u64(&tx, "total_down", down)?;
            self.write_u64(&tx, "total_conns", conns)?;
        }

        tx.commit()?;
        Ok(())
    }

    // ── 内部工具 ────────────────────────────────────────────────────────────

    fn decode_triple(&self, v: &[u8]) -> Result<(u64, u64, u64)> {
        let raw = self.open_val(v)?;
        match serde_json::from_slice::<[u64; 3]>(&raw) {
            Ok(a) => Ok((a[0], a[1], a[2])),
            Err(_) => Ok((0, 0, 0)),
        }
    }

    fn read_u64(&self, c: &Connection, key: &str) -> Result<u64> {
        Ok(kv_get(c, META, key)
            .ok()
            .flatten()
            .and_then(|b| self.open_val(&b).ok())
            .and_then(|v| String::from_utf8(v).ok())
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0))
    }

    fn write_u64(&self, c: &Connection, key: &str, value: u64) -> Result<()> {
        let enc = self.seal(value.to_string().as_bytes())?;
        kv_put(c, META, key, &enc)
    }
}

// ── SQL 辅助（表名均为本文件内的常量，不含外部输入）──────────────────────────

fn kv_get(c: &Connection, table: &str, k: &str) -> Result<Option<Vec<u8>>> {
    Ok(c.query_row(&format!("SELECT v FROM {table} WHERE k = ?1"), params![k], |r| r.get(0))
        .optional()?)
}

fn kv_put(c: &Connection, table: &str, k: &str, v: &[u8]) -> Result<()> {
    c.prepare_cached(&format!(
        "INSERT INTO {table}(k, v) VALUES (?1, ?2) ON CONFLICT(k) DO UPDATE SET v = excluded.v"
    ))?
    .execute(params![k, v])?;
    Ok(())
}

fn kv_all(c: &Connection, table: &str) -> Result<Vec<(String, Vec<u8>)>> {
    let mut stmt = c.prepare(&format!("SELECT k, v FROM {table}"))?;
    let rows = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
    Ok(rows.collect::<std::result::Result<_, _>>()?)
}

/// 把 `&str → [up, down, conns]` 的计数累加（值加密存储）。
fn bump(
    key: &MasterKey,
    c: &Connection,
    table: &str,
    k: &str,
    du: u64,
    dd: u64,
    dc: u64,
) -> Result<()> {
    let old = kv_get(c, table, k)?.unwrap_or_default();
    let [u, d, cnt] = match key.open(&old) {
        Ok(raw) => serde_json::from_slice::<[u64; 3]>(&raw).unwrap_or([0, 0, 0]),
        Err(_) => [0, 0, 0],
    };
    let s = format!("[{},{},{}]", u + du, d + dd, cnt + dc);
    let enc = key.seal(s.as_bytes())?;
    kv_put(c, table, k, &enc)
}

fn next_conn_id() -> u64 {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let base = now_ms() << 12;
    SEQ.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |prev| {
        Some(std::cmp::max(prev, base) + 1)
    })
    .unwrap_or_else(|_| base + 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_handles_can_write_same_file() {
        let dir = std::env::temp_dir().join(format!("flux-dbtest-{}", now_ms()));
        let path = dir.join("flux.sqlite");
        let a = Db::open(&path, MasterKey::from_bytes([7; 32])).unwrap();
        // 模拟服务运行时 `flux set-user` 另开一个进程/句柄写库
        let b = Db::open(&path, MasterKey::from_bytes([7; 32])).unwrap();
        b.set_panel_user("root").unwrap();
        assert_eq!(a.panel_settings().unwrap().user, "root");
        a.put_node("n1", &serde_json::json!({"name": "n1"})).unwrap();
        assert_eq!(b.list_nodes().unwrap().len(), 1);
        a.flush(&[("n1".into(), 10, 20)], &[]).unwrap();
        a.flush(&[("n1".into(), 1, 2)], &[]).unwrap();
        assert_eq!(b.load_totals().unwrap(), (11, 22, 0));
        assert_eq!(b.month_series().unwrap()[0].key.ends_with("|n1"), true);
        b.clear(None).unwrap();
        assert_eq!(a.load_totals().unwrap(), (0, 0, 0));
        let _ = std::fs::remove_dir_all(dir);
    }
}

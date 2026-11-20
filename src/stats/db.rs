//! redb 持久化层（全量加密）。
//!
//! - 所有表值经 [`MasterKey`] AES-256-GCM 加密后落盘。
//! - IP 表键 = HMAC(ip)、HOUR/MONTH 表键中的节点名 = HMAC(name)，
//!   明文不进键；hmac → 节点名映射保存在 META（值加密）。
//! - 节点配置存储在 `nodes` 表（键 = 节点名，值 = 加密 JSON），
//!   面板模式的节点增删改直接读写该表。
//! - 面板设置（用户名 / 密码哈希 / 端口）存 META。
//!
//! redb 是同步阻塞 API，且数据文件为单进程独占，因此所有数据库操作都由
//! 调用方放到 `spawn_blocking` 中执行；写入统一走 [`Db::flush`] 的单个写事务。
//! 数据**不会自动过期、不会自动清理**，只能由面板的「清理数据」触发 [`Db::clear`]。

use anyhow::{Context, Result};
use redb::{Database, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::crypto::MasterKey;
use super::{hour_bucket, month_bucket, now_ms, ConnRecord};

const CONN: TableDefinition<u64, &[u8]> = TableDefinition::new("conn");
const HOUR: TableDefinition<&str, &[u8]> = TableDefinition::new("hour");
const MONTH: TableDefinition<&str, &[u8]> = TableDefinition::new("month");
const IP: TableDefinition<&str, &[u8]> = TableDefinition::new("ip");
const META: TableDefinition<&str, &[u8]> = TableDefinition::new("meta");
const NODES: TableDefinition<&str, &[u8]> = TableDefinition::new("nodes");
/// 面板申请的 ACME 证书记录（值加密 JSON，与节点同级敏感数据）。
const CERTS: TableDefinition<&str, &[u8]> = TableDefinition::new("certs");

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
            pass_hash: crate::crypto::hash_password("admin").unwrap_or_default(),
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
    db: Database,
    key: MasterKey,
}

impl Db {
    pub fn open(path: &Path, key: MasterKey) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("cannot create db dir: {}", parent.display()))?;
        }
        let db = Database::create(path)
            .with_context(|| format!("cannot open redb: {}", path.display()))?;
        // 写事务的 open_table 会自动建表，确保后续读事务不会因表不存在而报错。
        {
            let txn = db.begin_write()?;
            let _ = txn.open_table(CONN)?;
            for t in [&HOUR, &MONTH, &IP, &META, &NODES, &CERTS] {
                let _ = txn.open_table(*t)?;
            }
            txn.commit()?;
        }
        tracing::info!("[stats] 数据库（已加密）: {}", path.display());
        Ok(Self { db, key })
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
        let txn = self.db.begin_read()?;
        let t = txn.open_table(META)?;
        let get = |k: &str| -> Option<String> {
            t.get(k).ok().flatten().and_then(|g| {
                self.open_val(g.value()).ok()
            }).and_then(|v| String::from_utf8(v).ok())
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

    fn write_meta(&self, k: &str, v: &str) -> Result<()> {
        let enc = self.seal(v.as_bytes())?;
        let txn = self.db.begin_write()?;
        {
            let mut t = txn.open_table(META)?;
            t.insert(k, enc.as_slice())?;
        }
        txn.commit()?;
        Ok(())
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
        let txn = self.db.begin_read()?;
        let t = txn.open_table(META)?;
        let mut map: std::collections::HashMap<String, String> = match t.get("node_names")? {
            Some(g) => serde_json::from_slice(&self.open_val(g.value())?).unwrap_or_default(),
            None => Default::default(),
        };
        drop(t);
        drop(txn);
        if map.contains_key(&h) {
            return Ok(());
        }
        map.insert(h, name.to_string());
        let bytes = serde_json::to_vec(&map)?;
        let enc = self.seal(&bytes)?;
        let txn = self.db.begin_write()?;
        {
            let mut t = txn.open_table(META)?;
            t.insert("node_names", enc.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    /// 只读获取 hmac → 节点名映射。
    fn node_names(&self) -> Result<std::collections::HashMap<String, String>> {
        let txn = self.db.begin_read()?;
        let t = txn.open_table(META)?;
        match t.get("node_names")? {
            Some(g) => Ok(serde_json::from_slice(&self.open_val(g.value())?).unwrap_or_default()),
            None => Ok(Default::default()),
        }
    }


    pub fn list_nodes(&self) -> Result<Vec<(String, serde_json::Value)>> {
        let txn = self.db.begin_read()?;
        let t = txn.open_table(NODES)?;
        let mut out = Vec::new();
        for entry in t.iter()? {
            let (k, v) = entry?;
            let name = k.value().to_string();
            let val: serde_json::Value =
                serde_json::from_slice(&self.open_val(v.value())?).unwrap_or_default();
            out.push((name, val));
        }
        Ok(out)
    }

    pub fn get_node(&self, name: &str) -> Result<Option<serde_json::Value>> {
        let txn = self.db.begin_read()?;
        let t = txn.open_table(NODES)?;
        match t.get(name)? {
            Some(g) => {
                let val = serde_json::from_slice(&self.open_val(g.value())?).unwrap_or_default();
                Ok(Some(val))
            }
            None => Ok(None),
        }
    }

    pub fn put_node(&self, name: &str, value: &serde_json::Value) -> Result<()> {
        let bytes = serde_json::to_vec(value)?;
        let enc = self.seal(&bytes)?;
        let txn = self.db.begin_write()?;
        {
            let mut t = txn.open_table(NODES)?;
            t.insert(name, enc.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    pub fn delete_node(&self, name: &str) -> Result<()> {
        let txn = self.db.begin_write()?;
        {
            let mut t = txn.open_table(NODES)?;
            t.remove(name)?;
        }
        txn.commit()?;
        Ok(())
    }

    // ── ACME 证书记录（面板 SSL 证书页）────────────────────────────────────

    pub fn list_certs(&self) -> Result<Vec<(String, serde_json::Value)>> {
        let txn = self.db.begin_read()?;
        let t = txn.open_table(CERTS)?;
        let mut out = Vec::new();
        for entry in t.iter()? {
            let (k, v) = entry?;
            let id = k.value().to_string();
            let val: serde_json::Value =
                serde_json::from_slice(&self.open_val(v.value())?).unwrap_or_default();
            out.push((id, val));
        }
        Ok(out)
    }

    pub fn get_cert(&self, id: &str) -> Result<Option<serde_json::Value>> {
        let txn = self.db.begin_read()?;
        let t = txn.open_table(CERTS)?;
        match t.get(id)? {
            Some(g) => {
                let val = serde_json::from_slice(&self.open_val(g.value())?).unwrap_or_default();
                Ok(Some(val))
            }
            None => Ok(None),
        }
    }

    pub fn put_cert(&self, id: &str, value: &serde_json::Value) -> Result<()> {
        let bytes = serde_json::to_vec(value)?;
        let enc = self.seal(&bytes)?;
        let txn = self.db.begin_write()?;
        {
            let mut t = txn.open_table(CERTS)?;
            t.insert(id, enc.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    pub fn delete_cert(&self, id: &str) -> Result<()> {
        let txn = self.db.begin_write()?;
        {
            let mut t = txn.open_table(CERTS)?;
            t.remove(id)?;
        }
        txn.commit()?;
        Ok(())
    }

    // ── 统计 ────────────────────────────────────────────────────────────────


    pub fn load_totals(&self) -> Result<(u64, u64, u64)> {
        let txn = self.db.begin_read()?;
        let t = txn.open_table(META)?;
        Ok((
            self.read_u64(&t, "total_up")?,
            self.read_u64(&t, "total_down")?,
            self.read_u64(&t, "total_conns")?,
        ))
    }

    /// 一批增量 + 一批连接记录，单个写事务完成。
    /// `deltas` 为 `(节点名, 上行增量, 下行增量)`。
    pub fn flush(&self, deltas: &[(String, u64, u64)], records: &[ConnRecord]) -> Result<()> {
        let now = now_ms();
        let hour = hour_bucket(now);
        let month = month_bucket(now);
        let txn = self.db.begin_write()?;

        // 键中的节点名用 HMAC 替换；映射表登记放在 flush 末尾的 META 块统一处理。
        let hmacs: Vec<String> = deltas.iter().map(|(n, _, _)| self.key.key_hash(n)).collect();

        {
            let mut t = txn.open_table(HOUR)?;
            for ((_, du, dd), h) in deltas.iter().zip(&hmacs) {
                bump(&self.key, &mut t, &format!("{hour}|{h}"), *du, *dd, 0)?;
            }
        }
        {
            let mut t = txn.open_table(MONTH)?;
            for ((_, du, dd), h) in deltas.iter().zip(&hmacs) {
                bump(&self.key, &mut t, &format!("{month}|{h}"), *du, *dd, 0)?;
            }
        }
        // 保证映射表含全部节点（包含本轮无流量的），供 series 反查名称。
        {
            let mut t = txn.open_table(META)?;
            let mut map: std::collections::HashMap<String, String> = t
                .get("node_names")
                .ok()
                .flatten()
                .and_then(|g| self.open_val(g.value()).ok())
                .and_then(|v| serde_json::from_slice(&v).ok())
                .unwrap_or_default();
            let mut changed = false;
            for (node, _) in deltas.iter().map(|(n, _, _)| (n, ())) {
                let h = self.key.key_hash(node);
                if !map.contains_key(&h) {
                    map.insert(h, node.to_string());
                    changed = true;
                }
            }
            if changed {
                let bytes = serde_json::to_vec(&map)?;
                let enc = self.seal(&bytes)?;
                t.insert("node_names", enc.as_slice())?;
            }
        }
        {
            let mut t = txn.open_table(CONN)?;
            for rec in records {
                let bytes = serde_json::to_vec(rec)?;
                let enc = self.seal(&bytes)?;
                t.insert(next_conn_id(), enc.as_slice())?;
            }
        }
        {
            let mut t = txn.open_table(IP)?;
            for rec in records {
                if rec.ip.is_empty() {
                    continue;
                }
                let key = self.key.key_hash(&rec.ip);
                let old: Vec<u8> = {
                    t.get(key.as_str())?
                        .map(|g| g.value().to_vec())
                        .unwrap_or_default()
                };
                let mut agg: IpAgg = serde_json::from_slice(&self.open_val(&old).unwrap_or_default())
                    .unwrap_or_default();
                if agg.first_ms == 0 || rec.ts_ms < agg.first_ms {
                    agg.first_ms = rec.ts_ms;
                }
                agg.last_ms = agg.last_ms.max(rec.ts_ms);
                agg.count += 1;
                agg.ip = rec.ip.clone();
                let bytes = serde_json::to_vec(&agg)?;
                let enc = self.seal(&bytes)?;
                t.insert(key.as_str(), enc.as_slice())?;
            }
        }
        {
            let mut t = txn.open_table(META)?;
            let du: u64 = deltas.iter().map(|x| x.1).sum();
            let dd: u64 = deltas.iter().map(|x| x.2).sum();
            let up = self.read_u64(&t, "total_up")?.saturating_add(du);
            let down = self.read_u64(&t, "total_down")?.saturating_add(dd);
            let conns = self.read_u64(&t, "total_conns")?.saturating_add(records.len() as u64);
            self.write_u64(&mut t, "total_up", up)?;
            self.write_u64(&mut t, "total_down", down)?;
            self.write_u64(&mut t, "total_conns", conns)?;
        }

        txn.commit()?;
        Ok(())
    }

    pub fn ip_count(&self) -> Result<usize> {
        let txn = self.db.begin_read()?;
        let t = txn.open_table(IP)?;
        Ok(t.iter()?.count())
    }

    /// 汇总 `from_bucket`（含）之后所有小时桶的上下行流量。
    pub fn sum_hours(&self, from_bucket: u64) -> Result<(u64, u64)> {
        let txn = self.db.begin_read()?;
        let t = txn.open_table(HOUR)?;
        let mut up = 0u64;
        let mut down = 0u64;
        for entry in t.iter()? {
            let (k, v) = entry?;
            let bucket = k
                .value()
                .split('|')
                .next()
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0);
            if bucket < from_bucket {
                continue;
            }
            let (_, u, d) = self.decode_triple(v.value())?;
            up += u;
            down += d;
        }
        Ok((up, down))
    }

    pub fn list_connections(&self, limit: usize) -> Result<Vec<ConnRecord>> {
        let txn = self.db.begin_read()?;
        let t = txn.open_table(CONN)?;
        let mut out = Vec::new();
        for entry in t.iter()?.rev() {
            let (_, v) = entry?;
            if let Ok(r) = serde_json::from_slice(&self.open_val(v.value())?) {
                out.push(r);
            }
            if out.len() >= limit {
                break;
            }
        }
        Ok(out)
    }

    pub fn list_ips(&self, limit: usize) -> Result<Vec<(String, IpAgg)>> {
        let txn = self.db.begin_read()?;
        let t = txn.open_table(IP)?;
        let mut out = Vec::new();
        for entry in t.iter()? {
            let (_, v) = entry?;
            let agg: IpAgg = serde_json::from_slice(&self.open_val(v.value())?).unwrap_or_default();
            out.push((agg.ip.clone(), agg));
        }
        out.sort_by(|a, b| b.1.last_ms.cmp(&a.1.last_ms));
        out.truncate(limit);
        Ok(out)
    }

    /// 小时桶序列（近 `hours` 小时内的所有点，键中的 hmac 已还原为节点名）。
    pub fn hour_series(&self, from_bucket: u64) -> Result<Vec<SeriesPoint>> {
        let map = self.node_names()?;
        let txn = self.db.begin_read()?;
        let t = txn.open_table(HOUR)?;
        let mut out = Vec::new();
        for entry in t.iter()? {
            let (k, v) = entry?;
            let key = k.value().to_string();
            let mut parts = key.split('|');
            let bucket = parts.next().and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
            let h = parts.next().unwrap_or("");
            if bucket < from_bucket {
                continue;
            }
            let (u, d, c) = self.decode_triple(v.value())?;
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
        let txn = self.db.begin_read()?;
        let t = txn.open_table(MONTH)?;
        let mut out = Vec::new();
        for entry in t.iter()? {
            let (k, v) = entry?;
            let key = k.value().to_string();
            let mut parts = key.split('|');
            let bucket = parts.next().unwrap_or("").to_string();
            let h = parts.next().unwrap_or("").to_string();
            let (u, d, c) = self.decode_triple(v.value())?;
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
        let txn = self.db.begin_write()?;

        let mut removed_up = 0u64;
        let mut removed_down = 0u64;
        let mut removed_conns = 0u64;

        // ── MONTH ────────────────────────────────────────────────────────────
        {
            let mut t = txn.open_table(MONTH)?;
            let keys: Vec<String> = t.iter()?.filter_map(|e| e.ok()).map(|(k, _)| k.value().to_string()).collect();
            let mut victims: Vec<String> = Vec::new();
            for key in &keys {
                let m = key.split('|').next().and_then(|s| s.parse::<u32>().ok());
                let hit = match month {
                    None => true,
                    Some(mm) => m == Some(mm),
                };
                if hit {
                    victims.push(key.clone());
                }
            }
            for key in victims {
                if let Some(v) = t.remove(key.as_str())? {
                    let (u, d, _) = self.decode_triple(v.value())?;
                    removed_up += u;
                    removed_down += d;
                }
            }
        }

        // ── HOUR ─────────────────────────────────────────────────────────────
        {
            let mut t = txn.open_table(HOUR)?;
            let keys: Vec<String> = t.iter()?.filter_map(|e| e.ok()).map(|(k, _)| k.value().to_string()).collect();
            let mut victims: Vec<String> = Vec::new();
            for key in &keys {
                let bucket = key.split('|').next().and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
                let hit = match month {
                    None => true,
                    Some(mm) => month_bucket(bucket.saturating_mul(3_600_000)) == mm,
                };
                if hit {
                    victims.push(key.clone());
                }
            }
            for key in victims {
                t.remove(key.as_str())?;
            }
        }

        // ── CONN ─────────────────────────────────────────────────────────────
        {
            let mut t = txn.open_table(CONN)?;
            let mut victims: Vec<u64> = Vec::new();
            for entry in t.iter()? {
                let (k, v) = entry?;
                let hit = match month {
                    None => true,
                    Some(mm) => {
                        let rec: Option<ConnRecord> =
                            serde_json::from_slice(&self.open_val(v.value()).unwrap_or_default()).ok();
                        rec.map(|r| month_bucket(r.ts_ms) == mm).unwrap_or(false)
                    }
                };
                if hit {
                    victims.push(k.value());
                }
            }
            for key in victims {
                t.remove(key)?;
                removed_conns += 1;
            }
        }

        // ── IP（仅在清空全部时重置；按月清理保留历史 IP 聚合）─────────────────
        if month.is_none() {
            let mut t = txn.open_table(IP)?;
            let keys: Vec<String> = t.iter()?.filter_map(|e| e.ok()).map(|(k, _)| k.value().to_string()).collect();
            for key in keys {
                t.remove(key.as_str())?;
            }
        }

        // ── META ─────────────────────────────────────────────────────────────
        {
            let mut t = txn.open_table(META)?;
            if month.is_none() {
                self.write_u64(&mut t, "total_up", 0)?;
                self.write_u64(&mut t, "total_down", 0)?;
                self.write_u64(&mut t, "total_conns", 0)?;
            } else {
                let up = self.read_u64(&t, "total_up")?.saturating_sub(removed_up);
                let down = self.read_u64(&t, "total_down")?.saturating_sub(removed_down);
                let conns = self.read_u64(&t, "total_conns")?.saturating_sub(removed_conns);
                self.write_u64(&mut t, "total_up", up)?;
                self.write_u64(&mut t, "total_down", down)?;
                self.write_u64(&mut t, "total_conns", conns)?;
            }
        }

        txn.commit()?;
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

    /// 读辅助：兼容读事务的 `ReadOnlyTable` 与写事务的 `Table`。
    fn read_u64<T>(&self, t: &T, key: &str) -> Result<u64>
    where
        T: redb::ReadableTable<&'static str, &'static [u8]>,
    {
        Ok(t.get(key)
            .ok()
            .flatten()
            .and_then(|g| self.open_val(g.value()).ok())
            .and_then(|v| String::from_utf8(v).ok())
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0))
    }

    fn write_u64(
        &self,
        t: &mut redb::Table<'_, &'static str, &'static [u8]>,
        key: &str,
        value: u64,
    ) -> Result<()> {
        let enc = self.seal(value.to_string().as_bytes())?;
        t.insert(key, enc.as_slice())?;
        Ok(())
    }
}

/// 把 `&str → [up, down, conns]` 的计数累加（值加密存储）。
fn bump(
    key: &MasterKey,
    t: &mut redb::Table<'_, &'static str, &'static [u8]>,
    k: &str,
    du: u64,
    dd: u64,
    dc: u64,
) -> Result<()> {
    let old: Vec<u8> = t.get(k)?.map(|g| g.value().to_vec()).unwrap_or_default();
    let [u, d, c] = match key.open(&old) {
        Ok(raw) => serde_json::from_slice::<[u64; 3]>(&raw).unwrap_or([0, 0, 0]),
        Err(_) => [0, 0, 0],
    };
    let s = format!("[{},{},{}]", u + du, d + dd, c + dc);
    let enc = key.seal(s.as_bytes())?;
    t.insert(k, enc.as_slice())?;
    Ok(())
}

fn next_conn_id() -> u64 {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let base = now_ms() << 12;
    SEQ.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |prev| {
        Some(std::cmp::max(prev, base) + 1)
    })
    .unwrap_or_else(|_| base + 1)
}

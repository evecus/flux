//! redb 持久化层。
//!
//! redb 是同步阻塞 API，且数据文件为单进程独占，因此所有数据库操作都由调用方
//! 放到 `spawn_blocking` 中执行；写入统一走 [`Db::flush`] 的单个写事务。
//! 数据**不会自动过期、不会自动清理**，只能由面板的「清理数据」触发 [`Db::clear`]。

use anyhow::{Context, Result};
use redb::{Database, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use super::{hour_bucket, month_bucket, now_ms, ConnRecord};

const CONN: TableDefinition<u64, &[u8]> = TableDefinition::new("conn");
const HOUR: TableDefinition<&str, &[u8]> = TableDefinition::new("hour");
const MONTH: TableDefinition<&str, &[u8]> = TableDefinition::new("month");
const IP: TableDefinition<&str, &[u8]> = TableDefinition::new("ip");
const META: TableDefinition<&str, &[u8]> = TableDefinition::new("meta");

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IpAgg {
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
}

impl Db {
    pub fn open(path: &Path) -> Result<Self> {
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
            let _ = txn.open_table(HOUR)?;
            let _ = txn.open_table(MONTH)?;
            let _ = txn.open_table(IP)?;
            let _ = txn.open_table(META)?;
            txn.commit()?;
        }
        tracing::info!("[stats] 数据库: {}", path.display());
        Ok(Self { db })
    }

    pub fn load_totals(&self) -> Result<(u64, u64, u64)> {
        let txn = self.db.begin_read()?;
        let t = txn.open_table(META)?;
        Ok((
            read_u64(&t, "total_up"),
            read_u64(&t, "total_down"),
            read_u64(&t, "total_conns"),
        ))
    }

    /// 一批增量 + 一批连接记录，单个写事务完成。
    /// `deltas` 为 `(节点名, 上行增量, 下行增量)`。
    pub fn flush(&self, deltas: &[(String, u64, u64)], records: &[ConnRecord]) -> Result<()> {
        let now = now_ms();
        let hour = hour_bucket(now);
        let month = month_bucket(now);
        let txn = self.db.begin_write()?;

        {
            let mut t = txn.open_table(HOUR)?;
            for (node, du, dd) in deltas {
                bump(&mut t, &format!("{hour}|{node}"), *du, *dd, 0)?;
            }
        }
        {
            let mut t = txn.open_table(MONTH)?;
            for (node, du, dd) in deltas {
                bump(&mut t, &format!("{month}|{node}"), *du, *dd, 0)?;
            }
        }
        {
            let mut t = txn.open_table(CONN)?;
            for rec in records {
                let bytes = serde_json::to_vec(rec)?;
                t.insert(next_conn_id(), bytes.as_slice())?;
            }
        }
        {
            let mut t = txn.open_table(IP)?;
            for rec in records {
                if rec.ip.is_empty() {
                    continue;
                }
                let old: Vec<u8> = {
                    t.get(rec.ip.as_str())?
                        .map(|g| g.value().to_vec())
                        .unwrap_or_default()
                };
                let mut agg: IpAgg = serde_json::from_slice(&old).unwrap_or_default();
                if agg.first_ms == 0 || rec.ts_ms < agg.first_ms {
                    agg.first_ms = rec.ts_ms;
                }
                agg.last_ms = agg.last_ms.max(rec.ts_ms);
                agg.count += 1;
                let bytes = serde_json::to_vec(&agg)?;
                t.insert(rec.ip.as_str(), bytes.as_slice())?;
            }
        }
        {
            let mut t = txn.open_table(META)?;
            let du: u64 = deltas.iter().map(|x| x.1).sum();
            let dd: u64 = deltas.iter().map(|x| x.2).sum();
            let up = read_u64(&t, "total_up").saturating_add(du);
            let down = read_u64(&t, "total_down").saturating_add(dd);
            let conns = read_u64(&t, "total_conns").saturating_add(records.len() as u64);
            write_u64(&mut t, "total_up", up)?;
            write_u64(&mut t, "total_down", down)?;
            write_u64(&mut t, "total_conns", conns)?;
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
            let (u, d, _) = decode_triple(v.value());
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
            if let Ok(r) = serde_json::from_slice::<ConnRecord>(v.value()) {
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
            let (k, v) = entry?;
            let agg: IpAgg = serde_json::from_slice(v.value()).unwrap_or_default();
            out.push((k.value().to_string(), agg));
        }
        out.sort_by(|a, b| b.1.last_ms.cmp(&a.1.last_ms));
        out.truncate(limit);
        Ok(out)
    }

    /// 小时桶序列（近 `hours` 小时内的所有点，按 key 返回，前端聚合）。
    pub fn hour_series(&self, from_bucket: u64) -> Result<Vec<SeriesPoint>> {
        let txn = self.db.begin_read()?;
        let t = txn.open_table(HOUR)?;
        let mut out = Vec::new();
        for entry in t.iter()? {
            let (k, v) = entry?;
            let key = k.value().to_string();
            let bucket = key
                .split('|')
                .next()
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0);
            if bucket < from_bucket {
                continue;
            }
            let (u, d, c) = decode_triple(v.value());
            out.push(SeriesPoint { key, up: u, down: d, conns: c });
        }
        Ok(out)
    }

    pub fn month_series(&self) -> Result<Vec<SeriesPoint>> {
        let txn = self.db.begin_read()?;
        let t = txn.open_table(MONTH)?;
        let mut out = Vec::new();
        for entry in t.iter()? {
            let (k, v) = entry?;
            let (u, d, c) = decode_triple(v.value());
            out.push(SeriesPoint {
                key: k.value().to_string(),
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
                    let (u, d, _) = decode_triple(v.value());
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
                        let rec: Option<ConnRecord> = serde_json::from_slice(v.value()).ok();
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
                write_u64(&mut t, "total_up", 0)?;
                write_u64(&mut t, "total_down", 0)?;
                write_u64(&mut t, "total_conns", 0)?;
            } else {
                let up = read_u64(&t, "total_up").saturating_sub(removed_up);
                let down = read_u64(&t, "total_down").saturating_sub(removed_down);
                let conns = read_u64(&t, "total_conns").saturating_sub(removed_conns);
                write_u64(&mut t, "total_up", up)?;
                write_u64(&mut t, "total_down", down)?;
                write_u64(&mut t, "total_conns", conns)?;
            }
        }

        txn.commit()?;
        Ok(())
    }
}

// ── 辅助 ────────────────────────────────────────────────────────────────────

type StrTable<'a> = redb::Table<'a, &'static str, &'static [u8]>;

/// 把 `&str → [up, down, conns]` 的计数累加。
fn bump(t: &mut StrTable<'_>, key: &str, du: u64, dd: u64, dc: u64) -> Result<()> {
    let old: Vec<u8> = t.get(key)?.map(|g| g.value().to_vec()).unwrap_or_default();
    let (u, d, c) = decode_triple(&old);
    let s = format!("[{},{},{}]", u + du, d + dd, c + dc);
    t.insert(key, s.as_bytes())?;
    Ok(())
}

fn decode_triple(v: &[u8]) -> (u64, u64, u64) {
    match serde_json::from_slice::<[u64; 3]>(v) {
        Ok(a) => (a[0], a[1], a[2]),
        Err(_) => (0, 0, 0),
    }
}

/// 同时适用于写事务的 `Table` 与读事务的 `ReadOnlyTable`。
fn read_u64<T>(t: &T, key: &str) -> u64
where
    T: redb::ReadableTable<&'static str, &'static [u8]>,
{
    t.get(key)
        .ok()
        .flatten()
        .and_then(|g| std::str::from_utf8(g.value()).ok().map(|s| s.to_string()))
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0)
}

fn write_u64(t: &mut StrTable<'_>, key: &str, value: u64) -> Result<()> {
    let s = value.to_string();
    t.insert(key, s.as_bytes())?;
    Ok(())
}

fn next_conn_id() -> u64 {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let base = now_ms() << 12;
    SEQ.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |prev| {
        Some(std::cmp::max(prev, base) + 1)
    })
    .unwrap_or(base + 1)
}

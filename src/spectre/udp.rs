//! Spectre UDP 会话管理与 datagram 分片重组。
//!
//! 从 spectre-master `src/protocol/udp.rs` 移植服务端所需部分
//! （客户端侧的 `ClientUdpMap` / `datagram_reassemble_loop` /
//! `send_udp_over_quic` 等不下沉：flux 是纯服务端，binary crate 里
//! 未使用的函数会触发 dead_code）。
//!
//! ## 与上游 spectre 的差异（会话读模型）
//!
//! 上游服务端每收到一个 datagram 只“轮询几个回包”（50ms 一次 +
//! 8×20ms），超过约 210ms 才到达的回包会被丢弃，对慢速 DNS 等场景
//! 会丢响应。flux 适配版改为**每会话一个长连接读任务**：会话创建时
//! spawn，循环 `recv_from`（带空闲超时），把每个回包分片后经
//! `conn.send_datagram` 推回客户端；读任务退出（空闲超时 / 通道错误 /
//! 连接断开）时自行从会话表移除。线格式不变，与 spectre 客户端兼容。

use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::{Buf, Bytes, BytesMut};
use quinn_jls as quinn;
use tokio::sync::Mutex;
use tracing::debug;

use crate::common::outbound::{Outbound, UdpRelay};
use crate::spectre::protocol::{Address, ProtocolError, UdpHeader};

/// 每连接最大未完成重组槽位数。
const MAX_REASSEMBLY_SLOTS: usize = 256;
/// 丢弃超过该年龄的未完成分片包。
const REASSEMBLY_TTL: Duration = Duration::from_secs(5);
/// 接受的最大分片数。
const MAX_FRAGMENTS: u8 = 64;
/// 单个 QUIC datagram（头之前）尝试装载的最大载荷。
pub const DEFAULT_MAX_DATAGRAM_PAYLOAD: usize = 1200;
/// UDP 接收缓冲区大小。
const UDP_BUF_SIZE: usize = 65535;

/// 飞行中分片包的键。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FragKey {
    session_id: u32,
    packet_id: u16,
}

#[derive(Debug)]
struct FragSlot {
    total: u8,
    parts: HashMap<u8, Bytes>,
    address: Address,
    created: Instant,
}

impl FragSlot {
    fn new(total: u8, address: Address) -> Self {
        Self {
            total,
            parts: HashMap::new(),
            address,
            created: Instant::now(),
        }
    }

    fn insert(&mut self, id: u8, data: Bytes) -> Option<(Address, Bytes)> {
        if id >= self.total {
            return None;
        }
        self.parts.insert(id, data);
        if self.parts.len() == self.total as usize {
            let mut out = BytesMut::new();
            for i in 0..self.total {
                let p = self.parts.remove(&i)?;
                out.extend_from_slice(&p);
            }
            Some((self.address.clone(), out.freeze()))
        } else {
            None
        }
    }
}

/// 重组 Spectre UDP datagram（可能分片）。
pub struct FragmentReassembler {
    slots: HashMap<FragKey, FragSlot>,
}

impl Default for FragmentReassembler {
    fn default() -> Self {
        Self::new()
    }
}

impl FragmentReassembler {
    pub fn new() -> Self {
        Self {
            slots: HashMap::new(),
        }
    }

    /// 喂入一个 datagram 载荷（已解密的 QUIC datagram 体）。
    /// 完整包就绪时返回 `Some((session_id, address, full_payload))`。
    pub fn push(&mut self, data: Bytes) -> Result<Option<(u32, Address, Bytes)>, ProtocolError> {
        self.gc();
        let mut buf = data.clone();
        let header = UdpHeader::decode(&mut buf)?;
        let payload = buf.copy_to_bytes(buf.remaining());

        if header.fragment_count == 0 || header.fragment_count > MAX_FRAGMENTS {
            return Err(ProtocolError::BufferTooShort);
        }

        // 未分片快路径
        if header.fragment_count == 1 {
            return Ok(Some((header.session_id, header.address, payload)));
        }

        let key = FragKey {
            session_id: header.session_id,
            packet_id: header.packet_id,
        };

        if self.slots.len() >= MAX_REASSEMBLY_SLOTS && !self.slots.contains_key(&key) {
            // 淘汰最旧的
            if let Some(old) = self
                .slots
                .iter()
                .min_by_key(|(_, s)| s.created)
                .map(|(k, _)| *k)
            {
                self.slots.remove(&old);
            }
        }

        let slot = self
            .slots
            .entry(key)
            .or_insert_with(|| FragSlot::new(header.fragment_count, header.address.clone()));

        if slot.total != header.fragment_count {
            // 分片数不一致 —— 丢弃该槽
            self.slots.remove(&key);
            return Ok(None);
        }

        if let Some((addr, full)) = slot.insert(header.fragment_id, payload) {
            self.slots.remove(&key);
            Ok(Some((header.session_id, addr, full)))
        } else {
            Ok(None)
        }
    }

    fn gc(&mut self) {
        let now = Instant::now();
        self.slots
            .retain(|_, s| now.duration_since(s.created) < REASSEMBLY_TTL);
    }
}

/// 把大 UDP 载荷切成可装入 `max_datagram` 的 Spectre 分片。
pub fn fragment_udp(
    session_id: u32,
    packet_id: u16,
    address: &Address,
    payload: &[u8],
    max_datagram: usize,
) -> Vec<Bytes> {
    // 估算头长：4+2+1+1 + 2+addr + 余量
    let addr_len = address.to_socket_addr_string().len() + 2;
    let hdr_overhead = 4 + 2 + 1 + 1 + addr_len + 8;
    let max_payload = max_datagram.saturating_sub(hdr_overhead).max(200);

    if payload.len() <= max_payload {
        let mut buf = BytesMut::with_capacity(hdr_overhead + payload.len());
        let h = UdpHeader {
            session_id,
            packet_id,
            fragment_id: 0,
            fragment_count: 1,
            address: address.clone(),
        };
        h.encode(&mut buf);
        buf.extend_from_slice(payload);
        return vec![buf.freeze()];
    }

    let chunks: Vec<&[u8]> = payload.chunks(max_payload).collect();
    let total = chunks.len().min(MAX_FRAGMENTS as usize) as u8;
    let mut out = Vec::with_capacity(total as usize);
    for (i, chunk) in chunks.iter().enumerate().take(total as usize) {
        let mut buf = BytesMut::with_capacity(hdr_overhead + chunk.len());
        let h = UdpHeader {
            session_id,
            packet_id,
            fragment_id: i as u8,
            fragment_count: total,
            address: address.clone(),
        };
        h.encode(&mut buf);
        buf.extend_from_slice(chunk);
        out.push(buf.freeze());
    }
    out
}

// ── 会话表 ────────────────────────────────────────────────────────────────

/// 每连接的 UDP 会话表：`session_id` → 出站通道。
///
/// 会话生命周期 = 读任务生命周期：读任务因空闲超时 / 通道错误 / 连接
/// 断开退出时自行从表中移除，不需要额外的 GC 任务。
pub type SessionTable = Arc<Mutex<HashMap<u32, Arc<UdpRelay>>>>;

pub fn new_session_table() -> SessionTable {
    Arc::new(Mutex::new(HashMap::new()))
}

/// 创建 / 获取会话所需的上下文（每连接一份）。
pub struct SessionCtx<'a> {
    pub outbound: &'a Outbound,
    /// 是否中继 IPv6 UDP（`udp-relay-ipv6`）。
    pub v6: bool,
    /// 回包经此连接推回客户端。
    pub conn: quinn::Connection,
    /// 回包 packet_id 分配器（每连接共享）。
    pub packet_id: Arc<AtomicU16>,
    /// 会话空闲超时。
    pub idle: Duration,
}

/// 确保会话存在（不存在则按出站配置建通道并 spawn 读任务），返回通道。
pub async fn get_or_create_session(
    table: &SessionTable,
    session_id: u32,
    ctx: &SessionCtx<'_>,
) -> io::Result<Arc<UdpRelay>> {
    if let Some(s) = table.lock().await.get(&session_id) {
        return Ok(Arc::clone(s));
    }

    let relay = Arc::new(UdpRelay::bind(ctx.outbound, ctx.v6).await?);
    table
        .lock()
        .await
        .insert(session_id, Arc::clone(&relay));

    // 长连接读任务：目标 → 客户端。
    let relay_reader = Arc::clone(&relay);
    let table_reader = Arc::clone(table);
    let conn = ctx.conn.clone();
    let packet_id = Arc::clone(&ctx.packet_id);
    let idle = ctx.idle;
    tokio::spawn(async move {
        let mut buf = vec![0u8; UDP_BUF_SIZE];
        loop {
            match tokio::time::timeout(idle, relay_reader.recv_from(&mut buf)).await {
                Ok(Ok((n, from))) => {
                    let addr = Address::new(from.ip().to_string(), from.port());
                    let pid = packet_id.fetch_add(1, Ordering::Relaxed);
                    let frames = fragment_udp(
                        session_id,
                        pid,
                        &addr,
                        &buf[..n],
                        DEFAULT_MAX_DATAGRAM_PAYLOAD,
                    );
                    let mut alive = true;
                    for frame in frames {
                        if conn.send_datagram(frame).is_err() {
                            alive = false;
                            break;
                        }
                    }
                    if !alive {
                        break;
                    }
                }
                Ok(Err(e)) => {
                    debug!("[spectre][udp] session {session_id} recv: {e}");
                    break;
                }
                Err(_) => {
                    // 空闲超时
                    debug!("[spectre][udp] session {session_id} idle timeout ({idle:?})");
                    break;
                }
            }
        }
        table_reader.lock().await.remove(&session_id);
    });

    Ok(relay)
}

/// 把 Address 解析为 SocketAddr（tokio 异步 DNS）。
pub async fn resolve_address(addr: &Address) -> io::Result<std::net::SocketAddr> {
    let s = addr.to_socket_addr_string();
    let mut it = tokio::net::lookup_host(s.clone()).await?;
    match it.next() {
        Some(a) => Ok(a),
        None => Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("resolve failed: {s}"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn udp_header_bytes(h: &UdpHeader) -> Bytes {
        let mut buf = BytesMut::new();
        h.encode(&mut buf);
        buf.freeze()
    }

    #[test]
    fn reasm_single_fragment() {
        let mut reasm = FragmentReassembler::new();
        let h = UdpHeader {
            session_id: 1,
            packet_id: 1,
            fragment_id: 0,
            fragment_count: 1,
            address: Address::new("8.8.8.8", 53),
        };
        let mut buf = BytesMut::new();
        h.encode(&mut buf);
        buf.extend_from_slice(b"query");
        let out = reasm.push(buf.freeze()).unwrap().unwrap();
        assert_eq!(out.0, 1);
        assert_eq!(&out.2[..], b"query");
    }

    #[test]
    fn reasm_two_fragments() {
        let mut reasm = FragmentReassembler::new();
        let addr = Address::new("1.1.1.1", 53);
        // 分 2 片，每片 3 字节
        for (i, part) in [b"aaa".as_slice(), b"bbb".as_slice()].iter().enumerate() {
            let h = UdpHeader {
                session_id: 7,
                packet_id: 9,
                fragment_id: i as u8,
                fragment_count: 2,
                address: addr.clone(),
            };
            let mut buf = BytesMut::new();
            h.encode(&mut buf);
            buf.extend_from_slice(part);
            let out = reasm.push(buf.freeze()).unwrap();
            if i == 0 {
                assert!(out.is_none(), "第一片不应完成重组");
            } else {
                let (sid, a, full) = out.unwrap();
                assert_eq!(sid, 7);
                assert_eq!(a.port, 53);
                assert_eq!(&full[..], b"aaabbb");
            }
        }
    }

    #[test]
    fn fragment_udp_roundtrip() {
        let addr = Address::new("8.8.8.8", 53);
        // 小包：单片
        let frames = fragment_udp(3, 1, &addr, b"small", DEFAULT_MAX_DATAGRAM_PAYLOAD);
        assert_eq!(frames.len(), 1);
        let mut reasm = FragmentReassembler::new();
        let out = reasm.push(frames[0].clone()).unwrap().unwrap();
        assert_eq!(&out.2[..], b"small");

        // 大包：强制 max_datagram 很小 → 多片，可被同一 reasm 重组
        let payload: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
        let frames = fragment_udp(4, 2, &addr, &payload, 300);
        assert!(frames.len() > 1);
        let mut reasm = FragmentReassembler::new();
        let mut result = None;
        for f in &frames {
            if let Some(v) = reasm.push(f.clone()).unwrap() {
                result = Some(v);
            }
        }
        let (_, _, full) = result.expect("所有分片应重组完整");
        assert_eq!(&full[..], &payload[..]);
    }

    #[test]
    fn reasm_rejects_zero_fragment_count() {
        let mut reasm = FragmentReassembler::new();
        let h = UdpHeader {
            session_id: 1,
            packet_id: 1,
            fragment_id: 0,
            fragment_count: 0,
            address: Address::new("8.8.8.8", 53),
        };
        assert!(reasm.push(udp_header_bytes(&h)).is_err());
    }

    #[tokio::test]
    async fn resolve_address_ip_literal() {
        let a = Address::new("127.0.0.1", 53);
        let sa = resolve_address(&a).await.unwrap();
        assert_eq!(sa.port(), 53);
        assert!(sa.is_ipv4());
    }
}

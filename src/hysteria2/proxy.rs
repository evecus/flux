//! 代理出站模块：TCP 双向转发 + UDP 关联（含分片重组）

use anyhow::Result;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::{timeout, Duration};
use tracing::{debug, warn};

use crate::common::net::{self as shared_net, OutboundBind};
use crate::hysteria2::auth::write_tcp_response;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const UDP_MAX_PKT: usize = 65507;

// Hysteria2 QUIC datagram 的安全最大载荷（QUIC MTU 1200 - 帧头余量）
// 超过此大小的 UDP 回包需要分片发送
const DATAGRAM_MAX_PAYLOAD: usize = 1100;

// ── TCP proxy ─────────────────────────────────────────────────────────────────

pub async fn handle_tcp_stream(
    mut quic_send: quinn::SendStream,
    mut quic_recv: quinn::RecvStream,
    target: String,
    bind_ip: OutboundBind,
) -> Result<()> {
    debug!("TCP proxy → {target}");

    let tcp = match timeout(CONNECT_TIMEOUT, shared_net::dial_tcp(&target, bind_ip)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            warn!("Connect to {target} failed: {e}");
            write_tcp_response(&mut quic_send, false, &e.to_string()).await?;
            // 显式 flush：确保响应字节在 finish() 之前已提交到 Quinn 发送缓冲
            let _ = quic_send.flush().await;
            let _ = quic_send.finish();
            return Ok(());
        }
        Err(_) => {
            warn!("Connect to {target} timed out");
            write_tcp_response(&mut quic_send, false, "connection timeout").await?;
            let _ = quic_send.flush().await;
            let _ = quic_send.finish();
            return Ok(());
        }
    };

    // 连接成功，先写响应再 flush，保证客户端在进入转发阶段前已收到 ok。
    // 不 flush 的话：quic_send 被 move 进 t2 后，响应数据停在 Quinn 内部缓冲里，
    // 要等 t2 第一次 write_all 才会随数据一起发出——此时客户端已经在等响应了，死锁。
    write_tcp_response(&mut quic_send, true, "Connected").await?;
    quic_send.flush().await?;

    let (mut tcp_r, mut tcp_w) = tcp.into_split();

    // quic_recv → tcp_w
    let t1 = tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        loop {
            match quic_recv.read(&mut buf).await {
                Ok(Some(0)) | Ok(None) | Err(_) => break,
                Ok(Some(n)) => {
                    if tcp_w.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
        let _ = tcp_w.shutdown().await;
    });

    // tcp_r → quic_send
    let t2 = tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        loop {
            match tcp_r.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if quic_send.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                    // 每次写完都 flush，避免数据在 Quinn 缓冲区里积压导致对端卡顿
                    if quic_send.flush().await.is_err() {
                        break;
                    }
                }
            }
        }
        let _ = quic_send.finish();
    });

    let _ = tokio::join!(t1, t2);
    debug!("TCP proxy {target} closed");
    Ok(())
}

// ── UDP frame 格式 ────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct UdpFrame {
    pub session_id: u32,
    pub packet_id: u16,
    pub frag_id: u8,
    pub frag_total: u8,
    pub addr: String,
    pub port: u16,
    pub payload: Bytes,
}

fn read_varint_bytes(data: &mut Bytes) -> Result<u64> {
    anyhow::ensure!(!data.is_empty(), "varint: no data");
    let first = data.get_u8();
    let extra = (first >> 6) as usize;
    let mut val = (first & 0x3f) as u64;
    for _ in 0..extra {
        anyhow::ensure!(!data.is_empty(), "varint: truncated");
        val = (val << 8) | data.get_u8() as u64;
    }
    Ok(val)
}

fn write_varint_bytes(buf: &mut BytesMut, val: u64) {
    if val < 64 {
        buf.put_u8(val as u8);
    } else if val < 16384 {
        buf.put_u16(0x4000 | val as u16);
    } else if val < 1_073_741_824 {
        buf.put_u32(0x8000_0000 | val as u32);
    } else {
        buf.put_u64(0xc000_0000_0000_0000 | val);
    }
}

fn split_host_port(s: &str) -> Result<(String, u16)> {
    let (host, port_str) = s
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("invalid addr (no port): {s}"))?;
    let host = host.trim_matches(|c| c == '[' || c == ']').to_string();
    let port: u16 = port_str.parse()?;
    Ok((host, port))
}

pub fn parse_udp_frame(mut data: Bytes) -> Result<UdpFrame> {
    anyhow::ensure!(data.len() >= 8, "UDP frame too short ({})", data.len());

    let session_id = data.get_u32();
    let packet_id = data.get_u16();
    let frag_id = data.get_u8();
    let frag_total = data.get_u8();

    let addr_len = read_varint_bytes(&mut data)? as usize;
    anyhow::ensure!(
        addr_len > 0 && addr_len <= 2048,
        "invalid addr_len: {addr_len}"
    );
    anyhow::ensure!(data.len() >= addr_len, "UDP frame: addr truncated");
    let addr_bytes = data.split_to(addr_len);
    let addr_str = String::from_utf8(addr_bytes.to_vec())?;
    let (addr, port) = split_host_port(&addr_str)?;

    let payload = data;

    Ok(UdpFrame {
        session_id,
        packet_id,
        frag_id,
        frag_total,
        addr,
        port,
        payload,
    })
}

/// 构建单个 UDP 回包帧
fn build_single_udp_frame(
    session_id: u32,
    packet_id: u16,
    frag_id: u8,
    frag_total: u8,
    addr_str: &str,
    payload: &[u8],
) -> Bytes {
    let addr_bytes = addr_str.as_bytes();
    let addr_len = addr_bytes.len() as u64;

    let varint_sz = if addr_len < 64 {
        1
    } else if addr_len < 16384 {
        2
    } else {
        4
    };
    let total = 4 + 2 + 1 + 1 + varint_sz + addr_bytes.len() + payload.len();
    let mut buf = BytesMut::with_capacity(total);

    buf.put_u32(session_id);
    buf.put_u16(packet_id);
    buf.put_u8(frag_id);
    buf.put_u8(frag_total);
    write_varint_bytes(&mut buf, addr_len);
    buf.put_slice(addr_bytes);
    buf.put_slice(payload);
    buf.freeze()
}

/// 构建 UDP 回包帧列表（服务端 → 客户端），超过 MTU 时自动分片。
///
/// 原来写死 frag_total=1，payload 超过 QUIC MTU 时 send_datagram 会返回
/// TooLarge 错误，导致大 UDP 包（如 DNS 响应、游戏数据等）被静默丢弃。
/// 现在按 DATAGRAM_MAX_PAYLOAD 切分，每片携带相同的地址头。
pub fn build_udp_frames(
    session_id: u32,
    packet_id: u16,
    src_addr: SocketAddr,
    payload: &[u8],
) -> Vec<Bytes> {
    let addr_str = match src_addr {
        SocketAddr::V4(a) => format!("{}:{}", a.ip(), a.port()),
        SocketAddr::V6(a) => format!("[{}]:{}", a.ip(), a.port()),
    };

    if payload.len() <= DATAGRAM_MAX_PAYLOAD {
        return vec![build_single_udp_frame(
            session_id, packet_id, 0, 1, &addr_str, payload,
        )];
    }

    let chunks: Vec<&[u8]> = payload.chunks(DATAGRAM_MAX_PAYLOAD).collect();
    let frag_total = chunks.len() as u8;
    chunks
        .into_iter()
        .enumerate()
        .map(|(i, chunk)| {
            build_single_udp_frame(session_id, packet_id, i as u8, frag_total, &addr_str, chunk)
        })
        .collect()
}

// ── UDP 分片重组（客户端 → 服务端方向） ──────────────────────────────────────

struct FragBuffer {
    total: u8,
    received: u8,
    frags: HashMap<u8, Bytes>,
    addr: String,
    port: u16,
}

impl FragBuffer {
    fn new(total: u8, addr: String, port: u16) -> Self {
        Self {
            total,
            received: 0,
            frags: HashMap::new(),
            addr,
            port,
        }
    }

    fn insert(&mut self, frag_id: u8, payload: Bytes) -> Option<(Bytes, String, u16)> {
        self.frags.entry(frag_id).or_insert(payload);
        self.received += 1;

        if self.received >= self.total {
            let mut ids: Vec<u8> = self.frags.keys().cloned().collect();
            ids.sort_unstable();
            let total_len: usize = ids.iter().map(|id| self.frags[id].len()).sum();
            let mut buf = BytesMut::with_capacity(total_len);
            for id in ids {
                buf.extend_from_slice(&self.frags[&id]);
            }
            Some((buf.freeze(), self.addr.clone(), self.port))
        } else {
            None
        }
    }
}

// ── UDP session 管理 ──────────────────────────────────────────────────────────

pub async fn handle_udp_session(
    session_id: u32,
    first_frame: UdpFrame,
    mut rx: mpsc::Receiver<UdpFrame>,
    send_datagram: Arc<dyn Fn(Bytes) -> Result<()> + Send + Sync>,
    bind_ip: OutboundBind,
) -> Result<()> {
    debug!("UDP session {session_id} started");

    let sock = Arc::new(shared_net::bind_udp(bind_ip, false).await?);

    let mut frag_table: HashMap<u16, FragBuffer> = HashMap::new();
    // 服务端→客户端方向的 packet_id 计数器，每个回包递增保证唯一
    let packet_id_counter = Arc::new(std::sync::atomic::AtomicU16::new(0));

    relay_frame(session_id, first_frame, &sock, &mut frag_table).await;

    let sock_recv = Arc::clone(&sock);
    let send2 = Arc::clone(&send_datagram);
    let counter2 = Arc::clone(&packet_id_counter);

    let recv_task = tokio::spawn(async move {
        let mut buf = vec![0u8; UDP_MAX_PKT];
        loop {
            match timeout(UDP_IDLE_TIMEOUT, sock_recv.recv_from(&mut buf)).await {
                Ok(Ok((n, src))) => {
                    let pid = counter2.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    // 使用 build_udp_frames 而非旧的 build_udp_frame，自动处理超 MTU 分片
                    let frames = build_udp_frames(session_id, pid, src, &buf[..n]);
                    for pkt in frames {
                        if let Err(e) = send2(pkt) {
                            debug!("UDP session {session_id}: send datagram error: {e}");
                            return;
                        }
                    }
                }
                Ok(Err(e)) => {
                    debug!("UDP session {session_id}: recv error: {e}");
                    break;
                }
                Err(_) => {
                    debug!("UDP session {session_id}: idle timeout");
                    break;
                }
            }
        }
    });

    while let Ok(Some(frame)) = timeout(UDP_IDLE_TIMEOUT, rx.recv()).await {
        relay_frame(session_id, frame, &sock, &mut frag_table).await;
    }

    recv_task.abort();
    debug!("UDP session {session_id} closed");
    Ok(())
}

async fn relay_frame(
    session_id: u32,
    frame: UdpFrame,
    sock: &UdpSocket,
    frag_table: &mut HashMap<u16, FragBuffer>,
) {
    let target = format!("{}:{}", frame.addr, frame.port);

    if frame.frag_total <= 1 {
        if let Err(e) = sock.send_to(&frame.payload, &target).await {
            warn!("UDP session {session_id}: send_to {target} error: {e}");
        }
        return;
    }

    let buf = frag_table
        .entry(frame.packet_id)
        .or_insert_with(|| FragBuffer::new(frame.frag_total, frame.addr.clone(), frame.port));

    if let Some((reassembled, addr, port)) = buf.insert(frame.frag_id, frame.payload) {
        frag_table.remove(&frame.packet_id);
        let reassembled_target = format!("{addr}:{port}");
        if let Err(e) = sock.send_to(&reassembled, &reassembled_target).await {
            warn!(
                "UDP session {session_id}: send_to {reassembled_target} (reassembled) error: {e}"
            );
        } else {
            debug!(
                "UDP session {session_id}: sent reassembled {} bytes → {reassembled_target}",
                reassembled.len()
            );
        }
    }
}

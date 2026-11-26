//! Spectre 的 Brutal 风格拥塞控制（quinn-jls `congestion::Controller`）。
//!
//! 从 spectre-master `src/protocol/brutal.rs` 移植。遵循 Hysteria2 设计：
//!
//! * 发送方被给定一个**目标速率**（字节/秒），不因丢包像 Cubic/BBR
//!   那样退让。
//! * 丢包用 5 秒滑窗内按秒分桶的 **ack rate** 度量
//!   （`acked / (acked + lost)`，下限 0.8）。
//! * `cwnd = target_bps * RTT * CWND_GAIN / ack_rate`。丢包由 QUIC 重传
//!   兜底，除以 ack rate 使 goodput 贴近目标速率。
//! * quinn 从窗口推导 pacing（`window * 1.25 / srtt`），无需独立 pacer。
//! * 目标速率 `0` = 关闭 Brutal，交还 quinn 的 BBR。
//!
//! 速率存放在共享的 [`BrutalHandle`] 中，服务端可在认证通过后（得知客户端
//! 声明的下载速率时）直接设置，无需重建连接。
//!
//! ## 与上游 spectre 的差异
//!
//! flux 固定 `quinn-proto-jls = 0.3.5`（shadowquic 0.3.7 依赖该版本；
//! 0.3.6+ 改了 `Controller` trait 签名），其 `on_congestion_event` 没有
//! `is_ecn` 参数，故此处按 0.3.5 的 4 参签名实现（ECN 触发时
//! `lost_bytes == 0`，同样被 Brutal 忽略）。

use quinn_jls as quinn;
use quinn::congestion::{BbrConfig, Controller, ControllerFactory};
use quinn_proto_jls::RttEstimator;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// ack-rate 窗口的秒桶数量（与 Hysteria 相同）。
const SLOT_COUNT: u64 = 5;
/// 观测字节数少于此值前忽略丢包估计（约 50 个满尺寸包，同 Hysteria 的
/// `minSampleCount`）。
const MIN_SAMPLE_BYTES: u64 = 50 * 1200;
/// ack rate 下限。补偿上限 1/0.8 = 1.25 倍。
const MIN_ACK_RATE: f64 = 0.8;
/// 相对一个 BDP 的窗口余量。
///
/// quinn 按 `window * 1.25 / srtt` pacing，实际 pacing 速率约为
/// `CWND_GAIN * 1.25 * target / ack_rate`。Hysteria 用 2.0（自带 pacer）；
/// 用 quinn 的 pacer 需要更小的值，否则发送速率超出声明值 2.5 倍并
/// 自我制造丢包。
const CWND_GAIN: f64 = 1.2;
/// 窗口下限（包数）。
const MIN_WINDOW_PACKETS: u64 = 16;
/// 窗口上限（字节）。
const MAX_WINDOW: u64 = 128 * 1024 * 1024;
/// 首个样本到达前使用的 RTT。
const DEFAULT_RTT: Duration = Duration::from_millis(150);

// ── 共享速率句柄 ──────────────────────────────────────────────────────────

/// 共享的线程安全目标速率（**字节/秒**，0 = 关闭 Brutal）。
#[derive(Clone, Debug)]
pub struct BrutalHandle(Arc<AtomicU64>);

impl BrutalHandle {
    pub fn new(bps: u64) -> Self {
        Self(Arc::new(AtomicU64::new(bps)))
    }

    pub fn set(&self, bps: u64) {
        self.0.store(bps, Ordering::Relaxed);
    }

    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

// ── ack-rate 追踪 ─────────────────────────────────────────────────────────

#[derive(Clone, Copy, Default, Debug)]
struct Slot {
    sec: u64,
    acked: u64,
    lost: u64,
}

#[derive(Clone, Debug)]
struct AckTracker {
    start: Instant,
    slots: [Slot; SLOT_COUNT as usize],
}

impl AckTracker {
    fn new(start: Instant) -> Self {
        Self {
            start,
            slots: [Slot::default(); SLOT_COUNT as usize],
        }
    }

    fn sec(&self, now: Instant) -> u64 {
        now.saturating_duration_since(self.start).as_secs()
    }

    fn add(&mut self, now: Instant, acked: u64, lost: u64) {
        let sec = self.sec(now);
        let slot = &mut self.slots[(sec % SLOT_COUNT) as usize];
        if slot.sec != sec {
            *slot = Slot {
                sec,
                acked: 0,
                lost: 0,
            };
        }
        slot.acked += acked;
        slot.lost += lost;
    }

    /// 最近 `SLOT_COUNT` 秒的 `acked / (acked + lost)`，取值
    /// `[MIN_ACK_RATE, 1.0]`。样本不足时返回 1.0。
    fn ack_rate(&self, now: Instant) -> f64 {
        let sec = self.sec(now);
        let (mut acked, mut lost) = (0u64, 0u64);
        for s in &self.slots {
            if s.sec <= sec && sec - s.sec < SLOT_COUNT {
                acked += s.acked;
                lost += s.lost;
            }
        }
        let total = acked + lost;
        if total < MIN_SAMPLE_BYTES {
            return 1.0;
        }
        (acked as f64 / total as f64).clamp(MIN_ACK_RATE, 1.0)
    }
}

// ── 控制器 ────────────────────────────────────────────────────────────────

pub struct BrutalController {
    handle: BrutalHandle,
    /// 目标速率为 0 时的退路。
    fallback: Box<dyn Controller>,
    tracker: AckTracker,
    ack_rate: f64,
    srtt: Duration,
    mtu: u16,
}

impl BrutalController {
    fn new(handle: BrutalHandle, now: Instant, mtu: u16) -> Self {
        Self {
            handle,
            fallback: Arc::new(BbrConfig::default()).build(now, mtu),
            tracker: AckTracker::new(now),
            ack_rate: 1.0,
            srtt: DEFAULT_RTT,
            mtu,
        }
    }

    fn min_window(&self) -> u64 {
        MIN_WINDOW_PACKETS * u64::from(self.mtu)
    }
}

impl std::fmt::Debug for BrutalController {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BrutalController")
            .field("target_bps", &self.handle.get())
            .field("ack_rate", &self.ack_rate)
            .field("srtt", &self.srtt)
            .finish()
    }
}

impl Controller for BrutalController {
    fn on_sent(&mut self, now: Instant, bytes: u64, last_packet_number: u64) {
        self.fallback.on_sent(now, bytes, last_packet_number);
    }

    fn on_ack(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        app_limited: bool,
        rtt: &RttEstimator,
    ) {
        self.tracker.add(now, bytes, 0);
        self.ack_rate = self.tracker.ack_rate(now);
        self.srtt = rtt.get().max(Duration::from_millis(1));
        self.fallback.on_ack(now, sent, bytes, app_limited, rtt);
    }

    fn on_end_acks(
        &mut self,
        now: Instant,
        in_flight: u64,
        app_limited: bool,
        largest_packet_num_acked: Option<u64>,
    ) {
        self.fallback
            .on_end_acks(now, in_flight, app_limited, largest_packet_num_acked);
    }

    fn on_congestion_event(
        &mut self,
        now: Instant,
        sent: Instant,
        is_persistent_congestion: bool,
        lost_bytes: u64,
    ) {
        // ECN 触发时 lost_bytes == 0，被 Brutal 忽略（0.3.5 的签名里
        // 没有单独的 is_ecn 参数）。
        if lost_bytes > 0 {
            self.tracker.add(now, 0, lost_bytes);
            self.ack_rate = self.tracker.ack_rate(now);
        }
        self.fallback
            .on_congestion_event(now, sent, is_persistent_congestion, lost_bytes);
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.mtu = new_mtu;
        self.fallback.on_mtu_update(new_mtu);
    }

    fn window(&self) -> u64 {
        let bps = self.handle.get();
        if bps == 0 {
            return self.fallback.window();
        }
        let w = bps as f64 * self.srtt.as_secs_f64() * CWND_GAIN / self.ack_rate;
        (w as u64).clamp(self.min_window(), MAX_WINDOW)
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(BrutalController {
            handle: self.handle.clone(),
            fallback: self.fallback.clone_box(),
            tracker: self.tracker.clone(),
            ack_rate: self.ack_rate,
            srtt: self.srtt,
            mtu: self.mtu,
        })
    }

    fn initial_window(&self) -> u64 {
        if self.handle.get() == 0 {
            self.fallback.initial_window()
        } else {
            self.window()
        }
    }

    fn into_any(self: Box<Self>) -> Box<dyn std::any::Any> {
        self
    }
}

// ── 工厂与传输层调优 ──────────────────────────────────────────────────────

pub struct BrutalFactory {
    handle: BrutalHandle,
}

impl BrutalFactory {
    pub fn new(handle: BrutalHandle) -> Arc<Self> {
        Arc::new(Self { handle })
    }
}

impl ControllerFactory for BrutalFactory {
    fn build(self: Arc<Self>, now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        Box::new(BrutalController::new(self.handle.clone(), now, current_mtu))
    }
}

/// 每流接收窗口（字节）。
const STREAM_RECV_WINDOW: u32 = 16 * 1024 * 1024;
/// 每连接接收窗口（字节）。
const CONN_RECV_WINDOW: u32 = 64 * 1024 * 1024;
/// 每连接发送窗口上限（字节）。
const SEND_WINDOW: u64 = 64 * 1024 * 1024;

/// 安装 Brutal 控制器并提高 QUIC 流控上限。
///
/// quinn 默认流控窗口（约 1.2 MB/流）会把吞吐卡在 `window / RTT`，
/// 无论拥塞控制器说什么，因此 Brutal 要达到高速率必须提高它们。
pub fn tune_transport(transport: &mut quinn::TransportConfig, handle: BrutalHandle) {
    transport
        .congestion_controller_factory(BrutalFactory::new(handle))
        .stream_receive_window(quinn::VarInt::from_u32(STREAM_RECV_WINDOW))
        .receive_window(quinn::VarInt::from_u32(CONN_RECV_WINDOW))
        .send_window(SEND_WINDOW);
}

// ── 大缓冲 UDP socket ─────────────────────────────────────────────────────

/// 请求的内核 UDP 缓冲区大小。内核会按 `net.core.rmem_max` /
/// `wmem_max` 截断；高速率场景需要调大这两个 sysctl。
const SOCKET_BUF: usize = 16 * 1024 * 1024;

/// 绑定一个放大收/发缓冲的 UDP socket。
///
/// 小缓冲区会在高速率下丢包，Brutal 会把这些丢包读成网络丢包并过度补偿。
pub fn bind_udp(addr: SocketAddr) -> std::io::Result<std::net::UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let socket = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
    if addr.is_ipv6() {
        let _ = socket.set_only_v6(false);
    }
    let _ = socket.set_recv_buffer_size(SOCKET_BUF);
    let _ = socket.set_send_buffer_size(SOCKET_BUF);
    socket.bind(&addr.into())?;
    socket.set_nonblocking(true)?;
    Ok(socket.into())
}

// ── 速率解析 ──────────────────────────────────────────────────────────────

/// 把速率字符串解析为 **字节/秒**。
///
/// 服务端入站本身不解析速率（Brutal 目标速率来自客户端 AUTH 帧声明的
/// `rx_bps`，单位即字节/秒）；保留该函数 + 单测用于固化单位语义。
///
/// * `100mbps` / `1gbps` / `512kbps` / `8000bps`：比特率（同 Hysteria）。
/// * 裸整数：字节/秒。
/// * `0`：禁用（退回 BBR）。
#[cfg(test)]
pub fn parse_rate(s: &str) -> Result<u64, String> {
    let t = s.trim().to_ascii_lowercase();
    let (num, mult): (&str, f64) = if let Some(n) = t.strip_suffix("gbps") {
        (n, 1e9 / 8.0)
    } else if let Some(n) = t.strip_suffix("mbps") {
        (n, 1e6 / 8.0)
    } else if let Some(n) = t.strip_suffix("kbps") {
        (n, 1e3 / 8.0)
    } else if let Some(n) = t.strip_suffix("bps") {
        (n, 1.0 / 8.0)
    } else {
        (t.as_str(), 1.0)
    };
    let v: f64 = num
        .trim()
        .parse()
        .map_err(|_| format!("invalid rate '{s}' (examples: 100mbps, 20mbps, 12500000)"))?;
    if v < 0.0 || !v.is_finite() {
        return Err(format!("invalid rate '{s}'"));
    }
    Ok((v * mult) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn brutal_handle_shared() {
        let h = BrutalHandle::new(0);
        let h2 = h.clone();
        h2.set(125_000);
        assert_eq!(h.get(), 125_000);
    }

    #[test]
    fn parse_rate_units() {
        assert_eq!(parse_rate("100mbps").unwrap(), 100_000_000 / 8);
        assert_eq!(parse_rate("1gbps").unwrap(), 1_000_000_000 / 8);
        assert_eq!(parse_rate("512kbps").unwrap(), 512_000 / 8);
        assert_eq!(parse_rate("8000bps").unwrap(), 1000);
        assert_eq!(parse_rate("12500000").unwrap(), 12_500_000);
        assert_eq!(parse_rate("0").unwrap(), 0);
        assert!(parse_rate("fast").is_err());
    }

    #[test]
    fn ack_tracker_rate_floors() {
        let start = Instant::now();
        let mut t = AckTracker::new(start);
        // 样本不足 → 1.0
        assert_eq!(t.ack_rate(start), 1.0);
        // 大量 ack + 10% lost → 0.9（高于 0.8 下限）
        let now = start + Duration::from_secs(1);
        t.add(now, 900 * 1200, 100 * 1200);
        let r = t.ack_rate(now);
        assert!((r - 0.9).abs() < 1e-9, "got {r}");
        // 极端丢包 → 被钳到 0.8
        t.add(now, 0, 10 * 1024 * 1024);
        let r = t.ack_rate(now);
        assert!((r - 0.8).abs() < 1e-9, "got {r}");
    }
}

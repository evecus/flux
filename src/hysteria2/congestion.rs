//! Brutal 拥塞控制算法
//!
//! Brutal 不走标准的慢启动/拥塞避免，而是以固定目标速率发送，
//! 只通过丢包率动态调整实际发送速率（允许少量丢包）。
//! 这里实现 quinn 的 `congestion::Controller` trait。

#![allow(dead_code)]

use quinn::congestion::{Controller, ControllerFactory};
use quinn_proto::RttEstimator;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Brutal 配置
#[derive(Debug, Clone)]
pub struct BrutalConfig {
    /// 目标发送速率（字节/秒），0 = 不限速
    pub send_bps: u64,
}

impl Default for BrutalConfig {
    fn default() -> Self {
        Self {
            send_bps: 50 * 1024 * 1024,
        } // 50 MB/s 默认
    }
}

// ── 内部统计窗口 ───────────────────────────────────────────────────────────────

const RTT_WINDOW: usize = 16;
const GAIN: f64 = 1.5; // 超发系数，补偿丢包
const MAX_LOSS_RATIO: f64 = 0.1; // 允许最大 10% 丢包

#[derive(Debug)]
struct Stats {
    ack_count: u64,
    loss_count: u64,
    window_start: Instant,
    rtt_samples: Vec<Duration>,
}

impl Stats {
    fn new() -> Self {
        Self {
            ack_count: 0,
            loss_count: 0,
            window_start: Instant::now(),
            rtt_samples: Vec::with_capacity(RTT_WINDOW),
        }
    }

    fn loss_ratio(&self) -> f64 {
        let total = self.ack_count + self.loss_count;
        if total == 0 {
            0.0
        } else {
            self.loss_count as f64 / total as f64
        }
    }

    fn avg_rtt(&self) -> Duration {
        if self.rtt_samples.is_empty() {
            return Duration::from_millis(50);
        }
        let sum: Duration = self.rtt_samples.iter().sum();
        sum / self.rtt_samples.len() as u32
    }

    fn push_rtt(&mut self, rtt: Duration) {
        if self.rtt_samples.len() >= RTT_WINDOW {
            self.rtt_samples.remove(0);
        }
        self.rtt_samples.push(rtt);
    }

    /// 每秒重置统计窗口
    fn maybe_reset(&mut self) {
        if self.window_start.elapsed() >= Duration::from_secs(1) {
            self.ack_count = 0;
            self.loss_count = 0;
            self.window_start = Instant::now();
        }
    }
}

// ── Controller ────────────────────────────────────────────────────────────────

pub struct BrutalController {
    config: BrutalConfig,
    /// 当前拥塞窗口（字节）
    window: u64,
    stats: Arc<Mutex<Stats>>,
}

impl BrutalController {
    fn new(config: BrutalConfig) -> Self {
        let initial_window = ((config.send_bps as f64) * 0.05 * GAIN) as u64;
        let initial_window = initial_window.clamp(32 * 1024, 16 * 1024 * 1024);
        Self {
            config,
            window: initial_window,
            stats: Arc::new(Mutex::new(Stats::new())),
        }
    }

    fn recalculate_window(&mut self) {
        let stats = self.stats.lock().unwrap();
        let rtt = stats.avg_rtt();
        let loss = stats.loss_ratio();
        drop(stats);

        let rtt_secs = rtt.as_secs_f64().max(0.001);
        let target_bps = self.config.send_bps as f64;

        let base_window = target_bps * rtt_secs;

        let loss_factor = if loss > MAX_LOSS_RATIO {
            (1.0 - loss).max(0.5)
        } else {
            GAIN
        };

        self.window = ((base_window * loss_factor) as u64).clamp(32 * 1024, 32 * 1024 * 1024);
    }
}

impl std::fmt::Debug for BrutalController {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BrutalController")
            .field("window", &self.window)
            .field("target_bps", &self.config.send_bps)
            .finish()
    }
}

impl Controller for BrutalController {
    fn on_sent(&mut self, _now: Instant, _bytes: u64, _last_packet_number: u64) {}

    fn on_ack(
        &mut self,
        _now: Instant,
        sent: Instant,
        bytes: u64,
        _app_limited: bool,
        rtt: &RttEstimator,
    ) {
        {
            let mut stats = self.stats.lock().unwrap();
            stats.ack_count += bytes;
            stats.push_rtt(rtt.get());
            stats.maybe_reset();
        }
        let _ = sent;
        self.recalculate_window();
    }

    fn on_congestion_event(
        &mut self,
        _now: Instant,
        _sent: Instant,
        _is_persistent_congestion: bool,
        _lost_bytes: u64,
    ) {
        let mut stats = self.stats.lock().unwrap();
        stats.loss_count += 1;
        stats.maybe_reset();
        drop(stats);
        self.recalculate_window();
    }

    fn on_mtu_update(&mut self, _new_mtu: u16) {}

    fn initial_window(&self) -> u64 {
        self.window
    }

    fn window(&self) -> u64 {
        self.window
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(BrutalController {
            config: self.config.clone(),
            window: self.window,
            stats: Arc::clone(&self.stats),
        })
    }

    fn into_any(self: Box<Self>) -> Box<dyn std::any::Any> {
        self
    }
}

// ── Factory ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct BrutalFactory {
    pub config: BrutalConfig,
}

impl ControllerFactory for BrutalFactory {
    fn build(self: Arc<Self>, _now: Instant, _current_mtu: u16) -> Box<dyn Controller> {
        Box::new(BrutalController::new(self.config.clone()))
    }
}

impl BrutalFactory {
    pub fn new(send_bps: u64) -> Arc<Self> {
        Arc::new(Self {
            config: BrutalConfig { send_bps },
        })
    }
}

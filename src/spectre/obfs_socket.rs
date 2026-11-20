//! 把 [`super::obfs`] 接进 quinn-jls 的 socket 抽象，使 quinn 实际收发的
//! 每个字节都经过 Salamander 混淆，对 Spectre 其余部分透明。
//!
//! ## 为什么包 `Runtime` 而不是传给 `Endpoint::new` 的 socket
//!
//! `Runtime::wrap_udp_socket` 是 `std::net::UdpSocket` 变成 quinn 实际
//! 驱动的 `AsyncUdpSocket` 的唯一入口——在这里做混淆，
//! `bind_udp` / `Endpoint::new` 调用点只需换成传哪个 `Runtime`，
//! 无需 `new_with_abstract_socket` 之类的改造。
//!
//! ## 与上游 spectre 的差异（API 版本）
//!
//! flux 固定 `quinn-jls = 0.3.4`（shadowquic 0.3.7 依赖该版本），其
//! `AsyncUdpSocket` 是旧版形状：`wrap_udp_socket` 返回
//! `Arc<dyn AsyncUdpSocket>`，发送走 `try_send(&self, &Transmit)` +
//! `create_io_poller()`，没有 `create_sender()` / `UdpSender` /
//! `poll_send`（那是 0.3.8 的新 API）。故本文件按 0.3.4 实现；
//! 混淆策略与上游完全一致。
//!
//! ## 开启混淆时禁用 GSO
//!
//! Salamander 给每个包前置 8 字节盐。GSO 把多个**同尺寸**段合并进一次
//! syscall；与每包长度变化混用正是会“悄悄破坏段边界”的那类 bug。
//! 因此 `max_transmit_segments` / `max_receive_segments` 都固定为 1，
//! 每个 datagram 过一次 syscall。极高吞吐下损耗一些 CPU（与 Hysteria
//! 自己的混淆层相同的取舍），但正确。

use super::obfs::{self, ObfsError};
use quinn_jls as quinn;
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncTimer, AsyncUdpSocket, Runtime, UdpPoller};
use std::fmt;
use std::future::Future;
use std::io::{self, IoSliceMut};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Instant;

/// 包装另一个 [`Runtime`]，使其产出的每个 [`AsyncUdpSocket`] 都以 `psk`
/// 做 Salamander 混淆。
#[derive(Debug)]
pub struct ObfsRuntime {
    inner: Arc<dyn Runtime>,
    psk: Arc<Vec<u8>>,
}

impl ObfsRuntime {
    /// `psk` 至少 [`obfs::MIN_PSK_LEN`] 字节，且两端必须一致。
    pub fn new(inner: Arc<dyn Runtime>, psk: Vec<u8>) -> Self {
        Self {
            inner,
            psk: Arc::new(psk),
        }
    }
}

impl Runtime for ObfsRuntime {
    fn new_timer(&self, i: Instant) -> Pin<Box<dyn AsyncTimer>> {
        self.inner.new_timer(i)
    }

    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        self.inner.spawn(future)
    }

    fn wrap_udp_socket(&self, t: std::net::UdpSocket) -> io::Result<Arc<dyn AsyncUdpSocket>> {
        let inner = self.inner.wrap_udp_socket(t)?;
        Ok(Arc::new(ObfsUdpSocket {
            inner,
            psk: self.psk.clone(),
        }))
    }

    fn now(&self) -> Instant {
        self.inner.now()
    }
}

struct ObfsUdpSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    psk: Arc<Vec<u8>>,
}

impl fmt::Debug for ObfsUdpSocket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ObfsUdpSocket").finish_non_exhaustive()
    }
}

impl AsyncUdpSocket for ObfsUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        // `create_io_poller` 消耗 `Arc<Self>`；这里把内部的 Arc 克隆一份
        // 传进去，`self` 本身不受影响。
        Arc::clone(&self.inner).create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        // Transmit 的 `contents` 借用与调用方缓冲同生命周期；这里只读它
        // 来构造新的、自持有的混淆缓冲，不涉及生命周期游戏。
        let obfuscated = obfs::obfuscate(&self.psk, transmit.contents)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        let out = Transmit {
            destination: transmit.destination,
            ecn: transmit.ecn,
            contents: &obfuscated,
            // 固定 1 段（混淆后长度）——见模块级文档：GSO 与每包盐框架
            // 不能安全混用。
            segment_size: None,
            src_ip: transmit.src_ip,
        };
        self.inner.try_send(&out)
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        // 先正常收进调用方缓冲，再就地逐个去混淆（去混淆后一定比上线文
        // 短 8 字节，必然放得下）。
        let n = match self.inner.poll_recv(cx, bufs, meta) {
            Poll::Ready(Ok(n)) => n,
            other => return other,
        };
        for i in 0..n {
            let len = meta[i].len;
            match obfs::deobfuscate(&self.psk, &bufs[i][..len]) {
                Ok(plain) => {
                    let plen = plain.len();
                    bufs[i][..plen].copy_from_slice(&plain);
                    meta[i].len = plen;
                    meta[i].stride = plen;
                }
                Err(ObfsError::PacketTooShort | ObfsError::PskTooShort) => {
                    // 不是本 PSK 的合法 Salamander 包（垃圾流量、探测，
                    // 或对端配错）。把长度清零，quinn 的 recv 循环
                    // （`while !data.is_empty()`）会跳过并丢弃它，
                    // 而不是把无法解析为 QUIC 的原始密文喂给 proto 层。
                    meta[i].len = 0;
                    meta[i].stride = 0;
                }
            }
        }
        Poll::Ready(Ok(n))
    }

    fn local_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        // 见模块级文档：GSO 与每包盐框架不混用。
        1
    }

    fn max_receive_segments(&self) -> usize {
        1
    }

    fn may_fragment(&self) -> bool {
        // 保守：不声明未针对可变包尺寸验证过的分片安全性。
        self.inner.may_fragment()
    }
}

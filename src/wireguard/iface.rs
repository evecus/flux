//! smoltcp 虚拟网络接口。
//!
//! `VirtualDevice` 是一个零拷贝的"假网卡"：
//!   - `inject()` 把来自 boringtun 的明文 IP 包放入接收队列。
//!   - smoltcp `Interface::poll()` 通过 `RxToken` 消费这些包，
//!     并通过 `TxToken` 将回包写入发送队列。
//!   - `drain_tx()` 取出发送队列里的包，交给 boringtun 加密后发回 peer。
//!
//! 使用 `Medium::Ip`（纯 IP，无以太网头），所以不需要 MAC 地址。

use std::collections::VecDeque;

use smoltcp::{
    iface::{Config, Interface, SocketSet},
    phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken},
    time::Instant as SmolInstant,
    wire::{HardwareAddress, IpCidr, Ipv4Address, Ipv6Address},
};

// ── VirtualDevice ─────────────────────────────────────────────────────────────

pub struct VirtualDevice {
    pub rx: VecDeque<Vec<u8>>,
    pub tx: VecDeque<Vec<u8>>,
}

impl VirtualDevice {
    pub fn new() -> Self {
        Self {
            rx: VecDeque::new(),
            tx: VecDeque::new(),
        }
    }

    /// 将明文 IP 包注入接收队列（供 smoltcp 消费）。
    pub fn inject(&mut self, pkt: Vec<u8>) {
        self.rx.push_back(pkt);
    }
}

impl Device for VirtualDevice {
    type RxToken<'a>
        = VirtRx
    where
        Self: 'a;
    type TxToken<'a>
        = VirtTx<'a>
    where
        Self: 'a;

    fn receive(&mut self, _ts: SmolInstant) -> Option<(VirtRx, VirtTx<'_>)> {
        let pkt = self.rx.pop_front()?;
        Some((VirtRx(pkt), VirtTx(&mut self.tx)))
    }

    fn transmit(&mut self, _ts: SmolInstant) -> Option<VirtTx<'_>> {
        Some(VirtTx(&mut self.tx))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = 1500;
        caps
    }
}

pub struct VirtRx(Vec<u8>);

impl RxToken for VirtRx {
    // smoltcp 0.11: RxToken::consume takes F: FnOnce(&mut [u8]) -> R
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = self.0;
        f(&mut buf)
    }
}

pub struct VirtTx<'a>(&'a mut VecDeque<Vec<u8>>);

impl<'a> TxToken for VirtTx<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        self.0.push_back(buf);
        r
    }
}

// ── VirtualIface ──────────────────────────────────────────────────────────────

/// smoltcp Interface + SocketSet，封装在一起方便传递。
pub struct VirtualIface {
    pub device: VirtualDevice,
    pub iface: Interface,
    pub sockets: SocketSet<'static>,
}

impl VirtualIface {
    /// 创建虚拟接口并分配服务端隧道地址。
    pub fn new(local_addrs: &[IpCidr]) -> Self {
        let mut device = VirtualDevice::new();

        let config = Config::new(HardwareAddress::Ip);
        let mut iface = Interface::new(config, &mut device, SmolInstant::now());

        iface.update_ip_addrs(|addrs| {
            for cidr in local_addrs {
                let _ = addrs.push(*cidr);
            }
        });

        iface
            .routes_mut()
            .add_default_ipv4_route(Ipv4Address::UNSPECIFIED)
            .ok();
        iface
            .routes_mut()
            .add_default_ipv6_route(Ipv6Address::UNSPECIFIED)
            .ok();

        let sockets = SocketSet::new(vec![]);

        Self {
            device,
            iface,
            sockets,
        }
    }

    /// 注入一个明文 IP 包并驱动 smoltcp poll，返回需要回传的出站包。
    pub fn inject_and_poll(&mut self, pkt: Vec<u8>) -> Vec<Vec<u8>> {
        self.device.inject(pkt);
        self.poll_inner();
        self.device.tx.drain(..).collect()
    }

    /// 驱动 smoltcp 定时器并收集出站包（不注入新包）。
    pub fn poll_and_collect_tx(&mut self) -> Vec<Vec<u8>> {
        self.poll_inner();
        self.device.tx.drain(..).collect()
    }

    fn poll_inner(&mut self) {
        let ts = SmolInstant::now();
        self.iface.poll(ts, &mut self.device, &mut self.sockets);
    }
}

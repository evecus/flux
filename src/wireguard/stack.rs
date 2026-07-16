//! Per-peer smoltcp stack actor — full VPN exit node.
//!
//! ## 数据流
//!
//! ```text
//!  WireGuard peer
//!    │  (加密 UDP)
//!    ▼
//!  boringtun::Tunn::decapsulate()
//!    │  明文 IP packet
//!    ▼
//!  StackTx ──► [Actor loop]
//!                 │
//!                 ├─ parse_flow_key() → (proto, src, dst)
//!                 │
//!                 ├─ 新 TCP 流:
//!                 │    add_tcp_socket() → smoltcp listen(dst)
//!                 │    inject_and_poll() → smoltcp 自动回 SYN-ACK
//!                 │    smoltcp Established → spawn TCP relay task
//!                 │      relay_fwd: real stream read → ActorMsg::TcpData → smoltcp send buf
//!                 │      relay_bwd: smoltcp recv buf → real stream write
//!                 │
//!                 ├─ 已有 TCP 流:
//!                 │    inject_and_poll() → smoltcp 维护 ACK/窗口
//!                 │    drain smoltcp recv buf → outbound_tx → real stream write
//!                 │
//!                 ├─ UDP 流:
//!                 │    add_udp_socket() → smoltcp bind(dst)
//!                 │    inject_and_poll() → smoltcp 收到 datagram
//!                 │    drain smoltcp udp recv → forward to real UdpSocket
//!                 │    real UdpSocket reply → ActorMsg::UdpReply → smoltcp send
//!                 │
//!                 └─ smoltcp 产生的出站 IP packet
//!                      → EncryptTx → boringtun::encapsulate() → WireGuard peer
//! ```

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use smoltcp::{
    iface::SocketHandle,
    socket::{
        tcp::{Socket as TcpSocket, SocketBuffer, State as TcpState},
        udp::{PacketBuffer, PacketMetadata, Socket as UdpSocket, UdpMetadata},
    },
    wire::{IpAddress, IpCidr, IpEndpoint, IpListenEndpoint, Ipv4Address, Ipv6Address},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket as TokioUdp},
    sync::mpsc,
    time,
};
use tracing::{debug, info, warn};

use crate::wireguard::iface::VirtualIface;

// ── 缓冲区大小 ────────────────────────────────────────────────────────────────

const TCP_RX_BUF: usize = 128 * 1024;
const TCP_TX_BUF: usize = 128 * 1024;
const UDP_QUEUE: usize = 64;
const UDP_BUF: usize = 64 * 1024;

// ── 公开类型 ──────────────────────────────────────────────────────────────────

/// 外部向 actor 推送明文入站 IP 包。
pub type StackTx = mpsc::Sender<Vec<u8>>;
/// Actor 向外推送需要加密回传的 IP 包。
pub type EncryptTx = mpsc::Sender<Vec<u8>>;

// ── 内部 Actor 消息 ────────────────────────────────────────────────────────────

enum Msg {
    /// 来自 boringtun 解密的入站 IP 包。
    Inbound(Vec<u8>),
    /// 来自真实远端 TCP 连接的数据 → 注入 smoltcp 发送缓冲区。
    TcpData { handle: SocketHandle, data: Vec<u8> },
    /// 来自真实远端 UDP socket 的回包 → 注入 smoltcp UDP 发送缓冲区。
    UdpReply { handle: SocketHandle, data: Vec<u8> },
    /// 定时器滴答：驱动 smoltcp 内部定时器、排空缓冲区。
    Tick,
}

// ── 流状态 ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FlowKey {
    proto: u8,
    src: SocketAddr,
    dst: SocketAddr,
}

struct TcpFlow {
    handle: SocketHandle,
    /// smoltcp recv buf → 真实远端写入通道。
    outbound_tx: mpsc::Sender<Vec<u8>>,
    relay_started: bool,
    last_active: Instant,
}

struct UdpFlow {
    handle: SocketHandle,
    /// 向真实远端发送的通道（由 udp relay task 消费）。
    outbound_tx: mpsc::Sender<(SocketAddr, Vec<u8>)>,
    last_active: Instant,
}

// ── 公开入口 ──────────────────────────────────────────────────────────────────

/// 启动 per-peer smoltcp actor，返回 StackTx 供调用方推包。
pub fn spawn_stack(local_addrs: Vec<IpCidr>, encrypt_tx: EncryptTx) -> StackTx {
    // 外部推入明文 IP 包的通道。
    let (stack_tx, stack_rx) = mpsc::channel::<Vec<u8>>(512);

    // 内部统一消息通道（actor 自己也往里发 TcpData / UdpReply / Tick）。
    let (actor_tx, actor_rx) = mpsc::channel::<Msg>(2048);

    // 把 stack_rx 转发到 actor_tx。
    {
        let fwd = actor_tx.clone();
        let mut rx = stack_rx;
        tokio::spawn(async move {
            while let Some(pkt) = rx.recv().await {
                if fwd.send(Msg::Inbound(pkt)).await.is_err() {
                    break;
                }
            }
        });
    }

    // 定时器：每 100 ms 发一次 Tick。
    {
        let fwd = actor_tx.clone();
        tokio::spawn(async move {
            let mut tick = time::interval(Duration::from_millis(100));
            loop {
                tick.tick().await;
                if fwd.send(Msg::Tick).await.is_err() {
                    break;
                }
            }
        });
    }

    // Actor 主循环。
    tokio::spawn(run_actor(local_addrs, encrypt_tx, actor_tx, actor_rx));

    stack_tx
}

// ── Actor 主循环 ──────────────────────────────────────────────────────────────

async fn run_actor(
    local_addrs: Vec<IpCidr>,
    encrypt_tx: EncryptTx,
    actor_tx: mpsc::Sender<Msg>,
    mut actor_rx: mpsc::Receiver<Msg>,
) {
    let mut iface = VirtualIface::new(&local_addrs);
    let mut tcp_flows: HashMap<FlowKey, TcpFlow> = HashMap::new();
    let mut udp_flows: HashMap<FlowKey, UdpFlow> = HashMap::new();

    while let Some(msg) = actor_rx.recv().await {
        match msg {
            // ── 入站 IP 包 ────────────────────────────────────────────────────
            Msg::Inbound(pkt) => {
                // 1. 解析流 key，按需建 smoltcp socket。
                if let Some(key) = parse_flow_key(&pkt) {
                    match key.proto {
                        6 => ensure_tcp(&mut iface, &mut tcp_flows, &key),
                        17 => ensure_udp(&mut iface, &mut udp_flows, &key, &actor_tx),
                        _ => {}
                    }
                }

                // 2. 注入 smoltcp 并收集出站包。
                let out = iface.inject_and_poll(pkt);
                flush_encrypt(&encrypt_tx, out).await;

                // 3. 新 Established TCP → 启动 relay。
                start_tcp_relays(&mut iface, &mut tcp_flows, &actor_tx).await;

                // 4. 排空 smoltcp TCP recv buf → 真实远端。
                drain_tcp_recv(&mut iface, &mut tcp_flows).await;

                // 5. 排空 smoltcp UDP recv buf → 真实远端。
                drain_udp_recv(&mut iface, &mut udp_flows).await;
            }

            // ── 真实远端 TCP 数据 → smoltcp 发送缓冲区 ───────────────────────
            Msg::TcpData { handle, data } => {
                feed_tcp_send(&mut iface, handle, &data);
                let out = iface.poll_and_collect_tx();
                flush_encrypt(&encrypt_tx, out).await;
            }

            // ── 真实远端 UDP 回包 → smoltcp UDP 发送缓冲区 ───────────────────
            Msg::UdpReply { handle, data } => {
                // 找原始 src（peer 的隧道内 IP）作为 smoltcp UDP 目标端点。
                let peer_ep = udp_flows
                    .iter()
                    .find(|(_, f)| f.handle == handle)
                    .map(|(k, _)| k.src);
                if let Some(peer_ep) = peer_ep {
                    feed_udp_send(&mut iface, handle, peer_ep, &data);
                }
                let out = iface.poll_and_collect_tx();
                flush_encrypt(&encrypt_tx, out).await;
            }

            // ── 定时器滴答 ────────────────────────────────────────────────────
            Msg::Tick => {
                let out = iface.poll_and_collect_tx();
                flush_encrypt(&encrypt_tx, out).await;
                drain_tcp_recv(&mut iface, &mut tcp_flows).await;
                drain_udp_recv(&mut iface, &mut udp_flows).await;
                start_tcp_relays(&mut iface, &mut tcp_flows, &actor_tx).await;
                evict_flows(&mut iface, &mut tcp_flows, &mut udp_flows);
            }
        }
    }
}

// ── Socket 创建 ───────────────────────────────────────────────────────────────

fn ensure_tcp(iface: &mut VirtualIface, tcp_flows: &mut HashMap<FlowKey, TcpFlow>, key: &FlowKey) {
    if tcp_flows.contains_key(key) {
        return;
    }

    let rx = SocketBuffer::new(vec![0u8; TCP_RX_BUF]);
    let tx = SocketBuffer::new(vec![0u8; TCP_TX_BUF]);
    let mut sock = TcpSocket::new(rx, tx);
    sock.set_nagle_enabled(false);
    sock.set_keep_alive(Some(smoltcp::time::Duration::from_secs(30)));

    let ep = IpListenEndpoint {
        addr: Some(ip_to_smoltcp(key.dst.ip())),
        port: key.dst.port(),
    };
    if sock.listen(ep).is_err() {
        warn!("[wg/stack] TCP listen {:?} failed", key.dst);
        return;
    }

    let handle = iface.sockets.add(sock);
    // outbound_tx 先用一个 dummy sender；relay 启动时再换真实的。
    let (outbound_tx, _rx) = mpsc::channel::<Vec<u8>>(1);
    tcp_flows.insert(
        key.clone(),
        TcpFlow {
            handle,
            outbound_tx,
            relay_started: false,
            last_active: Instant::now(),
        },
    );
    debug!("[wg/stack] TCP socket created for {:?}", key.dst);
}

fn ensure_udp(
    iface: &mut VirtualIface,
    udp_flows: &mut HashMap<FlowKey, UdpFlow>,
    key: &FlowKey,
    actor_tx: &mpsc::Sender<Msg>,
) {
    if udp_flows.contains_key(key) {
        return;
    }

    let rx = PacketBuffer::new(vec![PacketMetadata::EMPTY; UDP_QUEUE], vec![0u8; UDP_BUF]);
    let tx = PacketBuffer::new(vec![PacketMetadata::EMPTY; UDP_QUEUE], vec![0u8; UDP_BUF]);
    let mut sock = UdpSocket::new(rx, tx);
    let ep = IpListenEndpoint {
        addr: Some(ip_to_smoltcp(key.dst.ip())),
        port: key.dst.port(),
    };
    if sock.bind(ep).is_err() {
        warn!("[wg/stack] UDP bind {:?} failed", key.dst);
        return;
    }

    let handle = iface.sockets.add(sock);

    // 启动 UDP 出站 relay task。
    let (outbound_tx, outbound_rx) = mpsc::channel::<(SocketAddr, Vec<u8>)>(128);
    spawn_udp_relay(handle, outbound_rx, actor_tx.clone());

    udp_flows.insert(
        key.clone(),
        UdpFlow {
            handle,
            outbound_tx,
            last_active: Instant::now(),
        },
    );
    debug!("[wg/stack] UDP socket created for {:?}", key.dst);
}

// ── TCP relay 启动 ────────────────────────────────────────────────────────────

async fn start_tcp_relays(
    iface: &mut VirtualIface,
    tcp_flows: &mut HashMap<FlowKey, TcpFlow>,
    actor_tx: &mpsc::Sender<Msg>,
) {
    // 收集需要启动 relay 的 (key, handle, dst)。
    let to_start: Vec<(FlowKey, SocketHandle, SocketAddr)> = tcp_flows
        .iter()
        .filter(|(_, f)| {
            !f.relay_started
                && iface.sockets.get::<TcpSocket>(f.handle).state() == TcpState::Established
        })
        .map(|(k, f)| (k.clone(), f.handle, k.dst))
        .collect();

    for (key, handle, dst) in to_start {
        // 建新的 outbound_tx/rx 对替换 dummy。
        let (outbound_tx, outbound_rx) = mpsc::channel::<Vec<u8>>(256);
        if let Some(flow) = tcp_flows.get_mut(&key) {
            flow.outbound_tx = outbound_tx;
            flow.relay_started = true;
        }
        spawn_tcp_relay(handle, dst, outbound_rx, actor_tx.clone());
        info!("[wg/stack] TCP relay → {dst}");
    }
}

/// 启动双向 TCP relay task。
///
/// ```text
///  smoltcp recv buf  ──outbound_rx──►  real stream write   (bwd)
///  real stream read  ──TcpData msg──►  smoltcp send buf    (fwd)
/// ```
fn spawn_tcp_relay(
    handle: SocketHandle,
    dst: SocketAddr,
    outbound_rx: mpsc::Receiver<Vec<u8>>,
    actor_tx: mpsc::Sender<Msg>,
) {
    tokio::spawn(async move {
        match TcpStream::connect(dst).await {
            Err(e) => warn!("[wg/stack] TCP connect {dst}: {e}"),
            Ok(stream) => {
                let (mut reader, mut writer) = stream.into_split();

                // fwd: real remote → smoltcp send buf。
                let fwd_tx = actor_tx.clone();
                let fwd = tokio::spawn(async move {
                    let mut buf = vec![0u8; 16 * 1024];
                    loop {
                        match reader.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if fwd_tx
                                    .send(Msg::TcpData {
                                        handle,
                                        data: buf[..n].to_vec(),
                                    })
                                    .await
                                    .is_err()
                                {
                                    break;
                                }
                            }
                        }
                    }
                    debug!("[wg/stack] TCP fwd done for {dst}");
                });

                // bwd: smoltcp recv buf → real remote write。
                let mut outbound_rx = outbound_rx;
                let bwd = tokio::spawn(async move {
                    while let Some(data) = outbound_rx.recv().await {
                        if writer.write_all(&data).await.is_err() {
                            break;
                        }
                    }
                    debug!("[wg/stack] TCP bwd done for {dst}");
                });

                let _ = tokio::join!(fwd, bwd);
                info!("[wg/stack] TCP relay closed for {dst}");
            }
        }
    });
}

// ── smoltcp recv buf 排空 ─────────────────────────────────────────────────────

async fn drain_tcp_recv(iface: &mut VirtualIface, tcp_flows: &mut HashMap<FlowKey, TcpFlow>) {
    for flow in tcp_flows.values_mut() {
        if !flow.relay_started {
            continue;
        }
        let sock = iface.sockets.get_mut::<TcpSocket>(flow.handle);
        if !sock.may_recv() || sock.recv_queue() == 0 {
            continue;
        }

        let mut buf = vec![0u8; sock.recv_queue()];
        match sock.recv_slice(&mut buf) {
            Ok(0) | Err(_) => {}
            Ok(n) => {
                buf.truncate(n);
                let _ = flow.outbound_tx.send(buf).await;
                flow.last_active = Instant::now();
            }
        }
    }
}

async fn drain_udp_recv(iface: &mut VirtualIface, udp_flows: &mut HashMap<FlowKey, UdpFlow>) {
    for (key, flow) in udp_flows.iter_mut() {
        let sock = iface.sockets.get_mut::<UdpSocket>(flow.handle);
        while sock.can_recv() {
            match sock.recv() {
                Ok((data, _meta)) => {
                    let _ = flow.outbound_tx.send((key.dst, data.to_vec())).await;
                    flow.last_active = Instant::now();
                }
                Err(_) => break,
            }
        }
    }
}

// ── smoltcp send buf 填充 ─────────────────────────────────────────────────────

fn feed_tcp_send(iface: &mut VirtualIface, handle: SocketHandle, data: &[u8]) {
    let sock = iface.sockets.get_mut::<TcpSocket>(handle);
    if sock.may_send() {
        if let Err(e) = sock.send_slice(data) {
            debug!("[wg/stack] TCP send_slice: {e:?}");
        }
    }
}

fn feed_udp_send(iface: &mut VirtualIface, handle: SocketHandle, peer_ep: SocketAddr, data: &[u8]) {
    let sock = iface.sockets.get_mut::<UdpSocket>(handle);
    let meta = UdpMetadata {
        endpoint: sock_to_smoltcp(peer_ep),
        meta: Default::default(),
    };
    if let Err(e) = sock.send_slice(data, meta) {
        debug!("[wg/stack] UDP send_slice: {e:?}");
    }
}

// ── UDP 出站 relay task ───────────────────────────────────────────────────────

/// 从 outbound_rx 接收 (dst, payload)，用真实 UdpSocket 发出去，
/// 收到回包后通过 actor_tx 发 UdpReply 回 actor。
fn spawn_udp_relay(
    handle: SocketHandle,
    mut outbound_rx: mpsc::Receiver<(SocketAddr, Vec<u8>)>,
    actor_tx: mpsc::Sender<Msg>,
) {
    tokio::spawn(async move {
        // 惰性绑定：等第一个包到才决定 IPv4/IPv6。
        let mut sock4: Option<Arc<TokioUdp>> = None;
        let mut sock6: Option<Arc<TokioUdp>> = None;

        let mut reply_buf = vec![0u8; 65535];

        loop {
            // 等待下一个出站 datagram。
            let Some((dst, payload)) = outbound_rx.recv().await else {
                break;
            };

            let sock = if dst.is_ipv4() {
                if sock4.is_none() {
                    match TokioUdp::bind("0.0.0.0:0").await {
                        Ok(s) => sock4 = Some(Arc::new(s)),
                        Err(e) => {
                            warn!("[wg/stack] UDP bind v4: {e}");
                            continue;
                        }
                    }
                }
                sock4.as_ref().unwrap().clone()
            } else {
                if sock6.is_none() {
                    match TokioUdp::bind("[::]:0").await {
                        Ok(s) => sock6 = Some(Arc::new(s)),
                        Err(e) => {
                            warn!("[wg/stack] UDP bind v6: {e}");
                            continue;
                        }
                    }
                }
                sock6.as_ref().unwrap().clone()
            };

            if let Err(e) = sock.send_to(&payload, dst).await {
                warn!("[wg/stack] UDP send → {dst}: {e}");
                continue;
            }

            // 以 1 s 超时等回包（DNS 等协议单次交互）。
            if let Ok(Ok((n, _from))) =
                time::timeout(Duration::from_secs(1), sock.recv_from(&mut reply_buf)).await
            {
                let _ = actor_tx
                    .send(Msg::UdpReply {
                        handle,
                        data: reply_buf[..n].to_vec(),
                    })
                    .await;
            }
        }
    });
}

// ── 流淘汰 ────────────────────────────────────────────────────────────────────

fn evict_flows(
    iface: &mut VirtualIface,
    tcp_flows: &mut HashMap<FlowKey, TcpFlow>,
    udp_flows: &mut HashMap<FlowKey, UdpFlow>,
) {
    const TCP_IDLE: Duration = Duration::from_secs(300);
    const UDP_IDLE: Duration = Duration::from_secs(60);
    let now = Instant::now();

    tcp_flows.retain(|_, f| {
        let keep = now.duration_since(f.last_active) < TCP_IDLE;
        if !keep {
            iface.sockets.remove(f.handle);
        }
        keep
    });
    udp_flows.retain(|_, f| {
        let keep = now.duration_since(f.last_active) < UDP_IDLE;
        if !keep {
            iface.sockets.remove(f.handle);
        }
        keep
    });
}

// ── 工具函数 ──────────────────────────────────────────────────────────────────

async fn flush_encrypt(enc_tx: &EncryptTx, pkts: Vec<Vec<u8>>) {
    for pkt in pkts {
        let _ = enc_tx.send(pkt).await;
    }
}

fn parse_flow_key(pkt: &[u8]) -> Option<FlowKey> {
    match pkt.first().map(|b| b >> 4)? {
        4 => parse_ipv4_flow(pkt),
        6 => parse_ipv6_flow(pkt),
        _ => None,
    }
}

fn parse_ipv4_flow(pkt: &[u8]) -> Option<FlowKey> {
    if pkt.len() < 20 {
        return None;
    }
    let ihl = ((pkt[0] & 0x0f) as usize) * 4;
    let proto = pkt[9];
    if proto != 6 && proto != 17 {
        return None;
    }
    let src_ip = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
    let dst_ip = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
    let t = pkt.get(ihl..ihl + 4)?;
    Some(FlowKey {
        proto,
        src: SocketAddr::new(IpAddr::V4(src_ip), u16::from_be_bytes([t[0], t[1]])),
        dst: SocketAddr::new(IpAddr::V4(dst_ip), u16::from_be_bytes([t[2], t[3]])),
    })
}

fn parse_ipv6_flow(pkt: &[u8]) -> Option<FlowKey> {
    if pkt.len() < 44 {
        return None;
    }
    let proto = pkt[6];
    if proto != 6 && proto != 17 {
        return None;
    }
    let src_ip = ipv6_from_slice(&pkt[8..24]);
    let dst_ip = ipv6_from_slice(&pkt[24..40]);
    let t = pkt.get(40..44)?;
    Some(FlowKey {
        proto,
        src: SocketAddr::new(IpAddr::V6(src_ip), u16::from_be_bytes([t[0], t[1]])),
        dst: SocketAddr::new(IpAddr::V6(dst_ip), u16::from_be_bytes([t[2], t[3]])),
    })
}

fn ipv6_from_slice(b: &[u8]) -> Ipv6Addr {
    let mut a = [0u16; 8];
    for i in 0..8 {
        a[i] = u16::from_be_bytes([b[i * 2], b[i * 2 + 1]]);
    }
    Ipv6Addr::new(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7])
}

fn ip_to_smoltcp(ip: IpAddr) -> IpAddress {
    match ip {
        IpAddr::V4(v4) => IpAddress::Ipv4(Ipv4Address(v4.octets())),
        IpAddr::V6(v6) => IpAddress::Ipv6(Ipv6Address(v6.octets())),
    }
}

fn sock_to_smoltcp(addr: SocketAddr) -> IpEndpoint {
    IpEndpoint {
        addr: ip_to_smoltcp(addr.ip()),
        port: addr.port(),
    }
}

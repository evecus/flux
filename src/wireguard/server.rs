//! WireGuard 服务端 — VPN 出口节点。
//!
//! ## 整体流程
//!
//! ```text
//!  ┌─────────────────────────────────────────────────────────────────────┐
//!  │  UDP recv ──► boringtun::decapsulate() ──► 明文 IP pkt             │
//!  │                                                  │                  │
//!  │                         AllowedIPs 检查          │                  │
//!  │                                                  ▼                  │
//!  │                                         StackTx (per-peer actor)   │
//!  │                                                  │                  │
//!  │                          smoltcp 处理 TCP/UDP 状态机               │
//!  │                                                  │                  │
//!  │                          出站 IP pkt ◄───────────┘                  │
//!  │                                │                                    │
//!  │  boringtun::encapsulate() ◄────┘                                   │
//!  │                                │                                    │
//!  │  UDP send ◄────────────────────┘                                   │
//!  └─────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! 每个 peer 拥有独立的 smoltcp actor（`stack::spawn_stack`），互不阻塞。
//!
//! 对应 sing-box:
//!   transport/wireguard/endpoint.go  (`Endpoint.Start`)
//!   transport/wireguard/client_bind.go

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use boringtun::noise::{Tunn, TunnResult};
use ip_network::IpNetwork;
use ip_network_table::IpNetworkTable;
use smoltcp::wire::{IpCidr, Ipv4Address, Ipv4Cidr, Ipv6Address};
use tokio::{net::UdpSocket, sync::mpsc};
use tracing::{debug, info, warn};

use crate::config::WireGuardConfig;
use crate::wireguard::{
    peer::Peer,
    stack::{spawn_stack, StackTx},
};

const MAX_PACKET: usize = 65535;
const TIMER_TICK_MS: u64 = 250;

// ── 入口 ──────────────────────────────────────────────────────────────────────

pub async fn run(cfg: Arc<WireGuardConfig>) -> Result<()> {
    // 解码服务端私钥。
    let priv_bytes = decode_key(&cfg.private_key, "private_key")?;
    let private_key =
        x25519_dalek::StaticSecret::from(<[u8; 32]>::try_from(priv_bytes.as_slice())?);

    // 解析服务端隧道地址（smoltcp 虚拟接口 IP）。
    let server_cidrs: Vec<IpCidr> = cfg
        .server_address
        .iter()
        .filter_map(|s| parse_ip_cidr(s).ok())
        .collect();

    if server_cidrs.is_empty() {
        warn!("[wireguard] server_address 未配置，smoltcp 接口将无地址（部分功能受限）");
    }

    // ── 构建 peer 表 ──────────────────────────────────────────────────────────
    // pub_hex → Arc<Peer>
    let mut peer_map: HashMap<String, Arc<Peer>> = HashMap::new();
    // AllowedIPs 路由表（最长前缀匹配）→ pub_hex
    let mut allowed_ips_table: IpNetworkTable<String> = IpNetworkTable::new();
    // pub_hex → StackTx（smoltcp actor 入口）
    let mut stack_txs: HashMap<String, StackTx> = HashMap::new();
    // pub_hex → mpsc::Receiver<Vec<u8>>（smoltcp actor 出口，需要被加密发回）
    let mut encrypt_rxs: HashMap<String, mpsc::Receiver<Vec<u8>>> = HashMap::new();

    for (idx, peer_cfg) in cfg.peers.iter().enumerate() {
        let pub_bytes = decode_key(&peer_cfg.public_key, "peer public_key")?;
        let pub_key = x25519_dalek::PublicKey::from(<[u8; 32]>::try_from(pub_bytes.as_slice())?);

        let psk: Option<[u8; 32]> = match &peer_cfg.pre_shared_key {
            Some(s) => {
                let b = decode_key(s, "pre_shared_key")?;
                Some(<[u8; 32]>::try_from(b.as_slice())?)
            }
            None => None,
        };

        let tunnel = Tunn::new(
            private_key.clone(),
            pub_key,
            psk,
            peer_cfg.keepalive_interval,
            idx as u32,
            None,
        );

        let mut allowed_ips: Vec<IpNetwork> = Vec::new();
        for cidr in &peer_cfg.allowed_ips {
            let net: IpNetwork = cidr
                .parse()
                .with_context(|| format!("invalid allowed_ips: {cidr}"))?;
            allowed_ips.push(net);
        }

        let peer = Peer::new(Box::new(tunnel), allowed_ips.clone());
        let pub_hex = hex::encode(&pub_bytes);

        for net in &allowed_ips {
            allowed_ips_table.insert(*net, pub_hex.clone());
        }

        // 每个 peer 独立的 smoltcp actor。
        let (enc_tx, enc_rx) = mpsc::channel::<Vec<u8>>(1024);
        let stack_tx = spawn_stack(server_cidrs.clone(), enc_tx);

        peer_map.insert(pub_hex.clone(), peer);
        stack_txs.insert(pub_hex.clone(), stack_tx);
        encrypt_rxs.insert(pub_hex, enc_rx);

        info!(
            "[wireguard] peer #{idx}: allowed_ips={:?}",
            peer_cfg.allowed_ips
        );
    }

    let peer_map = Arc::new(peer_map);
    let stack_txs = Arc::new(stack_txs);

    // ── 绑定 UDP 套接字 ───────────────────────────────────────────────────────
    let listen_addr: SocketAddr = cfg.listen.parse()?;
    let socket = Arc::new(UdpSocket::bind(listen_addr).await?);
    info!(
        "[wireguard] listening on {listen_addr} ({} peers)",
        cfg.peers.len()
    );

    // ── 加密回传任务（每 peer 一个）────────────────────────────────────────────
    // smoltcp actor 产生明文 IP 包 → boringtun 加密 → 发回 peer。
    for (pub_hex, mut enc_rx) in encrypt_rxs {
        let socket_enc = Arc::clone(&socket);
        let peers_enc = Arc::clone(&peer_map);
        tokio::spawn(async move {
            let mut enc_buf = vec![0u8; MAX_PACKET];
            while let Some(ip_pkt) = enc_rx.recv().await {
                let Some(peer) = peers_enc.get(&pub_hex) else {
                    continue;
                };
                let ep = *peer.endpoint.lock().await;
                let Some(ep) = ep else { continue };

                let mut tun = peer.tunnel.lock().await;
                if let TunnResult::WriteToNetwork(pkt) = tun.encapsulate(&ip_pkt, &mut enc_buf) {
                    let _ = socket_enc.send_to(pkt, ep).await;
                }
            }
        });
    }

    // ── 定时器任务：驱动 boringtun keepalive / 重握手 ────────────────────────
    {
        let socket_timer = Arc::clone(&socket);
        let peers_timer = Arc::clone(&peer_map);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_millis(TIMER_TICK_MS));
            let mut buf = vec![0u8; MAX_PACKET];
            loop {
                tick.tick().await;
                for peer in peers_timer.values() {
                    let ep = *peer.endpoint.lock().await;
                    let Some(ep) = ep else { continue };
                    let mut tun = peer.tunnel.lock().await;
                    loop {
                        match tun.update_timers(&mut buf) {
                            TunnResult::WriteToNetwork(pkt) => {
                                let _ = socket_timer.send_to(pkt, ep).await;
                            }
                            TunnResult::Done => break,
                            TunnResult::Err(e) => {
                                debug!("[wireguard] timer error: {e:?}");
                                break;
                            }
                            _ => break,
                        }
                    }
                }
            }
        });
    }

    // ── 主接收循环 ────────────────────────────────────────────────────────────
    let mut recv_buf = vec![0u8; MAX_PACKET];
    let mut dec_buf = vec![0u8; MAX_PACKET];

    loop {
        let (n, src) = socket.recv_from(&mut recv_buf).await?;
        let raw = &recv_buf[..n];

        // 1. 找到对应的 peer。
        let (pub_hex, peer) = match find_peer(&peer_map, raw, src).await {
            Some(v) => v,
            None => {
                debug!("[wireguard] unknown src {src}, dropping");
                continue;
            }
        };

        // 2. 更新 peer 的外部端点和最后活跃时间。
        *peer.last_seen.lock().await = Instant::now();
        *peer.endpoint.lock().await = Some(src);

        // 3. boringtun 解密。
        // ip_owned: 把解密结果立即复制出来，释放对 dec_buf 的借用，
        // 这样步骤 4 的 drain_timers 可以复用同一块缓冲区。
        let ip_owned: Option<Vec<u8>> = {
            let mut tun = peer.tunnel.lock().await;
            let r = tun.decapsulate(Some(src.ip()), raw, &mut dec_buf);
            match r {
                TunnResult::WriteToNetwork(pkt) => {
                    let _ = socket.send_to(pkt, src).await;
                    None
                }
                TunnResult::WriteToTunnelV4(pkt, _) | TunnResult::WriteToTunnelV6(pkt, _) => {
                    Some(pkt.to_vec()) // 立即复制，释放 dec_buf 借用
                }
                TunnResult::Done => None,
                TunnResult::Err(e) => {
                    warn!("[wireguard] decapsulate from {src}: {e:?}");
                    None
                }
            }
        }; // dec_buf 借用在此结束

        // 4. 定时器驱动（可能产生 keepalive 包）。
        drain_timers(&peer, &socket, src, &mut dec_buf).await;

        // 5. 处理解密结果。
        let Some(ip_pkt) = ip_owned else { continue };

        // 6. AllowedIPs 检查。
        if !peer.allows(packet_src_ip(&ip_pkt)) {
            debug!("[wireguard] src IP not in AllowedIPs, dropping");
            continue;
        }

        // 7. 投递给对应 peer 的 smoltcp actor。
        if let Some(stack_tx) = stack_txs.get(&pub_hex) {
            let _ = stack_tx.send(ip_pkt).await;
        }
    }
}

// ── 辅助函数 ──────────────────────────────────────────────────────────────────

/// 根据外部 UDP 源地址找到对应 peer。
///
/// 快路径：peer 的 endpoint 已记录且匹配 `src`。
/// 慢路径（首次握手）：取第一个 peer（单 peer 场景下正确；
///   多 peer 场景下 WireGuard 握手包含 receiver index，
///   未来可解析 msg type=1/2 做精确匹配）。
async fn find_peer(
    peers: &HashMap<String, Arc<Peer>>,
    _raw: &[u8],
    src: SocketAddr,
) -> Option<(String, Arc<Peer>)> {
    for (hex, peer) in peers {
        if *peer.endpoint.lock().await == Some(src) {
            return Some((hex.clone(), Arc::clone(peer)));
        }
    }
    // 首次握手：fallback 到第一个 peer。
    peers.iter().next().map(|(h, p)| (h.clone(), Arc::clone(p)))
}

/// 排空 boringtun 定时器产生的出站包（keepalive、重握手等）。
async fn drain_timers(peer: &Arc<Peer>, socket: &UdpSocket, dst: SocketAddr, buf: &mut [u8]) {
    let mut tun = peer.tunnel.lock().await;
    loop {
        match tun.update_timers(buf) {
            TunnResult::WriteToNetwork(pkt) => {
                let _ = socket.send_to(pkt, dst).await;
            }
            TunnResult::Done => break,
            TunnResult::Err(_) => break,
            _ => break,
        }
    }
}

/// 从原始 IP 包头提取源地址（用于 AllowedIPs 检查）。
fn packet_src_ip(pkt: &[u8]) -> IpAddr {
    match pkt.first().map(|b| b >> 4) {
        Some(4) if pkt.len() >= 20 => IpAddr::V4(Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15])),
        Some(6) if pkt.len() >= 40 => IpAddr::V6(ipv6_from_slice(&pkt[8..24])),
        _ => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
    }
}

fn ipv6_from_slice(b: &[u8]) -> Ipv6Addr {
    let mut a = [0u16; 8];
    for i in 0..8 {
        a[i] = u16::from_be_bytes([b[i * 2], b[i * 2 + 1]]);
    }
    Ipv6Addr::new(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7])
}

fn decode_key(b64: &str, label: &str) -> Result<Vec<u8>> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    STANDARD
        .decode(b64.trim())
        .with_context(|| format!("invalid base64 for {label}"))
}

fn parse_ip_cidr(s: &str) -> Result<IpCidr> {
    let (ip_str, plen) = s
        .rsplit_once('/')
        .ok_or_else(|| anyhow::anyhow!("invalid CIDR: {s}"))?;
    let plen: u8 = plen.parse()?;
    let ip: IpAddr = ip_str.parse()?;
    Ok(match ip {
        IpAddr::V4(v4) => IpCidr::Ipv4(Ipv4Cidr::new(Ipv4Address(v4.octets()), plen)),
        IpAddr::V6(v6) => {
            IpCidr::Ipv6(smoltcp::wire::Ipv6Cidr::new(Ipv6Address(v6.octets()), plen))
        }
    })
}

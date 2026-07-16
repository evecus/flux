//! Per-peer WireGuard state: crypto tunnel + observed UDP endpoint.
//!
//! One `Peer` is created for each entry in `[[wireguard.peers]]`.
//! The boringtun `Tunn` is wrapped in a `Mutex` because its
//! `decapsulate` / `encapsulate` / `update_timers` methods take `&mut self`.

use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Instant,
};

use boringtun::noise::Tunn;
use ip_network::IpNetwork;
use tokio::sync::Mutex;

pub struct Peer {
    /// boringtun crypto state machine.
    pub tunnel: Mutex<Box<Tunn>>,

    /// The outer UDP address the peer is currently reachable at.
    /// Starts as `None`; set on first received packet.
    pub endpoint: Mutex<Option<SocketAddr>>,

    /// AllowedIPs: inner-tunnel source IPs this peer is permitted to use.
    pub allowed_ips: Vec<IpNetwork>,

    /// Monotonic timestamp of the last received packet from this peer.
    pub last_seen: Mutex<Instant>,
}

impl Peer {
    pub fn new(tunnel: Box<Tunn>, allowed_ips: Vec<IpNetwork>) -> Arc<Self> {
        Arc::new(Self {
            tunnel: Mutex::new(tunnel),
            endpoint: Mutex::new(None),
            allowed_ips,
            last_seen: Mutex::new(Instant::now()),
        })
    }

    /// Returns `true` if `addr` falls within any of this peer's AllowedIPs.
    pub fn allows(&self, addr: IpAddr) -> bool {
        self.allowed_ips.iter().any(|net| net.contains(addr))
    }
}

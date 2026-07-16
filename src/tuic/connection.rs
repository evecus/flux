use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket as StdUdpSocket},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use bytes::Bytes;
use quinn::{Connection as QuinnConnection, RecvStream, SendStream};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::{
    net::{self, TcpStream, UdpSocket},
    sync::{oneshot, Notify, RwLock as AsyncRwLock},
    time,
};
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::{
    config::TuicConfig,
    tuic::{
        error::Error,
        proto::{build_packet_header, Address, Command, PacketInfo, VERSION},
    },
};

// ── Authentication state ──────────────────────────────────────────────────────

#[derive(Clone)]
pub struct Authenticated(Arc<AuthInner>);

struct AuthInner {
    uuid: std::sync::RwLock<Option<Uuid>>,
    notify: Notify,
    is_authenticated: AtomicBool,
}

impl Authenticated {
    pub fn new() -> Self {
        Self(Arc::new(AuthInner {
            uuid: std::sync::RwLock::new(None),
            notify: Notify::new(),
            is_authenticated: AtomicBool::new(false),
        }))
    }

    pub fn set(&self, uuid: Uuid) {
        *self.0.uuid.write().unwrap() = Some(uuid);
        self.0.is_authenticated.store(true, Ordering::SeqCst);
        self.0.notify.notify_waiters();
    }

    #[allow(dead_code)]
    pub fn get(&self) -> Option<Uuid> {
        *self.0.uuid.read().unwrap()
    }

    pub fn is_authenticated(&self) -> bool {
        self.0.is_authenticated.load(Ordering::SeqCst)
    }

    pub async fn wait(&self) {
        if self.is_authenticated() {
            return;
        }
        let notified = self.0.notify.notified();
        if self.is_authenticated() {
            return;
        }
        notified.await;
    }
}

// ── UDP session ───────────────────────────────────────────────────────────────

pub struct UdpSession {
    assoc_id: u16,
    socket_v4: UdpSocket,
    socket_v6: Option<UdpSocket>,
    close_tx: AsyncRwLock<Option<oneshot::Sender<()>>>,
}

impl UdpSession {
    pub fn new(
        conn: Connection,
        assoc_id: u16,
        udp_relay_ipv6: bool,
        stream_timeout: Duration,
        max_pkt_size: usize,
    ) -> std::io::Result<Arc<Self>> {
        let socket_v4 = {
            let bind_addr_v4 = conn.cfg.outbound_bind_ipv4.unwrap_or(Ipv4Addr::UNSPECIFIED);
            let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
            s.set_nonblocking(true)?;
            s.bind(&SockAddr::from(SocketAddr::from((bind_addr_v4, 0))))?;
            UdpSocket::from_std(StdUdpSocket::from(s))?
        };

        let socket_v6 = if udp_relay_ipv6 {
            let bind_addr_v6 = conn.cfg.outbound_bind_ipv6.unwrap_or(Ipv6Addr::UNSPECIFIED);
            let s = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
            s.set_nonblocking(true)?;
            s.set_only_v6(true)?;
            s.bind(&SockAddr::from(SocketAddr::from((bind_addr_v6, 0))))?;
            Some(UdpSocket::from_std(StdUdpSocket::from(s))?)
        } else {
            None
        };

        let (tx, rx) = oneshot::channel::<()>();

        let session = Arc::new(Self {
            assoc_id,
            socket_v4,
            socket_v6,
            close_tx: AsyncRwLock::new(Some(tx)),
        });

        let session_listen = session.clone();
        tokio::spawn(async move {
            let mut rx = rx;
            let mut timeout = tokio::time::interval(stream_timeout);
            timeout.reset();
            loop {
                tokio::select! {
                    result = session_listen.recv(max_pkt_size) => {
                        timeout.reset();
                        match result {
                            Ok((pkt, addr)) => {
                                let addr_tuic = Address::SocketAddress(addr);
                                let hdr = build_packet_header(
                                    session_listen.assoc_id,
                                    rand::random::<u16>(),
                                    &addr_tuic,
                                    pkt.len() as u16,
                                );
                                // relay back via conn
                                let conn = conn.clone();
                                let pkt_clone = pkt.clone();
                                tokio::spawn(async move {
                                    conn.relay_udp_to_client(hdr, pkt_clone).await;
                                });
                            }
                            Err(e) => {
                                warn!("[TUIC][UDP][{:#06x}] recv error: {e}", session_listen.assoc_id);
                            }
                        }
                    }
                    _ = timeout.tick() => {
                        warn!("[TUIC][UDP][{:#06x}] session timeout", session_listen.assoc_id);
                        break;
                    }
                    _ = &mut rx => break,
                }
            }
        });

        Ok(session)
    }

    pub async fn send(&self, pkt: Bytes, addr: SocketAddr) -> std::io::Result<()> {
        let mut addr = addr;
        if let SocketAddr::V6(v6) = addr {
            if let Some(v4) = v6.ip().to_ipv4_mapped() {
                addr = SocketAddr::new(IpAddr::V4(v4), v6.port());
            }
        }
        let socket = match addr {
            SocketAddr::V4(_) => &self.socket_v4,
            SocketAddr::V6(_) => self.socket_v6.as_ref().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::Unsupported, "IPv6 UDP relay disabled")
            })?,
        };
        socket.send_to(&pkt, addr).await?;
        Ok(())
    }

    async fn recv(&self, max_pkt_size: usize) -> std::io::Result<(Bytes, SocketAddr)> {
        let recv_one = async |socket: &UdpSocket| -> std::io::Result<(Bytes, SocketAddr)> {
            let mut buf = vec![0u8; max_pkt_size];
            let (n, mut addr) = socket.recv_from(&mut buf).await?;
            if let SocketAddr::V6(v6) = addr {
                if let Some(v4) = v6.ip().to_ipv4_mapped() {
                    addr = SocketAddr::new(IpAddr::V4(v4), v6.port());
                }
            }
            buf.truncate(n);
            Ok((Bytes::from(buf), addr))
        };

        if let Some(v6) = &self.socket_v6 {
            tokio::select! {
                r = recv_one(&self.socket_v4) => r,
                r = recv_one(v6) => r,
            }
        } else {
            recv_one(&self.socket_v4).await
        }
    }

    pub async fn close(&self) {
        if let Some(tx) = self.close_tx.write().await.take() {
            let _ = tx.send(());
        }
    }
}

// ── Connection ────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct Connection {
    inner: QuinnConnection,
    auth: Authenticated,
    users: Arc<HashMap<Uuid, String>>,
    cfg: Arc<TuicConfig>,
    udp_sessions: Arc<tokio::sync::Mutex<HashMap<u16, Arc<UdpSession>>>>,
    udp_mode: Arc<std::sync::Mutex<Option<UdpMode>>>,
}

#[derive(Clone, Copy, Debug)]
enum UdpMode {
    Quic,
    Native,
}

impl std::fmt::Display for UdpMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UdpMode::Quic => write!(f, "quic"),
            UdpMode::Native => write!(f, "native"),
        }
    }
}

impl Connection {
    pub fn new(
        inner: QuinnConnection,
        users: Arc<HashMap<Uuid, String>>,
        cfg: Arc<TuicConfig>,
    ) -> Self {
        Self {
            inner,
            auth: Authenticated::new(),
            users,
            cfg,
            udp_sessions: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            udp_mode: Arc::new(std::sync::Mutex::new(None)),
        }
    }

    /// Main entry: handle a newly accepted QUIC connection
    pub async fn handle(self) {
        let peer = self.inner.remote_address();
        info!("[TUIC] connection from {peer}");

        // Spawn authentication timeout watchdog
        let conn_wdog = self.clone();
        let auth_timeout = self.cfg.auth_timeout;
        tokio::spawn(async move {
            time::sleep(auth_timeout).await;
            if !conn_wdog.auth.is_authenticated() {
                warn!("[TUIC] {peer} authentication timeout, closing");
                conn_wdog
                    .inner
                    .close(quinn::VarInt::from_u32(0), b"auth timeout");
            }
        });

        // Event loop
        loop {
            if self.inner.close_reason().is_some() {
                break;
            }
            let handle_next = async {
                tokio::select! {
                    res = self.inner.accept_uni() => {
                        let recv = res?;
                        let conn = self.clone();
                        tokio::spawn(async move { conn.handle_uni(recv).await });
                    }
                    res = self.inner.accept_bi() => {
                        let (send, recv) = res?;
                        let conn = self.clone();
                        tokio::spawn(async move { conn.handle_bi(send, recv).await });
                    }
                    res = self.inner.read_datagram() => {
                        let dg = res?;
                        let conn = self.clone();
                        tokio::spawn(async move { conn.handle_datagram(dg).await });
                    }
                }
                Ok::<_, Error>(())
            };

            match handle_next.await {
                Ok(()) => {}
                Err(e) if e.is_trivial() => {
                    debug!("[TUIC] {peer}: {e}");
                    break;
                }
                Err(e) => {
                    warn!("[TUIC] {peer}: {e}");
                    break;
                }
            }
        }

        info!("[TUIC] connection from {peer} closed");
    }

    // ── Unidirectional stream (Authenticate / Packet / Dissociate) ────────────

    async fn handle_uni(&self, mut recv: RecvStream) {
        // Peek 2 bytes to verify TUIC prefix before full parse
        let mut peek = [0u8; 2];
        if recv.read_exact(&mut peek).await.is_err() {
            return;
        }
        if !crate::tuic::proto::Command::is_tuic_prefix(peek) {
            warn!("[TUIC] non-TUIC unidirectional stream, ignoring");
            return;
        }

        // Re-read with restored 2 bytes prepended via a combined reader
        // Since quinn RecvStream doesn't support unread, we parse inline:
        let cmd = self.parse_command_with_prefix(peek, &mut recv).await;

        match cmd {
            Ok(Command::Authenticate(auth)) => {
                self.handle_authenticate(auth.uuid, auth.token).await
            }
            Ok(Command::Packet(info)) => {
                self.handle_packet_stream(info, &mut recv, UdpMode::Quic)
                    .await
            }
            Ok(Command::Dissociate(id)) => self.handle_dissociate(id).await,
            Ok(other) => warn!("[TUIC] unexpected command on uni stream: {:?}", other),
            Err(e) => warn!("[TUIC] uni stream parse error: {e}"),
        }
    }

    // ── Bidirectional stream (Connect) ────────────────────────────────────────

    async fn handle_bi(&self, send: SendStream, mut recv: RecvStream) {
        let mut peek = [0u8; 2];
        if recv.read_exact(&mut peek).await.is_err() {
            return;
        }
        if !crate::tuic::proto::Command::is_tuic_prefix(peek) {
            warn!("[TUIC] non-TUIC bidirectional stream, ignoring");
            return;
        }

        // Wait for auth
        if !self.auth.is_authenticated() {
            tokio::select! {
                () = self.auth.wait() => {}
                () = tokio::time::sleep(self.cfg.auth_timeout) => {
                    warn!("[TUIC] bi stream: auth wait timeout");
                    return;
                }
            }
        }

        let cmd = self.parse_command_with_prefix(peek, &mut recv).await;
        match cmd {
            Ok(Command::Connect(addr)) => self.handle_connect(addr, send, recv).await,
            Ok(other) => warn!("[TUIC] unexpected command on bi stream: {:?}", other),
            Err(e) => warn!("[TUIC] bi stream parse error: {e}"),
        }
    }

    // ── Datagram (Packet / Heartbeat) ─────────────────────────────────────────

    async fn handle_datagram(&self, dg: Bytes) {
        if dg.len() < 2 || !crate::tuic::proto::Command::is_tuic_prefix([dg[0], dg[1]]) {
            return;
        }

        if !self.auth.is_authenticated() {
            tokio::select! {
                () = self.auth.wait() => {}
                () = tokio::time::sleep(self.cfg.auth_timeout) => return,
            }
        }

        match Command::read_from_datagram(&dg) {
            Ok(Command::Packet(info)) => {
                // payload starts after header bytes
                let hdr_len = 2 + 8 + info.addr.to_bytes().len();
                if dg.len() < hdr_len {
                    return;
                }
                let payload = dg.slice(hdr_len..);
                self.handle_packet_data(info, payload, UdpMode::Native)
                    .await;
            }
            Ok(Command::Heartbeat) => debug!("[TUIC] heartbeat"),
            Ok(other) => warn!("[TUIC] unexpected datagram command: {:?}", other),
            Err(e) => warn!("[TUIC] datagram parse error: {e}"),
        }
    }

    // ── Command implementations ───────────────────────────────────────────────

    async fn handle_authenticate(&self, uuid: Uuid, token: [u8; 32]) {
        if self.auth.is_authenticated() {
            warn!("[TUIC] duplicate authentication from {uuid}");
            return;
        }

        // Validate: use TLS keying material exporter
        let valid = if let Some(password) = self.users.get(&uuid) {
            self.validate_token(&uuid, password, &token)
        } else {
            false
        };

        if valid {
            info!("[TUIC] authenticated: {uuid}");
            self.auth.set(uuid);
        } else {
            warn!("[TUIC] authentication failed for {uuid}");
            self.inner.close(quinn::VarInt::from_u32(0), b"auth failed");
        }
    }

    fn validate_token(&self, uuid: &Uuid, password: &str, token: &[u8; 32]) -> bool {
        // TUIC uses TLS keying material exporter:
        // label = uuid raw 16 bytes, context = password bytes
        let mut expected = [0u8; 32];
        if self
            .inner
            .export_keying_material(&mut expected, uuid.as_bytes(), password.as_bytes())
            .is_ok()
        {
            return expected == *token;
        }
        false
    }

    async fn handle_connect(&self, addr: Address, mut send: SendStream, mut recv: RecvStream) {
        let target = addr.to_string();
        info!("[TUIC][TCP] connecting to {target}");

        let mut stream = match self.dial_tcp(&addr).await {
            Ok(s) => s,
            Err(e) => {
                warn!("[TUIC][TCP] {target}: dial failed: {e}");
                let _ = send.reset(quinn::VarInt::from_u32(0));
                return;
            }
        };
        let _ = stream.set_nodelay(true);

        // Bidirectional copy
        let (mut tcp_r, mut tcp_w) = stream.split();
        let c2s = tokio::io::copy(&mut recv, &mut tcp_w);
        let s2c = tokio::io::copy(&mut tcp_r, &mut send);

        tokio::select! {
            r = c2s => {
                if let Err(e) = r { debug!("[TUIC][TCP] {target} c2s: {e}"); }
            }
            r = s2c => {
                if let Err(e) = r { debug!("[TUIC][TCP] {target} s2c: {e}"); }
            }
        }

        let _ = send.finish();
        info!("[TUIC][TCP] {target} done");
    }

    async fn handle_packet_stream(&self, info: PacketInfo, recv: &mut RecvStream, mode: UdpMode) {
        // Wait for auth
        if !self.auth.is_authenticated() {
            tokio::select! {
                () = self.auth.wait() => {}
                () = tokio::time::sleep(self.cfg.auth_timeout) => return,
            }
        }

        // Read payload
        let mut payload = vec![0u8; info.size as usize];
        if recv.read_exact(&mut payload).await.is_err() {
            return;
        }
        self.handle_packet_data(info, Bytes::from(payload), mode)
            .await;
    }

    async fn handle_packet_data(&self, info: PacketInfo, payload: Bytes, mode: UdpMode) {
        // Set/verify UDP mode consistency
        {
            let mut m = self.udp_mode.lock().unwrap();
            match *m {
                None => *m = Some(mode),
                Some(existing) => {
                    // Allow if same mode; warn if mismatch but continue
                    if matches!(
                        (existing, mode),
                        (UdpMode::Native, UdpMode::Quic) | (UdpMode::Quic, UdpMode::Native)
                    ) {
                        warn!("[TUIC][UDP] mode mismatch: expected {existing}, got {mode}");
                    }
                }
            }
        }

        let assoc_id = info.assoc_id;
        info!(
            "[TUIC][UDP][{assoc_id:#06x}] pkt {}/{} from {}",
            info.frag_id + 1,
            info.frag_total,
            info.addr
        );

        // Fragmentation: only support frag_total=1 for now (no reassembly needed for simple case)
        if info.frag_total != 1 {
            warn!("[TUIC][UDP][{assoc_id:#06x}] fragmented UDP not yet reassembled (frag {}/{}), dropping", info.frag_id + 1, info.frag_total);
            return;
        }

        // Resolve target
        let target_addr = match self.resolve_addr(&info.addr).await {
            Ok(a) => a,
            Err(e) => {
                warn!(
                    "[TUIC][UDP][{assoc_id:#06x}] resolve {} failed: {e}",
                    info.addr
                );
                return;
            }
        };

        // Get or create UDP session
        let session = {
            let mut sessions = self.udp_sessions.lock().await;
            if let Some(s) = sessions.get(&assoc_id) {
                s.clone()
            } else {
                match UdpSession::new(
                    self.clone(),
                    assoc_id,
                    self.cfg.udp_relay_ipv6,
                    self.cfg.udp_timeout,
                    self.cfg.max_udp_packet_size,
                ) {
                    Ok(s) => {
                        sessions.insert(assoc_id, s.clone());
                        s
                    }
                    Err(e) => {
                        warn!("[TUIC][UDP][{assoc_id:#06x}] session create failed: {e}");
                        return;
                    }
                }
            }
        };

        if let Err(e) = session.send(payload, target_addr).await {
            warn!("[TUIC][UDP][{assoc_id:#06x}] send to {target_addr}: {e}");
        }
    }

    async fn handle_dissociate(&self, assoc_id: u16) {
        info!("[TUIC][UDP][{assoc_id:#06x}] dissociate");
        if let Some(session) = self.udp_sessions.lock().await.remove(&assoc_id) {
            session.close().await;
        }
    }

    // ── Relay UDP back to TUIC client ─────────────────────────────────────────

    pub async fn relay_udp_to_client(&self, header: Vec<u8>, payload: Bytes) {
        let mode = *self.udp_mode.lock().unwrap();
        match mode {
            Some(UdpMode::Native) | None => {
                // Send as datagram
                let mut dg = bytes::BytesMut::with_capacity(header.len() + payload.len());
                dg.extend_from_slice(&header);
                dg.extend_from_slice(&payload);
                if let Err(e) = self.inner.send_datagram(dg.freeze()) {
                    warn!("[TUIC][UDP] relay datagram failed: {e}");
                }
            }
            Some(UdpMode::Quic) => {
                // Send as uni stream
                match self.inner.open_uni().await {
                    Ok(mut send) => {
                        let _ = send.write_all(&header).await;
                        let _ = send.write_all(&payload).await;
                        let _ = send.finish();
                    }
                    Err(e) => warn!("[TUIC][UDP] open_uni for relay failed: {e}"),
                }
            }
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    async fn dial_tcp(&self, addr: &Address) -> anyhow::Result<TcpStream> {
        let addrs = self.resolve_addr_list(addr).await?;
        let bind_ip = crate::common::net::OutboundBind::new(
            self.cfg.outbound_bind_ipv4,
            self.cfg.outbound_bind_ipv6,
        );
        let mut last_err = None;
        for sa in addrs {
            match crate::common::net::dial_tcp_addr(sa, bind_ip).await {
                Ok(s) => return Ok(s),
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err
            .map(|e| anyhow::anyhow!(e))
            .unwrap_or_else(|| anyhow::anyhow!("no addresses resolved for {addr}")))
    }

    async fn resolve_addr(&self, addr: &Address) -> anyhow::Result<SocketAddr> {
        let list = self.resolve_addr_list(addr).await?;
        list.into_iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!("no addresses resolved for {addr}"))
    }

    async fn resolve_addr_list(&self, addr: &Address) -> anyhow::Result<Vec<SocketAddr>> {
        match addr {
            Address::None => Err(anyhow::anyhow!("empty address")),
            Address::SocketAddress(sa) => Ok(vec![*sa]),
            Address::DomainAddress(domain, port) => {
                let addrs: Vec<SocketAddr> =
                    net::lookup_host((domain.as_str(), *port)).await?.collect();
                if addrs.is_empty() {
                    return Err(anyhow::anyhow!("DNS resolve failed for {domain}:{port}"));
                }
                Ok(addrs)
            }
        }
    }

    /// Parse a TUIC command when we've already consumed the 2-byte VER+TYPE prefix
    async fn parse_command_with_prefix(
        &self,
        prefix: [u8; 2],
        recv: &mut RecvStream,
    ) -> Result<Command, Error> {
        let ver = prefix[0];
        let cmd = prefix[1];

        if ver != VERSION {
            return Err(Error::Protocol(format!("unsupported TUIC version: {ver}")));
        }

        use crate::tuic::proto::{
            CMD_AUTHENTICATE, CMD_CONNECT, CMD_DISSOCIATE, CMD_HEARTBEAT, CMD_PACKET,
        };

        match cmd {
            CMD_AUTHENTICATE => {
                let mut buf = [0u8; 48];
                recv.read_exact(&mut buf).await.map_err(Error::from)?;
                let uuid = uuid::Uuid::from_bytes(buf[..16].try_into().unwrap());
                let token: [u8; 32] = buf[16..48].try_into().unwrap();
                Ok(Command::Authenticate(crate::tuic::proto::AuthInfo {
                    uuid,
                    token,
                }))
            }
            CMD_CONNECT => {
                let addr = Address::read_from(recv).await.map_err(Error::Io)?;
                Ok(Command::Connect(addr))
            }
            CMD_PACKET => {
                let mut buf = [0u8; 8];
                recv.read_exact(&mut buf).await.map_err(Error::from)?;
                let assoc_id = u16::from_be_bytes([buf[0], buf[1]]);
                let pkt_id = u16::from_be_bytes([buf[2], buf[3]]);
                let frag_total = buf[4];
                let frag_id = buf[5];
                let size = u16::from_be_bytes([buf[6], buf[7]]);
                let addr = Address::read_from(recv).await.map_err(Error::Io)?;
                Ok(Command::Packet(PacketInfo {
                    assoc_id,
                    _pkt_id: pkt_id,
                    frag_total,
                    frag_id,
                    size,
                    addr,
                }))
            }
            CMD_DISSOCIATE => {
                let mut buf = [0u8; 2];
                recv.read_exact(&mut buf).await.map_err(Error::from)?;
                Ok(Command::Dissociate(u16::from_be_bytes(buf)))
            }
            CMD_HEARTBEAT => Ok(Command::Heartbeat),
            _ => Err(Error::Protocol(format!("unknown command: {cmd}"))),
        }
    }
}

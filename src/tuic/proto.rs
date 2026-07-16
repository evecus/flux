/// TUIC protocol version
pub const VERSION: u8 = 0x05;

use std::{
    fmt::{Display, Formatter, Result as FmtResult},
    net::SocketAddr,
};

use tokio::io::{AsyncRead, AsyncReadExt};
use uuid::Uuid;

// ── Address ───────────────────────────────────────────────────────────────────

#[allow(clippy::enum_variant_names)]
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum Address {
    None,
    DomainAddress(String, u16),
    SocketAddress(SocketAddr),
}

impl Address {
    pub async fn read_from(r: &mut (impl AsyncRead + Unpin)) -> std::io::Result<Self> {
        let mut buf = [0u8; 1];
        r.read_exact(&mut buf).await?;
        match buf[0] {
            0xff => Ok(Self::None),
            0x00 => {
                // domain
                r.read_exact(&mut buf).await?;
                let len = buf[0] as usize;
                let mut domain_buf = vec![0u8; len + 2];
                r.read_exact(&mut domain_buf).await?;
                let port = u16::from_be_bytes([domain_buf[len], domain_buf[len + 1]]);
                domain_buf.truncate(len);
                let domain = String::from_utf8(domain_buf)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                Ok(Self::DomainAddress(domain, port))
            }
            0x01 => {
                // IPv4
                let mut b = [0u8; 6];
                r.read_exact(&mut b).await?;
                let port = u16::from_be_bytes([b[4], b[5]]);
                Ok(Self::SocketAddress(SocketAddr::from((
                    [b[0], b[1], b[2], b[3]],
                    port,
                ))))
            }
            0x02 => {
                // IPv6
                let mut b = [0u8; 18];
                r.read_exact(&mut b).await?;
                let ip = [
                    u16::from_be_bytes([b[0], b[1]]),
                    u16::from_be_bytes([b[2], b[3]]),
                    u16::from_be_bytes([b[4], b[5]]),
                    u16::from_be_bytes([b[6], b[7]]),
                    u16::from_be_bytes([b[8], b[9]]),
                    u16::from_be_bytes([b[10], b[11]]),
                    u16::from_be_bytes([b[12], b[13]]),
                    u16::from_be_bytes([b[14], b[15]]),
                ];
                let port = u16::from_be_bytes([b[16], b[17]]);
                Ok(Self::SocketAddress(SocketAddr::from((ip, port))))
            }
            t => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unknown address type: {t}"),
            )),
        }
    }

    /// Encode address into bytes for sending back to client
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::None => vec![0xff],
            Self::DomainAddress(domain, port) => {
                let mut v = Vec::with_capacity(4 + domain.len());
                v.push(0x00);
                v.push(domain.len() as u8);
                v.extend_from_slice(domain.as_bytes());
                v.extend_from_slice(&port.to_be_bytes());
                v
            }
            Self::SocketAddress(SocketAddr::V4(a)) => {
                let mut v = vec![0x01];
                v.extend_from_slice(&a.ip().octets());
                v.extend_from_slice(&a.port().to_be_bytes());
                v
            }
            Self::SocketAddress(SocketAddr::V6(a)) => {
                let mut v = vec![0x02];
                for seg in a.ip().segments() {
                    v.extend_from_slice(&seg.to_be_bytes());
                }
                v.extend_from_slice(&a.port().to_be_bytes());
                v
            }
        }
    }
}

impl Display for Address {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            Self::None => write!(f, "none"),
            Self::DomainAddress(d, p) => write!(f, "{d}:{p}"),
            Self::SocketAddress(a) => write!(f, "{a}"),
        }
    }
}

// ── Command types ─────────────────────────────────────────────────────────────

pub const CMD_AUTHENTICATE: u8 = 0x00;
pub const CMD_CONNECT: u8 = 0x01;
pub const CMD_PACKET: u8 = 0x02;
pub const CMD_DISSOCIATE: u8 = 0x03;
pub const CMD_HEARTBEAT: u8 = 0x04;

// ── Parsed commands ───────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct AuthInfo {
    pub uuid: Uuid,
    pub token: [u8; 32],
}

#[derive(Debug)]
pub struct PacketInfo {
    pub assoc_id: u16,
    pub _pkt_id: u16,
    pub frag_total: u8,
    pub frag_id: u8,
    pub size: u16,
    pub addr: Address,
}

#[derive(Debug)]
pub enum Command {
    Authenticate(AuthInfo),
    Connect(Address),
    Packet(PacketInfo),
    Dissociate(u16),
    Heartbeat,
}

impl Command {
    /// Read from datagram bytes (no stream, just a Bytes buffer)
    pub fn read_from_datagram(data: &bytes::Bytes) -> std::io::Result<Self> {
        use std::io::Cursor;
        // Use sync read via cursor - we already have all the bytes
        let mut c = Cursor::new(data.as_ref());
        Self::read_from_sync(&mut c)
    }

    fn read_from_sync(r: &mut impl std::io::Read) -> std::io::Result<Self> {
        let mut hdr = [0u8; 2];
        r.read_exact(&mut hdr)?;
        let ver = hdr[0];
        let cmd = hdr[1];
        if ver != VERSION {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unsupported TUIC version: {ver}"),
            ));
        }
        match cmd {
            CMD_AUTHENTICATE => {
                let mut buf = [0u8; 48];
                r.read_exact(&mut buf)?;
                let uuid = Uuid::from_bytes(buf[..16].try_into().unwrap());
                let token: [u8; 32] = buf[16..48].try_into().unwrap();
                Ok(Self::Authenticate(AuthInfo { uuid, token }))
            }
            CMD_PACKET => {
                let mut buf = [0u8; 8];
                r.read_exact(&mut buf)?;
                let assoc_id = u16::from_be_bytes([buf[0], buf[1]]);
                let pkt_id = u16::from_be_bytes([buf[2], buf[3]]);
                let frag_total = buf[4];
                let frag_id = buf[5];
                let size = u16::from_be_bytes([buf[6], buf[7]]);
                let addr = Self::read_address_sync(r)?;
                Ok(Self::Packet(PacketInfo {
                    assoc_id,
                    _pkt_id: pkt_id,
                    frag_total,
                    frag_id,
                    size,
                    addr,
                }))
            }
            CMD_HEARTBEAT => Ok(Self::Heartbeat),
            CMD_DISSOCIATE => {
                let mut buf = [0u8; 2];
                r.read_exact(&mut buf)?;
                Ok(Self::Dissociate(u16::from_be_bytes(buf)))
            }
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unexpected cmd {cmd} in datagram"),
            )),
        }
    }

    fn read_address_sync(r: &mut impl std::io::Read) -> std::io::Result<Address> {
        let mut buf = [0u8; 1];
        r.read_exact(&mut buf)?;
        match buf[0] {
            0xff => Ok(Address::None),
            0x00 => {
                r.read_exact(&mut buf)?;
                let len = buf[0] as usize;
                let mut domain_buf = vec![0u8; len + 2];
                r.read_exact(&mut domain_buf)?;
                let port = u16::from_be_bytes([domain_buf[len], domain_buf[len + 1]]);
                domain_buf.truncate(len);
                let domain = String::from_utf8(domain_buf)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                Ok(Address::DomainAddress(domain, port))
            }
            0x01 => {
                let mut b = [0u8; 6];
                r.read_exact(&mut b)?;
                let port = u16::from_be_bytes([b[4], b[5]]);
                Ok(Address::SocketAddress(SocketAddr::from((
                    [b[0], b[1], b[2], b[3]],
                    port,
                ))))
            }
            0x02 => {
                let mut b = [0u8; 18];
                r.read_exact(&mut b)?;
                let ip = [
                    u16::from_be_bytes([b[0], b[1]]),
                    u16::from_be_bytes([b[2], b[3]]),
                    u16::from_be_bytes([b[4], b[5]]),
                    u16::from_be_bytes([b[6], b[7]]),
                    u16::from_be_bytes([b[8], b[9]]),
                    u16::from_be_bytes([b[10], b[11]]),
                    u16::from_be_bytes([b[12], b[13]]),
                    u16::from_be_bytes([b[14], b[15]]),
                ];
                let port = u16::from_be_bytes([b[16], b[17]]);
                Ok(Address::SocketAddress(SocketAddr::from((ip, port))))
            }
            t => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unknown address type {t}"),
            )),
        }
    }

    /// Check if a 2-byte prefix looks like a TUIC command
    pub fn is_tuic_prefix(prefix: [u8; 2]) -> bool {
        prefix[0] == VERSION && prefix[1] <= CMD_HEARTBEAT
    }
}

/// Build a TUIC packet header for sending back to client (server→client direction)
pub fn build_packet_header(
    assoc_id: u16,
    pkt_id: u16,
    addr: &Address,
    payload_len: u16,
) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(VERSION);
    buf.push(CMD_PACKET);
    buf.extend_from_slice(&assoc_id.to_be_bytes());
    buf.extend_from_slice(&pkt_id.to_be_bytes());
    buf.push(1u8); // frag_total = 1
    buf.push(0u8); // frag_id = 0
    buf.extend_from_slice(&payload_len.to_be_bytes());
    buf.extend_from_slice(&addr.to_bytes());
    buf
}

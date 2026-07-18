//! VLESS protocol header parsing — mirrors Xray's encoding.go / address.go
//!
//! Request wire format (from Xray source, encoding.go DecodeRequestHeader):
//!
//!   [1B]  version   — must be 0x00
//!   [16B] UUID      — client identity
//!   [1B]  addon_len — length of protobuf addons (we skip, always 0 for flow=none)
//!   [NB]  addons    — ignored (flow control, xtls, etc.)
//!   [1B]  command   — 0x01=TCP, 0x02=UDP (we only handle TCP)
//!   [2B]  port      — big-endian u16  ← PortThenAddress() in Xray
//!   [1B]  addr_type — 0x01=IPv4, 0x02=Domain, 0x03=IPv6
//!   ...   addr      — 4B / (1B len + NB) / 16B
//!
//! Response wire format (EncodeResponseHeader):
//!   [1B]  version   — echo client version (0x00)
//!   [1B]  addon_len — 0x00 (no addons)
//!
//! Address type bytes match Xray's AddressFamilyByte assignments:
//!   IPv4   → 0x01
//!   Domain → 0x02
//!   IPv6   → 0x03

use anyhow::{bail, Result};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::debug;

// ── Constants (Xray protocol values) ─────────────────────────────────────────

pub const VLESS_VERSION: u8 = 0x00;

/// Request commands (mirrors Xray protocol.RequestCommand)
pub const CMD_TCP: u8 = 0x01;
pub const CMD_UDP: u8 = 0x02;

/// Address type bytes (mirrors Xray AddressFamilyByte assignments in encoding.go)
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x02;
const ATYP_IPV6: u8 = 0x03;

// ── Public types ──────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct VlessRequest {
    pub command: u8,
    /// Resolved target as "host:port"
    pub target: String,
}

// ── Request decoder ───────────────────────────────────────────────────────────

/// Decode a VLESS request header from `reader`.
///
/// Steps (directly mapping Xray's DecodeRequestHeader):
///   1. version check
///   2. UUID read + validate against expected bytes
///   3. skip addon bytes (protobuf, length-prefixed)
///   4. command byte
///   5. PortThenAddress: port (2B BE) then addr_type + addr bytes
///
/// On success returns the parsed request; the stream is positioned at the
/// first byte of the proxied payload.
pub async fn decode_request<R>(reader: &mut R, expected_uuid: &[u8; 16]) -> Result<VlessRequest>
where
    R: AsyncRead + Unpin,
{
    // 1. Version
    let version = reader.read_u8().await?;
    if version != VLESS_VERSION {
        bail!("vless: unsupported version {version:#x}, expected 0x00");
    }

    // 2. UUID (16 bytes) — mirrors Xray's validator.Get(id) check
    let mut uuid_buf = [0u8; 16];
    reader.read_exact(&mut uuid_buf).await?;
    if &uuid_buf != expected_uuid {
        bail!("vless: invalid UUID");
    }

    // 3. Addons (protobuf, 1-byte length prefix) — skip entirely (flow=none)
    //    Mirrors Xray DecodeHeaderAddons: read 1B length, then skip that many bytes.
    let addon_len = reader.read_u8().await? as usize;
    if addon_len > 0 {
        let mut discard = vec![0u8; addon_len];
        reader.read_exact(&mut discard).await?;
    }

    // 4. Command byte
    let command = reader.read_u8().await?;
    if command != CMD_TCP && command != CMD_UDP {
        bail!("vless: unsupported command {command:#x}");
    }

    // 5. PortThenAddress (matches Xray portFirstAddressParser.ReadAddressPort)
    //    port is 2B big-endian, then addr_type + addr
    let port = reader.read_u16().await?; // big-endian
    let addr = read_address(reader).await?;

    let target = format!("{addr}:{port}");
    debug!("vless: decoded request cmd={command:#x} target={target}");

    Ok(VlessRequest { command, target })
}

/// Read the address portion (addr_type + addr bytes).
/// Mirrors Xray addressParser.readAddress().
async fn read_address<R>(reader: &mut R) -> Result<String>
where
    R: AsyncRead + Unpin,
{
    let atyp = reader.read_u8().await?;
    match atyp {
        ATYP_IPV4 => {
            // 4 bytes IPv4
            let mut buf = [0u8; 4];
            reader.read_exact(&mut buf).await?;
            Ok(Ipv4Addr::from(buf).to_string())
        }
        ATYP_DOMAIN => {
            // 1-byte domain length, then domain bytes
            // Mirrors Xray: ReadFullFrom(reader, 1) for domainLength, then ReadFullFrom(reader, domainLength)
            let domain_len = reader.read_u8().await? as usize;
            if domain_len == 0 {
                bail!("vless: empty domain");
            }
            let mut domain_buf = vec![0u8; domain_len];
            reader.read_exact(&mut domain_buf).await?;
            let domain = String::from_utf8(domain_buf)?;
            Ok(domain)
        }
        ATYP_IPV6 => {
            // 16 bytes IPv6
            let mut buf = [0u8; 16];
            reader.read_exact(&mut buf).await?;
            Ok(format!("[{}]", Ipv6Addr::from(buf)))
        }
        _ => bail!("vless: unknown address type {atyp:#x}"),
    }
}

// ── Response encoder ──────────────────────────────────────────────────────────

/// Write a VLESS response header to `writer`.
///
/// Mirrors Xray's EncodeResponseHeader:
///   [1B] version   = 0x00
///   [1B] addon_len = 0x00  (no addons, flow=none)
///
/// Must be called before proxying any upstream data back to the client.
pub async fn encode_response<W>(writer: &mut W) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    writer.write_all(&[VLESS_VERSION, 0x00]).await?;
    Ok(())
}

// ── UUID helpers ──────────────────────────────────────────────────────────────

/// Parse a UUID string (with or without hyphens) into raw 16 bytes.
/// Matches the format Xray's uuid.ParseString accepts.
pub fn parse_uuid(s: &str) -> Result<[u8; 16]> {
    let hex: String = s.chars().filter(|c| *c != '-').collect();
    if hex.len() != 32 {
        bail!("vless: invalid UUID string: {s}");
    }
    let mut bytes = [0u8; 16];
    for i in 0..16 {
        bytes[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|_| anyhow::anyhow!("vless: invalid UUID hex at byte {i}"))?;
    }
    Ok(bytes)
}

// ── packetaddr (VLESS UDP relay framing) ──────────────────────────────────────
//
// 与 Xray `packetaddr/packetaddr.go` 一致：UDP 包通过同一 VLESS 流传输，
// 每个包前置 2 字节大端长度，载荷为 SOCKS5 风格的 ATYP+ADDR+PORT+payload。
//
//   入站/出站每包: [2B length BE] [1B ATYP] [addr] [2B port BE] [payload]
//   length = len(ATYP + addr + port + payload)
//
// 域名目标在 VLESS UDP 中按 Xray 行为处理：仅在解析时支持，实际拨号时
// 调用方应已用 lookup_host 把域名解析成 SocketAddr。

/// 读取一个 packetaddr 帧，返回 (源/目标地址, payload)。
///
/// `reader` 位置应在帧起始（即 2 字节长度前缀处）。
pub async fn read_packet<'a, R>(
    reader: &mut R,
    buf: &'a mut [u8],
) -> Result<(SocketAddr, &'a [u8])>
where
    R: AsyncRead + Unpin,
{
    let len = reader.read_u16().await? as usize;
    if len == 0 {
        bail!("vless: packetaddr: zero-length frame");
    }
    if len > buf.len() {
        bail!(
            "vless: packetaddr: frame too large ({len} > {})",
            buf.len()
        );
    }
    let frame = &mut buf[..len];
    reader.read_exact(frame).await?;

    // frame = ATYP + addr + port(2) + payload
    let atyp = frame[0];
    let (addr_len, ip) = match atyp {
        ATYP_IPV4 => (4, std::net::IpAddr::V4(Ipv4Addr::from([frame[1], frame[2], frame[3], frame[4]]))),
        ATYP_IPV6 => {
            let mut b = [0u8; 16];
            b.copy_from_slice(&frame[1..17]);
            (16, std::net::IpAddr::V6(Ipv6Addr::from(b)))
        }
        _ => bail!("vless: packetaddr: ATYP {atyp:#x} 不支持（packetaddr 仅承载已解析的 IP 地址）"),
    };
    let port_off = 1 + addr_len;
    if frame.len() < port_off + 2 {
        bail!("vless: packetaddr: frame truncated before port");
    }
    let port = u16::from_be_bytes([frame[port_off], frame[port_off + 1]]);
    let payload = &frame[port_off + 2..];
    Ok((SocketAddr::new(ip, port), payload))
}

/// 写一个 packetaddr 帧。
///
/// `writer` 位置应在帧起始处；写完后流位置指向下一帧。
pub async fn write_packet<W>(
    writer: &mut W,
    src: SocketAddr,
    payload: &[u8],
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    // addr 段：IPv4=4B，IPv6=16B；ATYP=1B；port=2B
    let addr_len = match src {
        SocketAddr::V4(_) => 4,
        SocketAddr::V6(_) => 16,
    };
    let frame_len = 1 + addr_len + 2 + payload.len();
    if frame_len > 0xFFFF {
        bail!("vless: packetaddr: frame too large ({frame_len} > 65535)");
    }

    let mut hdr = [0u8; 1 + 16 + 2]; // 最大头部空间
    hdr[0] = match src {
        SocketAddr::V4(v4) => {
            hdr[1..5].copy_from_slice(&v4.ip().octets());
            ATYP_IPV4
        }
        SocketAddr::V6(v6) => {
            hdr[1..17].copy_from_slice(&v6.ip().octets());
            ATYP_IPV6
        }
    };
    let port_off = 1 + addr_len;
    hdr[port_off..port_off + 2].copy_from_slice(&src.port().to_be_bytes());

    // 2B length 前缀
    writer.write_all(&(frame_len as u16).to_be_bytes()).await?;
    writer.write_all(&hdr[..1 + addr_len + 2]).await?;
    writer.write_all(payload).await?;
    Ok(())
}


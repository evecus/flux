//! UDP-over-TCP (UoT) codec for AnyTLS.
//!
//! 客户端为 UDP 会话打开一条到 magic host 的 AnyTLS stream，随后在这条字节流上
//! 复用多个 datagram。协议里有**两套不同的地址编码**，不能混用：
//!
//! * **stream 目标 / 请求头**：标准 SOCKS5 `ATYP | ADDR | PORT`
//!   （`0x01` IPv4 / `0x03` FQDN / `0x04` IPv6），对应 sing
//!   `M.SocksaddrSerializer.ReadAddrPort`。
//! * **每个 datagram 的地址**：sing UoT 专用 family byte
//!   （`0x00` IPv4 / `0x01` IPv6 / `0x02` FQDN），对应 `uot.AddrParser`。
//!
//! 线格式（对齐 `sing/common/uot` v0.5.1 与官方 anytls-go `cmd/server`）：
//!
//! ```text
//! v2 请求头: [isConnect: u8][SOCKS5 ADDR][PORT]
//!   isConnect=1 (clash-rs)  : 固定目标，后续每包只有 [LEN u16][DATA]
//!   isConnect=0 (ant / go)  : 每包自带 [UOT ADDR][LEN u16][DATA]
//! v1 (legacy)              : 无请求头，直接按 isConnect=0 的每包格式传输
//! ```
//!
//! 服务端回包在 connectionless 模式下必须带上**来源地址**（sing `Conn.WriteTo`
//! 用 `SocksaddrFromNet(addr)`），且一律用 family byte 表；connect 模式不带地址。

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// 服务端据以识别 UDP 会话的 magic host 片段（对齐官方 `strings.Contains`）。
pub const MAGIC_MARKER: &str = "udp-over-tcp.arpa";
pub const MAGIC_V2_HOST: &str = "sp.v2.udp-over-tcp.arpa";
pub const MAGIC_V1_HOST: &str = "sp.udp-over-tcp.arpa";

/// 单个 UDP 包长度上限（UoT 的 LEN 字段是 u16）。
pub const MAX_PACKET_LEN: usize = u16::MAX as usize;

// 标准 SOCKS5 ATYP（stream 目标 + v2 请求头中的目标地址）
const SOCKS_ATYP_V4: u8 = 0x01;
const SOCKS_ATYP_DOMAIN: u8 = 0x03;
const SOCKS_ATYP_V6: u8 = 0x04;

// sing UoT AddrParser family byte（每个 datagram 的地址）
const UOT_ATYP_V4: u8 = 0x00;
const UOT_ATYP_V6: u8 = 0x01;
const UOT_ATYP_DOMAIN: u8 = 0x02;

fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

/// 判断 stream 目标是否为 UoT 会话，返回协议版本（2 / 1）或 `None`。
pub fn classify_target(target: &str) -> Option<u8> {
    if target.starts_with(MAGIC_V2_HOST) {
        return Some(2);
    }
    if target.starts_with(MAGIC_V1_HOST) {
        return Some(1);
    }
    // 对齐官方 strings.Contains：任何包含该片段的域名都按 v2 处理。
    if target.contains(MAGIC_MARKER) {
        return Some(2);
    }
    None
}

/// 一个 UDP 目标地址。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UotAddr {
    Socket(SocketAddr),
    Domain(String, u16),
}

impl UotAddr {
    /// 由 `UdpRelay::recv_from` 拿到的来源地址构造回包地址。
    /// v4-mapped IPv6 归一成 IPv4，避免给客户端回一个它没发过的地址族。
    pub fn from_socket(addr: SocketAddr) -> Self {
        let ip = match addr.ip() {
            IpAddr::V6(v6) => v6.to_ipv4().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)),
            v4 => v4,
        };
        UotAddr::Socket(SocketAddr::new(ip, addr.port()))
    }

    /// 是否只能用 IPv6 socket 出站（用于 `UdpRelay::bind` 的 v6 hint）。
    pub fn is_ipv6(&self) -> bool {
        matches!(self, UotAddr::Socket(a) if a.is_ipv6())
    }

    /// 交给 `UdpRelay::send_to` 的 `host:port` 字符串。
    /// 域名保持原样，让链式 SOCKS5 出站以自己的方式解析，避免本地 DNS 泄漏。
    pub fn to_target(&self) -> String {
        match self {
            UotAddr::Socket(a) => a.to_string(),
            UotAddr::Domain(h, p) => format!("{h}:{p}"),
        }
    }

    /// 编码成 sing UoT `AddrParser` 的 `[family][addr][port]`。
    /// 服务端回包地址总是 `Socket`；`Domain` 分支仅用于测试与对称完整。
    pub fn encode_uot(&self, out: &mut Vec<u8>) {
        let port = match self {
            UotAddr::Socket(a) => {
                match a.ip() {
                    IpAddr::V4(ip) => {
                        out.push(UOT_ATYP_V4);
                        out.extend_from_slice(&ip.octets());
                    }
                    IpAddr::V6(ip) => {
                        out.push(UOT_ATYP_V6);
                        out.extend_from_slice(&ip.octets());
                    }
                }
                a.port()
            }
            UotAddr::Domain(h, p) => {
                out.push(UOT_ATYP_DOMAIN);
                // FQDN 在 UoT 里是 1 字节长度前缀，超过 255 必须截断；
                // 服务端回包不会走到这里。
                let len = h.len().min(u8::MAX as usize);
                out.push(len as u8);
                out.extend_from_slice(&h.as_bytes()[..len]);
                *p
            }
        };
        out.extend_from_slice(&port.to_be_bytes());
    }
}

/// 从 `buf` 解析一个地址，返回 `(地址, 已消费字节数)`。
///
/// `Ok(None)` 表示数据不足（UoT 是字节流，包可能被拆到多个 PSH 帧）；
/// `Err` 表示协议错误（未知 ATYP / 非法 UTF-8 域名）。
fn parse_addr(buf: &[u8], uot: bool) -> io::Result<Option<(UotAddr, usize)>> {
    if buf.is_empty() {
        return Ok(None);
    }

    let (v4, v6, domain) = if uot {
        (UOT_ATYP_V4, UOT_ATYP_V6, UOT_ATYP_DOMAIN)
    } else {
        (SOCKS_ATYP_V4, SOCKS_ATYP_V6, SOCKS_ATYP_DOMAIN)
    };
    let kind = if uot { "UoT" } else { "SOCKS5" };

    let atyp = buf[0];
    let (prefix, addr_len) = match atyp {
        a if a == v4 => (1, 4),
        a if a == v6 => (1, 16),
        a if a == domain => {
            if buf.len() < 2 {
                return Ok(None);
            }
            (2, buf[1] as usize)
        }
        other => return Err(invalid(format!("unknown {kind} ATYP 0x{other:02x}"))),
    };

    let need = prefix + addr_len + 2; // + PORT(2)
    if buf.len() < need {
        return Ok(None);
    }
    let port = u16::from_be_bytes([buf[need - 2], buf[need - 1]]);

    let addr = match atyp {
        a if a == v4 => {
            let b: [u8; 4] = buf[prefix..prefix + 4]
                .try_into()
                .map_err(|_| invalid("truncated IPv4 address"))?;
            UotAddr::Socket(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(b)), port))
        }
        a if a == v6 => {
            let b: [u8; 16] = buf[prefix..prefix + 16]
                .try_into()
                .map_err(|_| invalid("truncated IPv6 address"))?;
            UotAddr::Socket(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(b)), port))
        }
        _ => {
            let host = String::from_utf8(buf[prefix..prefix + addr_len].to_vec())
                .map_err(|_| invalid(format!("{kind} domain is not valid UTF-8")))?;
            UotAddr::Domain(host, port)
        }
    };
    Ok(Some((addr, need)))
}

/// UoT 会话的请求头解析结果。
#[derive(Debug, Clone)]
pub struct Request {
    /// true = 固定目标（connect 模式，包里不带地址）。
    pub is_connect: bool,
    /// connect 模式的固定目标；v1 / 仅作 v6 bind hint 时为 `None`。
    pub destination: Option<UotAddr>,
}

impl Request {
    /// legacy v1：协议里没有请求头，固定按 connectionless 处理。
    pub fn v1() -> Self {
        Request {
            is_connect: false,
            destination: None,
        }
    }

    /// `UdpRelay::bind` 的 v6 hint。
    pub fn bind_ipv6(&self) -> bool {
        self.destination.as_ref().is_some_and(|d| d.is_ipv6())
    }
}

/// 解析请求头。`Ok(None)` 表示数据不足，需要继续从 stream 读。
///
/// v1 不消耗任何字节（协议里没有请求头）。
/// `isConnect` 按 Go `encoding/binary` 读 bool 的语义处理：非 0 即 true。
pub fn parse_request(buf: &[u8], version: u8) -> io::Result<Option<(Request, usize)>> {
    if version < 2 {
        return Ok(Some((Request::v1(), 0)));
    }
    if buf.is_empty() {
        return Ok(None);
    }
    let is_connect = buf[0] != 0;
    let (destination, n) = match parse_addr(&buf[1..], false)? {
        Some(v) => v,
        None => return Ok(None),
    };
    Ok(Some((
        Request {
            is_connect,
            destination: Some(destination),
        },
        1 + n,
    )))
}

/// 从累加缓冲里解析一个完整 datagram。
///
/// 返回 `(目标地址, payload, 已消费字节数)`；`Ok(None)` 表示数据不足。
/// 调用方应在成功后 `advance(consumed)`，并在同一次循环里继续尝试解析下一个包。
pub fn parse_packet(buf: &[u8], req: &Request) -> io::Result<Option<(UotAddr, Vec<u8>, usize)>> {
    let mut off = 0usize;
    let target = if req.is_connect {
        req.destination
            .clone()
            .ok_or_else(|| invalid("UoT connect mode without a destination"))?
    } else {
        let (addr, n) = match parse_addr(buf, true)? {
            Some(v) => v,
            None => return Ok(None),
        };
        off += n;
        addr
    };

    if buf.len() < off + 2 {
        return Ok(None);
    }
    let len = u16::from_be_bytes([buf[off], buf[off + 1]]) as usize;
    off += 2;
    if buf.len() < off + len {
        return Ok(None);
    }
    let data = buf[off..off + len].to_vec();
    Ok(Some((target, data, off + len)))
}

/// 编码一个回包。`src` 为 `None` 表示 connect 模式（不带地址前缀）。
pub fn encode_packet(src: Option<&UotAddr>, data: &[u8]) -> io::Result<Vec<u8>> {
    if data.len() > MAX_PACKET_LEN {
        return Err(invalid(format!(
            "UDP packet too large for UoT: {} > {MAX_PACKET_LEN}",
            data.len()
        )));
    }
    let mut out = Vec::with_capacity(24 + data.len());
    if let Some(a) = src {
        a.encode_uot(&mut out);
    }
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
    Ok(out)
}

// ── 单元测试 ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn socks_domain(host: &str, port: u16) -> Vec<u8> {
        let mut v = vec![SOCKS_ATYP_DOMAIN, host.len() as u8];
        v.extend_from_slice(host.as_bytes());
        v.extend_from_slice(&port.to_be_bytes());
        v
    }

    #[test]
    fn classify_magic_hosts() {
        assert_eq!(classify_target("sp.v2.udp-over-tcp.arpa:443"), Some(2));
        assert_eq!(classify_target("sp.udp-over-tcp.arpa:0"), Some(1));
        assert_eq!(classify_target("example.com:443"), None);
        assert_eq!(classify_target("1.1.1.1:53"), None);
    }

    #[test]
    fn v2_connect_request_ipv4() {
        // clash-rs: isConnect=1 + SocksAddr(1.1.1.1:53)
        let mut buf = vec![1u8, SOCKS_ATYP_V4, 1, 1, 1, 1];
        buf.extend_from_slice(&53u16.to_be_bytes());
        let (req, n) = parse_request(&buf, 2).unwrap().unwrap();
        assert!(req.is_connect);
        assert_eq!(n, buf.len());
        assert!(!req.bind_ipv6());
        assert_eq!(
            req.destination.unwrap(),
            UotAddr::Socket("1.1.1.1:53".parse().unwrap())
        );
    }

    #[test]
    fn v2_connectionless_request_domain() {
        // ant: isConnect=0 + SocksAddr(dns.example:53)
        let mut buf = vec![0u8];
        buf.extend_from_slice(&socks_domain("dns.example", 53));
        let (req, n) = parse_request(&buf, 2).unwrap().unwrap();
        assert!(!req.is_connect);
        assert_eq!(n, buf.len());
        assert_eq!(
            req.destination.unwrap(),
            UotAddr::Domain("dns.example".into(), 53)
        );
    }

    #[test]
    fn v2_request_ipv6_bind_hint() {
        let mut buf = vec![1u8, SOCKS_ATYP_V6];
        buf.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        buf.extend_from_slice(&53u16.to_be_bytes());
        let (req, _) = parse_request(&buf, 2).unwrap().unwrap();
        assert!(req.bind_ipv6());
        assert_eq!(
            req.destination.unwrap(),
            UotAddr::Socket("[2001:db8::1]:53".parse().unwrap())
        );
    }

    #[test]
    fn v1_has_no_request_header() {
        let (req, n) = parse_request(&[], 1).unwrap().unwrap();
        assert_eq!(n, 0);
        assert!(!req.is_connect);
        assert!(req.destination.is_none());
        // 首字节会被当作第一个包的 family byte，而不是 isConnect
        let packet = [UOT_ATYP_V4, 8, 8, 8, 8, 0, 53, 0, 3, b'a', b'b', b'c'];
        let (target, data, used) = parse_packet(&packet, &req).unwrap().unwrap();
        assert_eq!(used, packet.len());
        assert_eq!(target, UotAddr::Socket("8.8.8.8:53".parse().unwrap()));
        assert_eq!(data.as_slice(), b"abc");
    }

    #[test]
    fn request_needs_more_bytes() {
        let partial = [0u8, SOCKS_ATYP_DOMAIN, 5, b'd', b'n'];
        assert!(parse_request(&partial, 2).unwrap().is_none());
        assert!(parse_request(&[], 2).unwrap().is_none());
    }

    #[test]
    fn connectionless_packet_across_frame_boundary() {
        let req = Request {
            is_connect: false,
            destination: None,
        };
        let mut wire = vec![UOT_ATYP_V4, 1, 2, 3, 4];
        wire.extend_from_slice(&80u16.to_be_bytes());
        wire.extend_from_slice(&5u16.to_be_bytes());
        wire.extend_from_slice(b"hello");

        // 逐字节喂入：必须一直返回 None，直到最后一个字节到达
        for i in 0..wire.len() - 1 {
            assert!(parse_packet(&wire[..i + 1], &req).unwrap().is_none());
        }
        let (target, data, used) = parse_packet(&wire, &req).unwrap().unwrap();
        assert_eq!(used, wire.len());
        assert_eq!(target, UotAddr::Socket("1.2.3.4:80".parse().unwrap()));
        assert_eq!(data.as_slice(), b"hello");
    }

    #[test]
    fn connectionless_packet_domain_target() {
        let req = Request::v1();
        let mut wire = vec![UOT_ATYP_DOMAIN, 3, b'a', b'b', b'c'];
        wire.extend_from_slice(&53u16.to_be_bytes());
        wire.extend_from_slice(&2u16.to_be_bytes());
        wire.extend_from_slice(&[0xab, 0xcd]);
        let (target, data, used) = parse_packet(&wire, &req).unwrap().unwrap();
        assert_eq!(used, wire.len());
        assert_eq!(target, UotAddr::Domain("abc".into(), 53));
        assert_eq!(target.to_target(), "abc:53");
        assert_eq!(data.as_slice(), &[0xab, 0xcd]);
    }

    #[test]
    fn connect_packet_has_no_address() {
        let req = Request {
            is_connect: true,
            destination: Some(UotAddr::Socket("9.9.9.9:53".parse().unwrap())),
        };
        let mut wire = 3u16.to_be_bytes().to_vec();
        wire.extend_from_slice(b"dns");
        let (target, data, used) = parse_packet(&wire, &req).unwrap().unwrap();
        assert_eq!(used, wire.len());
        assert_eq!(target, UotAddr::Socket("9.9.9.9:53".parse().unwrap()));
        assert_eq!(data.as_slice(), b"dns");
    }

    #[test]
    fn reply_encoding_roundtrip() {
        let req = Request::v1();
        let src = UotAddr::from_socket("8.8.4.4:53".parse().unwrap());
        let wire = encode_packet(Some(&src), b"reply").unwrap();
        let (target, data, used) = parse_packet(&wire, &req).unwrap().unwrap();
        assert_eq!(used, wire.len());
        assert_eq!(target, src);
        assert_eq!(data.as_slice(), b"reply");

        let connect_req = Request {
            is_connect: true,
            destination: Some(src.clone()),
        };
        let wire2 = encode_packet(None, b"reply").unwrap();
        let (target2, data2, used2) = parse_packet(&wire2, &connect_req).unwrap().unwrap();
        assert_eq!(used2, wire2.len());
        assert_eq!(target2, src);
        assert_eq!(data2.as_slice(), b"reply");
        // connect 回包比 connectionless 少 7 字节地址前缀
        assert_eq!(wire.len() - wire2.len(), 7);
    }

    #[test]
    fn v4_mapped_v6_is_normalized() {
        let a: SocketAddr = "[::ffff:1.2.3.4]:53".parse().unwrap();
        assert_eq!(
            UotAddr::from_socket(a),
            UotAddr::Socket("1.2.3.4:53".parse().unwrap())
        );
    }

    #[test]
    fn invalid_atyp_is_rejected() {
        let req = Request::v1();
        assert!(parse_packet(&[0x7f, 0, 0], &req).is_err());
        assert!(parse_request(&[0u8, 0x7f, 0, 0], 2).is_err());
    }

    #[test]
    fn oversized_reply_is_rejected() {
        let big = vec![0u8; MAX_PACKET_LEN + 1];
        assert!(encode_packet(None, &big).is_err());
    }
}

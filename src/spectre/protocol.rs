//! Spectre 协议线格式（wire format）。
//!
//! 从 spectre-master `src/protocol/mod.rs` 移植，保持与 spectre 客户端的
//! 完全线兼容：命令字、Address 编码（u16 长度 + "host:port" UTF-8）、
//! 各帧的字段顺序与 padding 语义都不变。
//!
//! 只保留服务端入站用得到的部分（客户端侧的请求编码等对称逻辑不下沉：
//! flux 是纯服务端，binary crate 里未使用的函数会触发 dead_code）。
//!
//! QUIC 层由 `quinn-jls`（JLS 补丁版 quinn）提供，TLS 层由 `rustls-jls`
//! 提供：认证失败的握手会被 quinn-jls 透明转发到伪装站点，本模块看到的
//! 连接一定已通过 JLS 认证。

use bytes::{Buf, BufMut, BytesMut};
use thiserror::Error;

/// 双向流上的命令字
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    TcpConnect = 0x01,
    UdpAssociate = 0x02,
    Auth = 0x03,
    Padding = 0xFF,
}

impl TryFrom<u8> for Command {
    type Error = ProtocolError;
    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0x01 => Ok(Command::TcpConnect),
            0x02 => Ok(Command::UdpAssociate),
            0x03 => Ok(Command::Auth),
            0xFF => Ok(Command::Padding),
            _ => Err(ProtocolError::UnknownCommand(v)),
        }
    }
}

#[derive(Error, Debug)]
pub enum ProtocolError {
    #[error("unknown command: {0:#x}")]
    UnknownCommand(u8),
    #[error("invalid address")]
    InvalidAddress,
    #[error("buffer too short")]
    BufferTooShort,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Address 编码：u16 长度 + UTF-8 "host:port"
#[derive(Debug, Clone)]
pub struct Address {
    pub host: String,
    pub port: u16,
}

impl Address {
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
        }
    }

    pub fn to_socket_addr_string(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        let s = self.to_socket_addr_string();
        let len = s.len() as u16;
        buf.put_u16(len);
        buf.put_slice(s.as_bytes());
    }

    pub fn decode(buf: &mut impl Buf) -> Result<Self, ProtocolError> {
        if buf.remaining() < 2 {
            return Err(ProtocolError::BufferTooShort);
        }
        let len = buf.get_u16() as usize;
        if buf.remaining() < len {
            return Err(ProtocolError::BufferTooShort);
        }
        let mut bytes = vec![0u8; len];
        buf.copy_to_slice(&mut bytes);
        let s = String::from_utf8(bytes).map_err(|_| ProtocolError::InvalidAddress)?;
        let (host, port_str) = s.rsplit_once(':').ok_or(ProtocolError::InvalidAddress)?;
        let port: u16 = port_str.parse().map_err(|_| ProtocolError::InvalidAddress)?;
        Ok(Self {
            host: host.to_string(),
            port,
        })
    }
}

/// TCP Connect 请求（客户端 → 服务端）。
///
/// 线格式里的 padding 字段仅起长度伪装作用，服务端不解其内容——解码时
/// 从缓冲区跳过（仍占用线格式位置，必须正确消耗）。
#[derive(Debug)]
pub struct TcpConnectRequest {
    pub address: Address,
}

impl TcpConnectRequest {
    pub fn decode(buf: &mut impl Buf) -> Result<Self, ProtocolError> {
        // cmd 已被调用方消费
        let address = Address::decode(buf)?;
        skip_padding(buf)?;
        Ok(Self { address })
    }
}

/// TCP Connect 响应（服务端 → 客户端）
#[derive(Debug)]
pub struct TcpConnectResponse {
    pub ok: bool,
    pub message: String,
    pub padding: Vec<u8>,
}

impl TcpConnectResponse {
    pub fn ok() -> Self {
        Self {
            ok: true,
            message: String::new(),
            padding: random_padding(TCP_RESPONSE_PADDING),
        }
    }

    pub fn err(msg: impl Into<String>) -> Self {
        Self {
            ok: false,
            message: msg.into(),
            padding: random_padding(TCP_RESPONSE_PADDING),
        }
    }

    pub fn encode(&self) -> BytesMut {
        let mut buf = BytesMut::new();
        buf.put_u8(if self.ok { 0x00 } else { 0x01 });
        let msg_bytes = self.message.as_bytes();
        buf.put_u16(msg_bytes.len() as u16);
        buf.put_slice(msg_bytes);
        buf.put_u16(self.padding.len() as u16);
        buf.put_slice(&self.padding);
        buf
    }
}

/// 认证请求（控制流上的简化认证，客户端 → 服务端）。
///
/// padding 字段同样只做长度伪装，服务端跳过（见 [`TcpConnectRequest`]）。
#[derive(Debug)]
pub struct AuthRequest {
    pub username: String,
    pub password: String,
    /// 客户端声明的接收速率（下载），字节/秒。0 = auto
    pub rx_bps: u64,
    /// 客户端声明的发送速率（上传），字节/秒。0 = auto
    pub tx_bps: u64,
}

impl AuthRequest {
    pub fn decode(buf: &mut impl Buf) -> Result<Self, ProtocolError> {
        // cmd 已被调用方消费
        if buf.remaining() < 1 {
            return Err(ProtocolError::BufferTooShort);
        }
        let _ver = buf.get_u8(); // 协议版本字节，服务端忽略

        if buf.remaining() < 2 {
            return Err(ProtocolError::BufferTooShort);
        }
        let ulen = buf.get_u16() as usize;
        if buf.remaining() < ulen {
            return Err(ProtocolError::BufferTooShort);
        }
        let mut ub = vec![0u8; ulen];
        buf.copy_to_slice(&mut ub);
        let username = String::from_utf8(ub).map_err(|_| ProtocolError::InvalidAddress)?;

        if buf.remaining() < 2 {
            return Err(ProtocolError::BufferTooShort);
        }
        let plen = buf.get_u16() as usize;
        if buf.remaining() < plen {
            return Err(ProtocolError::BufferTooShort);
        }
        let mut pb = vec![0u8; plen];
        buf.copy_to_slice(&mut pb);
        let password = String::from_utf8(pb).map_err(|_| ProtocolError::InvalidAddress)?;

        if buf.remaining() < 16 {
            return Err(ProtocolError::BufferTooShort);
        }
        let rx_bps = buf.get_u64();
        let tx_bps = buf.get_u64();

        skip_padding(buf)?;

        Ok(Self {
            username,
            password,
            rx_bps,
            tx_bps,
        })
    }
}

/// 跳过线格式中的 padding 字段：u16 长度 + 等量字节。
fn skip_padding(buf: &mut impl Buf) -> Result<(), ProtocolError> {
    if buf.remaining() < 2 {
        return Err(ProtocolError::BufferTooShort);
    }
    let pad_len = buf.get_u16() as usize;
    if buf.remaining() < pad_len {
        return Err(ProtocolError::BufferTooShort);
    }
    buf.advance(pad_len);
    Ok(())
}

/// 认证响应（服务端 → 客户端）
#[derive(Debug)]
pub struct AuthResponse {
    pub ok: bool,
    /// 服务端建议的接收速率（客户端应以该速率发送）
    pub rx_bps: u64,
    /// 服务端建议的发送速率
    pub tx_bps: u64,
    pub message: String,
    pub padding: Vec<u8>,
}

impl AuthResponse {
    pub fn ok(rx_bps: u64, tx_bps: u64) -> Self {
        Self {
            ok: true,
            rx_bps,
            tx_bps,
            message: String::new(),
            padding: random_padding(AUTH_PADDING),
        }
    }

    pub fn err(msg: impl Into<String>) -> Self {
        Self {
            ok: false,
            rx_bps: 0,
            tx_bps: 0,
            message: msg.into(),
            padding: random_padding(AUTH_PADDING),
        }
    }

    pub fn encode(&self) -> BytesMut {
        let mut buf = BytesMut::new();
        buf.put_u8(if self.ok { 0x00 } else { 0x01 });
        buf.put_u64(self.rx_bps);
        buf.put_u64(self.tx_bps);
        let msg = self.message.as_bytes();
        buf.put_u16(msg.len() as u16);
        buf.put_slice(msg);
        buf.put_u16(self.padding.len() as u16);
        buf.put_slice(&self.padding);
        buf
    }
}

/// UDP datagram 头（置于 QUIC datagram 载荷最前）
#[derive(Debug, Clone)]
pub struct UdpHeader {
    pub session_id: u32,
    pub packet_id: u16,
    pub fragment_id: u8,
    pub fragment_count: u8,
    pub address: Address,
}

impl UdpHeader {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u32(self.session_id);
        buf.put_u16(self.packet_id);
        buf.put_u8(self.fragment_id);
        buf.put_u8(self.fragment_count);
        self.address.encode(buf);
    }

    pub fn decode(buf: &mut impl Buf) -> Result<Self, ProtocolError> {
        if buf.remaining() < 4 + 2 + 1 + 1 {
            return Err(ProtocolError::BufferTooShort);
        }
        let session_id = buf.get_u32();
        let packet_id = buf.get_u16();
        let fragment_id = buf.get_u8();
        let fragment_count = buf.get_u8();
        let address = Address::decode(buf)?;
        Ok(Self {
            session_id,
            packet_id,
            fragment_id,
            fragment_count,
            address,
        })
    }
}

/// 生成指定长度区间内的随机 padding
pub fn random_padding(range: std::ops::Range<usize>) -> Vec<u8> {
    use rand::{Rng, RngCore};
    let mut rng = rand::thread_rng();
    let len = rng.gen_range(range);
    let mut v = vec![0u8; len];
    rng.fill_bytes(&mut v);
    v
}

// ── padding 长度分档 ──────────────────────────────────────────────────────
//
// 扁平且狭窄的 padding 区间本身就是可利用的统计特征。参考 Hysteria2
// （auth 256..2048、tcp request 64..512、tcp response 128..1024）按
// 消息类型使用不同且更宽的区间：AUTH 每连接仅一次，多几个字节无成本；
// 而每流一次的响应保持较小，避免 padding 明显拖累短流延迟。

pub const AUTH_PADDING: std::ops::Range<usize> = 128..1024;
pub const TCP_RESPONSE_PADDING: std::ops::Range<usize> = 32..384;
/// 应用层 keepalive 的 padding（见 [`PaddingFrame`]）。
pub const KEEPALIVE_PADDING: std::ops::Range<usize> = 16..512;

/// 纯 padding / keepalive 帧（`Command::Padding`，0xFF）。客户端在独立的
/// 短生命周期双向流上按抖动间隔发送，被动观测者看到的是大小、时机都不
/// 规律的“心跳”流，而不是固定周期的 QUIC PING。服务端收到后回一个随机
/// 长度的 padding 响应，使该流在大小/方向上与普通短请求应答无差异。
#[derive(Debug)]
pub struct PaddingFrame {
    pub padding: Vec<u8>,
}

impl PaddingFrame {
    /// 构造一个长度取自 `KEEPALIVE_PADDING` 的随机帧。
    pub fn random() -> Self {
        Self {
            padding: random_padding(KEEPALIVE_PADDING),
        }
    }

    pub fn encode(&self) -> BytesMut {
        let mut buf = BytesMut::new();
        buf.put_u8(Command::Padding as u8);
        buf.put_u16(self.padding.len() as u16);
        buf.put_slice(&self.padding);
        buf
    }

    pub fn decode(buf: &mut impl Buf) -> Result<Self, ProtocolError> {
        // cmd 已被调用方消费
        if buf.remaining() < 2 {
            return Err(ProtocolError::BufferTooShort);
        }
        let len = buf.get_u16() as usize;
        if buf.remaining() < len {
            return Err(ProtocolError::BufferTooShort);
        }
        let mut padding = vec![0u8; len];
        buf.copy_to_slice(&mut padding);
        Ok(Self { padding })
    }
}

/// 简易常数时间比较（防时序侧信道）
pub fn secure_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.as_bytes()
        .iter()
        .zip(b.as_bytes().iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 测试辅助：手工构造一个 AuthRequest 线格式（与客户端编码一致）。
    fn encode_auth_request(req: &AuthRequest) -> Vec<u8> {
        let mut buf = BytesMut::new();
        buf.put_u8(Command::Auth as u8);
        buf.put_u8(0x01); // 协议版本字节（服务端忽略）
        buf.put_u16(req.username.len() as u16);
        buf.put_slice(req.username.as_bytes());
        buf.put_u16(req.password.len() as u16);
        buf.put_slice(req.password.as_bytes());
        buf.put_u64(req.rx_bps);
        buf.put_u64(req.tx_bps);
        buf.put_u16(5); // padding 长度
        buf.put_slice(&[9u8; 5]);
        buf.to_vec()
    }

    #[test]
    fn address_roundtrip() {
        let a = Address::new("www.example.com", 443);
        let mut buf = BytesMut::new();
        a.encode(&mut buf);
        let mut cur = &buf[..];
        let b = Address::decode(&mut cur).unwrap();
        assert_eq!(b.host, "www.example.com");
        assert_eq!(b.port, 443);
        assert_eq!(cur.remaining(), 0);
    }

    #[test]
    fn tcp_connect_request_decode() {
        // cmd(1) + addr + pad_len(2) + pad
        let mut buf = BytesMut::new();
        buf.put_u8(Command::TcpConnect as u8);
        Address::new("1.2.3.4", 80).encode(&mut buf);
        buf.put_u16(3);
        buf.put_slice(&[1, 2, 3]);
        let cmd = Command::try_from(buf[0]).unwrap();
        assert_eq!(cmd, Command::TcpConnect);
        let req = TcpConnectRequest::decode(&mut &buf[1..]).unwrap();
        assert_eq!(req.address.host, "1.2.3.4");
        assert_eq!(req.address.port, 80);
    }

    #[test]
    fn tcp_connect_request_decode_skips_padding() {
        // padding 长度声明大于实际剩余 → BufferTooShort
        let mut buf = BytesMut::new();
        buf.put_u8(Command::TcpConnect as u8);
        Address::new("1.2.3.4", 80).encode(&mut buf);
        buf.put_u16(100);
        buf.put_slice(&[1, 2, 3]);
        assert!(matches!(
            TcpConnectRequest::decode(&mut &buf[1..]),
            Err(ProtocolError::BufferTooShort)
        ));
    }

    #[test]
    fn auth_request_decode() {
        let req = AuthRequest {
            username: "spectre".into(),
            password: "pw".into(),
            rx_bps: 125_000,
            tx_bps: 0,
        };
        let raw = encode_auth_request(&req);
        assert_eq!(Command::try_from(raw[0]).unwrap(), Command::Auth);
        let back = AuthRequest::decode(&mut &raw[1..]).unwrap();
        assert_eq!(back.username, "spectre");
        assert_eq!(back.password, "pw");
        assert_eq!(back.rx_bps, 125_000);
        assert_eq!(back.tx_bps, 0);
    }

    #[test]
    fn tcp_connect_response_encode_decode_shape() {
        // 服务端只编码；这里验证编码出的字节布局（status/msg/pad）可被
        // 对称读取（构造最小 reader）。
        let resp = TcpConnectResponse::err("connect failed");
        let buf = resp.encode();
        assert_eq!(buf[0], 0x01); // err
        let msg_len = u16::from_be_bytes([buf[1], buf[2]]) as usize;
        assert_eq!(&buf[3..3 + msg_len], b"connect failed");
    }

    #[test]
    fn udp_header_roundtrip() {
        let h = UdpHeader {
            session_id: 42,
            packet_id: 7,
            fragment_id: 1,
            fragment_count: 3,
            address: Address::new("8.8.8.8", 53),
        };
        let mut buf = BytesMut::new();
        h.encode(&mut buf);
        let mut cur = &buf[..];
        let back = UdpHeader::decode(&mut cur).unwrap();
        assert_eq!(back.session_id, 42);
        assert_eq!(back.fragment_id, 1);
        assert_eq!(back.fragment_count, 3);
        assert_eq!(back.address.port, 53);
    }

    #[test]
    fn padding_frame_roundtrip() {
        let f = PaddingFrame::random();
        assert!(f.padding.len() >= KEEPALIVE_PADDING.start);
        assert!(f.padding.len() < KEEPALIVE_PADDING.end);
        let buf = f.encode();
        let cmd = Command::try_from(buf[0]).unwrap();
        assert_eq!(cmd, Command::Padding);
        let back = PaddingFrame::decode(&mut &buf[1..]).unwrap();
        assert_eq!(back.padding.len(), f.padding.len());
    }

    #[test]
    fn secure_eq_works() {
        assert!(secure_eq("abc", "abc"));
        assert!(!secure_eq("abc", "abd"));
        assert!(!secure_eq("abc", "abcd"));
    }
}

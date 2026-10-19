//! 可选的报文外层混淆（“Salamander” 风格），从 Hysteria
//! `extras/obfs/salamander.go` 的设计移植。
//!
//! ## 为什么需要它
//!
//! JLS 伪装让**主动探测者**（建立连接并说 TLS）看到一个正常网站，但对
//! **被动观测者**无效——后者只看 UDP 包流而不完成握手：每个 Spectre 包
//! 仍是带公开、众所周知的 QUIC 头结构的 QUIC Initial / Handshake /
//! 1-RTT 包，一个“此头布局 = QUIC，且大小/时序聚集形态像代理而非
//! CDN 前置网站”的分类器可以在完全不碰 TLS 层的情况下标记它。
//!
//! Salamander 廉价地消除这个信号：每个外层 UDP 载荷用预共享密钥 +
//! 每包随机盐派生出的密钥流异或，上线文不再能解析为 QUIC——观测者
//! 看到的是无差别随机字节，与 WireGuard 等加密 datagram 协议无异。
//! 它是共享秘密方案，不是带完整性的加密（无 AEAD 标签），因此位于
//! QUIC 自身密码学**之外**，纯粹用于对抗结构性指纹——真正的认证与
//! 机密性仍由 QUIC/TLS 完成。
//!
//! ## 线格式
//!
//! ```text
//! [8 字节随机盐][载荷 XOR SHA256(psk || salt)，循环]
//! ```
//!
//! 与 Hysteria 相同的布局，仅把 BLAKE2b-256 换成 SHA-256（`sha2` 已是
//! flux 依赖，无需新增 crate）；安全属性（密钥化、盐多样化的 XOR
//! 密钥流混淆公开 QUIC 头）相同。
//!
//! 接入方式见 [`super::obfs_socket`]（包装 quinn-jls 的 `Runtime`）。

use sha2::{Digest, Sha256};

/// 最小 PSK 长度（与 Hysteria 相同的下限）。
pub const MIN_PSK_LEN: usize = 4;
const SALT_LEN: usize = 8;
const KEY_LEN: usize = 32; // SHA-256 输出

#[derive(Debug, thiserror::Error)]
pub enum ObfsError {
    #[error("obfuscation PSK must be at least {MIN_PSK_LEN} bytes")]
    PskTooShort,
    #[error("packet too short to contain a salt")]
    PacketTooShort,
}

fn keystream(psk: &[u8], salt: &[u8; SALT_LEN]) -> [u8; KEY_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(psk);
    hasher.update(salt);
    hasher.finalize().into()
}

/// 混淆一个出站包：`[8 字节随机盐][in XORed with SHA256(psk || salt)]`。
/// 返回完整线格式缓冲。
pub fn obfuscate(psk: &[u8], input: &[u8]) -> Result<Vec<u8>, ObfsError> {
    if psk.len() < MIN_PSK_LEN {
        return Err(ObfsError::PskTooShort);
    }
    use rand::RngCore;
    let mut salt = [0u8; SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    let key = keystream(psk, &salt);

    let mut out = Vec::with_capacity(SALT_LEN + input.len());
    out.extend_from_slice(&salt);
    out.extend(
        input
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ key[i % KEY_LEN]),
    );
    Ok(out)
}

/// [`obfuscate`] 的逆操作：读前置盐，重建同一密钥流，把其余部分 XOR
/// 回明文（原始 QUIC 包）。
pub fn deobfuscate(psk: &[u8], packet: &[u8]) -> Result<Vec<u8>, ObfsError> {
    if psk.len() < MIN_PSK_LEN {
        return Err(ObfsError::PskTooShort);
    }
    if packet.len() <= SALT_LEN {
        return Err(ObfsError::PacketTooShort);
    }
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&packet[..SALT_LEN]);
    let key = keystream(psk, &salt);

    let out = packet[SALT_LEN..]
        .iter()
        .enumerate()
        .map(|(i, b)| b ^ key[i % KEY_LEN])
        .collect();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let psk = b"correct horse battery staple";
        let msg = b"this looks like a QUIC Initial packet header, maybe";
        let packet = obfuscate(psk, msg).unwrap();
        // 每次调用盐不同 → 同一输入的密文不同
        let packet2 = obfuscate(psk, msg).unwrap();
        assert_ne!(packet, packet2);
        assert_eq!(deobfuscate(psk, &packet).unwrap(), msg);
        assert_eq!(deobfuscate(psk, &packet2).unwrap(), msg);
    }

    #[test]
    fn wrong_psk_does_not_panic_and_does_not_match() {
        let packet = obfuscate(b"real-psk-value", b"hello world").unwrap();
        let wrong = deobfuscate(b"wrong-psk-value", &packet).unwrap();
        assert_ne!(wrong, b"hello world");
    }

    #[test]
    fn psk_too_short_rejected() {
        assert!(matches!(obfuscate(b"ab", b"x"), Err(ObfsError::PskTooShort)));
    }

    #[test]
    fn truncated_packet_rejected() {
        assert!(matches!(
            deobfuscate(b"0123456789", &[1, 2, 3]),
            Err(ObfsError::PacketTooShort)
        ));
    }
}

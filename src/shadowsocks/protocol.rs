//! Shadowsocks 2022 AEAD protocol helpers.
//!
//! Wire format for TCP (2022-blake3-*, matching shadowsocks-libev / shadowsocks-rust):
//!
//! Request (client → server):
//! ```text
//! [salt: key_len bytes]   — plaintext
//! [AEAD chunk: TYPE(1) | TIMESTAMP(8) | ATYP(1) | ADDR(N) | PORT(2) | PADDING_LEN(2) | PADDING(M)]
//! repeated chunks: [2+TAG len_ct] [N+TAG payload_ct]
//! ```
//!
//! Response (server → client):
//! ```text
//! [salt: key_len bytes]   — plaintext
//! [AEAD chunk: TYPE(1) | TIMESTAMP(8) | REQUEST_SALT(key_len) | ... data ...]
//! repeated chunks: [2+TAG len_ct] [N+TAG payload_ct]
//! ```
//!
//! Key derivation (2022):
//!   master_key  = base64_decode(password)   — no KDF, key IS the password bytes
//!   session_key = BLAKE3-KDF(key=master_key, context="shadowsocks 2022 session subkey", salt)
//!                 truncated to key_len bytes
//!
//! AEAD nonce: 12-byte little-endian counter (unlike old HKDF-SHA1 which uses
//! a big-endian incrementing nonce; 2022 uses the same counter approach but
//! the counter is incremented per-chunk).

use anyhow::{bail, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::{SystemTime, UNIX_EPOCH};

use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use bytes::{Buf, BufMut, BytesMut};
use chacha20poly1305::ChaCha20Poly1305;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::config::ShadowsocksCipher;

// ── Constants ─────────────────────────────────────────────────────────────────

pub const MAX_CHUNK: usize = 0x3FFF;

/// Maximum allowed clock skew in seconds (30 seconds, same as shadowsocks-rust).
const MAX_TIMESTAMP_DIFF: u64 = 30;

/// Stream type bytes in the header.
pub const STREAM_TYPE_REQUEST: u8 = 0x00;
pub const STREAM_TYPE_RESPONSE: u8 = 0x01;

// ── Key derivation (2022-blake3) ──────────────────────────────────────────────

/// Derive a session subkey using BLAKE3's key-derivation mode.
///
/// Context string: "shadowsocks 2022 session subkey"
/// Input key material: master_key XOR-extended with salt (see below).
///
/// The 2022 spec derives the session key as:
///   blake3::derive_key(context, master_key || salt)
/// where `master_key || salt` is the IKM (input key material).
pub fn derive_session_subkey(master_key: &[u8], salt: &[u8], key_len: usize) -> Vec<u8> {
    const CONTEXT: &str = "shadowsocks 2022 session subkey";
    // IKM = master_key || salt
    let mut ikm = Vec::with_capacity(master_key.len() + salt.len());
    ikm.extend_from_slice(master_key);
    ikm.extend_from_slice(salt);
    let derived = blake3::derive_key(CONTEXT, &ikm);
    // BLAKE3 output is 32 bytes; truncate/use first key_len bytes
    derived[..key_len].to_vec()
}

/// Decode the base64 password into raw key bytes for 2022 ciphers.
/// The password IS the key (no EVP_BytesToKey).
pub fn decode_master_key(password: &str, key_len: usize) -> Result<Vec<u8>> {
    let key = BASE64.decode(password.trim()).map_err(|e| {
        anyhow::anyhow!("shadowsocks 2022: password must be base64-encoded key: {e}")
    })?;
    if key.len() != key_len {
        bail!(
            "shadowsocks 2022: key length mismatch: expected {} bytes, got {} bytes (check cipher and password)",
            key_len, key.len()
        );
    }
    Ok(key)
}

// ── Timestamp helpers ─────────────────────────────────────────────────────────

pub fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before epoch")
        .as_secs()
}

pub fn check_timestamp(ts: u64) -> Result<()> {
    let now = now_unix_secs();
    let diff = ts.abs_diff(now);
    if diff > MAX_TIMESTAMP_DIFF {
        bail!("shadowsocks 2022: timestamp diff {diff}s exceeds {MAX_TIMESTAMP_DIFF}s limit");
    }
    Ok(())
}

// ── AEAD helpers ──────────────────────────────────────────────────────────────

pub fn aead_encrypt(
    cipher: &ShadowsocksCipher,
    key: &[u8],
    nonce: &[u8; 12],
    pt: &[u8],
) -> Result<Vec<u8>> {
    let n = GenericArray::from_slice(nonce);
    let r = match cipher {
        ShadowsocksCipher::Blake3Aes128Gcm => Aes128Gcm::new_from_slice(key)
            .map_err(|e| anyhow::anyhow!("{e}"))?
            .encrypt(n, pt),
        ShadowsocksCipher::Blake3Aes256Gcm => Aes256Gcm::new_from_slice(key)
            .map_err(|e| anyhow::anyhow!("{e}"))?
            .encrypt(n, pt),
        ShadowsocksCipher::Blake3Chacha20Poly1305 => ChaCha20Poly1305::new_from_slice(key)
            .map_err(|e| anyhow::anyhow!("{e}"))?
            .encrypt(n, pt),
    };
    r.map_err(|_| anyhow::anyhow!("AEAD encrypt failed"))
}

pub fn aead_decrypt(
    cipher: &ShadowsocksCipher,
    key: &[u8],
    nonce: &[u8; 12],
    ct: &[u8],
) -> Result<Vec<u8>> {
    let n = GenericArray::from_slice(nonce);
    let r = match cipher {
        ShadowsocksCipher::Blake3Aes128Gcm => Aes128Gcm::new_from_slice(key)
            .map_err(|e| anyhow::anyhow!("{e}"))?
            .decrypt(n, ct),
        ShadowsocksCipher::Blake3Aes256Gcm => Aes256Gcm::new_from_slice(key)
            .map_err(|e| anyhow::anyhow!("{e}"))?
            .decrypt(n, ct),
        ShadowsocksCipher::Blake3Chacha20Poly1305 => ChaCha20Poly1305::new_from_slice(key)
            .map_err(|e| anyhow::anyhow!("{e}"))?
            .decrypt(n, ct),
    };
    r.map_err(|_| anyhow::anyhow!("AEAD decrypt failed"))
}

/// Increment a 12-byte little-endian nonce counter.
pub fn increment_nonce(n: &mut [u8; 12]) {
    for b in n.iter_mut() {
        *b = b.wrapping_add(1);
        if *b != 0 {
            break;
        }
    }
}

// ── Address I/O ───────────────────────────────────────────────────────────────

const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

/// Read SOCKS5-style address from a plaintext byte slice → `"host:port"`.
/// Used after the 2022 header has been decrypted.
pub fn parse_address(buf: &mut impl Buf) -> Result<String> {
    if buf.remaining() < 1 {
        bail!("shadowsocks 2022: truncated address (no ATYP)");
    }
    let atyp = buf.get_u8();
    let host = match atyp {
        ATYP_IPV4 => {
            if buf.remaining() < 4 {
                bail!("truncated IPv4");
            }
            let mut b = [0u8; 4];
            buf.copy_to_slice(&mut b);
            Ipv4Addr::from(b).to_string()
        }
        ATYP_DOMAIN => {
            if buf.remaining() < 1 {
                bail!("truncated domain length");
            }
            let len = buf.get_u8() as usize;
            if buf.remaining() < len {
                bail!("truncated domain");
            }
            let mut b = vec![0u8; len];
            buf.copy_to_slice(&mut b);
            String::from_utf8(b)?
        }
        ATYP_IPV6 => {
            if buf.remaining() < 16 {
                bail!("truncated IPv6");
            }
            let mut b = [0u8; 16];
            buf.copy_to_slice(&mut b);
            format!("[{}]", Ipv6Addr::from(b))
        }
        _ => bail!("shadowsocks 2022: unknown ATYP {atyp:#x}"),
    };
    if buf.remaining() < 2 {
        bail!("truncated port");
    }
    let port = buf.get_u16();
    Ok(format!("{host}:{port}"))
}

// ── 2022 Header parsing ───────────────────────────────────────────────────────

/// Parse and validate the 2022 request fixed header chunk.
/// Returns the target address string ("host:port").
pub fn parse_request_header(data: &[u8], expected_type: u8) -> Result<String> {
    // Minimum: TYPE(1) + TIMESTAMP(8) + ATYP(1) + IPv4(4) + PORT(2) + PADDING_LEN(2) = 18
    if data.len() < 18 {
        bail!(
            "shadowsocks 2022: request header too short ({} bytes)",
            data.len()
        );
    }

    let mut pos = 0;

    // TYPE (1 byte)
    let stream_type = data[pos];
    pos += 1;
    if stream_type != expected_type {
        bail!("shadowsocks 2022: wrong stream type {stream_type:#x}, expected {expected_type:#x}");
    }

    // TIMESTAMP (8 bytes, big-endian u64)
    let ts = u64::from_be_bytes(data[pos..pos + 8].try_into().unwrap());
    pos += 8;
    check_timestamp(ts)?;

    // Address (SOCKS5 style) — parse_address advances through the slice
    let mut remaining = BytesMut::from(&data[pos..]);
    let addr = parse_address(&mut remaining)?;

    // PADDING_LEN (2 bytes) + skip padding
    if remaining.remaining() < 2 {
        bail!("shadowsocks 2022: missing padding length");
    }
    let padding_len = remaining.get_u16() as usize;
    if remaining.remaining() < padding_len {
        bail!("shadowsocks 2022: truncated padding");
    }
    remaining.advance(padding_len);

    Ok(addr)
}

/// Parse the 2022 response fixed header chunk (server→client direction).
/// Returns the echoed request salt (for replay protection).
#[allow(dead_code)]
pub fn parse_response_header(data: &[u8], key_len: usize) -> Result<Vec<u8>> {
    // TYPE(1) + TIMESTAMP(8) + REQUEST_SALT(key_len)
    let min_len = 1 + 8 + key_len;
    if data.len() < min_len {
        bail!("shadowsocks 2022: response header too short");
    }

    let stream_type = data[0];
    if stream_type != STREAM_TYPE_RESPONSE {
        bail!("shadowsocks 2022: wrong stream type in response {stream_type:#x}");
    }

    let ts = u64::from_be_bytes(data[1..9].try_into().unwrap());
    check_timestamp(ts)?;

    let request_salt = data[9..9 + key_len].to_vec();
    Ok(request_salt)
}

// ── Request header builder ────────────────────────────────────────────────────

/// Build the plaintext request header payload (before AEAD encryption).
#[allow(dead_code)]
pub fn build_request_header(target: &str, salt_len: usize) -> Result<Vec<u8>> {
    let mut buf = BytesMut::new();

    // TYPE
    buf.put_u8(STREAM_TYPE_REQUEST);
    // TIMESTAMP
    buf.put_u64(now_unix_secs());
    // SOCKS5 address
    encode_address(target, &mut buf)?;
    // PADDING_LEN = 0 (server-side doesn't send request headers)
    buf.put_u16(0);

    let _ = salt_len; // server doesn't build request headers, but keep param for symmetry
    Ok(buf.to_vec())
}

/// Build the plaintext response header payload (before AEAD encryption).
pub fn build_response_header(request_salt: &[u8]) -> Vec<u8> {
    let mut buf = BytesMut::new();
    buf.put_u8(STREAM_TYPE_RESPONSE);
    buf.put_u64(now_unix_secs());
    buf.put_slice(request_salt);
    buf.to_vec()
}

#[allow(dead_code)]
fn encode_address(addr: &str, buf: &mut BytesMut) -> Result<()> {
    // addr is "host:port"
    let (host, port_str) = addr
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("invalid address: {addr}"))?;
    let port: u16 = port_str.parse()?;
    let host = host.trim_matches(|c| c == '[' || c == ']');

    if let Ok(ip4) = host.parse::<Ipv4Addr>() {
        buf.put_u8(ATYP_IPV4);
        buf.put_slice(&ip4.octets());
    } else if let Ok(ip6) = host.parse::<Ipv6Addr>() {
        buf.put_u8(ATYP_IPV6);
        buf.put_slice(&ip6.octets());
    } else {
        buf.put_u8(ATYP_DOMAIN);
        let host_bytes = host.as_bytes();
        if host_bytes.len() > 255 {
            bail!("domain too long: {}", host_bytes.len());
        }
        buf.put_u8(host_bytes.len() as u8);
        buf.put_slice(host_bytes);
    }
    buf.put_u16(port);
    Ok(())
}

// ── AeadReader ────────────────────────────────────────────────────────────────

pub struct AeadReader<R> {
    pub inner: R,
    pub cipher: ShadowsocksCipher,
    pub subkey: Vec<u8>,
    pub nonce: [u8; 12],
    pub buf: BytesMut,
}

impl<R: AsyncRead + Unpin> AeadReader<R> {
    pub fn new(inner: R, cipher: ShadowsocksCipher, subkey: Vec<u8>) -> Self {
        Self {
            inner,
            cipher,
            subkey,
            nonce: [0u8; 12],
            buf: BytesMut::new(),
        }
    }

    /// Decrypt one AEAD chunk from the wire into `self.buf`.
    /// Returns `false` on clean EOF.
    async fn fill_buf(&mut self) -> Result<bool> {
        let tag_len = self.cipher.tag_len();

        let mut len_ct = vec![0u8; 2 + tag_len];
        match self.inner.read_exact(&mut len_ct).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(false),
            Err(e) => return Err(e.into()),
        }
        let len_pt = aead_decrypt(&self.cipher, &self.subkey, &self.nonce, &len_ct)?;
        increment_nonce(&mut self.nonce);

        let payload_len = u16::from_be_bytes([len_pt[0], len_pt[1]]) as usize;
        let mut payload_ct = vec![0u8; payload_len + tag_len];
        self.inner.read_exact(&mut payload_ct).await?;
        let payload_pt = aead_decrypt(&self.cipher, &self.subkey, &self.nonce, &payload_ct)?;
        increment_nonce(&mut self.nonce);

        self.buf.put_slice(&payload_pt);
        Ok(true)
    }

    #[allow(dead_code)]
    pub async fn read_exact_plain(&mut self, dst: &mut [u8]) -> Result<()> {
        let mut written = 0;
        while written < dst.len() {
            if self.buf.is_empty() && !self.fill_buf().await? {
                bail!("shadowsocks 2022: unexpected EOF reading data");
            }
            let n = self.buf.len().min(dst.len() - written);
            dst[written..written + n].copy_from_slice(&self.buf[..n]);
            self.buf.advance(n);
            written += n;
        }
        Ok(())
    }

    pub async fn read_plain(&mut self, dst: &mut [u8]) -> Result<usize> {
        if self.buf.is_empty() && !self.fill_buf().await? {
            return Ok(0);
        }
        let n = self.buf.len().min(dst.len());
        dst[..n].copy_from_slice(&self.buf[..n]);
        self.buf.advance(n);
        Ok(n)
    }

    /// Read the first AEAD header chunk as raw bytes (for 2022 header parsing).
    pub async fn read_header_chunk(&mut self) -> Result<Vec<u8>> {
        let tag_len = self.cipher.tag_len();
        // Read length ciphertext
        let mut len_ct = vec![0u8; 2 + tag_len];
        self.inner.read_exact(&mut len_ct).await?;
        let len_pt = aead_decrypt(&self.cipher, &self.subkey, &self.nonce, &len_ct)?;
        increment_nonce(&mut self.nonce);

        let payload_len = u16::from_be_bytes([len_pt[0], len_pt[1]]) as usize;
        let mut payload_ct = vec![0u8; payload_len + tag_len];
        self.inner.read_exact(&mut payload_ct).await?;
        let payload_pt = aead_decrypt(&self.cipher, &self.subkey, &self.nonce, &payload_ct)?;
        increment_nonce(&mut self.nonce);

        Ok(payload_pt)
    }
}

// ── AeadWriter ────────────────────────────────────────────────────────────────

pub struct AeadWriter<W> {
    pub inner: W,
    pub cipher: ShadowsocksCipher,
    pub subkey: Vec<u8>,
    pub nonce: [u8; 12],
}

impl<W: AsyncWrite + Unpin> AeadWriter<W> {
    pub fn new(inner: W, cipher: ShadowsocksCipher, subkey: Vec<u8>) -> Self {
        Self {
            inner,
            cipher,
            subkey,
            nonce: [0u8; 12],
        }
    }

    pub async fn write_raw(&mut self, data: &[u8]) -> Result<()> {
        self.inner.write_all(data).await?;
        Ok(())
    }

    pub fn reset_subkey(&mut self, new_subkey: Vec<u8>) {
        self.subkey = new_subkey;
        self.nonce = [0u8; 12];
    }

    /// Write header chunk as a single AEAD-encrypted chunk.
    pub async fn write_header_chunk(&mut self, data: &[u8]) -> Result<()> {
        let chunk_len = data.len();
        let len_pt = [(chunk_len >> 8) as u8, chunk_len as u8];
        let len_ct = aead_encrypt(&self.cipher, &self.subkey, &self.nonce, &len_pt)?;
        increment_nonce(&mut self.nonce);
        let payload_ct = aead_encrypt(&self.cipher, &self.subkey, &self.nonce, data)?;
        increment_nonce(&mut self.nonce);
        self.inner.write_all(&len_ct).await?;
        self.inner.write_all(&payload_ct).await?;
        Ok(())
    }

    pub async fn write_data(&mut self, data: &[u8]) -> Result<()> {
        let mut offset = 0;
        while offset < data.len() {
            let chunk_len = (data.len() - offset).min(MAX_CHUNK);
            let chunk = &data[offset..offset + chunk_len];
            let len_pt = [(chunk_len >> 8) as u8, chunk_len as u8];
            let len_ct = aead_encrypt(&self.cipher, &self.subkey, &self.nonce, &len_pt)?;
            increment_nonce(&mut self.nonce);
            let payload_ct = aead_encrypt(&self.cipher, &self.subkey, &self.nonce, chunk)?;
            increment_nonce(&mut self.nonce);
            self.inner.write_all(&len_ct).await?;
            self.inner.write_all(&payload_ct).await?;
            offset += chunk_len;
        }
        Ok(())
    }

    pub async fn flush(&mut self) -> Result<()> {
        self.inner.flush().await?;
        Ok(())
    }
}

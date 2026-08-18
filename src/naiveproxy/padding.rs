//! naiveproxy 的长度 padding 协议（可选，默认关闭）。
//!
//! ⚠ 实验性实现：wire format 按官方文档描述的 `PaddedData` 结构实现，
//! 但由于无法在此环境中对着真实 naiveproxy 客户端做互操作测试，
//! 不保证在所有场景下（尤其是大数据量、流控受限导致底层 DATA 帧被
//! 拆分的情况）与官方实现逐字节兼容。建议先确认 `padding = false`
//! 时隧道工作正常，再自行验证开启后的效果。
//!
//! 官方文档描述的结构（首 8 次读 / 首 8 次写，双方向独立计数）：
//! ```c
//! struct PaddedData {
//!   uint8_t original_data_size_high; // original_data_size / 256
//!   uint8_t original_data_size_low;  // original_data_size % 256
//!   uint8_t padding_size;
//!   uint8_t original_data[original_data_size];
//!   uint8_t zeros[padding_size];
//! };
//! ```
//! `padding_size` 是 [0, 255] 均匀分布的随机整数。

use anyhow::{bail, Result};
use bytes::{Bytes, BytesMut};
use h2::{RecvStream, SendStream};
use rand::Rng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::naiveproxy::send_backpressured;

const FIRST_PADDINGS: usize = 8;
const MAX_PADDING_SIZE: usize = 255;

/// 生成 CONNECT 请求/响应头里 `padding` 字段的值：随机长度（`[min_len, max_len]`）
/// 的可打印字符串。官方实现要求这些字符"不易被 Huffman 编码、伪随机"，这里
/// 用大小写字母+数字的随机组合近似达到同等目的（不追求逐比特还原官方算法）。
pub fn random_padding_value(min_len: usize, max_len: usize) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    let len = rng.gen_range(min_len..=max_len);
    (0..len)
        .map(|_| CHARSET[rng.gen_range(0..CHARSET.len())] as char)
        .collect()
}

fn random_padding_size() -> usize {
    rand::thread_rng().gen_range(0..=MAX_PADDING_SIZE)
}

/// 把一段原始数据编码成 `PaddedData` 结构。
fn encode(original: &[u8]) -> Result<Bytes> {
    if original.len() > u16::MAX as usize {
        bail!("padded chunk too large: {} bytes", original.len());
    }
    let padding_size = random_padding_size();
    let mut out = BytesMut::with_capacity(3 + original.len() + padding_size);
    out.extend_from_slice(&(original.len() as u16).to_be_bytes());
    out.extend_from_slice(&[padding_size as u8]);
    out.extend_from_slice(original);
    out.resize(out.len() + padding_size, 0);
    Ok(out.freeze())
}

/// 从一个"小缓冲区 + h2 RecvStream 补给"的组合里读出恰好 `n` 字节。
/// 只依赖 `RecvStream::data()`（稳定公开 API），不使用底层 poll_data。
async fn read_exact_from_h2(
    recv: &mut RecvStream,
    carry: &mut BytesMut,
    n: usize,
) -> Result<Bytes> {
    while carry.len() < n {
        match recv.data().await {
            Some(Ok(chunk)) => carry.extend_from_slice(&chunk),
            Some(Err(e)) => bail!("h2 recv error: {e}"),
            None => bail!(
                "h2 stream ended early (wanted {n} bytes, have {})",
                carry.len()
            ),
        }
    }
    Ok(carry.split_to(n).freeze())
}

/// 解一个完整 `PaddedData`，返回其中的原始数据。
async fn decode_one(recv: &mut RecvStream, carry: &mut BytesMut) -> Result<Bytes> {
    let header = read_exact_from_h2(recv, carry, 3).await?;
    let size = u16::from_be_bytes([header[0], header[1]]) as usize;
    let padding_size = header[2] as usize;
    let data = read_exact_from_h2(recv, carry, size).await?;
    if padding_size > 0 {
        let _ = read_exact_from_h2(recv, carry, padding_size).await?;
    }
    Ok(data)
}

/// 双方都声明支持 padding 时使用的隧道转发：首 8 次读 / 首 8 次写做
/// PaddedData 包装，之后降级为普通透传（与 `relay_plain` 相同的逻辑）。
pub async fn relay_padded(
    mut recv: RecvStream,
    mut send: SendStream<Bytes>,
    outbound_r: tokio::net::tcp::OwnedReadHalf,
    mut outbound_w: tokio::net::tcp::OwnedWriteHalf,
) -> Result<()> {
    // ── 方向一：客户端 -> 服务端（对端前 8 次"写"是 padded 的，我们要解包）──
    let up = async move {
        let mut carry = BytesMut::new();
        let mut reads_done = 0usize;

        // 阶段一：前 FIRST_PADDINGS 次，按 PaddedData 结构解包
        while reads_done < FIRST_PADDINGS {
            let chunk = match decode_one(&mut recv, &mut carry).await {
                Ok(c) => c,
                Err(_) => {
                    let _ = outbound_w.shutdown().await;
                    return;
                }
            };
            reads_done += 1;
            if outbound_w.write_all(&chunk).await.is_err() {
                return;
            }
        }

        // 阶段二：先把 carry 里剩下的字节（若有）当普通数据转发一次
        if !carry.is_empty() {
            if outbound_w.write_all(&carry).await.is_err() {
                return;
            }
            carry.clear();
        }

        // 阶段三：降级为普通透传
        while let Some(Ok(chunk)) = recv.data().await {
            if outbound_w.write_all(&chunk).await.is_err() {
                break;
            }
        }
        let _ = outbound_w.shutdown().await;
    };

    // ── 方向二：服务端 -> 客户端（我们的"写"，前 8 次要 padded）──────────────
    let down = async move {
        let mut outbound_r = outbound_r;
        let mut writes_done = 0usize;
        let mut buf = [0u8; 16 * 1024];
        loop {
            let n = match outbound_r.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            let payload = if writes_done < FIRST_PADDINGS {
                match encode(&buf[..n]) {
                    Ok(p) => p,
                    Err(_) => break,
                }
            } else {
                Bytes::copy_from_slice(&buf[..n])
            };
            writes_done += 1;
            if send_backpressured(&mut send, payload).await.is_err() {
                break;
            }
        }
        let _ = send.send_data(Bytes::new(), true);
    };

    tokio::join!(up, down);
    Ok(())
}

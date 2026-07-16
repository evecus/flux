//! Hysteria2 协议工具：TCP 请求/响应读写 + padding 生成

use anyhow::Result;
use bytes::{BufMut, BytesMut};
use rand::Rng;
use tokio::io::AsyncReadExt;

// ── Padding ───────────────────────────────────────────────────────────────────

pub fn gen_padding(min: usize, max: usize) -> String {
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = rand::thread_rng();
    let len = rng.gen_range(min..max);
    (0..len)
        .map(|_| CHARS[rng.gen_range(0..CHARS.len())] as char)
        .collect()
}

// ── TCP 请求读取 ───────────────────────────────────────────────────────────────
//
// 格式（frame type 0x401 已由调用方消费）：
//   [varint] addr_len
//   [bytes]  addr  ("host:port")
//   [varint] padding_len
//   [bytes]  padding（丢弃）

pub async fn read_tcp_request(stream: &mut quinn::RecvStream) -> Result<String> {
    let addr_len = read_varint(stream).await? as usize;
    anyhow::ensure!(
        addr_len > 0 && addr_len <= 2048,
        "invalid addr_len: {addr_len}"
    );

    let mut addr_buf = vec![0u8; addr_len];
    stream.read_exact(&mut addr_buf).await?;
    let addr = String::from_utf8(addr_buf)?;

    let pad_len = read_varint(stream).await? as usize;
    if pad_len > 0 && pad_len <= 4096 {
        let mut discard = vec![0u8; pad_len];
        let _ = stream.read_exact(&mut discard).await;
    }

    Ok(addr)
}

// ── TCP 响应写入 ───────────────────────────────────────────────────────────────
//
// 格式：
//   [u8]     status (0x00=ok, 0x01=error)
//   [varint] message_len
//   [bytes]  message
//   [varint] padding_len
//   [bytes]  padding
//
// 注意：此函数只负责写入，不调用 flush()。
// 调用方在需要立刻发出（如发完响应后准备转发数据）时必须自行 flush。
// 原因：flush() 将 Quinn 内部缓冲强制提交到网络。如果不 flush，
// 数据可能停留在缓冲区，等下一次 write 才一起发出，导致对端等待。

pub async fn write_tcp_response(
    stream: &mut quinn::SendStream,
    ok: bool,
    message: &str,
) -> Result<()> {
    let msg = message.as_bytes();
    let pad_len = rand::thread_rng().gen_range(128usize..1024);
    let padding = gen_padding(pad_len, pad_len + 1).into_bytes();

    let mut buf = BytesMut::new();
    buf.put_u8(if ok { 0x00 } else { 0x01 });
    write_varint(&mut buf, msg.len() as u64);
    buf.put_slice(msg);
    write_varint(&mut buf, pad_len as u64);
    buf.put_slice(&padding);

    stream.write_all(&buf).await?;
    // 不在这里 flush：由调用方决定何时 flush，避免函数语义模糊。
    // proxy.rs 的 handle_tcp_stream 在调用本函数后会显式调用 flush()。
    Ok(())
}

// ── varint ────────────────────────────────────────────────────────────────────

async fn read_varint(stream: &mut quinn::RecvStream) -> Result<u64> {
    let first = stream.read_u8().await?;
    let len = 1usize << (first >> 6);
    let mut val = (first & 0x3f) as u64;
    for _ in 1..len {
        val = (val << 8) | stream.read_u8().await? as u64;
    }
    Ok(val)
}

fn write_varint(buf: &mut BytesMut, val: u64) {
    if val < 64 {
        buf.put_u8(val as u8);
    } else if val < 16384 {
        buf.put_u16(0x4000 | val as u16);
    } else if val < 1_073_741_824 {
        buf.put_u32(0x8000_0000 | val as u32);
    } else {
        buf.put_u64(0xc000_0000_0000_0000 | val);
    }
}

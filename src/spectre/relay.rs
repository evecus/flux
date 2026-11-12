//! QUIC 双向流与 TCP 流之间的双向中继。
//!
//! 从 spectre-master `src/protocol/relay.rs` 原样移植（仅依赖 tokio，
//! 与 quinn 版本无关）。

use tokio::io::{copy_buf, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

/// 拷贝缓冲。tokio 的 `copy` 用 8 KiB，在数百 Mbit/s 下 syscall 次数
/// 多得离谱。
const RELAY_BUF: usize = 256 * 1024;

/// 把 `r` 拷进 `w`，然后半关闭 `w`。
///
/// 对 quinn 的 `SendStream`，`shutdown()` 即 finish 该流。
async fn pipe<R, W>(r: R, mut w: W) -> std::io::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut r = BufReader::with_capacity(RELAY_BUF, r);
    let n = copy_buf(&mut r, &mut w).await?;
    let _ = w.shutdown().await;
    Ok(n)
}

/// 双向中继直到两侧都结束。
///
/// 每个方向在 EOF 时半关闭对侧，在途的另一方向数据不会被切断。
/// 任一方向失败时两侧一起 drop。
pub async fn relay<AR, AW, BR, BW>(a_r: AR, a_w: AW, b_r: BR, b_w: BW) -> std::io::Result<()>
where
    AR: AsyncRead + Unpin,
    AW: AsyncWrite + Unpin,
    BR: AsyncRead + Unpin,
    BW: AsyncWrite + Unpin,
{
    tokio::try_join!(pipe(a_r, b_w), pipe(b_r, a_w))?;
    Ok(())
}

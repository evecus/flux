//! AnyTLS session-layer multiplexer (server side).
//!
//! Frame format:
//!   CMD(1) | STREAM_ID(4 BE u32) | DATA_LEN(2 BE u16) | DATA(variable)
//!
//! Commands (v2 protocol):
//!   0  = cmdWaste              – padding, discard data
//!   1  = cmdSYN                – open stream (client→server)
//!   2  = cmdPSH                – data push
//!   3  = cmdFIN                – stream close
//!   4  = cmdSettings           – client→server capability negotiation
//!   5  = cmdAlert              – error, then close session
//!   6  = cmdUpdatePaddingScheme
//!   7  = cmdSYNACK             – server→client: stream accepted (v2)
//!   8  = cmdHeartRequest
//!   9  = cmdHeartResponse
//!  10  = cmdServerSettings     – server→client capability (v2)
//!
//! 注意：官方 `NewServerSession` 的 `sendPadding` 为 false，服务端**不发**
//! padding，只在 cmdSettings 时用本地 scheme 的 md5 与客户端协商。因此本模块的
//! 写任务只做帧序列化，不做流量整形（这是刻意对齐官方，不是缺失）。

use std::collections::HashMap;

use anyhow::Result;
use bytes::{BufMut, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tracing::{debug, warn};

use super::padding::SharedPadding;

// ── Command constants ─────────────────────────────────────────────────────────

const CMD_WASTE: u8 = 0;
const CMD_SYN: u8 = 1;
const CMD_PSH: u8 = 2;
const CMD_FIN: u8 = 3;
const CMD_SETTINGS: u8 = 4;
const CMD_ALERT: u8 = 5;
const CMD_UPDATE_PADDING: u8 = 6;
const CMD_SYNACK: u8 = 7;
const CMD_HEART_REQUEST: u8 = 8;
const CMD_HEART_RESPONSE: u8 = 9;
const CMD_SERVER_SETTINGS: u8 = 10;

const HEADER_SIZE: usize = 7; // CMD(1) + SID(4) + LEN(2)
const MAX_FRAME_DATA: usize = 0xFFFF; // 65535，单帧 payload 上限

/// 序列化一个帧。
fn frame_bytes(cmd: u8, sid: u32, data: &[u8]) -> BytesMut {
    let mut buf = BytesMut::with_capacity(HEADER_SIZE + data.len());
    buf.put_u8(cmd);
    buf.put_u32(sid);
    buf.put_u16(data.len() as u16);
    buf.put_slice(data);
    buf
}

// ── StreamReader / StreamWriter ───────────────────────────────────────────────

/// 一条流的**读半**：独占 PSH 接收队列与拼包缓冲。
///
/// 与 `StreamWriter` 完全分离，双向中继时各自被一个任务持有，不需要任何锁。
pub struct StreamReader {
    rx: mpsc::Receiver<Vec<u8>>,
    buf: BytesMut,
}

impl StreamReader {
    /// Read up to `dst.len()` bytes. Returns 0 on EOF.
    pub async fn read(&mut self, dst: &mut [u8]) -> std::io::Result<usize> {
        loop {
            if !self.buf.is_empty() {
                use bytes::Buf;
                let n = self.buf.len().min(dst.len());
                dst[..n].copy_from_slice(&self.buf[..n]);
                self.buf.advance(n);
                return Ok(n);
            }
            match self.rx.recv().await {
                // Empty vec is EOF signal
                Some(data) if data.is_empty() => return Ok(0),
                Some(data) => self.buf.put_slice(&data),
                None => return Ok(0),
            }
        }
    }

    /// Read exactly `dst.len()` bytes.
    pub async fn read_exact_from(&mut self, dst: &mut [u8]) -> std::io::Result<()> {
        let mut pos = 0;
        while pos < dst.len() {
            let n = self.read(&mut dst[pos..]).await?;
            if n == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "stream closed",
                ));
            }
            pos += n;
        }
        Ok(())
    }
}

/// 一条流的**写半**：所有帧经共享的 write channel 串行发出。
pub struct StreamWriter {
    pub stream_id: u32,
    write_tx: mpsc::Sender<(u8, u32, Vec<u8>)>,
    /// 服务端主动关闭流时通知会话层把该 sid 从 streams 表里摘掉。
    closed_tx: mpsc::UnboundedSender<u32>,
}

impl StreamWriter {
    /// Write data as PSH frame(s). Data > 65535 bytes is split into
    /// multiple PSH frames per the AnyTLS protocol spec (sing-anytls
    /// `writeDataFrame` behavior).
    pub async fn write(&self, data: &[u8]) -> std::io::Result<usize> {
        for chunk in data.chunks(MAX_FRAME_DATA) {
            self.write_tx
                .send((CMD_PSH, self.stream_id, chunk.to_vec()))
                .await
                .map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::BrokenPipe, "session closed")
                })?;
        }
        Ok(data.len())
    }

    /// Send a FIN frame to notify the remote peer this stream is done, and
    /// release the session's stream-table entry.
    pub async fn close(&self) -> std::io::Result<()> {
        let _ = self.write_tx.send((CMD_FIN, self.stream_id, vec![])).await;
        let _ = self.closed_tx.send(self.stream_id);
        Ok(())
    }

    /// Send SYNACK to confirm stream acceptance.
    /// 对齐官方 `Stream.HandshakeSuccess`：只有 v2 对端才发送 SYNACK，
    /// 否则 v1 客户端会收到它不认识的命令（且带 data 的失败帧会让它解析错位）。
    pub async fn handshake_success(&self, peer_version: u8) {
        if peer_version >= 2 {
            let _ = self
                .write_tx
                .send((CMD_SYNACK, self.stream_id, vec![]))
                .await;
        }
    }

    /// Send SYNACK with error to notify stream rejection (v2 only).
    pub async fn handshake_failure(&self, peer_version: u8, err: &str) {
        if peer_version >= 2 {
            let _ = self
                .write_tx
                .send((CMD_SYNACK, self.stream_id, err.as_bytes().to_vec()))
                .await;
        }
    }
}

/// A bidirectional stream within an AnyTLS session (handshake facade).
///
/// 握手阶段（读 SOCKS5 目标 / UoT 请求头、拨号、发 SYNACK）作为一个整体使用；
/// 进入双向中继前必须调用 [`StreamConn::into_split`] 拆成独立的读/写半，
/// 让上下行各自独占，**不要**用一把 Mutex 把两者包起来。
pub struct StreamConn {
    pub stream_id: u32,
    peer_version: u8,
    reader: StreamReader,
    writer: StreamWriter,
}

impl StreamConn {
    pub async fn read(&mut self, dst: &mut [u8]) -> std::io::Result<usize> {
        self.reader.read(dst).await
    }

    pub async fn read_exact_from(&mut self, dst: &mut [u8]) -> std::io::Result<()> {
        self.reader.read_exact_from(dst).await
    }

    pub async fn handshake_success(&self) {
        self.writer.handshake_success(self.peer_version).await
    }

    pub async fn handshake_failure(&self, err: &str) {
        self.writer.handshake_failure(self.peer_version, err).await
    }

    /// 拆成独立的读半与写半，供 `tokio::select!` 的两个方向分别持有。
    pub fn into_split(self) -> (StreamReader, StreamWriter) {
        (self.reader, self.writer)
    }
}

// ── run_server_session ────────────────────────────────────────────────────────

/// Run an AnyTLS server session on a post-auth TLS connection.
///
/// Calls `on_stream` for each new stream opened by the client.
/// The callback receives a `StreamConn`; it should read the SOCKS5 address,
/// connect upstream, and relay.
pub async fn run_server_session<S, F, Fut>(
    conn: S,
    padding: SharedPadding,
    mut on_stream: F,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    F: FnMut(StreamConn) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    // Writer channel: all streams share a single write task.
    let (write_tx, mut write_rx) = mpsc::channel::<(u8, u32, Vec<u8>)>(256);
    // 服务端主动关闭的流通过这条通道通知读循环清理 streams 表。
    let (closed_tx, mut closed_rx) = mpsc::unbounded_channel::<u32>();

    let (read_half, mut write_half) = tokio::io::split(conn);

    // Spawn writer task — serialises all outgoing frames.
    tokio::spawn(async move {
        while let Some((cmd, sid, data)) = write_rx.recv().await {
            // 控制帧不可拆分（拆开会产生第二个同 cmd 帧，破坏协议语义）。
            if cmd != CMD_PSH && data.len() > MAX_FRAME_DATA {
                warn!(
                    "[anytls] dropping oversized control frame cmd={cmd} sid={sid} len={}",
                    data.len()
                );
                continue;
            }
            // data 为空时 chunks() 不产生任何分片，必须单独发一个空帧
            // （FIN / SYNACK / HeartResponse 都是空 data）。
            if data.is_empty() {
                let buf = frame_bytes(cmd, sid, &[]);
                if write_half.write_all(&buf).await.is_err() {
                    return;
                }
                continue;
            }
            for chunk in data.chunks(MAX_FRAME_DATA) {
                let buf = frame_bytes(cmd, sid, chunk);
                if write_half.write_all(&buf).await.is_err() {
                    return;
                }
            }
        }
    });

    // ── Read loop ─────────────────────────────────────────────────────────────
    let mut read_half = read_half;
    let mut streams: HashMap<u32, mpsc::Sender<Vec<u8>>> = HashMap::new();
    let mut peer_version: u8 = 1;
    let mut received_settings = false;
    let mut hdr = [0u8; HEADER_SIZE];

    loop {
        // 惰性清理：服务端 downlink 发 FIN 后不会收到客户端的 FIN，若不主动
        // 摘除，长连接会话池里每条已关闭的流都会残留一个 Sender。
        while let Ok(sid) = closed_rx.try_recv() {
            streams.remove(&sid);
        }

        match read_half.read_exact(&mut hdr).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => {
                debug!("[anytls] session read error: {e}");
                break;
            }
        }

        let cmd = hdr[0];
        let sid = u32::from_be_bytes(hdr[1..5].try_into().unwrap());
        let dlen = u16::from_be_bytes(hdr[5..7].try_into().unwrap()) as usize;

        let data = if dlen > 0 {
            let mut d = vec![0u8; dlen];
            if read_half.read_exact(&mut d).await.is_err() {
                break;
            }
            d
        } else {
            vec![]
        };

        match cmd {
            CMD_WASTE => {
                // Silently discard padding
            }

            CMD_SETTINGS => {
                received_settings = true;
                let settings = parse_kv(&data);

                // Detect protocol version
                if let Some(v_str) = settings.get("v") {
                    if let Ok(v) = v_str.parse::<u8>() {
                        peer_version = v;
                    }
                }

                // Check padding-md5; send update if mismatch
                let client_md5 = settings
                    .get("padding-md5")
                    .map(|s| s.as_str())
                    .unwrap_or("");
                let scheme = padding.get();
                if client_md5 != scheme.md5_hex {
                    let _ = write_tx
                        .send((CMD_UPDATE_PADDING, 0, scheme.raw.clone()))
                        .await;
                }

                // If client is v2+, reply with cmdServerSettings
                if peer_version >= 2 {
                    let _ = write_tx
                        .send((CMD_SERVER_SETTINGS, 0, b"v=2".to_vec()))
                        .await;
                }
            }

            CMD_SYN => {
                if !received_settings {
                    let msg = b"client did not send its settings".to_vec();
                    let _ = write_tx.send((CMD_ALERT, 0, msg)).await;
                    break;
                }

                // 对齐官方 recvLoop：sid 已存在则忽略，绝不覆盖已有流。
                if streams.contains_key(&sid) {
                    debug!("[anytls] duplicate SYN for stream {sid}, ignoring");
                    continue;
                }

                let (stream_tx, stream_rx) = mpsc::channel::<Vec<u8>>(64);
                streams.insert(sid, stream_tx);

                let stream_conn = StreamConn {
                    stream_id: sid,
                    peer_version,
                    reader: StreamReader {
                        rx: stream_rx,
                        buf: BytesMut::new(),
                    },
                    writer: StreamWriter {
                        stream_id: sid,
                        write_tx: write_tx.clone(),
                        closed_tx: closed_tx.clone(),
                    },
                };

                // SYNACK 由 handle_stream / handle_uot_stream 在出站就绪后发送。
                // v2 客户端对 sid>=2 的流有 3 秒 SYNACK 超时，出站建立必须
                // 控制在这个窗口内，否则客户端会直接关掉整条 session。
                tokio::spawn(on_stream(stream_conn));
            }

            CMD_PSH => {
                if let Some(tx) = streams.get(&sid) {
                    // If receiver is gone, remove the stream entry
                    if tx.send(data).await.is_err() {
                        streams.remove(&sid);
                    }
                }
            }

            CMD_FIN => {
                if let Some(tx) = streams.remove(&sid) {
                    // Empty vec signals EOF to the stream reader
                    let _ = tx.send(vec![]).await;
                }
            }

            CMD_HEART_REQUEST => {
                let _ = write_tx.send((CMD_HEART_RESPONSE, sid, vec![])).await;
            }

            CMD_HEART_RESPONSE => {
                // Passive response; no action needed
            }

            CMD_ALERT => {
                let msg = String::from_utf8_lossy(&data);
                warn!("[anytls] alert from client: {msg}");
                break;
            }

            other => {
                debug!("[anytls] unknown cmd {other:#x}, ignoring");
            }
        }
    }

    // Signal EOF to all open streams
    for (_, tx) in streams.drain() {
        let _ = tx.send(vec![]).await;
    }

    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn parse_kv(data: &[u8]) -> HashMap<String, String> {
    let mut map = HashMap::new();
    if let Ok(s) = std::str::from_utf8(data) {
        for line in s.lines() {
            if let Some((k, v)) = line.split_once('=') {
                map.insert(k.trim().to_string(), v.trim().to_string());
            }
        }
    }
    map
}

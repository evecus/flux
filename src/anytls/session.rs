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

use std::collections::HashMap;

use anyhow::Result;
use bytes::{BufMut, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tracing::debug;

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

// ── StreamConn ────────────────────────────────────────────────────────────────

/// A bidirectional stream within an AnyTLS session.
///
/// `read`  ← PSH data delivered by the session read loop via `rx`.
/// `write` → sends PSH frames through the shared writer channel.
/// `close` → sends a FIN frame.
pub struct StreamConn {
    pub stream_id: u32,
    rx: mpsc::Receiver<Vec<u8>>,
    write_tx: mpsc::Sender<(u8, u32, Vec<u8>)>,
    buf: bytes::BytesMut,
}

impl StreamConn {
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

    /// Write data as a PSH frame.
    pub async fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.write_tx
            .send((CMD_PSH, self.stream_id, data.to_vec()))
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "session closed"))?;
        Ok(data.len())
    }

    /// Send a FIN frame to notify the remote peer this stream is done.
    pub async fn close(&mut self) -> std::io::Result<()> {
        let _ = self.write_tx.send((CMD_FIN, self.stream_id, vec![])).await;
        Ok(())
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

    let (read_half, mut write_half) = tokio::io::split(conn);

    // Spawn writer task — serialises all outgoing frames.
    tokio::spawn(async move {
        while let Some((cmd, sid, data)) = write_rx.recv().await {
            let mut buf = BytesMut::with_capacity(HEADER_SIZE + data.len());
            buf.put_u8(cmd);
            buf.put_u32(sid);
            buf.put_u16(data.len() as u16);
            buf.put_slice(&data);
            if write_half.write_all(&buf).await.is_err() {
                break;
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
                    let msg = b"client did not send its settings before opening a stream".to_vec();
                    let _ = write_tx.send((CMD_ALERT, 0, msg)).await;
                    break;
                }

                let (stream_tx, stream_rx) = mpsc::channel::<Vec<u8>>(64);
                streams.insert(sid, stream_tx);

                let stream_conn = StreamConn {
                    stream_id: sid,
                    rx: stream_rx,
                    write_tx: write_tx.clone(),
                    buf: BytesMut::new(),
                };

                // SYNACK for v2+ clients: confirms outbound connection
                // (we send it immediately; a full impl would send after TCP connect)
                if peer_version >= 2 {
                    let _ = write_tx.send((CMD_SYNACK, sid, vec![])).await;
                }

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
                tracing::warn!("[anytls] alert from client: {msg}");
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

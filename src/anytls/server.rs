//! AnyTLS server.
//!
//! Protocol (server side):
//!   1. Accept TLS connection.
//!   2. Auth packet: sha256(password)[32] | padding0_len[2 BE] | padding0[N].
//!   3. Session loop: multiplex streams, for each:
//!      a. Read SOCKS5 destination address.
//!      b. Connect upstream TCP.
//!      c. Relay bidirectionally.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use anyhow::{bail, Result};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

use crate::common::net::{self as shared_net, OutboundBind};
use crate::common::tls::standard as shared_tls;
use crate::config::AnyTlsConfig;

use super::padding::SharedPadding;
use super::session::{run_server_session, StreamConn};

pub async fn run(cfg: Arc<AnyTlsConfig>) -> Result<()> {
    // Build SHA-256 hash of password once at startup.
    let password_hash: Arc<[u8; 32]> = Arc::new({
        let mut h = Sha256::new();
        h.update(cfg.password.as_bytes());
        h.finalize().into()
    });

    // TLS is mandatory for AnyTLS.
    let tls_cfg = shared_tls::build(
        cfg.tls.cert_path.as_deref(),
        cfg.tls.key_path.as_deref(),
        cfg.tls.self_signed_domain.as_deref(),
    )?;
    let tls_acceptor = Arc::new(TlsAcceptor::from(Arc::new(tls_cfg)));

    // Padding scheme.
    let padding = Arc::new(SharedPadding::new_default());
    if let Some(ref scheme_str) = cfg.padding_scheme {
        if !padding.update(scheme_str.as_bytes()) {
            bail!("[anytls] invalid padding_scheme in config");
        }
    }

    let addr: SocketAddr = cfg.listen.parse()?;
    let listener = TcpListener::bind(addr).await?;
    info!("[anytls] listening on {addr}");

    let bind_ip = OutboundBind::new(cfg.outbound_bind_ipv4, cfg.outbound_bind_ipv6);

    loop {
        let (stream, peer) = listener.accept().await?;
        let acc = Arc::clone(&tls_acceptor);
        let pw_hash = Arc::clone(&password_hash);
        let pad = Arc::clone(&padding);

        tokio::spawn(async move {
            debug!("[anytls] new connection from {peer}");
            if let Err(e) = handle_conn(stream, peer, acc, pw_hash, pad, bind_ip).await {
                warn!("[anytls] {peer}: {e:#}");
            }
        });
    }
}

async fn handle_conn(
    stream: TcpStream,
    peer: SocketAddr,
    acceptor: Arc<TlsAcceptor>,
    password_hash: Arc<[u8; 32]>,
    padding: Arc<SharedPadding>,
    bind_ip: OutboundBind,
) -> Result<()> {
    let mut conn = acceptor.accept(stream).await?;

    // ── Authentication ──────────────────────────────────────────────────────
    // Format: sha256(password)[32] | padding0_len[2 BE u16] | padding0[N]
    let mut auth_buf = [0u8; 34];
    conn.read_exact(&mut auth_buf).await?;

    if &auth_buf[..32] != password_hash.as_ref() {
        debug!("[anytls] {peer}: auth failed");
        return Ok(());
    }

    let padding0_len = u16::from_be_bytes([auth_buf[32], auth_buf[33]]) as usize;
    if padding0_len > 0 {
        let mut discard = vec![0u8; padding0_len];
        conn.read_exact(&mut discard).await?;
    }

    info!("[anytls] {peer} authenticated");

    // ── Session loop ────────────────────────────────────────────────────────
    let pad_clone = (*padding).clone();
    run_server_session(conn, pad_clone, move |stream_conn| async move {
        if let Err(e) = handle_stream(stream_conn, peer, bind_ip).await {
            debug!("[anytls] stream error {peer}: {e:#}");
        }
    })
    .await?;

    debug!("[anytls] session closed: {peer}");
    Ok(())
}

async fn handle_stream(
    mut stream: StreamConn,
    peer: SocketAddr,
    bind_ip: OutboundBind,
) -> Result<()> {
    // Read SOCKS5 destination address.
    let target = read_socks5_addr(&mut stream).await?;
    let sid = stream.stream_id;
    info!("[anytls] {peer} → {target} (stream {sid})");

    // Connect upstream.
    let outbound =
        shared_net::dial_tcp_timeout(&target, bind_ip, std::time::Duration::from_secs(10))
            .await
            .map_err(|e| anyhow::anyhow!("connect {target} failed: {e}"))?;

    let (mut out_r, mut out_w) = outbound.into_split();
    let t1 = target.clone();
    let t2 = target.clone();

    // Wrap in Arc<Mutex> so read and write halves can be used concurrently.
    let stream = Arc::new(tokio::sync::Mutex::new(stream));
    let stream_r = Arc::clone(&stream);
    let stream_w = Arc::clone(&stream);

    // Uplink: AnyTLS stream → upstream TCP
    let uplink = async move {
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            let n = {
                let mut s = stream_r.lock().await;
                match s.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                }
            };
            if out_w.write_all(&buf[..n]).await.is_err() {
                break;
            }
        }
        let _ = out_w.shutdown().await;
        debug!("[anytls] uplink done {peer}→{t1} stream={sid}");
    };

    // Downlink: upstream TCP → AnyTLS stream
    let downlink = async move {
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            let n = match out_r.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            let mut s = stream_w.lock().await;
            if s.write(&buf[..n]).await.is_err() {
                break;
            }
        }
        // Send FIN to notify client this stream is done.
        let mut s = stream_w.lock().await;
        let _ = s.close().await;
        debug!("[anytls] downlink done {t2}→{peer} stream={sid}");
    };

    tokio::join!(uplink, downlink);
    Ok(())
}

/// Read a SOCKS5-format address (RFC 1928 §5) from a StreamConn.
/// Format: ATYP(1) | ADDR(N) | PORT(2 BE u16)
async fn read_socks5_addr(stream: &mut StreamConn) -> Result<String> {
    let mut atyp = [0u8; 1];
    stream.read_exact_from(&mut atyp).await?;

    let host = match atyp[0] {
        0x01 => {
            let mut b = [0u8; 4];
            stream.read_exact_from(&mut b).await?;
            Ipv4Addr::from(b).to_string()
        }
        0x03 => {
            let mut lb = [0u8; 1];
            stream.read_exact_from(&mut lb).await?;
            let mut b = vec![0u8; lb[0] as usize];
            stream.read_exact_from(&mut b).await?;
            String::from_utf8(b)?
        }
        0x04 => {
            let mut b = [0u8; 16];
            stream.read_exact_from(&mut b).await?;
            format!("[{}]", Ipv6Addr::from(b))
        }
        t => bail!("anytls: unknown ATYP {t:#x}"),
    };

    let mut pb = [0u8; 2];
    stream.read_exact_from(&mut pb).await?;
    let port = u16::from_be_bytes(pb);
    Ok(format!("{host}:{port}"))
}

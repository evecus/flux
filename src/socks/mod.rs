use std::{net::SocketAddr, sync::Arc};

use anyhow::{bail, Result};
use tokio::{
    io::{AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tracing::{debug, info, warn};

use crate::common::net as shared_net;
use crate::config::SocksConfig;

// ── SOCKS5 constants ──────────────────────────────────────────────────────────

const VER: u8 = 0x05;

// Auth methods
const METHOD_NO_AUTH: u8 = 0x00;
const METHOD_PASSWORD: u8 = 0x02;
const METHOD_NO_ACCEPTABLE: u8 = 0xFF;

// Commands
const CMD_CONNECT: u8 = 0x01;
// const CMD_BIND: u8 = 0x02;  // not supported
// const CMD_UDP_ASSOC: u8 = 0x03;  // not supported

// Address types
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

// Reply codes
const REP_SUCCESS: u8 = 0x00;
const REP_GENERAL_FAILURE: u8 = 0x01;
const REP_CMD_NOT_SUPPORTED: u8 = 0x07;
const REP_ATYP_NOT_SUPPORTED: u8 = 0x08;

// ── Entry point ───────────────────────────────────────────────────────────────

pub async fn run(cfg: Arc<SocksConfig>) -> Result<()> {
    let addr: SocketAddr = cfg.listen.parse()?;
    let listener = TcpListener::bind(addr).await?;
    let auth_label = if cfg.users.is_empty() {
        "none"
    } else {
        "password"
    };
    info!("[socks5] Listening on {addr} (auth={auth_label})");

    loop {
        let (stream, peer) = listener.accept().await?;
        let cfg2 = cfg.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(stream, peer, &cfg2).await {
                warn!("[socks5] {peer}: {e:#}");
            }
        });
    }
}

// ── Per-connection handler ────────────────────────────────────────────────────

async fn handle(mut stream: TcpStream, peer: SocketAddr, cfg: &SocksConfig) -> Result<()> {
    // ── Greeting ──────────────────────────────────────────────────────────────
    let ver = stream.read_u8().await?;
    if ver != VER {
        bail!("bad SOCKS version: 0x{ver:02x}");
    }

    let nmethods = stream.read_u8().await? as usize;
    let mut methods = vec![0u8; nmethods];
    stream.read_exact(&mut methods).await?;

    let use_password = !cfg.users.is_empty();

    if use_password && methods.contains(&METHOD_PASSWORD) {
        stream.write_all(&[VER, METHOD_PASSWORD]).await?;
        // Sub-negotiation: username/password (RFC 1929)
        let sub_ver = stream.read_u8().await?;
        if sub_ver != 0x01 {
            bail!("bad subneg version: 0x{sub_ver:02x}");
        }
        let ulen = stream.read_u8().await? as usize;
        let mut uname = vec![0u8; ulen];
        stream.read_exact(&mut uname).await?;
        let plen = stream.read_u8().await? as usize;
        let mut passwd = vec![0u8; plen];
        stream.read_exact(&mut passwd).await?;

        let uname_str = String::from_utf8_lossy(&uname);
        let passwd_str = String::from_utf8_lossy(&passwd);

        let ok = cfg
            .users
            .iter()
            .any(|u| u.username == uname_str.as_ref() && u.password == passwd_str.as_ref());

        if ok {
            stream.write_all(&[0x01, 0x00]).await?; // success
        } else {
            stream.write_all(&[0x01, 0x01]).await?; // failure
            bail!("authentication failed for user '{uname_str}'");
        }
    } else if !use_password && methods.contains(&METHOD_NO_AUTH) {
        stream.write_all(&[VER, METHOD_NO_AUTH]).await?;
    } else {
        stream.write_all(&[VER, METHOD_NO_ACCEPTABLE]).await?;
        bail!("no acceptable auth method");
    }

    // ── Request ───────────────────────────────────────────────────────────────
    let ver2 = stream.read_u8().await?;
    if ver2 != VER {
        bail!("bad SOCKS version in request: 0x{ver2:02x}");
    }
    let cmd = stream.read_u8().await?;
    let _rsv = stream.read_u8().await?; // reserved, must be 0x00
    let atyp = stream.read_u8().await?;

    let target_host = match atyp {
        ATYP_IPV4 => {
            let mut b = [0u8; 4];
            stream.read_exact(&mut b).await?;
            std::net::Ipv4Addr::from(b).to_string()
        }
        ATYP_DOMAIN => {
            let len = stream.read_u8().await? as usize;
            let mut b = vec![0u8; len];
            stream.read_exact(&mut b).await?;
            String::from_utf8(b)?
        }
        ATYP_IPV6 => {
            let mut b = [0u8; 16];
            stream.read_exact(&mut b).await?;
            format!("[{}]", std::net::Ipv6Addr::from(b))
        }
        _ => {
            send_reply(&mut stream, REP_ATYP_NOT_SUPPORTED).await?;
            bail!("unsupported address type: 0x{atyp:02x}");
        }
    };

    let port = stream.read_u16().await?;
    let target = format!("{target_host}:{port}");

    if cmd != CMD_CONNECT {
        send_reply(&mut stream, REP_CMD_NOT_SUPPORTED).await?;
        bail!("unsupported command: 0x{cmd:02x}");
    }

    // ── Connect to target ─────────────────────────────────────────────────────
    match shared_net::dial_tcp(
        &target,
        shared_net::OutboundBind::new(cfg.outbound_bind_ipv4, cfg.outbound_bind_ipv6),
    )
    .await
    {
        Ok(outbound) => {
            send_reply(&mut stream, REP_SUCCESS).await?;
            info!("[socks5] {peer} -> {target}");
            relay(stream, outbound).await?;
        }
        Err(e) => {
            send_reply(&mut stream, REP_GENERAL_FAILURE).await?;
            bail!("connect to {target} failed: {e}");
        }
    }

    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Send a minimal SOCKS5 reply with the given reply code.
/// BND.ADDR = 0.0.0.0, BND.PORT = 0 (acceptable for CONNECT).
async fn send_reply<W: AsyncWrite + Unpin>(w: &mut W, rep: u8) -> Result<()> {
    // VER REP RSV ATYP  BND.ADDR(4)  BND.PORT(2)
    w.write_all(&[VER, rep, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
        .await?;
    Ok(())
}

async fn relay(inbound: TcpStream, outbound: TcpStream) -> Result<()> {
    let (mut ir, mut iw) = inbound.into_split();
    let (mut or, mut ow) = outbound.into_split();
    let a = async {
        let _ = tokio::io::copy(&mut ir, &mut ow).await;
        let _ = ow.shutdown().await;
    };
    let b = async {
        let _ = tokio::io::copy(&mut or, &mut iw).await;
        let _ = iw.shutdown().await;
    };
    tokio::join!(a, b);
    debug!("[socks5] connection closed");
    Ok(())
}

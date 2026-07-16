use std::{net::SocketAddr, sync::Arc};

use anyhow::{bail, Result};
use sha2::{Digest, Sha224};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

use crate::common::net::{self as shared_net, OutboundBind};
use crate::common::tls::standard as shared_tls;
use crate::common::transport::websocket as shared_ws;
use crate::common::transport::xhttp::{XhttpConfig, XhttpServer};
use crate::config::TrojanConfig;

pub async fn run(cfg: Arc<TrojanConfig>) -> Result<()> {
    let tls_acceptor = if let Some(t) = &cfg.tls {
        let sc = shared_tls::build(
            t.cert_path.as_deref(),
            t.key_path.as_deref(),
            t.self_signed_domain.as_deref(),
        )?;
        Some(Arc::new(TlsAcceptor::from(Arc::new(sc))))
    } else {
        None
    };
    let addr: SocketAddr = cfg.listen.parse()?;
    let listener = TcpListener::bind(addr).await?;
    info!(
        "[trojan] Listening on {addr} (transport={}, tls={})",
        cfg.transport.r#type,
        if tls_acceptor.is_some() { "yes" } else { "no" },
    );

    // ── xhttp：server 级别 session 表 ─────────────────────────────────────────
    if cfg.transport.r#type == "xhttp" {
        let xh_cfg = XhttpConfig {
            path: cfg.transport.xhttp_path.clone(),
            host: cfg.transport.xhttp_host.clone(),
        };
        let xhttp_server = XhttpServer::new(xh_cfg);
        let password = cfg.password.clone();
        let bind_ip = OutboundBind::new(cfg.outbound_bind_ipv4, cfg.outbound_bind_ipv6);

        let srv_feed = xhttp_server.clone();
        let tls2 = tls_acceptor.clone();
        tokio::spawn(async move {
            loop {
                let (stream, peer) = match listener.accept().await {
                    Ok(p) => p,
                    Err(e) => {
                        warn!("[trojan] accept error: {e}");
                        continue;
                    }
                };
                match &tls2 {
                    None => {
                        srv_feed.feed_plain(stream, peer);
                    }
                    Some(acc) => {
                        let acc = Arc::clone(acc);
                        let srv = srv_feed.clone();
                        tokio::spawn(async move {
                            match acc.accept(stream).await {
                                Ok(tls) => srv.feed_tls(tls, peer),
                                Err(e) => warn!("[trojan] {peer} TLS: {e}"),
                            }
                        });
                    }
                }
            }
        });

        loop {
            match xhttp_server.accept().await {
                None => {
                    warn!("[trojan] xhttp server closed");
                    break;
                }
                Some(xhs) => {
                    let pw = password.clone();
                    tokio::spawn(async move {
                        let peer: SocketAddr = "0.0.0.0:0".parse().unwrap();
                        let mut io: Box<dyn AsyncReadWrite> = Box::new(xhs);
                        if let Err(e) = process(&mut *io, peer, &pw, bind_ip).await {
                            warn!("[trojan] {peer}: {e:#}");
                        }
                    });
                }
            }
        }
        return Ok(());
    }

    // ── 其他 transport ────────────────────────────────────────────────────────
    loop {
        let (stream, peer) = listener.accept().await?;
        let cfg2 = cfg.clone();
        let acc = tls_acceptor.clone();
        tokio::spawn(async move {
            if let Err(e) = handle(stream, peer, &cfg2, acc).await {
                warn!("[trojan] {peer}: {e:#}")
            }
        });
    }
}

async fn handle(
    stream: TcpStream,
    peer: SocketAddr,
    cfg: &TrojanConfig,
    tls_acceptor: Option<Arc<TlsAcceptor>>,
) -> Result<()> {
    let transport = cfg.transport.r#type.as_str();
    let ws_path = cfg.transport.ws_path.as_str();
    let ws_host = cfg.transport.ws_host.as_deref();

    let mut io: Box<dyn AsyncReadWrite> = match (transport, tls_acceptor) {
        ("tcp", None) => Box::new(stream),
        ("tcp", Some(acc)) => Box::new(acc.accept(stream).await?),
        ("ws", None) => Box::new(shared_ws::accept_plain(stream, ws_path, ws_host).await?),
        ("ws", Some(acc)) => {
            let tls = acc.accept(stream).await?;
            Box::new(shared_ws::accept_tls(tls, ws_path, ws_host).await?)
        }
        _ => bail!("trojan: unknown transport"),
    };
    process(
        &mut *io,
        peer,
        &cfg.password,
        OutboundBind::new(cfg.outbound_bind_ipv4, cfg.outbound_bind_ipv6),
    )
    .await
}

async fn process<S: AsyncRead + AsyncWrite + Unpin + ?Sized>(
    io: &mut S,
    peer: SocketAddr,
    password: &str,
    bind_ip: OutboundBind,
) -> Result<()> {
    let target = decode_trojan(io, password).await?;
    info!("[trojan] {peer} -> {target}");
    let outbound = shared_net::dial_tcp(&target, bind_ip).await?;
    relay(io, outbound).await
}

trait AsyncReadWrite: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncReadWrite for T {}

async fn decode_trojan<S: AsyncRead + Unpin + ?Sized>(s: &mut S, password: &str) -> Result<String> {
    let mut line = Vec::new();
    loop {
        let b = s.read_u8().await?;
        line.push(b);
        if line.ends_with(b"\r\n") {
            break;
        }
        if line.len() > 256 {
            bail!("bad auth")
        }
    }
    let got = String::from_utf8_lossy(&line[..line.len() - 2]);
    let expected = hex::encode(Sha224::digest(password.as_bytes()));
    if got != expected {
        bail!("invalid password");
    }
    let cmd = s.read_u8().await?;
    if cmd != 1 {
        bail!("only tcp supported");
    }
    let atyp = s.read_u8().await?;
    let host = match atyp {
        1 => {
            let mut b = [0; 4];
            s.read_exact(&mut b).await?;
            std::net::Ipv4Addr::from(b).to_string()
        }
        3 => {
            let l = s.read_u8().await? as usize;
            let mut b = vec![0; l];
            s.read_exact(&mut b).await?;
            String::from_utf8(b)?
        }
        4 => {
            let mut b = [0; 16];
            s.read_exact(&mut b).await?;
            format!("[{}]", std::net::Ipv6Addr::from(b))
        }
        _ => bail!("bad atyp"),
    };
    let port = s.read_u16().await?;
    let mut crlf = [0; 2];
    s.read_exact(&mut crlf).await?;
    Ok(format!("{host}:{port}"))
}

async fn relay<S: AsyncRead + AsyncWrite + Unpin + ?Sized>(
    inbound: &mut S,
    outbound: TcpStream,
) -> Result<()> {
    let (mut or, mut ow) = outbound.into_split();
    let (mut ir, mut iw) = tokio::io::split(inbound);
    let a = async {
        let _ = tokio::io::copy(&mut ir, &mut ow).await;
        let _ = ow.shutdown().await;
    };
    let b = async {
        let _ = tokio::io::copy(&mut or, &mut iw).await;
        let _ = iw.shutdown().await;
    };
    tokio::join!(a, b);
    debug!("[trojan] closed");
    Ok(())
}

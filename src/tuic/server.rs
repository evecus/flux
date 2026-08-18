use std::{collections::HashMap, net::UdpSocket as StdUdpSocket, sync::Arc};

use anyhow::{Context, Result};
use quinn::{
    crypto::rustls::QuicServerConfig, Endpoint, EndpointConfig, IdleTimeout, ServerConfig,
    TokioRuntime, TransportConfig, VarInt,
};
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    ServerConfig as RustlsServerConfig,
};
use rustls_pemfile;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tracing::{info, warn};
use uuid::Uuid;

use crate::{config::TuicConfig, tuic::connection::Connection};

pub async fn run(cfg: Arc<TuicConfig>) -> Result<()> {
    // ── Build TLS config ──────────────────────────────────────────────────────
    let crypto = build_tls(&cfg).await?;

    // ── ALPN: TUIC-over-QUIC compatibility (use "h3") ─────────────────────────
    let mut crypto = crypto;
    crypto.alpn_protocols = vec![b"h3".to_vec()];
    crypto.max_early_data_size = u32::MAX;

    let quic_server_cfg =
        QuicServerConfig::try_from(crypto).context("failed to create QUIC server config")?;

    // ── Transport config ──────────────────────────────────────────────────────
    let mut transport = TransportConfig::default();
    transport
        .max_concurrent_bidi_streams(VarInt::from_u32(512))
        .max_concurrent_uni_streams(VarInt::from_u32(512))
        .max_idle_timeout(Some(
            IdleTimeout::try_from(cfg.max_idle_time).context("invalid max_idle_time")?,
        ));

    let mut server_cfg = ServerConfig::with_crypto(Arc::new(quic_server_cfg));
    server_cfg.transport_config(Arc::new(transport));

    // ── Bind UDP socket ───────────────────────────────────────────────────────
    let listen_addr: std::net::SocketAddr = cfg
        .listen
        .parse()
        .with_context(|| format!("invalid listen address: {}", cfg.listen))?;

    let socket = {
        let domain = if listen_addr.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };
        let s = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))
            .context("failed to create UDP socket")?;
        s.bind(&SockAddr::from(listen_addr))
            .context("failed to bind UDP socket")?;
        StdUdpSocket::from(s)
    };

    let endpoint = Endpoint::new(
        EndpointConfig::default(),
        Some(server_cfg),
        socket,
        Arc::new(TokioRuntime),
    )?;

    // ── Build user map ────────────────────────────────────────────────────────
    let users: Arc<HashMap<Uuid, String>> = Arc::new(cfg.users.clone());

    info!("[TUIC] listening on {listen_addr}");

    // ── Accept loop ───────────────────────────────────────────────────────────
    loop {
        match endpoint.accept().await {
            Some(connecting) => match connecting.accept() {
                Ok(conn) => {
                    let users = users.clone();
                    let cfg = cfg.clone();
                    tokio::spawn(async move {
                        match conn.await {
                            Ok(connection) => {
                                let conn = Connection::new(connection, users, cfg);
                                conn.handle().await;
                            }
                            Err(e) => {
                                let msg = e.to_string();
                                if msg.contains("peer doesn't support any known protocol") {
                                    tracing::warn!(
                                        "[TUIC] handshake ALPN mismatch: client did not offer 'h3'. Ensure client is TUIC-over-QUIC and ALPN includes 'h3'. error={msg}"
                                    );
                                } else {
                                    tracing::debug!("[TUIC] incoming connection failed: {e}");
                                }
                            }
                        }
                    });
                }
                Err(e) => {
                    tracing::debug!("[TUIC] accept error: {e}");
                }
            },
            None => {
                warn!("[TUIC] endpoint closed");
                break;
            }
        }
    }

    Ok(())
}

async fn build_tls(cfg: &TuicConfig) -> Result<RustlsServerConfig> {
    let tls = cfg.tls.as_ref();
    match (
        tls.and_then(|t| t.cert_path.as_deref()),
        tls.and_then(|t| t.key_path.as_deref()),
    ) {
        (Some(cert_path), Some(key_path)) => {
            // Load from file
            let cert_data = tokio::fs::read(cert_path)
                .await
                .with_context(|| format!("read cert: {cert_path}"))?;
            let key_data = tokio::fs::read(key_path)
                .await
                .with_context(|| format!("read key: {key_path}"))?;

            let certs: Vec<CertificateDer<'static>> =
                rustls_pemfile::certs(&mut cert_data.as_slice())
                    .collect::<Result<_, _>>()
                    .context("parse cert PEM")?;

            let key = rustls_pemfile::private_key(&mut key_data.as_slice())
                .context("parse key PEM")?
                .context("no private key found")?;

            let cfg =
                RustlsServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                    .with_no_client_auth()
                    .with_single_cert(certs, key)
                    .context("TLS config")?;
            Ok(cfg)
        }
        _ => {
            // Self-signed
            let domain = tls
                .and_then(|t| t.self_signed_domain.clone())
                .unwrap_or_else(|| "tuic.local".to_string());
            warn!("[TUIC] no cert/key provided, generating self-signed cert for '{domain}'");
            let cert = rcgen::generate_simple_self_signed(vec![domain])
                .context("generate self-signed cert")?;
            let cert_der = CertificateDer::from(cert.cert);
            let key_der = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());

            let cfg =
                RustlsServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                    .with_no_client_auth()
                    .with_single_cert(vec![cert_der], PrivateKeyDer::Pkcs8(key_der))
                    .context("TLS config")?;
            Ok(cfg)
        }
    }
}

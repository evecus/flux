//! TLS configuration utilities.
//!
//! Two separate builders:
//!   build_hy2_tls  — for Hysteria2, ALPN=["h3"]
//!   (VLESS TLS is handled in vless/tls/standard.rs, ALPN=["h2","http/1.1"])

use anyhow::{Context, Result};
use rcgen::{generate_simple_self_signed, CertifiedKey};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use rustls_pemfile::{certs, private_key};
use std::fs::File;
use std::io::BufReader;
use tracing::info;

use crate::config::Hy2TlsConfig;

/// Build rustls ServerConfig for Hysteria2 (QUIC, ALPN = "h3").
pub fn build_hy2_tls(cfg: &Hy2TlsConfig) -> Result<ServerConfig> {
    let (cert_chain, private_key) = match (&cfg.cert_path, &cfg.key_path) {
        (Some(cert_path), Some(key_path)) => {
            info!("[hy2/tls] Loading cert: {cert_path}");
            info!("[hy2/tls] Loading key : {key_path}");
            let chain = load_certs(cert_path)?;
            let key = load_key(key_path)?;
            (chain, key)
        }
        _ => {
            let domain = cfg
                .self_signed_domain
                .clone()
                .unwrap_or_else(|| "localhost".to_string());
            info!("[hy2/tls] Generating self-signed cert for: {domain}");
            let CertifiedKey { cert, key_pair } = generate_simple_self_signed(vec![domain.clone()])
                .with_context(|| format!("self-signed cert for {domain}"))?;
            let cert_der = CertificateDer::from(cert.der().to_vec());
            let key_der = PrivateKeyDer::try_from(key_pair.serialize_der())
                .map_err(|e| anyhow::anyhow!("serialize key: {e}"))?;
            (vec![cert_der], key_der)
        }
    };

    let mut sc = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)
        .context("build rustls ServerConfig for Hysteria2")?;

    // Hysteria2 runs over QUIC/HTTP3 — ALPN must be "h3"
    sc.alpn_protocols = vec![b"h3".to_vec()];

    Ok(sc)
}

fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>> {
    let f = File::open(path).with_context(|| format!("open cert: {path}"))?;
    let chain: Vec<_> = certs(&mut BufReader::new(f))
        .collect::<Result<Vec<_>, _>>()
        .context("parse PEM certs")?;
    anyhow::ensure!(!chain.is_empty(), "no certs in {path}");
    Ok(chain)
}

fn load_key(path: &str) -> Result<PrivateKeyDer<'static>> {
    let f = File::open(path).with_context(|| format!("open key: {path}"))?;
    private_key(&mut BufReader::new(f))
        .context("parse PEM key")?
        .ok_or_else(|| anyhow::anyhow!("no private key in {path}"))
}

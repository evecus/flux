//! Standard TLS for VLESS.
//!
//! Builds a rustls ServerConfig with ALPN ["h2", "http/1.1"] — the same
//! ALPNs Xray uses for VLESS+TLS. This is separate from the Hysteria2 TLS
//! config which uses ALPN ["h3"].

use anyhow::{Context, Result};
use rcgen::{generate_simple_self_signed, CertifiedKey};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use rustls_pemfile::{certs, private_key};
use std::fs::File;
use std::io::BufReader;
use tracing::info;

/// Build a rustls ServerConfig for VLESS+TLS.
///
/// Accepts the three fields from `VlessTlsConfig::Tls { cert, key, self_signed_domain }`.
pub fn build(
    cert_path: Option<&str>,
    key_path: Option<&str>,
    self_signed_domain: Option<&str>,
) -> Result<ServerConfig> {
    let (cert_chain, private_key) = match (cert_path, key_path) {
        (Some(cert_path), Some(key_path)) => {
            info!("[vless/tls] Loading cert: {cert_path}");
            info!("[vless/tls] Loading key : {key_path}");
            let chain = load_certs(cert_path)?;
            let key = load_key(key_path)?;
            (chain, key)
        }
        _ => {
            let domain = self_signed_domain.unwrap_or("localhost").to_string();
            info!("[vless/tls] Generating self-signed cert for domain: {domain}");
            let CertifiedKey { cert, key_pair } = generate_simple_self_signed(vec![domain.clone()])
                .with_context(|| format!("failed to generate self-signed cert for {domain}"))?;
            let cert_der = CertificateDer::from(cert.der().to_vec());
            let key_der = PrivateKeyDer::try_from(key_pair.serialize_der())
                .map_err(|e| anyhow::anyhow!("serialize key: {e}"))?;
            (vec![cert_der], key_der)
        }
    };

    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)
        .context("build rustls ServerConfig for VLESS")?;

    // ALPN: h2 + http/1.1 — what Xray VLESS+TLS advertises
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(server_config)
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

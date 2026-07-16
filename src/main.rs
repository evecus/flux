mod anytls;
mod common;
mod config;
mod generate;
mod http;
mod hysteria2;
mod naiveproxy;
mod shadowsocks;
mod socks;
mod trojan;
mod tuic;
mod vless;
mod vmess;
mod wireguard;

use anyhow::{Context, Result};
use std::sync::Arc;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls crypto provider");

    // ── generate 子命令（不需要 config，执行后直接退出）────────────────────────
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(|s| s.as_str()) == Some("generate") {
        match args.get(2).map(|s| s.as_str()) {
            Some("wireguard-keypair") => return generate::wireguard_keypair(),
            Some("reality-keypair") => return generate::reality_keypair(),
            Some("uuid") => return generate::uuid(),
            Some("password") => {
                let length: usize = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(16);
                return generate::password(length);
            }
            _ => {
                eprintln!("用法:");
                eprintln!(
                    "  flux generate wireguard-keypair        生成 WireGuard 服务端+客户端密钥对"
                );
                eprintln!("  flux generate reality-keypair          生成 Reality x25519 密钥对");
                eprintln!("  flux generate uuid                     生成随机 UUID v4");
                eprintln!("  flux generate password [位数]          生成随机密码（默认16位）");
                std::process::exit(1);
            }
        }
    }

    let config_path = parse_config_arg();

    let cfg = config::load(&config_path)
        .with_context(|| format!("failed to load config: {config_path}"))?;

    let filter = EnvFilter::try_new(&cfg.log.level).unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .compact()
        .init();

    info!("flux starting, config: {config_path}");

    if cfg.is_empty() {
        anyhow::bail!(
            "no nodes configured — add at least one [[node]] section with type = \"vless\" / \
             \"vmess\" / \"trojan\" / \"shadowsocks\" / \"hysteria2\" / \"tuic\" / \
             \"wireguard\" / \"anytls\" / \"socks\" / \"http\" / \"naiveproxy\""
        );
    }

    // ── tag 唯一性校验 ────────────────────────────────────────────────────────
    if let Some(dup) = cfg.check_duplicate_tags() {
        anyhow::bail!("duplicate node tag: \"{dup}\" — each [[node]] must have a unique tag");
    }

    let mut handles = Vec::new();

    for node in cfg.node {
        let tag = node.tag.clone();
        match node.inner {
            // ── Hysteria2 ─────────────────────────────────────────────────────
            config::NodeInner::Hysteria2(c) => {
                let c = Arc::new(c);
                info!("[{tag}] hysteria2, listen: {}", c.listen);
                handles.push(tokio::spawn(async move {
                    if let Err(e) = hysteria2::server::run(c).await {
                        tracing::error!("[{tag}] server exited: {e:#}");
                    }
                }));
            }

            // ── VLESS ─────────────────────────────────────────────────────────
            config::NodeInner::Vless(c) => {
                let tls_label = match &c.tls {
                    None => "none",
                    Some(config::VlessTlsConfig::Tls { .. }) => "tls",
                    Some(config::VlessTlsConfig::Reality(_)) => "reality",
                };
                let c = Arc::new(c);
                info!(
                    "[{tag}] vless, listen: {}, transport={}, tls={tls_label}",
                    c.listen, c.transport.r#type,
                );
                handles.push(tokio::spawn(async move {
                    if let Err(e) = vless::listener::run(c).await {
                        tracing::error!("[{tag}] server exited: {e:#}");
                    }
                }));
            }

            // ── VMess ─────────────────────────────────────────────────────────
            config::NodeInner::Vmess(c) => {
                let c = Arc::new(c);
                info!(
                    "[{tag}] vmess, listen: {}, transport={}",
                    c.listen, c.transport.r#type
                );
                handles.push(tokio::spawn(async move {
                    if let Err(e) = vmess::run(c).await {
                        tracing::error!("[{tag}] server exited: {e:#}");
                    }
                }));
            }

            // ── Trojan ────────────────────────────────────────────────────────
            config::NodeInner::Trojan(c) => {
                let c = Arc::new(c);
                info!(
                    "[{tag}] trojan, listen: {}, transport={}",
                    c.listen, c.transport.r#type
                );
                handles.push(tokio::spawn(async move {
                    if let Err(e) = trojan::run(c).await {
                        tracing::error!("[{tag}] server exited: {e:#}");
                    }
                }));
            }

            // ── Shadowsocks ───────────────────────────────────────────────────
            config::NodeInner::Shadowsocks(c) => {
                let c = Arc::new(c);
                info!(
                    "[{tag}] shadowsocks, listen: {}, method={:?}, transport={}",
                    c.listen, c.method, c.transport.r#type,
                );
                handles.push(tokio::spawn(async move {
                    if let Err(e) = shadowsocks::server::run(c).await {
                        tracing::error!("[{tag}] server exited: {e:#}");
                    }
                }));
            }

            // ── TUIC ──────────────────────────────────────────────────────────
            config::NodeInner::Tuic(c) => {
                let c = Arc::new(c);
                info!(
                    "[{tag}] tuic, listen: {}, users: {}",
                    c.listen,
                    c.users.len()
                );
                handles.push(tokio::spawn(async move {
                    if let Err(e) = tuic::run(c).await {
                        tracing::error!("[{tag}] server exited: {e:#}");
                    }
                }));
            }

            // ── WireGuard ─────────────────────────────────────────────────────
            config::NodeInner::Wireguard(c) => {
                let c = Arc::new(c);
                info!(
                    "[{tag}] wireguard, listen: {}, peers: {}",
                    c.listen,
                    c.peers.len()
                );
                handles.push(tokio::spawn(async move {
                    if let Err(e) = wireguard::server::run(c).await {
                        tracing::error!("[{tag}] server exited: {e:#}");
                    }
                }));
            }

            // ── AnyTLS ────────────────────────────────────────────────────────
            config::NodeInner::Anytls(c) => {
                let c = Arc::new(c);
                info!("[{tag}] anytls, listen: {}", c.listen);
                handles.push(tokio::spawn(async move {
                    if let Err(e) = anytls::server::run(c).await {
                        tracing::error!("[{tag}] server exited: {e:#}");
                    }
                }));
            }

            // ── SOCKS5 ────────────────────────────────────────────────────────
            config::NodeInner::Socks(c) => {
                let auth_label = if c.users.is_empty() {
                    "no-auth"
                } else {
                    "password"
                };
                let c = Arc::new(c);
                info!("[{tag}] socks5, listen: {}, auth={auth_label}", c.listen);
                handles.push(tokio::spawn(async move {
                    if let Err(e) = socks::run(c).await {
                        tracing::error!("[{tag}] server exited: {e:#}");
                    }
                }));
            }

            // ── HTTP CONNECT ──────────────────────────────────────────────────
            config::NodeInner::Http(c) => {
                let auth_label = if c.users.is_empty() {
                    "no-auth"
                } else {
                    "password"
                };
                let tls_label = if c.tls.is_some() { "tls" } else { "plain" };
                let c = Arc::new(c);
                info!(
                    "[{tag}] http, listen: {}, auth={auth_label}, tls={tls_label}",
                    c.listen
                );
                handles.push(tokio::spawn(async move {
                    if let Err(e) = http::run(c).await {
                        tracing::error!("[{tag}] server exited: {e:#}");
                    }
                }));
            }

            // ── NaiveProxy ────────────────────────────────────────────────────
            config::NodeInner::Naiveproxy(c) => {
                let c = Arc::new(c);
                info!(
                    "[{tag}] naiveproxy, listen: {}, users: {}, padding={}",
                    c.listen,
                    c.users.len(),
                    c.padding,
                );
                handles.push(tokio::spawn(async move {
                    if let Err(e) = naiveproxy::run(c).await {
                        tracing::error!("[{tag}] server exited: {e:#}");
                    }
                }));
            }
        }
    }

    tokio::signal::ctrl_c()
        .await
        .context("failed to listen for ctrl-c")?;
    info!("Shutting down...");
    for h in handles {
        h.abort();
    }

    Ok(())
}

fn parse_config_arg() -> String {
    let args: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < args.len() {
        if args[i] == "-c" {
            if let Some(path) = args.get(i + 1) {
                return path.clone();
            }
        }
        i += 1;
    }
    "config.toml".to_string()
}

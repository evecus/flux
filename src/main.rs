mod anytls;
mod common;
mod config;
mod generate;
mod http;
mod hysteria2;
mod naiveproxy;
mod shadowquic;
mod shadowsocks;
mod socks;
mod spectre;
mod stats;
mod web;
mod trojan;
mod tuic;
mod vless;
mod vmess;
mod wireguard;

use anyhow::{Context, Result};
use std::sync::Arc;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[cfg(feature = "jemalloc")]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

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

    let (config_path, base_dir) = resolve_config_paths()?;

    let cfg = config::load_with_base(&config_path, Some(base_dir.as_path()))
        .with_context(|| format!("failed to load config: {config_path}"))?;

    let level = cfg.log_level.trim();
    let filter = if level.eq_ignore_ascii_case("off") {
        EnvFilter::new("off")
    } else {
        EnvFilter::try_from_default_env().unwrap_or_else(|_| {
            EnvFilter::try_new(level).unwrap_or_else(|_| EnvFilter::new("info"))
        })
    };
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .compact()
        .init();

    info!("flux starting, config: {config_path}, base-dir: {}", base_dir.display());

    if cfg.is_empty() {
        anyhow::bail!(
            "no nodes configured — add at least one entry under `nodes:`              (type: vless / vmess / trojan / shadowsocks / hysteria2 / tuic /              wireguard / anytls / socks / http / naiveproxy / shadowquic / spectre)"
        );
    }

    // name uniqueness is checked in config::load_with_base

    let mut handles = Vec::new();

    // ── Web 面板：只有 web: true 才启用统计、数据库与 HTTP 服务 ────────────────
    // web: false 时 stats 全局单例不存在，所有埋点都是一次空指针判断的 no-op，
    // 且不会创建或打开 redb 文件。
    if cfg.web {
        let node_infos: Vec<stats::NodeInfo> = cfg
            .nodes
            .iter()
            .map(|n| {
                let (proto, listen, port) = n.inner.describe();
                stats::NodeInfo {
                    name: n.name.clone(),
                    proto: proto.to_string(),
                    listen: listen.to_string(),
                    port,
                }
            })
            .collect();
        let db_path = cfg
            .db_path
            .clone()
            .context("web: db path not resolved")?;
        let stats = stats::init(&db_path, node_infos)
            .with_context(|| format!("failed to init stats db: {}", db_path.display()))?;
        let (user, pass) = cfg.web_credentials().expect("checked in config::finalize");
        let bind = cfg.web_bind.clone();
        let user = user.to_string();
        let pass = pass.to_string();
        info!("[web] 面板启用: http://{bind}, 数据文件 {}", db_path.display());
        handles.push(tokio::spawn(async move {
            if let Err(e) = web::run(&bind, user, pass, stats).await {
                tracing::error!("[web] server exited: {e:#}");
            }
        }));
    } else {
        info!("[web] 面板未启用：统计与数据库均未加载");
    }

    for node in cfg.nodes {
        let tag = node.name.clone();
        match node.inner {
            // ── Hysteria2 ─────────────────────────────────────────────────────
            config::NodeInner::Hysteria2(c) => {
                let c = Arc::new(c);
                info!("[{tag}] hysteria2, listen: {}", config::format_listen(&c.listen, c.port));
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
                    config::format_listen(&c.listen, c.port), c.transport.kind,
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
                    config::format_listen(&c.listen, c.port), c.transport.kind
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
                    config::format_listen(&c.listen, c.port), c.transport.kind
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
                    config::format_listen(&c.listen, c.port), c.method, c.transport.kind,
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
                    config::format_listen(&c.listen, c.port),
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
                    config::format_listen(&c.listen, c.port),
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
                info!("[{tag}] anytls, listen: {}", config::format_listen(&c.listen, c.port));
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
                info!("[{tag}] socks5, listen: {}, auth={auth_label}", config::format_listen(&c.listen, c.port));
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
                let tls_label = if c.tls.is_set() { "tls" } else { "plain" };
                let c = Arc::new(c);
                info!(
                    "[{tag}] http, listen: {}, auth={auth_label}, tls={tls_label}",
                    config::format_listen(&c.listen, c.port)
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
                    config::format_listen(&c.listen, c.port),
                    c.users.len(),
                    c.padding,
                );
                handles.push(tokio::spawn(async move {
                    if let Err(e) = naiveproxy::run(c).await {
                        tracing::error!("[{tag}] server exited: {e:#}");
                    }
                }));
            }

            // ── ShadowQuic ─────────────────────────────────────────────────────
            config::NodeInner::Shadowquic(c) => {
                let c = Arc::new(c);
                info!(
                    "[{tag}] shadowquic, listen: {}, users: {}, jls_upstream: {}",
                    config::format_listen(&c.listen, c.port),
                    c.users.len(),
                    c.jls_upstream,
                );
                handles.push(tokio::spawn(async move {
                    if let Err(e) = shadowquic::run(c).await {
                        tracing::error!("[{tag}] server exited: {e:#}");
                    }
                }));
            }

            // ── Spectre ───────────────────────────────────────────────────────
            config::NodeInner::Spectre(c) => {
                let c = Arc::new(c);
                info!(
                    "[{tag}] spectre, listen: {}, sni={}, upstream={}, obfs={}",
                    config::format_listen(&c.listen, c.port),
                    c.server_name,
                    c.upstream,
                    if c.obfs_psk.is_some() { "on" } else { "off" },
                );
                handles.push(tokio::spawn(async move {
                    if let Err(e) = spectre::run(c).await {
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

/// `-d /path` 且未指定 `-c` 时，自动在该目录下寻找 yaml 配置。
/// 优先 `config.yaml` / `config.yml`；否则收集所有 `.yaml` / `.yml`，
/// 恰好一个就使用它，多个则报错要求用 `-c` 明确指定。
fn find_yaml_in_dir(dir: &std::path::Path) -> Result<std::path::PathBuf> {
    for name in ["config.yaml", "config.yml"] {
        let p = dir.join(name);
        if p.is_file() {
            return Ok(p);
        }
    }
    let mut found: Vec<std::path::PathBuf> = std::fs::read_dir(dir)
        .with_context(|| format!("cannot read -d dir: {}", dir.display()))?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.is_file()
                && p.extension()
                    .and_then(|s| s.to_str())
                    .map(|s| {
                        let s = s.to_ascii_lowercase();
                        s == "yaml" || s == "yml"
                    })
                    .unwrap_or(false)
        })
        .collect();
    found.sort();
    match found.len() {
        0 => anyhow::bail!(
            "-d {} 下未找到 .yaml / .yml 配置文件（可用 -c 指定）",
            dir.display()
        ),
        1 => Ok(found.remove(0)),
        _ => anyhow::bail!(
            "-d {} 下存在多个 yaml 配置，请用 -c 指定：{}",
            dir.display(),
            found
                .iter()
                .map(|p| p.file_name().unwrap_or_default().to_string_lossy())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

/// Resolve `-c` / `-d` into (config_path, base_dir).
///
/// - `flux -d /path`           → config `/path/config.yaml`, base `/path`
/// - `flux -d /path -c a.yaml` → config `/path/a.yaml` (if relative), base `/path`
/// - `flux -c /abs/c.yaml`     → config absolute, base = parent dir
/// - `flux -c ./c.yaml`        → resolved against cwd, base = parent of config
///
/// Relative `cert-path` / `key-path` in the config are resolved against `base_dir`.
fn resolve_config_paths() -> Result<(String, std::path::PathBuf)> {
    use std::path::PathBuf;
    let args: Vec<String> = std::env::args().collect();
    let mut config_arg: Option<String> = None;
    let mut dir_arg: Option<PathBuf> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-c" | "--config" => {
                if let Some(p) = args.get(i + 1) {
                    config_arg = Some(p.clone());
                    i += 2;
                    continue;
                }
            }
            "-d" | "--dir" | "--directory" => {
                if let Some(p) = args.get(i + 1) {
                    dir_arg = Some(PathBuf::from(p));
                    i += 2;
                    continue;
                }
            }
            _ => {}
        }
        i += 1;
    }

    if let Some(dir) = dir_arg {
        let dir = if dir.is_absolute() {
            dir
        } else {
            std::env::current_dir()
                .context("get current dir")?
                .join(dir)
        };
        if !dir.is_dir() {
            anyhow::bail!("-d path is not a directory: {}", dir.display());
        }
        let cfg = match config_arg {
            Some(c) => {
                let p = PathBuf::from(&c);
                if p.is_absolute() {
                    p
                } else {
                    dir.join(p)
                }
            }
            None => find_yaml_in_dir(&dir)?,
        };
        Ok((cfg.to_string_lossy().into_owned(), dir))
    } else {
        let cfg = match config_arg {
            Some(c) => {
                let p = PathBuf::from(&c);
                if p.is_absolute() {
                    p
                } else {
                    std::env::current_dir()
                        .context("get current dir")?
                        .join(p)
                }
            }
            None => {
                std::env::current_dir()
                    .context("get current dir")?
                    .join("config.yaml")
            }
        };
        let base = cfg
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."));
        Ok((cfg.to_string_lossy().into_owned(), base))
    }
}


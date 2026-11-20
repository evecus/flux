//! flux 入口。
//!
//! 两种互斥的运行方式：
//! - `flux -c xx.yaml`：纯配置模式。只支持 `log-level` 与 `nodes`，
//!   不启用面板、不打开数据库。
//! - `flux -d /path`：面板模式。完全无配置文件，加密数据库 `flux.db` 与
//!   主密钥 `flux.key` 自动生成到 /path；网页面板默认端口 9080，
//!   默认账号/密码 admin/admin，均可在面板设置页或用 set-* 子命令修改。
//!
//! 管理子命令（修改面板设置后退出）：
//!   flux set-user <name> -d /path
//!   flux set-password <pwd> -d /path
//!   flux set-port <port> -d /path

mod acme;
mod anytls;
mod common;
mod config;
mod crypto;
mod generate;
mod http;
mod hysteria2;
mod keystore;
mod naiveproxy;
mod node_manager;
mod share_link;
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

use anyhow::{bail, Context, Result};
use std::path::PathBuf;
use std::sync::Arc;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[cfg(feature = "jemalloc")]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

/// 简易参数解析结果。
struct Args {
    config: Option<String>,
    dir: Option<PathBuf>,
    /// (子命令名, 值)
    set_cmd: Option<(String, String)>,
}

fn parse_args() -> Result<Args> {
    let args: Vec<String> = std::env::args().collect();
    let mut out = Args {
        config: None,
        dir: None,
        set_cmd: None,
    };
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-c" | "--config" => {
                out.config = Some(
                    args.get(i + 1)
                        .context("-c 需要一个配置文件路径参数")?
                        .clone(),
                );
                i += 2;
            }
            "-d" | "--dir" | "--directory" => {
                out.dir = Some(PathBuf::from(
                    args.get(i + 1).context("-d 需要一个目录路径参数")?,
                ));
                i += 2;
            }
            "set-user" | "set-password" | "set-port" => {
                let val = args
                    .get(i + 1)
                    .with_context(|| format!("{} 需要一个参数", args[i]))?
                    .clone();
                out.set_cmd = Some((args[i].clone(), val));
                i += 2;
            }
            other => {
                bail!("未知参数 `{other}`\n\n{}", usage());
            }
        }
    }
    if out.set_cmd.is_some() && out.dir.is_none() {
        bail!("set-user / set-password / set-port 必须配合 `-d /path` 使用\n\n{}", usage());
    }
    if out.set_cmd.is_some() && out.config.is_some() {
        bail!("set-* 子命令只在 -d 面板模式下有效（-c 配置模式没有面板）");
    }
    if out.config.is_some() && out.dir.is_some() {
        bail!("-c 与 -d 不能同时使用：\n  -c xx.yaml  → 纯配置模式（无面板无数据库）\n  -d /path    → 面板模式（无配置文件，节点存加密数据库）");
    }
    Ok(out)
}

fn usage() -> String {
    "用法:\n  \
     flux -c xx.yaml                          纯配置模式（仅 log-level + nodes，无面板/数据库）\n  \
     flux -d /path                            面板模式（加密数据库 + Web 面板，默认 admin/admin, 端口 9080）\n  \
     flux set-user <name> -d /path            修改面板登录用户名\n  \
     flux set-password <pwd> -d /path         修改面板登录密码\n  \
     flux set-port <port> -d /path            修改面板端口\n  \
     flux generate wireguard-keypair          生成 WireGuard 密钥对\n  \
     flux generate reality-keypair            生成 Reality x25519 密钥对\n  \
     flux generate uuid                       生成随机 UUID v4\n  \
     flux generate password [位数]            生成随机密码（默认16位）"
        .to_string()
}

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls crypto provider");

    let args = parse_args()?;

    // ── generate 子命令（不需要任何配置，执行后直接退出）────────────────────
    if std::env::args().nth(1).as_deref() == Some("generate") {
        match std::env::args().nth(2).as_deref() {
            Some("wireguard-keypair") => return generate::wireguard_keypair(),
            Some("reality-keypair") => return generate::reality_keypair(),
            Some("uuid") => return generate::uuid(),
            Some("password") => {
                let length: usize = std::env::args()
                    .nth(3)
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(16);
                return generate::password(length);
            }
            _ => {
                eprintln!("{usage}", usage = usage());
                std::process::exit(1);
            }
        }
    }

    // ── set-* 子命令：打开数据库改设置后退出 ────────────────────────────────
    if let Some((cmd, val)) = &args.set_cmd {
        let dir = args.dir.as_ref().expect("checked in parse_args");
        return run_set_command(cmd, val, dir);
    }

    match (&args.config, &args.dir) {
        (Some(cfg_path), None) => run_config_mode(cfg_path).await,
        (None, Some(dir)) => run_panel_mode(dir).await,
        _ => {
            eprintln!("{usage}", usage = usage());
            std::process::exit(1);
        }
    }
}

/// 初始化日志（两种模式共用）。
fn init_tracing(level: &str) {
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
}

// ── 纯配置模式（-c）──────────────────────────────────────────────────────────

async fn run_config_mode(config_path: &str) -> Result<()> {
    let cfg_path = PathBuf::from(config_path);
    let base_dir = cfg_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));

    let cfg = config::load_with_base(config_path, Some(base_dir.as_path()))
        .with_context(|| format!("failed to load config: {config_path}"))?;

    init_tracing(cfg.log_level.trim());
    info!("flux starting (config mode), config: {config_path}");

    if cfg.is_empty() {
        bail!("no nodes configured — add at least one entry under `nodes:`");
    }

    // 启动前端口预检（fail-fast）。
    for node in &cfg.nodes {
        let (_, _, port) = node.inner.describe();
        let layer = node.inner.layer();
        if node_manager::NodeManager::port_in_use_layer(port, layer) {
            bail!(
                "节点 `{}` 的端口 {port} 已被占用（{} 层），无法启动",
                node.name,
                layer.name()
            );
        }
    }

    // 相对路径已在 load_with_base 内按 base_dir 解析完成。
    let total = cfg.nodes.len();
    for node in cfg.nodes {
        node_manager::spawn_protocol(node);
    }

    info!("已启动 {total} 个节点（无面板、无数据库）");
    tokio::signal::ctrl_c()
        .await
        .context("failed to listen for ctrl-c")?;
    info!("Shutting down...");
    Ok(())
}

// ── 面板模式（-d）────────────────────────────────────────────────────────────

async fn run_panel_mode(dir: &PathBuf) -> Result<()> {
    let dir = if dir.is_absolute() {
        dir.clone()
    } else {
        std::env::current_dir()
            .context("get current dir")?
            .join(dir)
    };
    if !dir.is_dir() {
        bail!("-d path is not a directory: {}", dir.display());
    }

    // 加密自检：尽早暴露运行环境的 AES 问题。
    crypto::selftest().context("加密自检失败")?;

    // 主密钥 + 加密数据库。
    let key = keystore::load_or_create(&dir)?;
    let db_path = dir.join("flux.db");
    let stats = stats::init(&db_path, key)
        .with_context(|| format!("failed to init stats db: {}", db_path.display()))?;
    let settings = stats
        .db
        .panel_settings()
        .context("failed to load panel settings")?;

    init_tracing("info");
    info!("flux starting (panel mode), data dir: {}", dir.display());
    info!(
        "[web] 面板设置: user={}, port={}（数据库: {}）",
        settings.user,
        settings.port,
        db_path.display()
    );

    let manager = node_manager::NodeManager::new(dir.clone(), Arc::clone(&stats));

    // 启动 ACME 自动续签任务（每 12h 扫描，到期前 30 天续签并热重载节点）。
    tokio::spawn(acme::run_renew_task(
        Arc::clone(&stats.db),
        dir.clone(),
        Arc::clone(&manager),
    ));

    // 启动前端口预检：节点端口 + 面板端口。
    manager.preflight_ports(Some(settings.port))?;

    manager.start_all();

    // ── Web 面板（端口可在运行中修改，自动重绑定）──────────────────────────
    let (port_tx, port_rx) = tokio::sync::watch::channel(settings.port);
    let host = "0.0.0.0".to_string();
    let mgr = Arc::clone(&manager);
    let web_state = web::WebState::new(
        settings.user,
        settings.pass_hash,
        Arc::clone(&stats),
        mgr,
        port_tx,
    );
    info!("[web] 面板已启用: http://{host}:{}", settings.port);
    let web_handle = tokio::spawn(web::run(host, port_rx, web_state));

    tokio::signal::ctrl_c()
        .await
        .context("failed to listen for ctrl-c")?;
    info!("Shutting down...");
    web_handle.abort();
    Ok(())
}

// ── set-* 子命令 ─────────────────────────────────────────────────────────────

fn run_set_command(cmd: &str, val: &str, dir: &PathBuf) -> Result<()> {
    let key = keystore::load_or_create(dir)?;
    let db_path = dir.join("flux.db");
    let db = stats::db::Db::open(&db_path, key)
        .with_context(|| format!("failed to open db: {}", db_path.display()))?;

    match cmd {
        "set-user" => {
            if val.trim().is_empty() {
                bail!("用户名不能为空");
            }
            db.set_panel_user(val.trim())?;
            println!("面板登录用户名已改为 `{}`", val.trim());
        }
        "set-password" => {
            if val.is_empty() {
                bail!("密码不能为空");
            }
            let hash = crypto::hash_password(val)?;
            db.set_panel_pass_hash(&hash)?;
            println!("面板登录密码已修改");
        }
        "set-port" => {
            let port: u16 = val
                .parse()
                .with_context(|| format!("无效端口 `{val}`（1-65535）"))?;
            if port == 0 {
                bail!("端口不能为 0");
            }
            db.set_panel_port(port)?;
            println!("面板端口已改为 {port}（重启 flux 后生效）");
        }
        _ => unreachable!(),
    }
    Ok(())
}

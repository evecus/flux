use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use anyhow::Result;
use rand::RngCore;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

use crate::common::net as shared_net;
use crate::common::tls::standard as shared_tls;
use crate::common::transport::websocket as shared_ws;
use crate::common::transport::xhttp::{XhttpConfig, XhttpServer};
use crate::config::ShadowsocksConfig;
use crate::shadowsocks::protocol::{
    build_response_header, decode_master_key, derive_session_subkey, now_unix_secs,
    parse_request_header, AeadReader, AeadWriter, STREAM_TYPE_REQUEST,
};

// ── Salt replay cache ─────────────────────────────────────────────────────────
//
// 2022-blake3 规范要求服务端缓存已见过的请求 salt，在时间窗口内拒绝重复 salt，
// 防止重放攻击。sing-box 通过 sing-shadowsocks 库内部实现此机制。
//
// 本实现用 Mutex<HashMap> 做简单的时间窗口缓存，每次插入时顺带清理过期条目，
// 无需后台清理任务。

/// Salt 重放保护缓存窗口（秒）。与时间戳校验窗口对齐（30s），留 2x 余量。
const SALT_CACHE_WINDOW_SECS: u64 = 120;

struct SaltCache {
    entries: Mutex<HashMap<Vec<u8>, u64>>,
    window_secs: u64,
}

impl SaltCache {
    fn new(window_secs: u64) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            window_secs,
        }
    }

    /// 检查 salt 是否为重放。返回 `true` 表示通过（非重放），`false` 表示重放。
    /// 通过时自动插入缓存。
    fn check_and_insert(&self, salt: &[u8]) -> bool {
        let now = now_unix_secs();
        let mut entries = self.entries.lock().unwrap();

        // 清理过期条目
        entries.retain(|_, ts| now.saturating_sub(*ts) < self.window_secs);

        // 检查是否已存在
        if entries.contains_key(salt) {
            return false;
        }

        entries.insert(salt.to_vec(), now);
        true
    }
}

pub async fn run(cfg: Arc<ShadowsocksConfig>) -> Result<()> {
    let key_len = cfg.method.key_len();
    let master_key = Arc::new(decode_master_key(&cfg.password, key_len)?);
    let salt_cache = Arc::new(SaltCache::new(SALT_CACHE_WINDOW_SECS));

    let tls_acceptor: Option<Arc<TlsAcceptor>> = if let Some(tls_cfg) = &cfg.tls {
        let sc = shared_tls::build(
            tls_cfg.cert_path.as_deref(),
            tls_cfg.key_path.as_deref(),
            tls_cfg.self_signed_domain.as_deref(),
        )?;
        Some(Arc::new(TlsAcceptor::from(Arc::new(sc))))
    } else {
        None
    };

    let addr: SocketAddr = cfg.listen.parse()?;
    let listener = TcpListener::bind(addr).await?;
    info!(
        "[shadowsocks] listening on {addr} (method={:?}, transport={}, tls={})",
        cfg.method,
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
        let key2 = Arc::clone(&master_key);
        let cfg2 = Arc::clone(&cfg);
        let sc2 = Arc::clone(&salt_cache);

        let srv_feed = xhttp_server.clone();
        let tls2 = tls_acceptor.clone();
        tokio::spawn(async move {
            loop {
                let (stream, peer) = match listener.accept().await {
                    Ok(p) => p,
                    Err(e) => {
                        warn!("[shadowsocks] accept error: {e}");
                        continue;
                    }
                };
                debug!("[shadowsocks] new connection from {peer}");
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
                                Err(e) => warn!("[shadowsocks] {peer} TLS: {e}"),
                            }
                        });
                    }
                }
            }
        });

        loop {
            match xhttp_server.accept().await {
                None => {
                    warn!("[shadowsocks] xhttp server closed");
                    break;
                }
                Some(xhs) => {
                    let key = Arc::clone(&key2);
                    let cfg3 = Arc::clone(&cfg2);
                    let sc3 = Arc::clone(&sc2);
                    tokio::spawn(async move {
                        let peer: SocketAddr = "0.0.0.0:0".parse().unwrap();
                        if let Err(e) = process(xhs, peer, &cfg3, &key, &sc3).await {
                            warn!("[shadowsocks] {peer}: {e:#}");
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
        let cfg2 = Arc::clone(&cfg);
        let key = Arc::clone(&master_key);
        let sc2 = Arc::clone(&salt_cache);
        let acc = tls_acceptor.clone();

        tokio::spawn(async move {
            debug!("[shadowsocks] new connection from {peer}");
            if let Err(e) = handle_conn(stream, peer, &cfg2, &key, &sc2, acc).await {
                warn!("[shadowsocks] {peer}: {e:#}");
            }
        });
    }
}

async fn handle_conn(
    stream: TcpStream,
    peer: SocketAddr,
    cfg: &ShadowsocksConfig,
    master_key: &[u8],
    salt_cache: &SaltCache,
    tls_acceptor: Option<Arc<TlsAcceptor>>,
) -> Result<()> {
    let transport = cfg.transport.r#type.as_str();

    match (transport, tls_acceptor) {
        ("tcp", None) => process(stream, peer, cfg, master_key, salt_cache).await,
        ("tcp", Some(acc)) => {
            let tls = acc.accept(stream).await?;
            process(tls, peer, cfg, master_key, salt_cache).await
        }
        ("ws", None) => {
            let ws =
                shared_ws::accept_plain(stream, &shared_ws::opts_from_transport(&cfg.transport))
                    .await?;
            process(ws, peer, cfg, master_key, salt_cache).await
        }
        ("ws", Some(acc)) => {
            let tls = acc.accept(stream).await?;
            let ws =
                shared_ws::accept_tls(tls, &shared_ws::opts_from_transport(&cfg.transport)).await?;
            process(ws, peer, cfg, master_key, salt_cache).await
        }
        (other, _) => anyhow::bail!("shadowsocks: unknown transport '{other}'"),
    }
}

async fn process<S>(
    mut stream: S,
    peer: SocketAddr,
    cfg: &ShadowsocksConfig,
    master_key: &[u8],
    salt_cache: &SaltCache,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let salt_len = cfg.method.salt_len();
    let cipher = cfg.method.clone();

    // Step 1: 读取客户端 salt
    let mut client_salt = vec![0u8; salt_len];
    stream.read_exact(&mut client_salt).await?;

    // Step 2: salt 重放保护（2022 规范要求）
    if !salt_cache.check_and_insert(&client_salt) {
        warn!("[shadowsocks] {peer}: replay detected (duplicate salt)");
        anyhow::bail!("shadowsocks 2022: replay detected (duplicate salt)");
    }

    // Step 3: 派生上行会话子密钥
    let up_subkey = derive_session_subkey(master_key, &client_salt, salt_len);

    let (read_half, write_half) = tokio::io::split(stream);
    let mut aead_r = AeadReader::new(read_half, cipher.clone(), up_subkey);

    // Step 4: 读取并解析请求头
    let header_data = aead_r.read_header_chunk().await?;
    let target = parse_request_header(&header_data, STREAM_TYPE_REQUEST)?;
    info!("[shadowsocks] {peer} → {target}");

    // Step 5: 拨号出站
    let outbound = shared_net::dial_tcp_timeout(
        &target,
        shared_net::OutboundBind::new(cfg.outbound_bind_ipv4, cfg.outbound_bind_ipv6),
        std::time::Duration::from_secs(10),
    )
    .await
    .map_err(|e| anyhow::anyhow!("connect {target} failed: {e}"))?;

    // Step 6: 生成响应 salt 并派生下行会话子密钥
    let mut resp_salt = vec![0u8; salt_len];
    rand::thread_rng().fill_bytes(&mut resp_salt);
    let dn_subkey = derive_session_subkey(master_key, &resp_salt, salt_len);

    // Step 7: 写响应 salt（明文）→ 重置子密钥 → 写响应头 AEAD chunk
    let mut aead_w = AeadWriter::new(write_half, cipher.clone(), vec![0u8; salt_len]);
    aead_w.write_raw(&resp_salt).await?;
    aead_w.reset_subkey(dn_subkey);

    let resp_header = build_response_header(&client_salt);
    aead_w.write_header_chunk(&resp_header).await?;
    aead_w.flush().await?;

    // Step 8: 双向 relay
    let (mut out_r, mut out_w) = outbound.into_split();
    let t = target.clone();

    // 上行：解密客户端数据 → 写入出站
    let uplink = async move {
        let mut tmp = vec![0u8; 65536];
        loop {
            let n = match aead_r.read_plain(&mut tmp).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            if out_w.write_all(&tmp[..n]).await.is_err() {
                break;
            }
        }
        let _ = out_w.shutdown().await;
        debug!("[shadowsocks] uplink closed {peer}→{t}");
    };

    // 下行：读取出站数据 → AEAD 加密写入客户端
    let t2 = target.clone();
    let downlink = async move {
        let mut tmp = vec![0u8; 65536];
        loop {
            let n = match tokio::io::AsyncReadExt::read(&mut out_r, &mut tmp).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            if aead_w.write_data(&tmp[..n]).await.is_err() {
                break;
            }
            if aead_w.flush().await.is_err() {
                break;
            }
        }
        // 优雅关闭：确保最后一个 AEAD chunk 已 flush，再关闭写端
        let _ = aead_w.flush().await;
        debug!("[shadowsocks] downlink closed {t2}→{peer}");
    };

    tokio::join!(uplink, downlink);
    debug!("[shadowsocks] relay done: {peer} ↔ {target}");
    Ok(())
}

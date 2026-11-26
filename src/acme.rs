//! ACME（Let's Encrypt）DNS-01 证书申请与自动续签。
//!
//! 仅支持 Cloudflare DNS API（REST，无 SDK）：申请时按域名在
//! `_acme-challenge.<domain>` 建 TXT 记录完成验证，结束后自动清理。
//! 证书记录存于加密数据库（`certs` 表），申请/续签成功后同时把 PEM
//! 写到 `<数据目录>/certs/<id>.crt|.key`，节点通过 `cert-ref` 引用。
//!
//! 流程对齐 Xray/acme.sh 的 DNS-01 惯例：
//! 账号注册 → 订单 → 建 TXT → 等待传播 → 提交挑战 → 轮询 → CSR → finalize。

use anyhow::{anyhow, bail, Context, Result};
use instant_acme::{
    Account, AuthorizationStatus, ChallengeType, Identifier, LetsEncrypt, NewAccount, NewOrder,
    OrderStatus,
};
use rcgen::{CertificateParams, DistinguishedName, KeyPair};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::time::{sleep, Duration};
use tracing::{error, info, warn};

use crate::stats::db::Db;

/// 传给验证前的 DNS 传播等待。Let's Encrypt 验证服务器从权威 DNS 查询，
/// Cloudflare 传播很快，30 秒 + 后续轮询足够稳。
const DNS_PROPAGATION_WAIT: Duration = Duration::from_secs(30);
/// 订单状态轮询间隔与总超时。
const ORDER_POLL_INTERVAL: Duration = Duration::from_secs(10);
const ORDER_TIMEOUT: Duration = Duration::from_secs(300);
/// 续签检查周期与提前续签阈值。
const RENEW_CHECK_INTERVAL: Duration = Duration::from_secs(12 * 3600);
const RENEW_BEFORE_DAYS: i64 = 30;

// ── Cloudflare DNS API ───────────────────────────────────────────────────────

fn cf_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .context("build http client")
}

/// 解析 FQDN 所属 zone：优先用用户填的 zone-id，否则列出全部 zone 后
/// 取与 FQDN 后缀匹配的最长项（正确处理多级 zone，如 a.b.com 与 b.com 共存）。
async fn cf_resolve_zone(token: &str, zone_id_hint: &str, fqdn: &str) -> Result<String> {
    if !zone_id_hint.is_empty() {
        return Ok(zone_id_hint.to_string());
    }
    let client = cf_client()?;
    let resp = client
        .get("https://api.cloudflare.com/client/v4/zones?per_page=50")
        .bearer_auth(token)
        .send()
        .await
        .context("cloudflare: list zones")?
        .json::<Value>()
        .await
        .context("cloudflare: parse zones response")?;
    if resp["success"].as_bool() != Some(true) {
        bail!(
            "cloudflare list zones: {}",
            cf_error_msg(&resp).unwrap_or_else(|| "unknown".into())
        );
    }
    let mut best: Option<(String, usize)> = None;
    if let Some(zones) = resp["result"].as_array() {
        for z in zones {
            let Some(name) = z["name"].as_str() else { continue };
            let id = match z["id"].as_str() {
                Some(i) => i,
                None => continue,
            };
            let is_suffix = fqdn == name
                || fqdn
                    .strip_suffix(name)
                    .map(|rest| rest.ends_with('.') || rest.is_empty())
                    .unwrap_or(false);
            if is_suffix && best.as_ref().map_or(true, |(_, l)| name.len() > *l) {
                best = Some((id.to_string(), name.len()));
            }
        }
    }
    best.map(|(id, _)| id)
        .ok_or_else(|| anyhow!("cloudflare: token 无权访问域名 `{fqdn}` 所属 zone"))
}

fn cf_error_msg(resp: &Value) -> Option<String> {
    resp["errors"]
        .as_array()
        .and_then(|a| a.first())
        .and_then(|e| e["message"].as_str())
        .map(|s| s.to_string())
}

async fn cf_create_txt(token: &str, zone_id: &str, name: &str, content: &str) -> Result<String> {
    let client = cf_client()?;
    let url = format!(
        "https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records"
    );
    let body = json!({"type": "TXT", "name": name, "content": content, "ttl": 60});
    let resp = client
        .post(&url)
        .bearer_auth(token)
        .json(&body)
        .send()
        .await
        .with_context(|| format!("cloudflare create TXT {name}"))?
        .json::<Value>()
        .await
        .context("cloudflare: parse create response")?;
    if resp["success"].as_bool() != Some(true) {
        bail!(
            "cloudflare create TXT {name}: {}",
            cf_error_msg(&resp).unwrap_or_else(|| "unknown".into())
        );
    }
    resp["result"]["id"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| anyhow!("cloudflare create TXT {name}: no record id"))
}

async fn cf_delete_txt(token: &str, zone_id: &str, record_id: &str) {
    let client = match cf_client() {
        Ok(c) => c,
        Err(_) => return,
    };
    let url = format!(
        "https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_id}"
    );
    if let Err(e) = client.delete(&url).bearer_auth(token).send().await {
        warn!("[acme] cloudflare delete TXT {record_id}: {e}");
    }
}

// ── 证书记录存取 ─────────────────────────────────────────────────────────────

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// 解析证书链第一张证书的 not_after，返回 Unix 毫秒。
pub fn parse_cert_expiry_ms(cert_pem: &str) -> Option<u64> {
    use std::io::BufReader;
    let der = rustls_pemfile::certs(&mut BufReader::new(cert_pem.as_bytes()))
        .filter_map(|r| r.ok())
        .next()?;
    let (_, cert) = x509_parser::parse_x509_certificate(&der).ok()?;
    let secs = cert.validity().not_after.timestamp();
    u64::try_from(secs).ok().map(|s| s.saturating_mul(1000))
}

fn set_status(db: &Arc<Db>, id: &str, status: &str, err: &str) -> Result<()> {
    if let Some(mut rec) = db.get_cert(id)? {
        rec["status"] = json!(status);
        rec["error"] = json!(err);
        db.put_cert(id, &rec)?;
    }
    Ok(())
}

/// 申请/续签单张证书（数据库记录 → ACME → 存库 + 写 PEM 文件）。
pub async fn run_issue(db: Arc<Db>, id: &str, dir: &Path) -> Result<()> {
    let mut rec = db
        .get_cert(id)?
        .ok_or_else(|| anyhow!("证书 {id} 不存在"))?;

    let domains: Vec<String> = rec["domains"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|d| d.as_str())
                .map(|s| s.trim().to_lowercase())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default();
    if domains.is_empty() {
        bail!("未填写证书域名");
    }
    let email = rec["email"].as_str().unwrap_or("").trim().to_string();
    if email.is_empty() {
        bail!("未填写 ACME 账户邮箱");
    }
    let token = rec["cf-token"].as_str().unwrap_or("").trim().to_string();
    if token.is_empty() {
        bail!("未填写 Cloudflare API Token");
    }
    let zone_hint = rec["zone-id"].as_str().unwrap_or("").trim().to_string();

    set_status(&db, id, "pending", "").context("update cert status")?;
    info!("[acme] 开始申请证书 {id}: domains={domains:?}");

    match do_acme(&domains, &email, &token, &zone_hint).await {
        Ok((cert_pem, key_pem)) => {
            let expires = parse_cert_expiry_ms(&cert_pem).unwrap_or_else(|| {
                // 解析失败时按 Let's Encrypt 90 天估算。
                now_ms() + 90 * 24 * 3600 * 1000
            });
            rec["status"] = json!("active");
            rec["error"] = json!("");
            rec["cert-pem"] = json!(cert_pem);
            rec["key-pem"] = json!(key_pem);
            rec["issued-at-ms"] = json!(now_ms());
            rec["expires-at-ms"] = json!(expires);
            db.put_cert(id, &rec).context("save cert record")?;
            write_pem_files(dir, id, &rec).context("write pem files")?;
            info!(
                "[acme] 证书 {id} 申请成功，到期时间 {}",
                chrono_like(expires)
            );
            Ok(())
        }
        Err(e) => {
            error!("[acme] 证书 {id} 申请失败: {e:#}");
            let _ = set_status(&db, id, "error", &format!("{e:#}"));
            Err(e)
        }
    }
}

/// 毫秒时间戳 → `YYYY-MM-DD`（不引入 chrono，手写转换）。
fn chrono_like(ms: u64) -> String {
    let secs = (ms / 1000) as i64;
    let days = secs / 86400;
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02}")
}

/// Howard Hinnant 的 days → civil 算法。
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// 把证书 PEM 写到 `<dir>/certs/<id>.crt|.key`（权限 600），节点 cert-ref 引用时读取。
pub fn write_pem_files(dir: &Path, id: &str, rec: &Value) -> Result<()> {
    let certs_dir = dir.join("certs");
    std::fs::create_dir_all(&certs_dir)
        .with_context(|| format!("create dir: {}", certs_dir.display()))?;
    let crt = certs_dir.join(format!("{id}.crt"));
    let key = certs_dir.join(format!("{id}.key"));
    let cert_pem = rec["cert-pem"].as_str().unwrap_or("");
    let key_pem = rec["key-pem"].as_str().unwrap_or("");
    if cert_pem.is_empty() || key_pem.is_empty() {
        bail!("证书记录缺少 PEM 内容");
    }
    std::fs::write(&crt, cert_pem)
        .with_context(|| format!("write {}", crt.display()))?;
    std::fs::write(&key, key_pem)
        .with_context(|| format!("write {}", key.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

/// ACME DNS-01 主流程，返回 (证书链 PEM, 私钥 PEM)。
async fn do_acme(domains: &[String], email: &str, token: &str, zone_hint: &str) -> Result<(String, String)> {
    let account = Account::create(
        &NewAccount {
            contact: &[&format!("mailto:{email}")],
            terms_of_service_agreed: true,
            only_return_existing: false,
        },
        LetsEncrypt::Production.url(),
        None,
    )
    .await
    .context("create ACME account")?;
    // instant-acme 0.6 的 create 返回 (Account, AccountCredentials)，后续只用 Account。
    let (account, _account_credentials) = account;

    let identifiers: Vec<Identifier> = domains.iter().map(|d| Identifier::Dns(d.clone())).collect();
    let mut order = account
        .new_order(&NewOrder {
            identifiers: &identifiers,
        })
        .await
        .context("create order")?;

    let authorizations = order.authorizations().await.context("get authorizations")?;

    // (zone_id, record_id) — 用于结束后清理。
    let mut txt_records: Vec<(String, String)> = Vec::new();

    for authz in &authorizations {
        if matches!(authz.status, AuthorizationStatus::Valid) {
            continue;
        }
        let challenge = authz
            .challenges
            .iter()
            .find(|c| matches!(c.r#type, ChallengeType::Dns01))
            .ok_or_else(|| anyhow!("authorization 无 DNS-01 挑战"))?;
        let dns_value = order.key_authorization(challenge).dns_value();
        let domain = match &authz.identifier {
            Identifier::Dns(d) => d.clone(),
        };
        let txt_name = format!("_acme-challenge.{domain}");
        let zone_id = cf_resolve_zone(token, zone_hint, &domain)
            .await
            .with_context(|| format!("resolve zone for {domain}"))?;
        let record_id = cf_create_txt(token, &zone_id, &txt_name, &dns_value)
            .await
            .with_context(|| format!("create TXT {txt_name}"))?;
        txt_records.push((zone_id, record_id));
        info!("[acme] TXT 记录已创建: {txt_name}");
        sleep(DNS_PROPAGATION_WAIT).await;
        order
            .set_challenge_ready(&challenge.url)
            .await
            .with_context(|| format!("set challenge ready for {domain}"))?;
    }

    // 轮询订单直到 Ready（全部验证通过）。
    let deadline = std::time::Instant::now() + ORDER_TIMEOUT;
    loop {
        sleep(ORDER_POLL_INTERVAL).await;
        order.refresh().await.context("refresh order")?;
        match order.state().status {
            OrderStatus::Ready => break,
            OrderStatus::Invalid => {
                cleanup_txt(token, &txt_records).await;
                bail!("ACME 订单验证失败（域名 DNS 是否正确解析到本服务器？Token 权限是否足够？）");
            }
            _ => {}
        }
        if std::time::Instant::now() > deadline {
            cleanup_txt(token, &txt_records).await;
            bail!("ACME 验证超时（{}s）", ORDER_TIMEOUT.as_secs());
        }
    }

    // 生成密钥与 CSR 并 finalize。
    let key_pair = KeyPair::generate().context("generate key pair")?;
    let mut params =
        CertificateParams::new(domains.to_vec()).context("cert params")?;
    params.distinguished_name = DistinguishedName::new();
    let csr = params
        .serialize_request(&key_pair)
        .context("serialize CSR")?;

    order.finalize(csr.der().as_ref()).await.context("finalize")?;

    let deadline = std::time::Instant::now() + ORDER_TIMEOUT;
    let chain = loop {
        sleep(Duration::from_secs(3)).await;
        order.refresh().await.context("refresh after finalize")?;
        match order.state().status {
            OrderStatus::Valid => {
                let pem = order
                    .certificate()
                    .await
                    .context("get certificate")?
                    .ok_or_else(|| anyhow!("order 无证书内容"))?;
                break pem;
            }
            OrderStatus::Invalid => bail!("ACME 订单在 finalize 后失效"),
            _ => {}
        }
        if std::time::Instant::now() > deadline {
            bail!("等待证书签发超时");
        }
    };

    cleanup_txt(token, &txt_records).await;
    Ok((chain, key_pair.serialize_pem()))
}

async fn cleanup_txt(token: &str, records: &[(String, String)]) {
    for (zone, rid) in records {
        cf_delete_txt(token, zone, rid).await;
    }
}

// ── 自动续签 ─────────────────────────────────────────────────────────────────

/// 后台续签任务：每 12 小时扫描一次，距到期 <30 天的 active 证书自动续签，
/// 成功后热重载引用它的节点。
pub async fn run_renew_task(
    db: Arc<Db>,
    dir: PathBuf,
    manager: Arc<crate::node_manager::NodeManager>,
) {
    // 启动 1 分钟后先检查一轮（覆盖「上次运行时即将到期」的场景）。
    sleep(Duration::from_secs(60)).await;
    loop {
        if let Err(e) = renew_all(&db, &dir, &manager).await {
            error!("[acme] renew round failed: {e:#}");
        }
        sleep(RENEW_CHECK_INTERVAL).await;
    }
}

async fn renew_all(db: &Arc<Db>, dir: &Path, manager: &Arc<crate::node_manager::NodeManager>) -> Result<()> {
    let certs = db.list_certs()?;
    for (id, rec) in certs {
        if rec["status"].as_str() != Some("active") || rec["auto-renew"].as_bool() != Some(true) {
            continue;
        }
        let expires = rec["expires-at-ms"].as_u64().unwrap_or(0);
        let days_left = ((expires as i64 - now_ms() as i64) / 86_400_000).max(0);
        if days_left > RENEW_BEFORE_DAYS {
            continue;
        }
        info!("[acme] 自动续签 {id}（{days_left} 天后到期）");
        match run_issue(Arc::clone(db), &id, dir).await {
            Ok(()) => {
                manager.reload_nodes_using_cert(&id);
                info!("[acme] 自动续签完成: {id}");
            }
            Err(e) => error!("[acme] 自动续签失败 {id}: {e:#}"),
        }
    }
    Ok(())
}

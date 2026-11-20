//! 节点分享链接生成：把节点的原始声明（kebab-case JSON，来自 Web 面板的
//! `list_details`）转换为客户端通用的订阅/分享 URI（vless:// / vmess:// ...）。
//!
//! 只做「字符串拼装 + base64 / 公钥派生」，不触碰运行中的节点。

use anyhow::{Context, Result};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use serde_json::Value;

use crate::config;

/// URI 片段百分号编码（unreserved 字符原样，其余转 %XX）。
fn pct(s: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::new();
    for &b in s.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 15) as usize] as char);
        }
    }
    out
}

fn gs(v: &Value, k: &str) -> String {
    v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string()
}
fn gs_or(v: &Value, k: &str, default: &str) -> String {
    v.get(k)
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or(default)
        .to_string()
}
fn has_tls(v: &Value) -> bool {
    v.get("cert").is_some() || v.get("key").is_some() || v.get("self-signed-domain").is_some()
}
/// 是否使用自签证书（含强制 TLS 但未配外部证书时程序自动签发的自签证书）。
/// 只有自签才需要在分享链接里开启 allowInsecure / skip-cert-verify / insecure；
/// 真实证书（cert + key）由公共 CA 签发，客户端应正常校验，不能放行不安全连接。
fn is_self_signed(v: &Value) -> bool {
    // 显式配置了自签域名
    if !gs(v, "self-signed-domain").is_empty() {
        return true;
    }
    // 强制 TLS 的协议未配外部证书 → 服务端自动签发自签证书
    let kind = gs(v, "type");
    let forced_tls = matches!(kind.as_str(), "hysteria2" | "tuic" | "anytls" | "naiveproxy");
    forced_tls && gs(v, "cert").is_empty()
}
/// SNI：自签域名 → 证书域名（为真实证书导出单独配置）→ 对外地址。
/// 泛域名证书（`*.example.com`）做 SNI 不规范（部分客户端/网关拒绝 `*.` 开头
/// 的 SNI），替换为具体子域：优先取传输 host 头 / 对外地址中是泛域名子域的
/// 那个，否则退回最常见的 `www.<主域>`（`*.example.com` 覆盖 www.example.com）。
fn sni_of(v: &Value, host: &str) -> String {
    let s = gs_or(v, "self-signed-domain", "");
    if !s.is_empty() {
        return s;
    }
    let s = gs_or(v, "cert-domain", "");
    if s.is_empty() {
        return host.to_string();
    }
    if let Some(base) = s.strip_prefix("*.") {
        let candidates = [gs(v, "host"), host.to_string()];
        let suffix = format!(".{base}");
        for c in candidates {
            if !c.is_empty() && c.ends_with(&suffix) {
                return c;
            }
        }
        return format!("www.{base}");
    }
    s
}
/// users[0] 的指定字段。
fn user_field(v: &Value, field: &str) -> String {
    v.get("users")
        .and_then(|x| x.as_array())
        .and_then(|a| a.first())
        .and_then(|u| u.get(field))
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string()
}

/// 清洗对外地址：去掉 scheme 与尾部斜杠；IPv6 请用户自带方括号。
fn clean_host(host: &str) -> String {
    let s = host.trim();
    let s = s
        .strip_prefix("https://")
        .or_else(|| s.strip_prefix("http://"))
        .unwrap_or(s);
    s.trim_end_matches('/').to_string()
}

/// 生成分享链接。`node` 为节点原始声明，`host` 为客户端连接的对外域名/IP。
pub fn build(node: &Value, host: &str) -> Result<String> {
    let host = clean_host(host);
    if host.is_empty() {
        anyhow::bail!("对外地址不能为空（请填写域名或 IP，不含端口）");
    }
    let kind = gs(node, "type");
    let port = node
        .get("port")
        .and_then(|x| x.as_u64())
        .context("node has no port")?;
    let name = gs(node, "name");
    let frag = format!("#{}", pct(&name));

    let link = match kind.as_str() {
        // ── VLESS ──────────────────────────────────────────────────────────
        "vless" => {
            let uuid = gs(node, "uuid");
            let transport = gs_or(node, "transport", "tcp");
            // XHTTP over HTTP/3：对齐 Xray 分享链接 `type=xhttp&alpn=h3`。
            // H3 与 TLS 分支的默认 alpn 互斥——URL 出现重复 alpn 参数时，
            // Go Query().Get 取第一个值，但取后值的解析器会错连成 h2。
            let is_h3 = transport == "xhttp"
                && node.get("h3").and_then(|x| x.as_bool()).unwrap_or(false);
            let mut q: Vec<String> = vec!["encryption=none".into(), format!("type={transport}")];
            // 传输参数（ws / xhttp 的 path & host）
            if transport == "ws" || transport == "xhttp" {
                q.push(format!("path={}", pct(&gs_or(node, "path", "/"))));
                if let Some(h) = node.get("host").and_then(|x| x.as_str()).filter(|s| !s.is_empty()) {
                    q.push(format!("host={}", pct(h)));
                }
                if is_h3 {
                    q.push("alpn=h3".into());
                    q.push("mode=auto".into());
                }
            }
            // 安全层
            let priv_key = gs(node, "reality-private-key");
            if !priv_key.is_empty() {
                let pbk = config::reality_public_key(&priv_key)
                    .context("invalid reality-private-key, cannot build share link")?;
                let sid = node
                    .get("reality-short-ids")
                    .and_then(|x| x.as_array())
                    .and_then(|a| a.first())
                    .and_then(|s| s.as_str())
                    .unwrap_or("");
                let sni = gs_or(node, "reality-server-name", &host);
                q.push("security=reality".into());
                q.push(format!("pbk={pbk}"));
                q.push(format!("sid={sid}"));
                q.push(format!("sni={}", pct(&sni)));
                q.push("fp=chrome".into());
            } else if has_tls(node) {
                q.push("security=tls".into());
                q.push(format!("sni={}", pct(&sni_of(node, &host))));
                // fp 对 QUIC 握手无效（uTLS 不参与 H3），H3 模式不导出；
                // alpn 已由 H3 分支给出，不再追加默认 h2 列表。
                if !is_h3 {
                    q.push("fp=chrome".into());
                    q.push("alpn=h2,http/1.1".into());
                }
                // 自签证书客户端不信任，必须放行不安全连接才能连上。
                if is_self_signed(node) {
                    q.push("allowInsecure=1".into());
                }
            } else {
                q.push("security=none".into());
            }
            format!("vless://{uuid}@{host}:{port}?{}{}", q.join("&"), frag)
        }

        // ── VMess（base64 标准 JSON）─────────────────────────────────────
        "vmess" => {
            let tls = if has_tls(node) { "tls" } else { "" };
            // 自签证书需在客户端放行不安全校验，否则连不上；真实证书保持严格校验。
            let skip_verify = has_tls(node) && is_self_signed(node);
            let obj = serde_json::json!({
                "v": "2",
                "ps": name,
                "add": host,
                "port": port,
                "id": gs(node, "uuid"),
                "aid": "0",
                "net": gs_or(node, "transport", "tcp"),
                "type": "none",
                "host": gs_or(node, "host", ""),
                "path": gs_or(node, "path", ""),
                "tls": tls,
                "sni": if has_tls(node) { sni_of(node, &host) } else { String::new() },
                "skip-cert-verify": skip_verify,
            });
            format!("vmess://{}", STANDARD.encode(obj.to_string()))
        }

        // ── Trojan ────────────────────────────────────────────────────────
        "trojan" => {
            let pass = gs(node, "password");
            let transport = gs_or(node, "transport", "tcp");
            // H3 与 TLS 分支的默认 alpn 互斥（同 vless，避免重复 alpn 参数）。
            let is_h3 = transport == "xhttp"
                && node.get("h3").and_then(|x| x.as_bool()).unwrap_or(false);
            let mut q: Vec<String> = Vec::new();
            if has_tls(node) {
                q.push(format!("sni={}", pct(&sni_of(node, &host))));
                if !is_h3 {
                    q.push("alpn=h2,http/1.1".into());
                }
                if is_self_signed(node) {
                    q.push("allowInsecure=1".into());
                }
            } else {
                q.push("security=none".into());
            }
            if transport == "ws" || transport == "xhttp" {
                q.push(format!("type={transport}"));
                q.push(format!("path={}", pct(&gs_or(node, "path", "/"))));
                if let Some(h) = node.get("host").and_then(|x| x.as_str()).filter(|s| !s.is_empty()) {
                    q.push(format!("host={}", pct(h)));
                }
                if is_h3 {
                    q.push("alpn=h3".into());
                    q.push("mode=auto".into());
                }
            }
            let suffix = if q.is_empty() { String::new() } else { format!("?{}", q.join("&")) };
            format!("trojan://{}@{host}:{port}{suffix}{frag}", pct(&pass))
        }

        // ── Shadowsocks（SIP002）─────────────────────────────────────────
        "shadowsocks" => {
            let method = gs_or(node, "method", "2022-blake3-aes-256-gcm");
            let pass = gs(node, "password");
            let cred = URL_SAFE_NO_PAD.encode(format!("{method}:{pass}"));
            format!("ss://{cred}@{host}:{port}{frag}")
        }

        // ── Hysteria2 ─────────────────────────────────────────────────────
        "hysteria2" => {
            let pass = gs(node, "password");
            let mut q: Vec<String> = vec![format!("sni={}", pct(&sni_of(node, &host)))];
            if is_self_signed(node) {
                q.push("insecure=1".into());
            }
            if let Some(up) = node.get("up").and_then(|x| x.as_str()).filter(|s| !s.is_empty()) {
                q.push(format!("up={}", pct(up)));
            }
            if let Some(down) = node.get("down").and_then(|x| x.as_str()).filter(|s| !s.is_empty()) {
                q.push(format!("down={}", pct(down)));
            }
            format!("hysteria2://{}@{host}:{port}?{}{}", pct(&pass), q.join("&"), frag)
        }

        // ── TUIC ──────────────────────────────────────────────────────────
        "tuic" => {
            let uuid = user_field(node, "uuid");
            let pass = user_field(node, "password");
            let mut q: Vec<String> = vec![
                "congestion_control=bbr".into(),
                "alpn=h3".into(),
                format!("sni={}", pct(&sni_of(node, &host))),
            ];
            if let Some(cc) = node.get("congestion-control").and_then(|x| x.as_str()).filter(|s| !s.is_empty()) {
                q[0] = format!("congestion_control={cc}");
            }
            if is_self_signed(node) {
                q.push("allow_insecure=1".into());
            }
            format!("tuic://{}:{}@{host}:{port}?{}{}", pct(&uuid), pct(&pass), q.join("&"), frag)
        }

        // ── AnyTLS ────────────────────────────────────────────────────────
        "anytls" => {
            let pass = gs(node, "password");
            let sni = sni_of(node, &host);
            let insecure = if is_self_signed(node) { "&allowInsecure=1" } else { "" };
            format!("anytls://{}@{host}:{port}?sni={}{}{}", pct(&pass), pct(&sni), insecure, frag)
        }

        // ── SOCKS5 ────────────────────────────────────────────────────────
        "socks" => {
            let user = user_field(node, "username");
            let pass = user_field(node, "password");
            if user.is_empty() {
                format!("socks5://{host}:{port}{frag}")
            } else {
                format!("socks5://{}:{}@{host}:{port}{frag}", pct(&user), pct(&pass))
            }
        }

        // ── HTTP ──────────────────────────────────────────────────────────
        "http" => {
            let user = user_field(node, "username");
            let pass = user_field(node, "password");
            let scheme = if has_tls(node) { "https" } else { "http" };
            if user.is_empty() {
                format!("{scheme}://{host}:{port}{frag}")
            } else {
                format!("{scheme}://{}:{}@{host}:{port}{frag}", pct(&user), pct(&pass))
            }
        }

        // ── NaiveProxy ────────────────────────────────────────────────────
        "naiveproxy" => {
            let user = user_field(node, "username");
            let pass = user_field(node, "password");
            format!("naive+https://{}:{}@{host}:{port}{frag}", pct(&user), pct(&pass))
        }

        // ── WireGuard：无通用 URI 标准，返回一段可用的客户端配置文本 ─────
        "wireguard" => {
            let priv_key = gs(node, "private-key");
            let pub_key = config::wireguard_public_key(&priv_key)
                .context("invalid wireguard private-key")?;
            let addresses: String = node
                .get("server-address")
                .and_then(|x| x.as_array())
                .map(|a| a.iter().filter_map(|s| s.as_str()).collect::<Vec<_>>().join(", "))
                .unwrap_or_default();
            let mtu = gs_or(node, "mtu", "1420");
            let dns = gs_or(node, "dns", "1.1.1.1");
            let mut text = format!(
                "[Interface]\nPrivateKey = {priv_key}\nAddress = {addresses}\nDNS = {dns}\nMTU = {mtu}\n listenPort = 0\n\n"
            );
            if let Some(peers) = node.get("peers").and_then(|x| x.as_array()) {
                for p in peers {
                    let pk = p.get("public-key").and_then(|x| x.as_str()).unwrap_or("");
                    let allowed = p.get("allowed-ips").and_then(|x| x.as_str()).unwrap_or("0.0.0.0/0, ::/0");
                    text.push_str(&format!("[Peer]\nPublicKey = {pk}\nAllowedIPs = {allowed}\nEndpoint = {host}:{port}\n\n"));
                }
            }
            text.push_str(&format!("# 服务端公钥（供对端配置）: {pub_key}\n"));
            text.trim_end().to_string()
        }

        // ── ShadowQuic / Spectre ────────────────────────────────────────
        // spectre://用户名:密码@服务器IP:端口?sni=www.cloudflare.com#节点名
        // 两个协议字段位置不同：spectre 的凭据在顶层，shadowquic 在 users[0]。
        "shadowquic" | "spectre" => {
            let (user, pass) = if kind == "spectre" {
                (gs(node, "username"), gs(node, "password"))
            } else {
                (user_field(node, "username"), user_field(node, "password"))
            };
            // SNI：显式 server-name 优先；shadowquic 留空时从 jls-upstream 推断；最后退回对外地址。
            let sni = {
                let explicit = gs(node, "server-name");
                if !explicit.is_empty() {
                    explicit
                } else if kind == "shadowquic" {
                    let upstream = gs(node, "jls-upstream");
                    if upstream.is_empty() {
                        host.clone()
                    } else {
                        // "google.com:443" → "google.com"（去掉端口，兼容带 scheme / userinfo）
                        let stripped = upstream
                            .rsplit('@')
                            .next()
                            .unwrap_or(&upstream)
                            .trim_start_matches("https://")
                            .trim_start_matches("http://");
                        stripped
                            .rsplit_once(':')
                            .map(|(h, _)| h.to_string())
                            .unwrap_or_else(|| stripped.to_string())
                    }
                } else {
                    host.clone()
                }
            };
            // 用户名可选：留空则只放密码（:pass@）。
            let userinfo = if user.is_empty() {
                pct(&pass)
            } else {
                format!("{}:{}", pct(&user), pct(&pass))
            };
            format!(
                "{kind}://{userinfo}@{host}:{port}?sni={}{frag}",
                pct(&sni)
            )
        }

        other => anyhow::bail!("不支持导出协议 `{other}` 的分享链接"),
    };

    Ok(link)
}

//! `flux generate` 子命令：密钥对生成工具。
//!
//! 用法：
//!   flux generate wireguard-keypair      — 生成一套 WireGuard 服务端+客户端密钥
//!   flux generate reality-keypair        — 生成 Reality x25519 密钥对
//!   flux generate uuid                   — 生成随机 UUID v4
//!   flux generate password [位数]        — 生成随机密码（大小写字母+数字，默认16位）

use anyhow::Result;
use base64::{engine::general_purpose::STANDARD, engine::general_purpose::URL_SAFE_NO_PAD, Engine};

// ── UUID ──────────────────────────────────────────────────────────────────────

/// 生成一个随机 UUID v4。
pub fn uuid() -> Result<()> {
    let id = uuid::Uuid::new_v4();
    println!("{id}");
    Ok(())
}

// ── Password ──────────────────────────────────────────────────────────────────

/// 生成随机密码：大小写字母 + 数字，默认 16 位。
pub fn password(length: usize) -> Result<()> {
    use rand::Rng;
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = rand::thread_rng();
    let pwd: String = (0..length)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect();
    println!("{pwd}");
    Ok(())
}

// ── WireGuard ─────────────────────────────────────────────────────────────────

/// 生成一套完整的 WireGuard 密钥：服务端私钥/公钥 + 客户端私钥/公钥。
/// WireGuard 密钥格式：标准 base64（与 wg genkey / wg pubkey 输出一致）。
pub fn wireguard_keypair() -> Result<()> {
    use x25519_dalek::{PublicKey, StaticSecret};

    let server_priv = StaticSecret::random_from_rng(rand::thread_rng());
    let server_pub = PublicKey::from(&server_priv);

    let client_priv = StaticSecret::random_from_rng(rand::thread_rng());
    let client_pub = PublicKey::from(&client_priv);

    let server_priv_b64 = STANDARD.encode(server_priv.to_bytes());
    let server_pub_b64 = STANDARD.encode(server_pub.to_bytes());
    let client_priv_b64 = STANDARD.encode(client_priv.to_bytes());
    let client_pub_b64 = STANDARD.encode(client_pub.to_bytes());

    println!("=== WireGuard 密钥对 ===");
    println!();
    println!("# ── 服务端（填入 flux config.toml）──");
    println!("[wireguard]");
    println!("private_key    = \"{server_priv_b64}\"");
    println!("# 对应公钥（填入客户端 wg0.conf [Peer] PublicKey）：");
    println!("# {server_pub_b64}");
    println!();
    println!("# ── 客户端 1（wg0.conf）──");
    println!("[Interface]");
    println!("PrivateKey = {client_priv_b64}");
    println!("Address    = 10.0.0.2/24");
    println!("DNS        = 1.1.1.1");
    println!();
    println!("[Peer]");
    println!("PublicKey           = {server_pub_b64}");
    println!("Endpoint            = 你的服务器IP:51820");
    println!("AllowedIPs          = 0.0.0.0/0, ::/0");
    println!("PersistentKeepalive = 25");
    println!();
    println!("# ── 将客户端公钥填入服务端 config.toml ──");
    println!("[[wireguard.peers]]");
    println!("public_key  = \"{client_pub_b64}\"");
    println!("allowed_ips = [\"10.0.0.2/32\"]");

    Ok(())
}

// ── Reality ───────────────────────────────────────────────────────────────────

/// 生成 Reality 所需的 x25519 密钥对。
/// 格式：URL-safe base64（无填充），与 Xray / sing-box 保持一致。
pub fn reality_keypair() -> Result<()> {
    use x25519_dalek::{PublicKey, StaticSecret};

    let private = StaticSecret::random_from_rng(rand::thread_rng());
    let public = PublicKey::from(&private);

    let private_b64 = URL_SAFE_NO_PAD.encode(private.to_bytes());
    let public_b64 = URL_SAFE_NO_PAD.encode(public.to_bytes());

    // 生成一个随机 short_id（8 字节 hex，16 字符）
    let mut short_id_bytes = [0u8; 8];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut short_id_bytes);
    let short_id = hex::encode(short_id_bytes);

    println!("=== Reality 密钥对 ===");
    println!();
    println!("# ── 服务端（填入 flux config.toml）──────────────────────────────");
    println!("# 注意：服务端只需 private_key，public_key 仅客户端使用");
    println!("[[vless]]");
    println!("listen = \"0.0.0.0:443\"");
    println!("uuid   = \"你的UUID\"");
    println!();
    println!("[vless.tls]");
    println!("type        = \"reality\"");
    println!("private_key = \"{private_b64}\"");
    println!("short_ids   = [\"{short_id}\"]");
    println!("dest        = \"www.microsoft.com:443\"");
    println!("server_name = \"www.microsoft.com\"");
    println!();
    println!("# ── 客户端（Xray / sing-box）────────────────────────────────────────");
    println!("# public_key = \"{public_b64}\"");
    println!("# short_id   = \"{short_id}\"");
    println!();
    println!("# ── 原始值 ──────────────────────────────────────────────────────────");
    println!("private_key (服务端) : {private_b64}");
    println!("public_key  (客户端) : {public_b64}");
    println!("short_id             : {short_id}");

    Ok(())
}

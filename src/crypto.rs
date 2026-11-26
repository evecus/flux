//! 数据库静态加密层。
//!
//! - 值加密：AES-256-GCM，输出 `nonce(12B) || ciphertext+tag`。
//! - 键哈希：HMAC-SHA256 截断 16 字节（hex），用于把 IP / 节点名这类敏感
//!   内容从 数据库表键里移除（键必须可检索，只能用确定性哈希替代）。
//! - 密码哈希：PBKDF2-HMAC-SHA256，100k 迭代，格式 `salt_hex$hash_hex`。

use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{bail, Context, Result};
use hmac::{Hmac, Mac};
use sha2::Sha256;

/// 256-bit 主密钥。
#[derive(Clone)]
pub struct MasterKey([u8; 32]);

impl MasterKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// 随机生成主密钥。
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut k = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut k);
        Self(k)
    }

    fn cipher(&self) -> Aes256Gcm {
        Aes256Gcm::new(aes_gcm::aead::generic_array::GenericArray::from_slice(
            &self.0,
        ))
    }

    /// 加密：`nonce(12B) || ct+tag`。
    pub fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ct = self
            .cipher()
            .encrypt(&nonce, plaintext)
            .map_err(|_| anyhow::anyhow!("aes-gcm encrypt failed"))?;
        let mut out = Vec::with_capacity(12 + ct.len());
        out.extend_from_slice(nonce.as_slice());
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// 解密 [`MasterKey::seal`] 的输出。
    pub fn open(&self, blob: &[u8]) -> Result<Vec<u8>> {
        if blob.len() < 13 {
            bail!("ciphertext too short");
        }
        let (nonce, ct) = blob.split_at(12);
        self.cipher()
            .decrypt(Nonce::from_slice(nonce), ct)
            .map_err(|_| anyhow::anyhow!("aes-gcm decrypt failed (wrong key or corrupt db)"))
    }

    /// 确定性键哈希：HMAC-SHA256(key, data) 截断 16 字节 hex。
    /// 同一输入恒得同一输出，用于替换表键中的敏感明文。
    pub fn key_hash(&self, data: &str) -> String {
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = <HmacSha256 as hmac::Mac>::new_from_slice(&self.0).expect("hmac accepts any key length");
        mac.update(data.as_bytes());
        let out = mac.finalize().into_bytes();
        hex::encode(&out[..16])
    }
}

const PBKDF2_ITERS: u32 = 100_000;

/// PBKDF2-HMAC-SHA256（单 32 字节块）。
fn pbkdf2(password: &[u8], salt: &[u8], iters: u32) -> [u8; 32] {
    type HmacSha256 = Hmac<Sha256>;
    // U1 = PRF(P, S || INT(1))
    let mut mac = <HmacSha256 as hmac::Mac>::new_from_slice(password).expect("hmac accepts any key length");
    mac.update(salt);
    mac.update(&1u32.to_be_bytes());
    let mut u: [u8; 32] = mac.finalize().into_bytes().into();
    let mut out = u;
    for _ in 1..iters {
        let mut mac = <HmacSha256 as hmac::Mac>::new_from_slice(password).expect("hmac accepts any key length");
        mac.update(&u);
        u = mac.finalize().into_bytes().into();
        for (a, b) in out.iter_mut().zip(u.iter()) {
            *a ^= *b;
        }
    }
    out
}

/// 生成密码哈希 `salt_hex$hash_hex`（PBKDF2-HMAC-SHA256, 100k 迭代）。
pub fn hash_password(password: &str) -> Result<String> {
    use rand::RngCore;
    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);
    let h = pbkdf2(password.as_bytes(), &salt, PBKDF2_ITERS);
    Ok(format!("{}${}", hex::encode(salt), hex::encode(h)))
}

/// 校验密码（常数时间比较）。
pub fn verify_password(password: &str, stored: &str) -> bool {
    let Some((salt_hex, hash_hex)) = stored.split_once('$') else {
        return false;
    };
    let Ok(salt) = hex::decode(salt_hex) else { return false };
    let Ok(expect) = hex::decode(hash_hex) else { return false };
    let got = pbkdf2(password.as_bytes(), &salt, PBKDF2_ITERS);
    if got.len() != expect.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in got.iter().zip(expect.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

/// 自检：加密/解密回环 + 密码哈希回环（程序启动时调用，尽早暴露环境问题）。
pub fn selftest() -> Result<()> {
    let key = MasterKey::generate();
    let msg = b"flux-encryption-selftest";
    let sealed = key.seal(msg).context("selftest seal")?;
    let opened = key.open(&sealed).context("selftest open")?;
    if opened != msg {
        bail!("selftest roundtrip mismatch");
    }
    let h = hash_password("selftest-pw").context("selftest hash_password")?;
    if !verify_password("selftest-pw", &h) {
        bail!("selftest password verify failed");
    }
    Ok(())
}

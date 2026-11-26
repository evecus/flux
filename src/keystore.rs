//! 主密钥文件管理。
//!
//! `-d /path` 模式下，主密钥保存在 `/path/flux.key`（明文 64 hex 字符），
//! 负责加密 `flux.sqlite` 的所有值与敏感键。首次运行自动生成，unix 下权限 600。
//! 防护目标：仅泄露 `flux.sqlite` 文件（备份/快照/误传）时数据不可读。

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

use crate::crypto::MasterKey;

const KEY_FILE: &str = "flux.key";

pub fn key_path(dir: &Path) -> PathBuf {
    dir.join(KEY_FILE)
}

/// 读取主密钥；文件不存在则生成并写入。
pub fn load_or_create(dir: &Path) -> Result<MasterKey> {
    let path = key_path(dir);
    if path.exists() {
        let raw = std::fs::read_to_string(&path)
            .with_context(|| format!("cannot read key file: {}", path.display()))?;
        let hex_str = raw.trim();
        let bytes = hex::decode(hex_str)
            .with_context(|| format!("invalid key file (expected 64 hex chars): {}", path.display()))?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("key file must contain 32 bytes"))?;
        return Ok(MasterKey::from_bytes(arr));
    }

    let key = MasterKey::generate();
    std::fs::write(&path, hex::encode(key.as_bytes()))
        .with_context(|| format!("cannot write key file: {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("cannot chmod 600 key file: {}", path.display()))?;
    }
    tracing::info!("[keystore] 已生成主密钥: {}", path.display());
    Ok(key)
}

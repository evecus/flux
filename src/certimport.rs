//! 证书压缩包导入（面板「SSL 证书 → 上传证书」）。
//!
//! 接受一个 zip，里面是 PEM 格式的证书与私钥（`.crt` / `.pem` / `.cer` / `.key` 等任意
//! 文件名都可以，按**内容**识别，不依赖扩展名）。全程在内存中读取，不解压到磁盘。
//!
//! 流程：收集所有证书与私钥 → 用私钥找到匹配的叶子证书（防止传错/混搭）→
//! 按 issuer→subject 把中间证书串成完整链 → 检查未过期 → 输出规范化 PEM。
//! 常见布局均可：`fullchain.pem + privkey.pem`、`cert.crt + ca-bundle.crt + private.key`、
//! 证书与私钥合并在同一个 `.pem` 里。

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls_pemfile::Item;
use std::io::{Cursor, Read};

const MAX_ENTRIES: usize = 64;
const MAX_FILE_BYTES: u64 = 1024 * 1024;
const MAX_CHAIN: usize = 8;

pub struct ImportedCert {
    pub domains: Vec<String>,
    /// 叶子 + 中间证书（PEM，多块拼接）。
    pub cert_pem: String,
    pub key_pem: String,
    pub expires_ms: u64,
}

fn to_pem(label: &str, der: &[u8]) -> String {
    let b64 = STANDARD.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

fn key_label(k: &PrivateKeyDer<'_>) -> &'static str {
    match k {
        PrivateKeyDer::Pkcs1(_) => "RSA PRIVATE KEY",
        PrivateKeyDer::Sec1(_) => "EC PRIVATE KEY",
        _ => "PRIVATE KEY",
    }
}

fn key_matches(cert: &CertificateDer<'static>, key: &PrivateKeyDer<'static>) -> bool {
    let Ok(signing) = rustls::crypto::ring::sign::any_supported_type(&key.clone_key()) else {
        return false;
    };
    rustls::sign::CertifiedKey::new(vec![cert.clone()], signing)
        .keys_match()
        .is_ok()
}

pub fn import_zip(data: &[u8]) -> Result<ImportedCert> {
    let mut zip = zip::ZipArchive::new(Cursor::new(data))
        .context("不是有效的 zip 压缩包（目前仅支持 .zip）")?;
    if zip.len() > MAX_ENTRIES {
        bail!("压缩包内文件过多（最多 {MAX_ENTRIES} 个）");
    }

    let mut certs: Vec<CertificateDer<'static>> = Vec::new();
    let mut keys: Vec<PrivateKeyDer<'static>> = Vec::new();
    let mut saw_encrypted = false;

    for i in 0..zip.len() {
        let mut f = match zip.by_index(i) {
            Ok(f) => f,
            Err(e) => bail!("读取压缩包条目失败（带密码的 zip 不支持）：{e}"),
        };
        if f.is_dir() {
            continue;
        }
        let name = f.name().to_string();
        let base = name.rsplit('/').next().unwrap_or("");
        if name.starts_with("__MACOSX") || base.starts_with('.') {
            continue;
        }
        // 限制单文件解压后大小，防 zip 炸弹（size 字段可伪造，所以读取时再截断）。
        let mut buf = Vec::new();
        if Read::take(&mut f, MAX_FILE_BYTES + 1).read_to_end(&mut buf).is_err()
            || buf.len() as u64 > MAX_FILE_BYTES
        {
            continue;
        }
        if !buf.windows(11).any(|w| w == b"-----BEGIN ") {
            continue; // 非 PEM 文件（README 等）直接忽略
        }
        let text = String::from_utf8_lossy(&buf);
        if text.contains("ENCRYPTED PRIVATE KEY") || text.contains("ENCRYPTED") && text.contains("Proc-Type") {
            saw_encrypted = true;
        }
        for item in rustls_pemfile::read_all(&mut buf.as_slice()) {
            match item {
                Ok(Item::X509Certificate(c)) => {
                    if !certs.contains(&c) {
                        certs.push(c);
                    }
                }
                Ok(Item::Pkcs1Key(k)) => keys.push(PrivateKeyDer::from(k)),
                Ok(Item::Pkcs8Key(k)) => keys.push(PrivateKeyDer::from(k)),
                Ok(Item::Sec1Key(k)) => keys.push(PrivateKeyDer::from(k)),
                _ => {}
            }
        }
    }

    if certs.is_empty() {
        bail!("压缩包中没有找到 PEM 格式的证书（需要 .crt/.pem 文本文件，.pfx/.p12/.der 暂不支持）");
    }
    if keys.is_empty() {
        if saw_encrypted {
            bail!("私钥带密码保护（ENCRYPTED），请先用 openssl 去除密码后再上传");
        }
        bail!("压缩包中没有找到 PEM 格式的私钥（.key 文件）");
    }

    // 用私钥找出对应的叶子证书。
    let mut found: Option<(usize, usize)> = None;
    'outer: for (ki, k) in keys.iter().enumerate() {
        for (ci, c) in certs.iter().enumerate() {
            if key_matches(c, k) {
                found = Some((ci, ki));
                break 'outer;
            }
        }
    }
    let Some((leaf_idx, key_idx)) = found else {
        bail!("私钥与压缩包中的任何证书都不匹配，请确认 key 与 crt 是同一套");
    };

    // 解析 subject / issuer，沿 issuer→subject 串链。
    struct Meta {
        subject: Vec<u8>,
        issuer: Vec<u8>,
    }
    let metas: Vec<Option<Meta>> = certs
        .iter()
        .map(|c| {
            x509_parser::parse_x509_certificate(c).ok().map(|(_, x)| Meta {
                subject: x.subject().as_raw().to_vec(),
                issuer: x.issuer().as_raw().to_vec(),
            })
        })
        .collect();
    let mut chain = vec![leaf_idx];
    while chain.len() < MAX_CHAIN {
        let cur = *chain.last().unwrap();
        let Some(m) = &metas[cur] else { break };
        if m.subject == m.issuer {
            break; // 到根了
        }
        let next = (0..certs.len()).find(|i| {
            !chain.contains(i) && metas[*i].as_ref().is_some_and(|n| n.subject == m.issuer)
        });
        match next {
            Some(n) => chain.push(n),
            None => break,
        }
    }

    // 叶子信息：域名 / 有效期。
    let (_, leaf) = x509_parser::parse_x509_certificate(&certs[leaf_idx])
        .map_err(|e| anyhow::anyhow!("证书解析失败: {e}"))?;
    let not_after = leaf.validity().not_after.timestamp();
    let expires_ms = u64::try_from(not_after).unwrap_or(0).saturating_mul(1000);
    if not_after < crate::stats::now_ms() as i64 / 1000 {
        bail!("证书已过期，请上传有效证书");
    }
    let mut domains: Vec<String> = Vec::new();
    if let Ok(Some(san)) = leaf.subject_alternative_name() {
        for g in &san.value.general_names {
            if let x509_parser::extensions::GeneralName::DNSName(d) = g {
                if !domains.iter().any(|x| x == d) {
                    domains.push(d.to_string());
                }
            }
        }
    }
    if domains.is_empty() {
        if let Some(cn) = leaf.subject().iter_common_name().next().and_then(|a| a.as_str().ok()) {
            domains.push(cn.to_string());
        }
    }
    if domains.is_empty() {
        domains.push("(未识别域名)".to_string());
    }

    let cert_pem: String = chain.iter().map(|i| to_pem("CERTIFICATE", &certs[*i])).collect();
    let key = &keys[key_idx];
    let key_pem = to_pem(key_label(key), key.secret_der());

    Ok(ImportedCert { domains, cert_pem, key_pem, expires_ms })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn make_zip(files: &[(&str, &str)]) -> Vec<u8> {
        let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
        for (n, c) in files {
            w.start_file(*n, zip::write::SimpleFileOptions::default()).unwrap();
            w.write_all(c.as_bytes()).unwrap();
        }
        w.finish().unwrap().into_inner()
    }

    #[test]
    fn imports_crt_and_key_by_content() {
        let ck = rcgen::generate_simple_self_signed(vec!["a.example.com".into(), "b.example.com".into()]).unwrap();
        let z = make_zip(&[
            ("readme.txt", "hello"),
            ("sub/server.crt", &ck.cert.pem()),
            ("sub/server.key", &ck.key_pair.serialize_pem()),
        ]);
        let r = import_zip(&z).unwrap();
        assert_eq!(r.domains, vec!["a.example.com", "b.example.com"]);
        assert!(r.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(r.key_pem.contains("PRIVATE KEY"));
        assert!(r.expires_ms > crate::stats::now_ms());
        // 规范化后的 PEM 可被 rustls_pemfile 重新读取
        assert!(rustls_pemfile::private_key(&mut r.key_pem.as_bytes()).unwrap().is_some());
        assert_eq!(rustls_pemfile::certs(&mut r.cert_pem.as_bytes()).count(), 1);
    }

    #[test]
    fn combined_pem_in_one_file() {
        let ck = rcgen::generate_simple_self_signed(vec!["c.example.com".into()]).unwrap();
        let both = format!("{}{}", ck.cert.pem(), ck.key_pair.serialize_pem());
        assert!(import_zip(&make_zip(&[("all.pem", &both)])).is_ok());
    }

    #[test]
    fn mismatched_key_rejected() {
        let a = rcgen::generate_simple_self_signed(vec!["a.com".into()]).unwrap();
        let b = rcgen::generate_simple_self_signed(vec!["b.com".into()]).unwrap();
        let z = make_zip(&[("a.crt", &a.cert.pem()), ("b.key", &b.key_pair.serialize_pem())]);
        let e = import_zip(&z).err().unwrap().to_string();
        assert!(e.contains("不匹配"), "{e}");
    }

    #[test]
    fn missing_key_and_non_zip_rejected() {
        let a = rcgen::generate_simple_self_signed(vec!["a.com".into()]).unwrap();
        assert!(import_zip(&make_zip(&[("a.crt", &a.cert.pem())])).is_err());
        assert!(import_zip(b"not a zip").is_err());
    }
}

//! Attestation 拦截：解析 KeyParameter[] 提取 challenge / package，
//! 调用 certgen 构造伪造证书链，替换真 HAL 返回的证书链。
//!
//! # 策略：证书链替换（cert-chain swap）
//!
//! 完整 KeyMint 实现需要自己生成密钥并签发证明该密钥的 leaf 证书——但作为
//! HAL 代理我们拿不到真 HAL opaque keyBlob 内部的密钥。因此采用与 keystore2
//! 层 hook 相同的实用策略：
//!
//! 1. 把 generateKey/importKey 原样转发给真 HAL（含 attestation 参数），
//!    真 HAL 返回 real keyBlob + real characteristics + real cert chain。
//! 2. 调用 certgen 用 keybox 生成伪造证书链（leaf 证明 certgen 自生成的
//!    密钥，由 keybox 私钥签发）。
//! 3. 把 real KeyCreationResult.certificateChain 替换为伪造链，keyBlob
//!    与 characteristics 保留真 HAL 的。
//!
//! # 已知局限
//!
//! leaf 证书证明的公钥 ≠ keyBlob 内部密钥的公钥。仅检查证书链有效性 +
//! attestation 扩展内容的 app 会通过；同时校验 keyBlob 公钥与 leaf 公钥
//! 一致的高级检测会失败。这是 HAL 代理路径的固有限制——要彻底解决需
//! 完整实现 KeyMint（自己生成密钥 + 自签 leaf），不在本骨架范围。
//!
//! # 替代路径
//!
//! 若需 keyBlob 与 leaf 公钥一致，可在 begin()/finish() 拦截签名操作，
//! 用 certgen 生成的私钥代替真 HAL 签名——但需实现完整 IKeyMintOperation
//! 代理，复杂度高，留作后续。

use crate::android::hardware::security::keymint::{
    Certificate::Certificate,
    KeyCharacteristics::KeyCharacteristics,
    KeyCreationResult::KeyCreationResult,
    KeyParameter::KeyParameter,
    KeyParameterValue::KeyParameterValue,
    SecurityLevel::SecurityLevel,
    Tag::Tag,
};
use anyhow::{Context, Result};
use certgen::KeyAlgorithm;
use certgen::{build_attested_chain, generate_attested_keypair, DeviceInfo, KeyPair};

/// 从 KeyParameter[] 提取 attestation 关键参数：
/// - ATTESTATION_CHALLENGE（非空才拦截）
/// - ATTESTATION_APPLICATION_ID（用作 package_name，缺失则用 caller 包名）
/// - ALGORITHM（ec/rsa 选择 keybox）
pub struct AttestationRequest {
    pub challenge: Vec<u8>,
    /// 优先取 ATTESTATION_APPLICATION_ID，否则用 caller 包名。
    pub package_name: String,
    /// `ec` / `rsa`，根据 ALGORITHM tag 推断；缺省 ec。
    pub algorithm: String,
}

/// 扫描 KeyParameter[]，若含非空 ATTESTATION_CHALLENGE 则返回 Some(request)。
pub fn parse_attestation_request(
    params: &[KeyParameter],
    caller_package: &str,
) -> Option<AttestationRequest> {
    let mut challenge: Option<Vec<u8>> = None;
    let mut app_id: Option<String> = None;
    let mut algorithm = "ec".to_string();

    for p in params {
        // Tag 是 i32 enum，直接比较变体名。
        match p.r#tag {
            Tag::r#ATTESTATION_CHALLENGE => {
                if let KeyParameterValue::r#Blob(b) = &p.r#value {
                    if !b.is_empty() {
                        challenge = Some(b.clone());
                    }
                }
            }
            Tag::r#ATTESTATION_APPLICATION_ID => {
                if let KeyParameterValue::r#Blob(b) = &p.r#value {
                    if !b.is_empty() {
                        app_id = Some(String::from_utf8_lossy(b).into_owned());
                    }
                }
            }
            Tag::r#ALGORITHM => {
                // Algorithm 是 declare_binder_enum! 生成的 newtype(pub i32)，
                // 取 .get() 拿底层 i32：RSA=1, EC=3。
                if let KeyParameterValue::r#Algorithm(alg) = &p.r#value {
                    match alg.get() {
                        1 => algorithm = "rsa".into(),
                        3 => algorithm = "ec".into(),
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }

    let challenge = challenge?;
    let package_name = app_id
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| {
            if caller_package.is_empty() {
                "android".into()
            } else {
                caller_package.into()
            }
        });
    Some(AttestationRequest {
        challenge,
        package_name,
        algorithm,
    })
}

/// 用 certgen 生成伪造证书链，替换 real KeyCreationResult 的 certificateChain。
///
/// keyBlob / keyCharacteristics 保留真 HAL 的（保证 crypto 操作可用）。
/// 失败时返回 original（透传真 HAL 结果），避免单次证书生成失败导致
/// generateKey 整体失败瘫痪 keystore2。
///
/// 这是 **leaf_hack 模式**（对应 TEESimulator `?`）：leaf 公钥 ≠ keyBlob 公钥，
/// 高级检测会失败。要彻底解决用 [`forge_key_generation`]。
pub fn forge_certificate_chain(
    real_result: KeyCreationResult,
    req: &AttestationRequest,
    keybox_xml: &[u8],
    device: &DeviceInfo,
) -> KeyCreationResult {
    match generate_attested_keypair(
        keybox_xml,
        &req.algorithm,
        &req.challenge,
        &req.package_name,
        device,
    ) {
        Ok(blob) => match parse_certgen_blob(&blob) {
            Ok(certs) => {
                let certificate_chain: Vec<Certificate> = certs
                    .into_iter()
                    .map(|der| Certificate { r#encodedCertificate: der })
                    .collect();
                log::debug!(
                    "fktee-hal: 伪造证书链 {} 张 (alg={} pkg={})",
                    certificate_chain.len(),
                    req.algorithm,
                    req.package_name
                );
                KeyCreationResult {
                    r#keyBlob: real_result.r#keyBlob,
                    r#keyCharacteristics: real_result.r#keyCharacteristics,
                    r#certificateChain: certificate_chain,
                }
            }
            Err(e) => {
                log::warn!("fktee-hal: 解析 certgen 输出失败，透传真 HAL 证书链: {e:#}");
                real_result
            }
        },
        Err(e) => {
            log::warn!("fktee-hal: certgen 生成失败，透传真 HAL 证书链: {e:#}");
            real_result
        }
    }
}

/// 解析 certgen 输出字节流：
/// ```text
/// u32 BE  private_key_len
/// [u8]    private_key_pkcs8
/// u32 BE  cert_count
/// 重复 cert_count 次:
///     u32 BE  cert_len
///     [u8]    cert_der
/// ```
/// 只取证书链（private_key 在 cert-chain swap 路径下不用）。
fn parse_certgen_blob(blob: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut r = Reader::new(blob);
    let priv_len = r.read_u32()? as usize;
    r.skip(priv_len).context("跳过 private_key")?;
    let cert_count = r.read_u32()? as usize;
    let mut certs = Vec::with_capacity(cert_count);
    for i in 0..cert_count {
        let len = r.read_u32()? as usize;
        let der = r.read_bytes(len).context(format!("读 cert #{i}"))?;
        certs.push(der.to_vec());
    }
    Ok(certs)
}

/// 解析 certgen 输出，同时取出 private_key_pkcs8 与证书链。
///
/// generation 模式需要 private_key 来构造软件 keyBlob。
#[allow(dead_code)]
fn parse_certgen_blob_full(blob: &[u8]) -> Result<(Vec<u8>, Vec<Vec<u8>>)> {
    let mut r = Reader::new(blob);
    let priv_len = r.read_u32()? as usize;
    let pkcs8 = r.read_bytes(priv_len).context("读 private_key")?.to_vec();
    let cert_count = r.read_u32()? as usize;
    let mut certs = Vec::with_capacity(cert_count);
    for i in 0..cert_count {
        let len = r.read_u32()? as usize;
        let der = r.read_bytes(len).context(format!("读 cert #{i}"))?;
        certs.push(der.to_vec());
    }
    Ok((pkcs8, certs))
}

/// **generation 模式**（对应 TEESimulator `!` Force Generation Mode）。
///
/// 完全软件生成虚拟密钥：不透传真 HAL，自己生成 keypair + 用 keybox 签出
/// attestation 证书链。keyBlob 是自描述的软件格式（见 [`crate::keystore`]），
/// leaf 证书公钥 == keyBlob 内部密钥公钥，彻底解决公钥不一致问题。
///
/// begin() 时 [`crate::keystore::is_software_blob`] 识别此 keyBlob，返回
/// [`crate::operation::SoftwareOperation`] 用软件密钥签名。
///
/// # 参数
/// - `params`: 调用方请求的 KeyParameter[]（原样作为 keyCharacteristics）。
/// - `req`: 解析出的 attestation 请求（challenge / package / algorithm）。
/// - `keybox_xml`: keybox.xml 字节。
/// - `device`: 设备信息。
///
/// # 失败处理
/// 返回 `Err`，调用方应 fallback 到真 HAL 透传（不伪造），避免 generateKey
/// 整体失败。调用方据此决定是否回退 leaf_hack 或透传。
pub fn forge_key_generation(
    params: &[KeyParameter],
    req: &AttestationRequest,
    keybox_xml: &[u8],
    device: &DeviceInfo,
) -> std::result::Result<KeyCreationResult, GenerationError> {
    let alg_enum = match req.algorithm.as_str() {
        "rsa" => KeyAlgorithm::Rsa,
        "ec" => KeyAlgorithm::Ecdsa,
        other => {
            return Err(GenerationError::UnsupportedAlgorithm(other.into()));
        }
    };

    // 1. 软件生成密钥对 + 用 keybox 签出 attestation 证书链。
    let chain = build_attested_chain_from_xml(keybox_xml, alg_enum, req, device)
        .map_err(GenerationError::CertGen)?;

    // 2. 从 pkcs8 派生 SPKI，构造 KeyPair（用于 keyBlob 打包 + 后续签名）。
    let public_spki = certgen::spki_from_pkcs8(&chain.private_key_pkcs8)
        .map_err(|e| GenerationError::Internal(format!("spki 派生失败: {e:#}")))?;
    let kp = KeyPair::from_pkcs8_and_spki(
        chain.private_key_pkcs8.clone(),
        public_spki,
        alg_enum,
    );

    // 3. 打包软件 keyBlob + 注册到全局表（供 begin 时取出）。
    let key_blob = crate::keystore::pack_keyblob(&kp);
    crate::keystore::register(&key_blob, chain.private_key_pkcs8.clone(), alg_enum);

    // 4. 构造证书链（Certificate 仅含 encodedCertificate DER）。
    let certificate_chain: Vec<Certificate> = chain
        .certificates_der
        .into_iter()
        .map(|der| Certificate {
            r#encodedCertificate: der,
        })
        .collect();

    // 5. keyCharacteristics：用调用方请求的 params 作为授权列表。
    //    securityLevel 设为 KEYSTORE（软件密钥的真实级别），避免 keystore2
    //    把它当硬件密钥做额外约束。
    let characteristics = vec![KeyCharacteristics {
        r#securityLevel: SecurityLevel::r#KEYSTORE,
        r#authorizations: params.to_vec(),
    }];

    log::info!(
        "fktee-hal: generation mode 生成虚拟密钥 (alg={} pkg={} certs={} keyBlob={}B)",
        req.algorithm,
        req.package_name,
        certificate_chain.len(),
        key_blob.len()
    );

    Ok(KeyCreationResult {
        r#keyBlob: key_blob,
        r#keyCharacteristics: characteristics,
        r#certificateChain: certificate_chain,
    })
}

/// generation 模式失败原因。调用方据此决定 fallback 策略。
#[allow(dead_code)]
#[derive(Debug)]
pub enum GenerationError {
    UnsupportedAlgorithm(String),
    CertGen(anyhow::Error),
    Internal(String),
}

/// 从 keybox.xml + attestation 请求构建完整证书链（pkcs8 + certs）。
///
/// 复用 certgen 的 `build_attested_chain`，但直接拿 `CertChainResult` 而非
/// `generate_attested_keypair` 的打包字节流（避免一次序列化/反序列化往返）。
fn build_attested_chain_from_xml(
    keybox_xml: &[u8],
    alg: KeyAlgorithm,
    req: &AttestationRequest,
    device: &DeviceInfo,
) -> Result<certgen::CertChainResult> {
    let xml = std::str::from_utf8(keybox_xml)
        .map_err(|e| anyhow::anyhow!("keybox.xml not utf-8: {e}"))?;
    let keybox = certgen::Keybox::from_xml(xml)?;
    let kb = keybox
        .select(alg)
        .ok_or_else(|| anyhow::anyhow!("keybox 中缺少 {alg:?} 密钥"))?;
    build_attested_chain(kb, alg, &req.challenge, &req.package_name, device)
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn need(&self, n: usize) -> Result<()> {
        anyhow::ensure!(self.pos + n <= self.buf.len(), "需 {n} 字节，仅剩 {}", self.buf.len() - self.pos);
        Ok(())
    }
    fn read_u32(&mut self) -> Result<u32> {
        self.need(4)?;
        let v = u32::from_be_bytes(self.buf[self.pos..self.pos + 4].try_into().unwrap());
        self.pos += 4;
        Ok(v)
    }
    fn read_bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        self.need(n)?;
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    fn skip(&mut self, n: usize) -> Result<()> {
        self.need(n)?;
        self.pos += n;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_certgen_blob_extracts_certs() {
        // 构造一个最小 blob：priv_len=2, priv=[0xaa,0xbb], cert_count=1, cert_len=3, cert=[0x01,0x02,0x03]
        let mut blob = Vec::new();
        blob.extend_from_slice(&2u32.to_be_bytes());
        blob.extend_from_slice(&[0xaa, 0xbb]);
        blob.extend_from_slice(&1u32.to_be_bytes());
        blob.extend_from_slice(&3u32.to_be_bytes());
        blob.extend_from_slice(&[0x01, 0x02, 0x03]);
        let certs = parse_certgen_blob(&blob).unwrap();
        assert_eq!(certs, vec![vec![0x01, 0x02, 0x03]]);
    }

    #[test]
    fn parse_certgen_blob_rejects_truncated() {
        let blob = [0u8; 2]; // 不足 4 字节读 u32
        assert!(parse_certgen_blob(&blob).is_err());
    }
}

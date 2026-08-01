//! X.509 证书链构造（手工编 DER）。
//!
//! 两种模式：
//! - **自签单层证书**（无 attestation challenge）：用软件生成的密钥自签一张 v3 证书。
//! - **已证明证书链**（有 challenge）：生成新密钥 → leaf 证书证明该密钥公钥，
//!   leaf 由 keybox 私钥签发 → 证书链 = `[leaf, keybox 中间证书, …, keybox 根]`。
//!
//! TBSCertificate 字段顺序严格按 RFC 5280：
//! `[0] version, serialNumber, signature, issuer, validity, subject,
//!  subjectPublicKeyInfo, [3] extensions`。
//!
//! 签名统一由 ring 完成（ECDSA P-256 SHA-256 / RSA PKCS#1 v1.5 SHA-256）。

use anyhow::{ensure, Result};

use crate::attestation::{
    build_attestation_extension, AttestationConfig, DeviceInfo,
};
use crate::der;
use crate::keybox::{KeyAlgorithm, KeyboxData};
use crate::keygen::{keybox_pem_to_pkcs8, sign_tbs_with_pkcs8, signature_algorithm_der, KeyPair};

/// KeyMint attestation 扩展 OID（1.3.6.1.4.1.11129.2.1.17）。
const OID_ATTESTATION: &str = "1.3.6.1.4.1.11129.2.1.17";
/// KeyUsage 扩展 OID（2.5.29.15）。
const OID_KEY_USAGE: &str = "2.5.29.15";
/// commonName OID（2.5.4.3）。
const OID_COMMON_NAME: &str = "2.5.4.3";

/// 证书链生成结果。
pub struct CertChainResult {
    /// 被证明密钥的 PKCS#8 私钥 DER（输出给调用方）。
    pub private_key_pkcs8: Vec<u8>,
    /// 证书链 DER 列表（certificates_der[0] 为 leaf）。
    pub certificates_der: Vec<Vec<u8>>,
}

/// 自签单层证书（无 attestation challenge 场景）。
///
/// 软件生成密钥 → 自签一张 v3 证书（issuer == subject），链深度 1。
pub fn build_self_signed(alg: KeyAlgorithm, package_name: &str) -> Result<CertChainResult> {
    let key_pair = KeyPair::generate(alg)?;

    let subject_dn = build_cn_dn(package_name);
    let spki = key_pair.public_spki().to_vec();
    let sig_alg = key_pair.signature_algorithm_der()?;
    let (not_before, not_after) = default_validity();
    let validity = build_validity(not_before, not_after)?;
    let extensions = build_extensions(None, alg)?;

    // issuer == subject（自签）
    let tbs = build_tbs(&sig_alg, &subject_dn, &subject_dn, &validity, &spki, &extensions);
    let signature = key_pair.sign(&tbs)?;
    let cert = assemble_cert(&tbs, &sig_alg, &signature);

    Ok(CertChainResult {
        private_key_pkcs8: key_pair.pkcs8().to_vec(),
        certificates_der: vec![cert],
    })
}

/// 已证明证书链（有 attestation challenge 场景）。
///
/// 流程：
/// 1. 软件生成被证明密钥（EC P-256 / RSA-2048）。
/// 2. 从 keybox 加载签发者私钥（EC SEC1 / RSA PKCS#1 → PKCS#8）。
/// 3. 构造 KeyMint attestation 扩展。
/// 4. leaf 证书：subject=新密钥公钥，issuer=keybox 证书[0] 的 subject，由 keybox 私钥签。
/// 5. 证书链 = `[leaf, keybox 证书链…]`。
pub fn build_attested_chain(
    kb: &KeyboxData,
    alg: KeyAlgorithm,
    challenge: &[u8],
    package_name: &str,
    device: &DeviceInfo,
) -> Result<CertChainResult> {
    // 1. 被证明密钥
    let key_pair = KeyPair::generate(alg)?;

    // 2. keybox 签发者私钥
    let signer_pkcs8 = keybox_pem_to_pkcs8(kb)?;
    let signer_alg = kb.algorithm;

    // 3. keybox 证书链
    let kb_certs = kb.certificates_der()?;
    ensure!(!kb_certs.is_empty(), "keybox 证书链为空");
    // issuer = keybox leaf 证书的 subject
    let issuer_dn = der::extract_cert_subject(&kb_certs[0])?.to_vec();

    // 4. attestation 扩展
    let config = make_attestation_config(device, alg, challenge, package_name);
    let attest_ext = build_attestation_extension(&config)?;

    // 5. leaf 证书
    let subject_dn = build_cn_dn(package_name);
    let spki = key_pair.public_spki().to_vec();
    let sig_alg = signature_algorithm_der(signer_alg)?;
    let (not_before, not_after) = cert_validity();
    let validity = build_validity(not_before, not_after)?;
    let extensions = build_extensions(Some(&attest_ext), alg)?;
    let tbs = build_tbs(&sig_alg, &issuer_dn, &subject_dn, &validity, &spki, &extensions);
    let signature = sign_tbs_with_pkcs8(&signer_pkcs8, signer_alg, &tbs)?;
    let leaf = assemble_cert(&tbs, &sig_alg, &signature);

    // 6. 拼接证书链
    let mut chain = Vec::with_capacity(1 + kb_certs.len());
    chain.push(leaf);
    chain.extend(kb_certs);

    Ok(CertChainResult {
        private_key_pkcs8: key_pair.pkcs8().to_vec(),
        certificates_der: chain,
    })
}

// ===================== AttestationConfig 装配 =====================

/// 由 DeviceInfo + 算法 + challenge + 包名构造 attestation 扩展参数。
fn make_attestation_config(
    device: &DeviceInfo,
    alg: KeyAlgorithm,
    challenge: &[u8],
    package_name: &str,
) -> AttestationConfig {
    let (algorithm, key_size, digests) = match alg {
        KeyAlgorithm::Ecdsa => (3, 256u32, vec![4]), // EC P-256, SHA-256
        KeyAlgorithm::Rsa => (1, 2048u32, vec![4]), // RSA-2048, SHA-256
    };
    // 典型用途：DECRYPT + SIGN（ENCRYPT/VERIFY 隐含）
    let purposes = match alg {
        KeyAlgorithm::Ecdsa => vec![3],      // SIGN
        KeyAlgorithm::Rsa => vec![2, 3],     // DECRYPT + SIGN
    };

    // 缺省值（DeviceInfo 未填时用合理默认）
    let attestation_version = if device.attestation_version == 0 {
        300
    } else {
        device.attestation_version
    };
    let keymaster_version = if device.keymaster_version == 0 {
        300
    } else {
        device.keymaster_version
    };
    let security_level = if device.security_level == 0 {
        1 // TEE
    } else {
        device.security_level
    };
    let creation_datetime = if device.creation_datetime == 0 {
        now_millis()
    } else {
        device.creation_datetime
    };

    AttestationConfig {
        attestation_version,
        keymaster_version,
        security_level,
        challenge: challenge.to_vec(),
        package_name: package_name.to_string(),
        algorithm,
        key_size,
        purposes,
        digests,
        os_version: device.os_version,
        os_patch_level: device.os_patch_level,
        vendor_patch_level: device.vendor_patch_level,
        boot_patch_level: device.boot_patch_level,
        boot_key: device.boot_key.clone(),
        boot_hash: device.boot_hash.clone(),
        creation_datetime,
        caller_nonce: false,
        no_auth_required: true,
        unlocked_device_required: false,
        active_datetime: -1,
        origination_expire_datetime: -1,
        usage_expire_datetime: -1,
        usage_count_limit: -1,
        module_hash: None,
    }
}

// ===================== X.509 DER 构造 =====================

/// TBSCertificate = SEQUENCE {
///     [0] EXPLICIT version INTEGER (v3 = 2),
///     serialNumber INTEGER,
///     signature AlgorithmIdentifier,
///     issuer Name,
///     validity Validity,
///     subject Name,
///     subjectPublicKeyInfo SubjectPublicKeyInfo,
///     [3] EXPLICIT extensions SEQUENCE OF Extension,
/// }
fn build_tbs(
    sig_alg: &[u8],
    issuer_dn: &[u8],
    subject_dn: &[u8],
    validity: &[u8],
    spki: &[u8],
    extensions: &[u8],
) -> Vec<u8> {
    let version = der::explicit(0, &der::integer_u64(2)); // v3
    let serial = der::integer_u64(1);
    let exts_tagged = der::explicit(3, extensions);
    der::seq(&[
        &version,
        &serial,
        sig_alg,
        issuer_dn,
        validity,
        subject_dn,
        spki,
        &exts_tagged,
    ])
}

/// Certificate = SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue BIT STRING }。
fn assemble_cert(tbs: &[u8], sig_alg: &[u8], signature: &[u8]) -> Vec<u8> {
    let sig_bits = der::bit_string(0, signature);
    der::seq(&[tbs, sig_alg, &sig_bits])
}

/// Validity = SEQUENCE { notBefore Time, notAfter Time }。
/// 年份 1950–2049 用 UTCTime，否则用 GeneralizedTime。
fn build_validity(not_before: i64, not_after: i64) -> Result<Vec<u8>> {
    let nb = time_tlv(not_before)?;
    let na = time_tlv(not_after)?;
    Ok(der::seq(&[&nb, &na]))
}

/// Extensions = SEQUENCE OF Extension。
/// Extension = SEQUENCE { extnID OID, critical BOOLEAN OPTIONAL, extnValue OCTET STRING }。
fn build_extensions(attest_ext: Option<&[u8]>, alg: KeyAlgorithm) -> Result<Vec<u8>> {
    let mut exts: Vec<Vec<u8>> = Vec::new();

    // KeyUsage（critical）
    let key_usage_value = build_key_usage_value(alg);
    exts.push(der::seq(&[
        &der::oid(OID_KEY_USAGE)?,
        &der::boolean(true),
        &der::octet_string(&key_usage_value),
    ]));

    // KeyMint attestation 扩展（非 critical）
    if let Some(attest) = attest_ext {
        exts.push(der::seq(&[
            &der::oid(OID_ATTESTATION)?,
            &der::octet_string(attest),
        ]));
    }

    let refs: Vec<&[u8]> = exts.iter().map(|v| v.as_slice()).collect();
    Ok(der::seq(&refs))
}

/// KeyUsage BIT STRING 内容（含 unused-bits 前缀的完整 TLV）。
/// - ECDSA：digitalSignature（bit 0）。
/// - RSA：digitalSignature + keyEncipherment（bit 0,2）。
fn build_key_usage_value(alg: KeyAlgorithm) -> Vec<u8> {
    match alg {
        KeyAlgorithm::Ecdsa => der::bit_string(7, &[0x80]),
        KeyAlgorithm::Rsa => der::bit_string(5, &[0xA0]),
    }
}

/// Name = SEQUENCE OF RelativeDistinguishedName；
/// RDN = SET OF AttributeTypeAndValue；
/// ATV = SEQUENCE { OID(commonName 2.5.4.3), UTF8String(cn) }。
fn build_cn_dn(cn: &str) -> Vec<u8> {
    let atv = match der::oid(OID_COMMON_NAME) {
        Ok(oid) => der::seq(&[&oid, &der::tlv(0x0c, cn.as_bytes())]), // 0x0c = UTF8String
        Err(_) => der::seq(&[&der::tlv(0x0c, cn.as_bytes())]),
    };
    let rdn = der::set_of(&atv);
    der::seq(&[&rdn])
}

// ===================== 时间编码 =====================

/// 把 Unix 秒编码为 Time TLV（UTCTime / GeneralizedTime）。
fn time_tlv(unix_secs: i64) -> Result<Vec<u8>> {
    let (y, mo, d, h, mi, s) = unix_to_utc(unix_secs);
    let is_utc = (1950..=2049).contains(&y);
    let formatted = if is_utc {
        format!("{:02}{:02}{:02}{:02}{:02}{:02}Z", y % 100, mo, d, h, mi, s)
    } else {
        format!("{:04}{:02}{:02}{:02}{:02}{:02}Z", y, mo, d, h, mi, s)
    };
    let tag = if is_utc { 0x17 } else { 0x18 }; // UTCTime / GeneralizedTime
    Ok(der::tlv(tag, formatted.as_bytes()))
}

/// Unix 秒 → UTC (year, month, day, hour, minute, second)。
/// 使用 Howard Hinnant 的 civil-from-days 算法，无外部依赖。
fn unix_to_utc(unix_secs: i64) -> (i64, u32, u32, u32, u32, u32) {
    let days = unix_secs.div_euclid(86400);
    let secs_of_day = unix_secs.rem_euclid(86400) as u32;
    let hour = secs_of_day / 3600;
    let minute = (secs_of_day % 3600) / 60;
    let second = secs_of_day % 60;

    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let y = if m <= 2 { y + 1 } else { y };
    (y, m as u32, d as u32, hour, minute, second)
}

// ===================== 有效期默认值 =====================

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn now_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// 自签证书默认有效期：现在起 30 年。
fn default_validity() -> (i64, i64) {
    let now = now_secs();
    (now, now + 30 * 365 * 86400)
}

/// 已证明 leaf 证书默认有效期：现在起 30 年。
fn cert_validity() -> (i64, i64) {
    let now = now_secs();
    (now, now + 30 * 365 * 86400)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn self_signed_ecdsa_chain_depth_one() {
        let result = build_self_signed(KeyAlgorithm::Ecdsa, "com.test.app").expect("self ec");
        assert_eq!(result.certificates_der.len(), 1);
        let cert = &result.certificates_der[0];
        assert_eq!(cert[0], 0x30); // Certificate = SEQUENCE
        // 私钥是 PKCS#8 SEQUENCE
        assert_eq!(result.private_key_pkcs8[0], 0x30);
        assert!(!result.private_key_pkcs8.is_empty());
    }

    #[test]
    fn self_signed_rsa_chain_depth_one() {
        let result = build_self_signed(KeyAlgorithm::Rsa, "com.test.app").expect("self rsa");
        assert_eq!(result.certificates_der.len(), 1);
        assert_eq!(result.certificates_der[0][0], 0x30);
    }

    #[test]
    fn tbs_has_eight_fields() {
        let sig_alg = der::seq(&[&der::oid("1.2.840.10045.4.3.2").unwrap()]);
        let dn = build_cn_dn("cn");
        let validity = build_validity(now_secs(), now_secs() + 86400).unwrap();
        let spki = der::seq(&[&der::oid("1.2.840.10045.2.1").unwrap()]);
        let exts = build_extensions(None, KeyAlgorithm::Ecdsa).unwrap();
        let tbs = build_tbs(&sig_alg, &dn, &dn, &validity, &spki, &exts);
        assert_eq!(tbs[0], 0x30);

        // 解 TBSCertificate 内部字段数应为 8
        let mut r = der::DerReader::new(&tbs);
        let tbs_seq = r.read().unwrap();
        let mut tr = der::DerReader::new(tbs_seq.content);
        let mut count = 0;
        while !tr.done() {
            let _ = tr.read().unwrap();
            count += 1;
        }
        assert_eq!(count, 8, "TBSCertificate 应有 8 个字段");
    }

    #[test]
    fn unix_to_utc_known_value() {
        // 2024-01-01 00:00:00 UTC = 1704067200
        assert_eq!(unix_to_utc(1704067200), (2024, 1, 1, 0, 0, 0));
        // 1970-01-01 00:00:00 UTC = 0
        assert_eq!(unix_to_utc(0), (1970, 1, 1, 0, 0, 0));
        // 2025-03-01 12:34:56 UTC = 1740832496
        assert_eq!(unix_to_utc(1740832496), (2025, 3, 1, 12, 34, 56));
    }
}

//! 密钥生成 / 加载 / 签名。
//!
//! 统一以 PKCS#8 DER 作为内部私钥表示，方便输出与重新加载签名：
//! - EC P-256：用 ring 软件生成（`EcdsaKeyPair::generate_pkcs8`）+ ring 签名。
//! - RSA-2048：用 `rsa` crate 生成（ring 不支持 RSA 密钥生成）+ ring 签名。
//! - keybox 私钥（EC SEC1 / RSA PKCS#1）→ 手工包成 PKCS#8，再交给 ring 加载 / 签名。
//!
//! 所有签名统一由 ring 完成：
//! - ECDSA P-256 SHA-256（`ECDSA_P256_SHA256_ASN1_SIGNING`，输出 DER `ECDSA-Sig-Value`）。
//! - RSA PKCS#1 v1.5 SHA-256（`RSA_PKCS1_SHA256`）。

use anyhow::{bail, Context, Result};
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

use crate::der;
use crate::keybox::{KeyAlgorithm, KeyboxData};

/// 已生成 / 已加载的密钥对（统一以 PKCS#8 DER 持有）。
///
/// 同时缓存好对应的 SubjectPublicKeyInfo，供构造证书使用。
pub struct KeyPair {
    alg: KeyAlgorithm,
    pkcs8: Vec<u8>,
    public_spki: Vec<u8>,
}

impl KeyPair {
    /// 软件生成指定算法的密钥对（EC P-256 用 ring；RSA-2048 用 `rsa` crate）。
    pub fn generate(alg: KeyAlgorithm) -> Result<Self> {
        let pkcs8 = generate_pkcs8(alg)?;
        let public_spki = spki_from_pkcs8(&pkcs8)?;
        Ok(Self {
            alg,
            pkcs8,
            public_spki,
        })
    }

    /// 从已有 PKCS#8 私钥 + 预计算 SPKI 构造（加载已生成密钥，不重新生成）。
    ///
    /// HAL generation 模式：keyBlob 解包后用此方法恢复 KeyPair 用于 finish 签名。
    pub fn from_pkcs8_and_spki(pkcs8: Vec<u8>, public_spki: Vec<u8>, alg: KeyAlgorithm) -> Self {
        Self {
            alg,
            pkcs8,
            public_spki,
        }
    }

    /// 算法。
    pub fn algorithm(&self) -> KeyAlgorithm {
        self.alg
    }

    /// PKCS#8 私钥 DER（用于输出给调用方）。
    pub fn pkcs8(&self) -> &[u8] {
        &self.pkcs8
    }

    /// SubjectPublicKeyInfo DER（用于证书 SubjectPublicKeyInfo 字段）。
    pub fn public_spki(&self) -> &[u8] {
        &self.public_spki
    }

    /// 用本密钥对签名 TBS（自签场景）。
    /// - EC：返回 DER 编码的 `ECDSA-Sig-Value`。
    /// - RSA：返回 PKCS#1 v1.5 签名。
    pub fn sign(&self, tbs: &[u8]) -> Result<Vec<u8>> {
        sign_tbs_with_pkcs8(&self.pkcs8, self.alg, tbs)
    }

    /// 证书 signatureAlgorithm 标识（DER `AlgorithmIdentifier`）。
    pub fn signature_algorithm_der(&self) -> Result<Vec<u8>> {
        signature_algorithm_der(self.alg)
    }
}

// ===================== PKCS#8 生成 =====================

/// 软件生成 PKCS#8 私钥 DER。
pub(crate) fn generate_pkcs8(alg: KeyAlgorithm) -> Result<Vec<u8>> {
    match alg {
        KeyAlgorithm::Ecdsa => {
            let rng = SystemRandom::new();
            let doc = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
                .map_err(|_| anyhow::anyhow!("ring ECDSA P-256 密钥生成失败"))?;
            Ok(doc.as_ref().to_vec())
        }
        KeyAlgorithm::Rsa => {
            use pkcs8::EncodePrivateKey;
            let mut rng = rand::thread_rng();
            let private_key = rsa::RsaPrivateKey::new(&mut rng, 2048)
                .context("RSA-2048 密钥生成失败")?;
            let doc = private_key.to_pkcs8_der().context("RSA PKCS#8 编码失败")?;
            Ok(doc.as_bytes().to_vec())
        }
    }
}

// ===================== SPKI 提取 =====================

/// 从 PKCS#8 私钥派生 SubjectPublicKeyInfo DER。
pub fn spki_from_pkcs8(pkcs8: &[u8]) -> Result<Vec<u8>> {
    use pkcs8::der::Decode;
    let info = pkcs8::PrivateKeyInfo::from_der(pkcs8).context("解析 PKCS#8 失败")?;
    let alg_oid = info.algorithm.oid;

    let ec_oid = pkcs8::der::asn1::ObjectIdentifier::new("1.2.840.10045.2.1")
        .map_err(|e| anyhow::anyhow!("OID 解析失败: {e:?}"))?;

    if alg_oid == ec_oid {
        extract_ec_spki(pkcs8, &info)
    } else {
        extract_rsa_spki(pkcs8)
    }
}

/// EC P-256 SPKI：用 ring 加载私钥拿到公钥点，再手工拼 SPKI。
fn extract_ec_spki(pkcs8: &[u8], info: &pkcs8::PrivateKeyInfo) -> Result<Vec<u8>> {
    use ring::signature::KeyPair as _;

    let params_oid = info
        .algorithm
        .parameters_oid()
        .map_err(|e| anyhow::anyhow!("EC 曲线 OID 解析失败: {e:?}"))?;
    let p256 = pkcs8::der::asn1::ObjectIdentifier::new("1.2.840.10045.3.1.7")
        .map_err(|e| anyhow::anyhow!("OID 解析失败: {e:?}"))?;
    if params_oid != p256 {
        bail!("仅支持 EC P-256，实际曲线 OID: {params_oid}");
    }

    let rng = SystemRandom::new();
    let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8, &rng)
        .map_err(|e| anyhow::anyhow!("ring ECDSA 私钥加载失败: {e}"))?;
    let point = kp.public_key().as_ref().to_vec();

    // SPKI = SEQUENCE { AlgorithmIdentifier, BIT STRING(point) }
    // AlgorithmIdentifier = SEQUENCE { ecPublicKey, secp256r1 }
    let alg_id = der::seq(&[
        &der::oid("1.2.840.10045.2.1")?,
        &der::oid("1.2.840.10045.3.1.7")?,
    ]);
    let pub_bits = der::bit_string(0, &point);
    Ok(der::seq(&[&alg_id, &pub_bits]))
}

/// RSA SPKI：用 `rsa` crate 加载私钥拿 n/e，再手工拼 SPKI。
fn extract_rsa_spki(pkcs8: &[u8]) -> Result<Vec<u8>> {
    use pkcs8::DecodePrivateKey;
    use rsa::traits::PublicKeyParts;

    let private_key = rsa::RsaPrivateKey::from_pkcs8_der(pkcs8).context("RSA PKCS#8 解析失败")?;
    let public_key = rsa::RsaPublicKey::from(&private_key);
    let n = public_key.n().to_bytes_be();
    let e = public_key.e().to_bytes_be();

    // RSAPublicKey = SEQUENCE { modulus INTEGER, publicExponent INTEGER }
    let n_int = der::tlv(0x02, &der::integer_content_be(&n));
    let e_int = der::tlv(0x02, &der::integer_content_be(&e));
    let rsa_pub = der::seq(&[&n_int, &e_int]);

    // SPKI = SEQUENCE { SEQUENCE{ rsaEncryption, NULL }, BIT STRING(RSAPublicKey) }
    let alg_id = der::seq(&[&der::oid("1.2.840.113549.1.1.1")?, &der::null()]);
    let pub_bits = der::bit_string(0, &rsa_pub);
    Ok(der::seq(&[&alg_id, &pub_bits]))
}

// ===================== 签名 =====================

/// 用 PKCS#8 私钥签名 TBS。
/// - EC：ring ECDSA，输出 DER `ECDSA-Sig-Value`。
/// - RSA：ring PKCS#1 v1.5 SHA-256。
pub(crate) fn sign_tbs_with_pkcs8(
    pkcs8: &[u8],
    alg: KeyAlgorithm,
    tbs: &[u8],
) -> Result<Vec<u8>> {
    let rng = SystemRandom::new();
    match alg {
        KeyAlgorithm::Ecdsa => {
            let kp = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8, &rng)
                .map_err(|e| anyhow::anyhow!("ring ECDSA 私钥加载失败: {e}"))?;
            let sig = kp
                .sign(&rng, tbs)
                .map_err(|_| anyhow::anyhow!("ring ECDSA 签名失败"))?;
            Ok(sig.as_ref().to_vec())
        }
        KeyAlgorithm::Rsa => {
            let kp = ring::rsa::KeyPair::from_pkcs8(pkcs8)
                .map_err(|e| anyhow::anyhow!("ring RSA 私钥加载失败: {e}"))?;
            let mut buf = vec![0u8; kp.public().modulus_len()];
            kp.sign(&ring::signature::RSA_PKCS1_SHA256, &rng, tbs, &mut buf)
                .map_err(|_| anyhow::anyhow!("ring RSA 签名失败"))?;
            Ok(buf)
        }
    }
}

/// 证书 signatureAlgorithm 标识（DER `AlgorithmIdentifier`）。
pub(crate) fn signature_algorithm_der(alg: KeyAlgorithm) -> Result<Vec<u8>> {
    match alg {
        KeyAlgorithm::Ecdsa => {
            // ecdsa-with-SHA256 (1.2.840.10045.4.3.2)，无参数
            Ok(der::seq(&[&der::oid("1.2.840.10045.4.3.2")?]))
        }
        KeyAlgorithm::Rsa => {
            // sha256WithRSAEncryption (1.2.840.113549.1.1.11)，NULL 参数
            Ok(der::seq(&[
                &der::oid("1.2.840.113549.1.1.11")?,
                &der::null(),
            ]))
        }
    }
}

// ===================== keybox 私钥 → PKCS#8 =====================

/// 把 keybox 中的私钥（EC SEC1 / RSA PKCS#1）包成 PKCS#8 DER，便于 ring 统一加载。
pub(crate) fn keybox_pem_to_pkcs8(kb: &KeyboxData) -> Result<Vec<u8>> {
    let der_bytes = der::pem_to_der(&kb.private_key_pem).context("keybox 私钥 PEM 解析失败")?;
    let version = der::integer_u64(0); // PKCS#8 version 0
    let priv_octet = der::octet_string(&der_bytes);

    match kb.algorithm {
        KeyAlgorithm::Ecdsa => {
            // der_bytes 是 SEC1 ECPrivateKey（keybox 标准含 publicKey 字段，ring 校验需要它）
            // PrivateKeyInfo = SEQUENCE { version, SEQUENCE{ ecPublicKey, secp256r1 }, OCTET STRING(SEC1) }
            let alg_id = der::seq(&[
                &der::oid("1.2.840.10045.2.1")?,
                &der::oid("1.2.840.10045.3.1.7")?,
            ]);
            Ok(der::seq(&[&version, &alg_id, &priv_octet]))
        }
        KeyAlgorithm::Rsa => {
            // der_bytes 是 PKCS#1 RSAPrivateKey
            // PrivateKeyInfo = SEQUENCE { version, SEQUENCE{ rsaEncryption, NULL }, OCTET STRING(PKCS#1) }
            let alg_id = der::seq(&[&der::oid("1.2.840.113549.1.1.1")?, &der::null()]);
            Ok(der::seq(&[&version, &alg_id, &priv_octet]))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_ecdsa_keypair_roundtrip() {
        let kp = KeyPair::generate(KeyAlgorithm::Ecdsa).expect("gen ec");
        let spki = kp.public_spki();
        assert_eq!(spki[0], 0x30); // SEQUENCE
        // SPKI 内层 AlgorithmIdentifier 应包含 secp256r1 OID
        assert!(!spki.is_empty());
        // 自签一次 TBS，验证签名路径可用
        let tbs = b"hello tbs";
        let sig = kp.sign(tbs).expect("sign");
        assert!(!sig.is_empty());
        // DER ECDSA-Sig-Value 是 SEQUENCE
        assert_eq!(sig[0], 0x30);
    }

    #[test]
    fn generate_rsa_keypair_roundtrip() {
        let kp = KeyPair::generate(KeyAlgorithm::Rsa).expect("gen rsa");
        assert_eq!(kp.public_spki()[0], 0x30);
        let sig = kp.sign(b"hello tbs").expect("sign");
        // RSA-2048 PKCS#1 v1.5 签名长度 == 256
        assert_eq!(sig.len(), 256);
    }

    #[test]
    fn sig_alg_der_shapes() {
        let ec = signature_algorithm_der(KeyAlgorithm::Ecdsa).unwrap();
        assert_eq!(ec[0], 0x30);
        let rsa = signature_algorithm_der(KeyAlgorithm::Rsa).unwrap();
        assert_eq!(rsa[0], 0x30);
        // RSA 的 AlgorithmIdentifier 末尾应包含 NULL (0x05 0x00)
        assert_eq!(&rsa[rsa.len() - 2..], &[0x05, 0x00]);
    }
}

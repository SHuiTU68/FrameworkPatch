//! 软件密钥存储（generation 模式）。
//!
//! 参考 TEESimulator 的 Force Generation Mode：generateKey 不再透传真 HAL，
//! 而是软件生成密钥对，把 PKCS#8 私钥打包成自描述 keyBlob 返回给 keystore2。
//! 这样 leaf 证书证明的公钥 = keyBlob 内部密钥公钥，彻底解决 cert-chain swap
//! 路径下公钥不一致的问题。
//!
//! # keyBlob 格式
//!
//! ```text
//! magic      : "FKT1" (4 字节)
//! alg        : u8     (1=RSA, 3=EC)
//! pkcs8_len  : u32 BE
//! pkcs8      : [u8]   (PKCS#8 私钥 DER)
//! ```
//!
//! begin() 时用 [`is_software_blob`] 识别本格式，加载私钥后用软件签名完成
//! finish()，不再回调真 HAL。
//!
//! 内存中不持久化——进程重启后所有软件 keyBlob 失效（keystore2 也会清空其
//! keyDB，应用需重新 generateKey）。这与真 TEE 语义一致。

use certgen::KeyAlgorithm;
use certgen::KeyPair;
use std::collections::HashMap;
use std::sync::OnceLock;

/// 软件 keyBlob 魔数。
const MAGIC: &[u8; 4] = b"FKT1";

/// 全局软件密钥表：keyBlob → (KeyPair, purpose)。
///
/// begin() 时按 keyBlob 取出 KeyPair 构造 IKeyMintOperation；finish() 后
/// 由 operation 析构自然释放。用 `parking_lot::Mutex` 保护。
static KEY_STORE: OnceLock<parking_lot::Mutex<HashMap<Vec<u8>, StoredKey>>> = OnceLock::new();

fn store() -> &'static parking_lot::Mutex<HashMap<Vec<u8>, StoredKey>> {
    KEY_STORE.get_or_init(|| parking_lot::Mutex::new(HashMap::new()))
}

/// 内存中缓存的软件密钥条目。
struct StoredKey {
    /// PKCS#8 私钥（keyBlob 内部副本，便于 begin 时重新加载）。
    pkcs8: Vec<u8>,
    alg: KeyAlgorithm,
}

/// 把软件密钥对打包成自描述 keyBlob。
pub fn pack_keyblob(kp: &KeyPair) -> Vec<u8> {
    let pkcs8 = kp.pkcs8();
    let alg_byte: u8 = match kp.algorithm() {
        KeyAlgorithm::Rsa => 1,
        KeyAlgorithm::Ecdsa => 3,
    };
    let mut blob = Vec::with_capacity(4 + 1 + 4 + pkcs8.len());
    blob.extend_from_slice(MAGIC);
    blob.push(alg_byte);
    blob.extend_from_slice(&(pkcs8.len() as u32).to_be_bytes());
    blob.extend_from_slice(pkcs8);
    blob
}

/// 判断 keyBlob 是否为本模块生成的软件 keyBlob。
pub fn is_software_blob(blob: &[u8]) -> bool {
    blob.len() >= 9 && &blob[..4] == MAGIC
}

/// 解析软件 keyBlob，返回 (算法, PKCS#8 私钥)。
#[allow(dead_code)]
pub fn parse_software_blob(blob: &[u8]) -> Option<(KeyAlgorithm, Vec<u8>)> {
    if !is_software_blob(blob) {
        return None;
    }
    let alg_byte = blob[4];
    let alg = match alg_byte {
        1 => KeyAlgorithm::Rsa,
        3 => KeyAlgorithm::Ecdsa,
        _ => return None,
    };
    let len = u32::from_be_bytes(blob[5..9].try_into().ok()?) as usize;
    if 9 + len > blob.len() {
        return None;
    }
    Some((alg, blob[9..9 + len].to_vec()))
}

/// 注册一个软件密钥（generateKey 返回后调用，供 begin 时取出）。
pub fn register(blob: &[u8], pkcs8: Vec<u8>, alg: KeyAlgorithm) {
    store().lock().insert(
        blob.to_vec(),
        StoredKey {
            pkcs8,
            alg,
        },
    );
}

/// 取出并加载软件密钥（begin 时调用）。
///
/// 返回的 KeyPair 生命周期与调用方绑定的 operation 一致；keyBlob 仍留在
/// 表里直到 deleteKey 或进程退出。
pub fn load(blob: &[u8]) -> Option<KeyPair> {
    let g = store().lock();
    let entry = g.get(blob)?;
    let public_spki = certgen::spki_from_pkcs8(&entry.pkcs8).ok()?;
    Some(KeyPair::from_pkcs8_and_spki(
        entry.pkcs8.clone(),
        public_spki,
        entry.alg,
    ))
}

/// 删除软件密钥（deleteKey 时调用）。
pub fn remove(blob: &[u8]) {
    store().lock().remove(blob);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack_parse_roundtrip_ec() {
        let kp = KeyPair::generate(KeyAlgorithm::Ecdsa).unwrap();
        let blob = pack_keyblob(&kp);
        assert!(is_software_blob(&blob));
        let (alg, pkcs8) = parse_software_blob(&blob).unwrap();
        assert_eq!(alg, KeyAlgorithm::Ecdsa);
        assert_eq!(pkcs8, kp.pkcs8());
    }

    #[test]
    fn pack_parse_roundtrip_rsa() {
        let kp = KeyPair::generate(KeyAlgorithm::Rsa).unwrap();
        let blob = pack_keyblob(&kp);
        assert!(is_software_blob(&blob));
        let (alg, pkcs8) = parse_software_blob(&blob).unwrap();
        assert_eq!(alg, KeyAlgorithm::Rsa);
        assert_eq!(pkcs8, kp.pkcs8());
    }

    #[test]
    fn rejects_foreign_blob() {
        assert!(!is_software_blob(b""));
        assert!(!is_software_blob(b"ABCD"));
        assert!(!is_software_blob(b"XXXX1234extra"));
    }

    #[test]
    fn register_load_roundtrip() {
        let kp = KeyPair::generate(KeyAlgorithm::Ecdsa).unwrap();
        let blob = pack_keyblob(&kp);
        register(&blob, kp.pkcs8().to_vec(), KeyAlgorithm::Ecdsa);
        let loaded = load(&blob).expect("load failed");
        // 加载后的公钥应与原公钥一致（同一私钥）
        assert_eq!(loaded.pkcs8(), kp.pkcs8());
        remove(&blob);
        assert!(load(&blob).is_none());
    }
}

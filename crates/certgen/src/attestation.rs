//! KeyMint / Keymaster attestation 扩展构造（OID 1.3.6.1.4.1.11129.2.1.17）。
//!
//! 扩展值（OCTET STRING 内容）是 `KeyDescription` SEQUENCE：
//! ```text
//! KeyDescription ::= SEQUENCE {
//!     attestationVersion         INTEGER,
//!     attestationSecurityLevel   ENUMERATED,
//!     keymasterVersion           INTEGER,
//!     keymasterSecurityLevel     ENUMERATED,
//!     attestationChallenge       OCTET STRING,
//!     uniqueId                   OCTET STRING,
//!     softwareEnforced           AuthorizationList,
//!     teeEnforced                AuthorizationList,
//! }
//! ```
//!
//! `AuthorizationList` 的各字段使用上下文 EXPLICIT 标签，标签号即 KeyMint Tag。
//! 部分字段按 `attestationVersion` / Android 版本门控（详见各字段注释）。
//!
//! 所有 DER 均通过 [`crate::der`] 模块手工编码，以保证字段顺序与真机一致。

use anyhow::Result;

use crate::der;

/// 设备 / 版本信息（从 JNI 传入的字节流解包）。
///
/// 打包格式（全部大端，按顺序）：
/// - `i32` android_version
/// - `i32` os_version（`-1` 表示不报告）
/// - `i32` os_patch_level（`-1` 表示不报告）
/// - `i32` vendor_patch_level（`-1` 表示不报告）
/// - `i32` boot_patch_level（`-1` 表示不报告）
/// - `i32` keymaster_version
/// - `i32` attestation_version
/// - `i32` security_level（0=Software, 1=TEE, 2=StrongBox）
/// - `i64` creation_datetime（毫秒；`0` 表示使用当前时间）
/// - `u32` boot_key_len + `boot_key` 字节
/// - `u32` boot_hash_len + `boot_hash` 字节
#[derive(Debug, Clone, Default)]
pub struct DeviceInfo {
    pub android_version: i32,
    pub os_version: i32,
    pub os_patch_level: i32,
    pub vendor_patch_level: i32,
    pub boot_patch_level: i32,
    pub keymaster_version: i32,
    pub attestation_version: i32,
    pub security_level: i32,
    /// 密钥创建时间（Unix 毫秒）。
    pub creation_datetime: i64,
    pub boot_key: Vec<u8>,
    pub boot_hash: Vec<u8>,
}

impl DeviceInfo {
    /// 从字节流解包（格式见结构体文档）。
    pub fn unpack(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes);
        let android_version = r.read_i32()?;
        let os_version = r.read_i32()?;
        let os_patch_level = r.read_i32()?;
        let vendor_patch_level = r.read_i32()?;
        let boot_patch_level = r.read_i32()?;
        let keymaster_version = r.read_i32()?;
        let attestation_version = r.read_i32()?;
        let security_level = r.read_i32()?;
        let creation_datetime = r.read_i64()?;
        let boot_key = r.read_blob()?;
        let boot_hash = r.read_blob()?;
        Ok(Self {
            android_version,
            os_version,
            os_patch_level,
            vendor_patch_level,
            boot_patch_level,
            keymaster_version,
            attestation_version,
            security_level,
            creation_datetime,
            boot_key,
            boot_hash,
        })
    }
}

/// 构造 KeyMint attestation 扩展所需的全部参数。
#[derive(Debug, Clone)]
pub struct AttestationConfig {
    /// attestationVersion（100=KM3, 200=KM4, 300=KeyMint1, 400=KeyMint2…）。
    pub attestation_version: i32,
    /// keymasterVersion。
    pub keymaster_version: i32,
    /// attestationSecurityLevel / keymasterSecurityLevel（0=Software, 1=TEE, 2=StrongBox）。
    pub security_level: i32,
    /// attestationChallenge。
    pub challenge: Vec<u8>,
    /// 调用方包名（写入 attestationApplicationId）。
    pub package_name: String,
    /// 密钥算法（1=RSA, 3=EC）。
    pub algorithm: i32,
    /// 密钥长度（位）。
    pub key_size: u32,
    /// 用途集合（1=ENCRYPT, 2=DECRYPT, 3=SIGN, 4=VERIFY, 5=DERIVE, 6=WRAP）。
    pub purposes: Vec<i32>,
    /// 摘要集合（4=SHA256, 5=SHA384…）。
    pub digests: Vec<i32>,
    /// OS 版本（如 140000），`-1` 表示不报告。
    pub os_version: i32,
    /// OS 补丁级别（如 20250301），`-1` 表示不报告。
    pub os_patch_level: i32,
    pub vendor_patch_level: i32,
    pub boot_patch_level: i32,
    /// verifiedBootKey（32 字节）。
    pub boot_key: Vec<u8>,
    /// verifiedBootHash（32 字节）。
    pub boot_hash: Vec<u8>,
    /// 密钥创建时间（Unix 毫秒）。
    pub creation_datetime: i64,
    /// [303] CALLER_NONCE 是否允许（存在即 NULL）。
    pub caller_nonce: bool,
    /// [503] NO_AUTH_REQUIRED（存在即 NULL）。
    pub no_auth_required: bool,
    /// [509] UNLOCKED_DEVICE_REQUIRED（存在即 NULL）。
    pub unlocked_device_required: bool,
    /// [400] ACTIVE_DATETIME（毫秒），`-1` 表示不报告。
    pub active_datetime: i64,
    /// [401] ORIGINATION_EXPIRE_DATETIME（毫秒），`-1` 表示不报告。
    pub origination_expire_datetime: i64,
    /// [402] USAGE_EXPIRE_DATETIME（毫秒），`-1` 表示不报告。
    pub usage_expire_datetime: i64,
    /// [405] USAGE_COUNT_LIMIT，`-1` 表示不报告。
    pub usage_count_limit: i32,
    /// [724] MODULE_HASH（仅 attestationVersion >= 400）。
    pub module_hash: Option<Vec<u8>>,
}

/// 构造 KeyMint attestation 扩展值（`KeyDescription` SEQUENCE 的 DER）。
///
/// 该返回值会被证书扩展以 `OCTET STRING` 包裹（由 certbuilder 完成）。
pub fn build_attestation_extension(config: &AttestationConfig) -> Result<Vec<u8>> {
    let sw_enforced = build_software_enforced(config)?;
    let tee_enforced = build_tee_enforced(config)?;

    // KeyDescription SEQUENCE（字段顺序固定，与真机一致）
    let parts: Vec<Vec<u8>> = vec![
        der::integer_nonneg(config.attestation_version as i64)?, // attestationVersion
        der::enumerated(config.security_level as i64),           // attestationSecurityLevel
        der::integer_nonneg(config.keymaster_version as i64)?,   // keymasterVersion
        der::enumerated(config.security_level as i64),           // keymasterSecurityLevel
        der::octet_string(&config.challenge),                    // attestationChallenge
        der::octet_string(&[]),                                  // uniqueId（恒空）
        sw_enforced,                                             // softwareEnforced
        tee_enforced,                                            // teeEnforced
    ];
    let refs: Vec<&[u8]> = parts.iter().map(|v| v.as_slice()).collect();
    Ok(der::seq(&refs))
}

// ===================== softwareEnforced =====================

fn build_software_enforced(config: &AttestationConfig) -> Result<Vec<u8>> {
    let mut fields: Vec<(u32, Vec<u8>)> = Vec::new();

    // [303] CALLER_NONCE — NULL
    if config.caller_nonce {
        fields.push((303, der::null()));
    }
    // [400] ACTIVE_DATETIME — INTEGER（毫秒）
    if config.active_datetime >= 0 {
        fields.push((400, der::integer_nonneg(config.active_datetime)?));
    }
    // [401] ORIGINATION_EXPIRE_DATETIME — INTEGER（毫秒）
    if config.origination_expire_datetime >= 0 {
        fields.push((401, der::integer_nonneg(config.origination_expire_datetime)?));
    }
    // [402] USAGE_EXPIRE_DATETIME — INTEGER（毫秒）
    if config.usage_expire_datetime >= 0 {
        fields.push((402, der::integer_nonneg(config.usage_expire_datetime)?));
    }
    // [405] USAGE_COUNT_LIMIT — INTEGER
    if config.usage_count_limit >= 0 {
        fields.push((405, der::integer_nonneg(config.usage_count_limit as i64)?));
    }
    // [509] UNLOCKED_DEVICE_REQUIRED — NULL
    if config.unlocked_device_required {
        fields.push((509, der::null()));
    }
    // [701] CREATION_DATETIME — INTEGER（毫秒）
    if config.creation_datetime >= 0 {
        fields.push((701, der::integer_nonneg(config.creation_datetime)?));
    }
    // [709] ATTESTATION_APPLICATION_ID — OCTET STRING(AttestationApplicationId SEQUENCE)
    if !config.package_name.is_empty() {
        let app_id = build_attestation_application_id(&config.package_name)?;
        fields.push((709, der::octet_string(&app_id)));
    }
    // [724] MODULE_HASH — OCTET STRING（仅 attestationVersion >= 400）
    if config.attestation_version >= 400 {
        if let Some(hash) = &config.module_hash {
            fields.push((724, der::octet_string(hash)));
        }
    }

    Ok(build_authorization_list(fields))
}

// ===================== teeEnforced =====================

fn build_tee_enforced(config: &AttestationConfig) -> Result<Vec<u8>> {
    let mut fields: Vec<(u32, Vec<u8>)> = Vec::new();

    // [1] PURPOSE — SET OF INTEGER
    if !config.purposes.is_empty() {
        fields.push((1, set_of_integers(&config.purposes)?));
    }
    // [2] ALGORITHM — INTEGER（1=RSA, 3=EC）
    fields.push((2, der::integer_nonneg(config.algorithm as i64)?));
    // [3] KEY_SIZE — INTEGER（位）
    fields.push((3, der::integer_nonneg(config.key_size as i64)?));
    // [5] DIGEST — SET OF INTEGER
    if !config.digests.is_empty() {
        fields.push((5, set_of_integers(&config.digests)?));
    }
    // [10] EC_CURVE — INTEGER（仅 EC：1=P-256）
    if config.algorithm == 3 {
        fields.push((10, der::integer_nonneg(1)?)); // P-256
    }
    // [503] NO_AUTH_REQUIRED — NULL
    if config.no_auth_required {
        fields.push((503, der::null()));
    }
    // [702] ORIGIN — INTEGER 0（GENERATED）
    fields.push((702, der::integer_nonneg(0)?));
    // [704] ROOT_OF_TRUST — SEQUENCE
    fields.push((704, build_root_of_trust(config)));
    // [705] OS_VERSION — INTEGER
    if config.os_version >= 0 {
        fields.push((705, der::integer_nonneg(config.os_version as i64)?));
    }
    // [706] OS_PATCHLEVEL — INTEGER
    if config.os_patch_level >= 0 {
        fields.push((706, der::integer_nonneg(config.os_patch_level as i64)?));
    }
    // [718] VENDOR_PATCHLEVEL — INTEGER
    if config.vendor_patch_level >= 0 {
        fields.push((718, der::integer_nonneg(config.vendor_patch_level as i64)?));
    }
    // [719] BOOT_PATCHLEVEL — INTEGER
    if config.boot_patch_level >= 0 {
        fields.push((719, der::integer_nonneg(config.boot_patch_level as i64)?));
    }
    // [723] ATTESTATION_ID_SECOND_IMEI — OCTET STRING（仅 attestationVersion >= 300）
    // 当前不注入 IMEI，留空（真机有则写）。

    Ok(build_authorization_list(fields))
}

/// RootOfTrust ::= SEQUENCE {
///     verifiedBootKey    OCTET STRING,
///     deviceLocked       BOOLEAN,
///     verifiedBootState  ENUMERATED,   -- 0=Verified
///     verifiedBootHash   OCTET STRING,
/// }
fn build_root_of_trust(config: &AttestationConfig) -> Vec<u8> {
    let parts: Vec<Vec<u8>> = vec![
        der::octet_string(&config.boot_key),
        der::boolean(true), // deviceLocked
        der::enumerated(0), // verifiedBootState = Verified
        der::octet_string(&config.boot_hash),
    ];
    let refs: Vec<&[u8]> = parts.iter().map(|v| v.as_slice()).collect();
    der::seq(&refs)
}

/// AttestationApplicationId ::= SEQUENCE {
///     packageInfos   SET OF PackageInfo,
///     signatures     SET OF Signature,
///     applicationId  OCTET STRING,
/// }
/// PackageInfo ::= SEQUENCE { packageName OCTET STRING, version INTEGER }
/// Signature ::= OCTET STRING
fn build_attestation_application_id(package_name: &str) -> Result<Vec<u8>> {
    let pkg_name_oct = der::octet_string(package_name.as_bytes());
    let version_int = der::integer_u64(1);
    let pkg_info = der::seq(&[&pkg_name_oct, &version_int]);
    let package_infos = der::set_of(&pkg_info); // SET OF PackageInfo（单个）
    let signatures = der::set_of(&[]); // 空 SET OF
    let app_id = der::octet_string(package_name.as_bytes());
    Ok(der::seq(&[&package_infos, &signatures, &app_id]))
}

// ===================== AuthorizationList 装配 =====================

/// 把 `(tag, value)` 列表按 tag 升序排序后，每个用 EXPLICIT 上下文标签包裹，
/// 再包成一个 SEQUENCE（即 AuthorizationList）。
fn build_authorization_list(mut fields: Vec<(u32, Vec<u8>)>) -> Vec<u8> {
    fields.sort_by_key(|(t, _)| *t);
    let parts: Vec<Vec<u8>> = fields.iter().map(|(t, v)| der::explicit(*t, v)).collect();
    let refs: Vec<&[u8]> = parts.iter().map(|v| v.as_slice()).collect();
    der::seq(&refs)
}

/// 构造 SET OF INTEGER（DER 要求元素按编码字节升序排序）。
fn set_of_integers(values: &[i32]) -> Result<Vec<u8>> {
    let mut encoded: Vec<Vec<u8>> = Vec::with_capacity(values.len());
    for v in values {
        encoded.push(der::integer_nonneg(*v as i64)?);
    }
    encoded.sort();
    let mut content = Vec::new();
    for e in &encoded {
        content.extend_from_slice(e);
    }
    Ok(der::set_of(&content))
}

// ===================== 简易大端读取器（解包 DeviceInfo） =====================

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn need(&self, n: usize) -> Result<()> {
        anyhow::ensure!(
            self.pos + n <= self.buf.len(),
            "DeviceInfo: 需 {} 字节，仅剩 {}",
            n,
            self.buf.len() - self.pos
        );
        Ok(())
    }
    fn read_u32(&mut self) -> Result<u32> {
        self.need(4)?;
        let v = u32::from_be_bytes(self.buf[self.pos..self.pos + 4].try_into().unwrap());
        self.pos += 4;
        Ok(v)
    }
    fn read_i32(&mut self) -> Result<i32> {
        Ok(self.read_u32()? as i32)
    }
    fn read_i64(&mut self) -> Result<i64> {
        self.need(8)?;
        let v = i64::from_be_bytes(self.buf[self.pos..self.pos + 8].try_into().unwrap());
        self.pos += 8;
        Ok(v)
    }
    fn read_blob(&mut self) -> Result<Vec<u8>> {
        let len = self.read_u32()? as usize;
        self.need(len)?;
        let v = self.buf[self.pos..self.pos + len].to_vec();
        self.pos += len;
        Ok(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_config() -> AttestationConfig {
        AttestationConfig {
            attestation_version: 300,
            keymaster_version: 300,
            security_level: 1,
            challenge: b"challenge-bytes".to_vec(),
            package_name: "com.example.app".to_string(),
            algorithm: 3,
            key_size: 256,
            purposes: vec![2, 3],
            digests: vec![4],
            os_version: 140000,
            os_patch_level: 20250301,
            vendor_patch_level: 20250301,
            boot_patch_level: 20250301,
            boot_key: vec![0xAA; 32],
            boot_hash: vec![0xBB; 32],
            creation_datetime: 1_700_000_000_000,
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

    #[test]
    fn extension_is_sequence_with_eight_top_fields() {
        let cfg = sample_config();
        let ext = build_attestation_extension(&cfg).expect("build ext");
        // 顶层必须是 SEQUENCE
        assert_eq!(ext[0], 0x30);
        // 用内置 DerReader 把顶层 8 个字段解出来，验证数量
        let mut r = crate::der::DerReader::new(&ext);
        let top = r.read().expect("read top");
        assert_eq!(top.tag, 0x30);
        let mut tr = crate::der::DerReader::new(top.content);
        let mut count = 0;
        while !tr.done() {
            let _ = tr.read().expect("read field");
            count += 1;
        }
        assert_eq!(count, 8, "KeyDescription 应有 8 个字段");
    }

    #[test]
    fn device_info_roundtrip() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&14u32.to_be_bytes()); // android_version
        buf.extend_from_slice(&140000i32.to_be_bytes());
        buf.extend_from_slice(&20250301i32.to_be_bytes());
        buf.extend_from_slice(&(-1i32).to_be_bytes()); // vendor
        buf.extend_from_slice(&(-1i32).to_be_bytes()); // boot
        buf.extend_from_slice(&300i32.to_be_bytes()); // keymaster
        buf.extend_from_slice(&300i32.to_be_bytes()); // attest
        buf.extend_from_slice(&1i32.to_be_bytes()); // security
        buf.extend_from_slice(&1_700_000_000_000i64.to_be_bytes());
        let key = vec![0xAA; 32];
        buf.extend_from_slice(&(key.len() as u32).to_be_bytes());
        buf.extend_from_slice(&key);
        let hash = vec![0xBB; 32];
        buf.extend_from_slice(&(hash.len() as u32).to_be_bytes());
        buf.extend_from_slice(&hash);

        let di = DeviceInfo::unpack(&buf).expect("unpack");
        assert_eq!(di.android_version, 14);
        assert_eq!(di.os_version, 140000);
        assert_eq!(di.vendor_patch_level, -1);
        assert_eq!(di.attestation_version, 300);
        assert_eq!(di.boot_key, key);
        assert_eq!(di.boot_hash, hash);
    }
}

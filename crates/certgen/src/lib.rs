//! FKTee-rs 证书生成库（纯 Rust 实现）。
//!
//! 本 crate 负责：
//! - 解析 `keybox.xml`（EC + RSA 多 keybox）
//! - 用 ring 生成 / 加载密钥对（EC P-256 软件生成、EC/RSA 从 keybox 私钥加载）
//! - 手工编 DER 构造 KeyMint attestation 扩展（OID 1.3.6.1.4.1.11129.2.1.17）
//! - 手工编 DER 构造 X.509 证书链（leaf 由 keybox 私钥签出 + keybox 证书链）
//! - 通过 JNI 暴露给 daemon 调用
//!
//! 所有 DER 均通过内置 `der` 模块手工编码，以保证字段顺序与真机一致；
//! OID 解析复用 [`der`] crate（[`der::asn1::ObjectIdentifier`]）。
//!
//! 错误处理统一使用 [`anyhow::Result`]。

#![allow(clippy::needless_lifetimes)]

mod attestation;
mod certbuilder;
mod keybox;
mod keygen;

// 内部低层编码工具：手工 DER 编 / 解码 + PEM/base64。
// 放在 lib.rs 里以 `pub(crate)` 暴露给其它模块复用，避免重复实现。
mod der {
    use anyhow::{ensure, Result};

    // ===================== 长度 / TLV =====================

    /// 写 DER 长度（短形式 / 长形式）。
    pub(crate) fn write_len(out: &mut Vec<u8>, len: usize) {
        if len < 0x80 {
            out.push(len as u8);
        } else {
            let mut buf = Vec::new();
            let mut l = len;
            while l > 0 {
                buf.push((l & 0xff) as u8);
                l >>= 8;
            }
            buf.reverse();
            out.push(0x80 | buf.len() as u8);
            out.extend_from_slice(&buf);
        }
    }

    /// 追加一个单字节 tag 的 TLV。
    pub(crate) fn write_tlv(out: &mut Vec<u8>, tag: u8, content: &[u8]) {
        out.push(tag);
        write_len(out, content.len());
        out.extend_from_slice(content);
    }

    /// 生成一个单字节 tag 的 TLV（返回独立 Vec）。
    pub(crate) fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        write_tlv(&mut out, tag, content);
        out
    }

    /// 追加一个多字节 tag 的 TLV（用于 tag number > 30 的上下文标签）。
    pub(crate) fn write_tlv_tagged(out: &mut Vec<u8>, tag_bytes: &[u8], content: &[u8]) {
        out.extend_from_slice(tag_bytes);
        write_len(out, content.len());
        out.extend_from_slice(content);
    }

    /// 生成上下文标签的 tag 字节。
    /// `constructed = true` 表示构造类型（EXPLICIT 标签需要构造类型）。
    pub(crate) fn context_tag_bytes(constructed: bool, num: u32) -> Vec<u8> {
        let class = 0x80; // context specific
        let pc = if constructed { 0x20 } else { 0x00 };
        let base = class | pc;
        if num < 0x1f {
            vec![base | (num as u8)]
        } else {
            // 长形式 tag：首字节 base|0x1f，后接 base-128 编码的 tag number
            let mut bytes = vec![base | 0x1f];
            let mut tmp = Vec::new();
            let mut n = num;
            while n > 0 {
                tmp.push((n & 0x7f) as u8);
                n >>= 7;
            }
            tmp.reverse();
            for (i, &b) in tmp.iter().enumerate() {
                bytes.push(if i < tmp.len() - 1 { b | 0x80 } else { b });
            }
            bytes
        }
    }

    /// `[num] EXPLICIT content` —— 构造上下文标签包裹 content。
    pub(crate) fn explicit(num: u32, content: &[u8]) -> Vec<u8> {
        let tag = context_tag_bytes(true, num);
        let mut out = Vec::new();
        write_tlv_tagged(&mut out, &tag, content);
        out
    }

    // ===================== 常用 ASN.1 原语 =====================

    pub(crate) fn sequence(content: &[u8]) -> Vec<u8> {
        tlv(0x30, content)
    }
    /// 把多个 TLV 片段拼接后包成一个 SEQUENCE（X.509 / PKCS8 常用）。
    pub(crate) fn seq(parts: &[&[u8]]) -> Vec<u8> {
        let total: usize = parts.iter().map(|p| p.len()).sum();
        let mut content = Vec::with_capacity(total);
        for p in parts {
            content.extend_from_slice(p);
        }
        sequence(&content)
    }
    pub(crate) fn set_of(content: &[u8]) -> Vec<u8> {
        tlv(0x31, content)
    }
    pub(crate) fn octet_string(data: &[u8]) -> Vec<u8> {
        tlv(0x04, data)
    }
    pub(crate) fn null() -> Vec<u8> {
        vec![0x05, 0x00]
    }
    pub(crate) fn boolean(v: bool) -> Vec<u8> {
        if v {
            vec![0x01, 0x01, 0xff]
        } else {
            vec![0x01, 0x01, 0x00]
        }
    }
    pub(crate) fn bit_string(unused: u8, data: &[u8]) -> Vec<u8> {
        let mut c = Vec::with_capacity(data.len() + 1);
        c.push(unused);
        c.extend_from_slice(data);
        tlv(0x03, &c)
    }
    /// ENUMERATED（与 INTEGER 内容编码一致，tag=0x0a）。
    pub(crate) fn enumerated(v: i64) -> Vec<u8> {
        tlv(0x0a, &integer_content_u64(v.max(0) as u64))
    }
    /// UTCTime（`YYMMDDHHMMSSZ`）。
    pub(crate) fn utctime(s: &str) -> Vec<u8> {
        tlv(0x17, s.as_bytes())
    }

    /// 非负整数内容字节（不含 tag/len，已加前导 0x00 防止被当成负数）。
    pub(crate) fn integer_content_u64(v: u64) -> Vec<u8> {
        let be = v.to_be_bytes();
        integer_content_be(&be)
    }
    /// 由大端字节构造 INTEGER 内容（去掉前导零，必要时补 0x00 符号位）。
    pub(crate) fn integer_content_be(be: &[u8]) -> Vec<u8> {
        let mut s = be;
        while s.len() > 1 && s[0] == 0 {
            s = &s[1..];
        }
        let mut content = Vec::with_capacity(s.len() + 1);
        if !s.is_empty() && (s[0] & 0x80) != 0 {
            content.push(0x00);
        }
        content.extend_from_slice(s);
        content
    }
    pub(crate) fn integer_u64(v: u64) -> Vec<u8> {
        tlv(0x02, &integer_content_u64(v))
    }
    /// 非负 i64 的 INTEGER（attestation 里的版本号 / patch level 均非负）。
    pub(crate) fn integer_nonneg(v: i64) -> Result<Vec<u8>> {
        ensure!(v >= 0, "der: integer must be non-negative, got {v}");
        Ok(integer_u64(v as u64))
    }

    /// 用 [`der`] crate 解析 OID 字符串，返回完整 TLV（tag=0x06）。
    pub(crate) fn oid(s: &str) -> Result<Vec<u8>> {
        let o = der::asn1::ObjectIdentifier::new(s)
            .map_err(|e| anyhow::anyhow!("invalid OID {s}: {e:?}"))?;
        Ok(tlv(0x06, o.as_bytes()))
    }

    // ===================== DER 解码（游标） =====================

    /// 一个 DER 元素：tag 首字节、tag 全部字节、内容、完整 TLV 切片。
    pub(crate) struct DerElement<'a> {
        pub tag: u8,
        pub content: &'a [u8],
        pub full: &'a [u8],
    }

    pub(crate) struct DerReader<'a> {
        buf: &'a [u8],
        pos: usize,
    }

    impl<'a> DerReader<'a> {
        pub(crate) fn new(buf: &'a [u8]) -> Self {
            Self { buf, pos: 0 }
        }
        pub(crate) fn done(&self) -> bool {
            self.pos >= self.buf.len()
        }
        /// 读取下一个 TLV 元素。
        pub(crate) fn read(&mut self) -> Result<DerElement<'a>> {
            ensure!(self.pos < self.buf.len(), "der: unexpected end of input");
            let start = self.pos;
            let first = self.buf[self.pos];
            // 处理多字节 tag
            let tag_len = if (first & 0x1f) == 0x1f {
                let mut i = self.pos + 1;
                while i < self.buf.len() && (self.buf[i] & 0x80) != 0 {
                    i += 1;
                }
                ensure!(i < self.buf.len(), "der: truncated multi-byte tag");
                (i + 1) - self.pos
            } else {
                1
            };
            self.pos += tag_len;
            ensure!(self.pos < self.buf.len(), "der: length octet missing");
            let first_len = self.buf[self.pos];
            self.pos += 1;
            let content_len = if first_len & 0x80 == 0 {
                first_len as usize
            } else {
                let n = (first_len & 0x7f) as usize;
                ensure!(n <= 8, "der: length too large");
                ensure!(self.pos + n <= self.buf.len(), "der: length octets missing");
                let mut l = 0usize;
                for _ in 0..n {
                    l = (l << 8) | self.buf[self.pos] as usize;
                    self.pos += 1;
                }
                l
            };
            ensure!(
                self.pos + content_len <= self.buf.len(),
                "der: content overflow"
            );
            let content = &self.buf[self.pos..self.pos + content_len];
            self.pos += content_len;
            let full = &self.buf[start..self.pos];
            Ok(DerElement {
                tag: first,
                content,
                full,
            })
        }
    }

    /// 从 X.509 证书 DER 中提取 Subject Name 的完整 TLV 字节（用作 leaf 的 Issuer）。
    pub(crate) fn extract_cert_subject(cert_der: &[u8]) -> Result<&[u8]> {
        let mut r = DerReader::new(cert_der);
        let cert = r.read()?;
        ensure!(cert.tag == 0x30, "cert: outer not SEQUENCE");
        let mut tr = DerReader::new(cert.content);
        let tbs = tr.read()?;
        ensure!(tbs.tag == 0x30, "cert: tbs not SEQUENCE");
        let mut tr = DerReader::new(tbs.content);
        // [0] EXPLICIT version（可选）
        let mut el = tr.read()?;
        if el.tag == 0xa0 {
            el = tr.read()?;
        }
        ensure!(el.tag == 0x02, "cert: serialNumber expected");
        el = tr.read()?; // signature AlgorithmIdentifier
        ensure!(el.tag == 0x30, "cert: sigAlg expected");
        el = tr.read()?; // issuer
        ensure!(el.tag == 0x30, "cert: issuer expected");
        el = tr.read()?; // validity
        ensure!(el.tag == 0x30, "cert: validity expected");
        el = tr.read()?; // subject
        ensure!(el.tag == 0x30, "cert: subject expected");
        Ok(el.full)
    }

    /// 从 PKCS#1 RSAPrivateKey DER 中提取 (modulus, publicExponent) 的 INTEGER 内容字节。
    pub(crate) fn extract_rsa_pubkey_contents(pkcs1: &[u8]) -> Result<(&[u8], &[u8])> {
        let mut r = DerReader::new(pkcs1);
        let seq = r.read()?;
        ensure!(seq.tag == 0x30, "pkcs1: not SEQUENCE");
        let mut tr = DerReader::new(seq.content);
        let _version = tr.read()?;
        let n = tr.read()?;
        let e = tr.read()?;
        ensure!(n.tag == 0x02 && e.tag == 0x02, "pkcs1: n/e not INTEGER");
        Ok((n.content, e.content))
    }

    // ===================== PEM / base64 =====================

    /// 标准 base64 解码（忽略空白）。
    pub(crate) fn base64_decode(s: &str) -> Result<Vec<u8>> {
        const TABLE: &[u8] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut val: u32 = 0;
        let mut bits: u32 = 0;
        let mut out = Vec::new();
        for ch in s.chars() {
            if ch == '=' {
                break;
            }
            if ch.is_whitespace() {
                continue;
            }
            let idx = TABLE
                .iter()
                .position(|&b| b as char == ch)
                .ok_or_else(|| anyhow::anyhow!("base64: invalid char {ch}"))?;
            val = (val << 6) | (idx as u32);
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push((val >> bits) as u8);
                val &= (1u32 << bits) - 1;
            }
        }
        Ok(out)
    }

    /// 从 PEM 文本（带 `-----BEGIN ...-----` 头尾）提取 DER 字节。
    /// 若未发现头尾，则把整段当作 base64 解码。
    pub(crate) fn pem_to_der(pem: &str) -> Result<Vec<u8>> {
        let mut body = String::new();
        let mut saw_header = false;
        let mut in_body = false;
        for line in pem.lines() {
            let line = line.trim();
            if line.starts_with("-----BEGIN") {
                saw_header = true;
                in_body = true;
                continue;
            }
            if line.starts_with("-----END") {
                in_body = false;
                continue;
            }
            if in_body {
                body.push_str(line);
            }
        }
        if !saw_header {
            // 没有头尾，整段当 base64
            body.clear();
            for line in pem.lines() {
                body.push_str(line.trim());
            }
        }
        ensure!(!body.is_empty(), "pem: empty body");
        base64_decode(&body)
    }
}

// ===================== 公共 API 导出 =====================

pub use attestation::{build_attestation_extension, AttestationConfig, DeviceInfo};
pub use certbuilder::{build_attested_chain, build_self_signed, CertChainResult};
pub use keybox::{KeyAlgorithm, Keybox, KeyboxData};
pub use keygen::KeyPair;

/// 证书生成器门面（facade）。
///
/// daemon 通过此结构持有证书生成上下文占位；具体生成逻辑复用本 crate 的
/// [`generate_attested_keypair`] 等自由函数。当前为无状态占位，后续可扩展为
/// 缓存 keybox / 设备信息等运行时上下文。
#[derive(Debug, Clone, Default)]
pub struct CertGen;

impl CertGen {
    /// 创建一个默认的证书生成器。
    pub fn new() -> Self {
        Self
    }
}

/// 生成已证明密钥对，返回字节流：
///
/// ```text
/// u32 BE  private_key_len
/// [u8]    private_key_pkcs8
/// u32 BE  cert_count
/// 重复 cert_count 次:
///     u32 BE  cert_len
///     [u8]    cert_der
/// ```
///
/// - `keybox_xml`：keybox.xml 内容（UTF-8）。
/// - `algorithm`：`"ecdsa"`/`"ec"` 或 `"rsa"`。
/// - `challenge`：attestation challenge（为空则走自签单层证书模式）。
/// - `package_name`：调用方包名（写入 attestationApplicationId）。
/// - `device`：设备 / 版本信息（见 [`DeviceInfo`]）。
pub fn generate_attested_keypair(
    keybox_xml: &[u8],
    algorithm: &str,
    challenge: &[u8],
    package_name: &str,
    device: &DeviceInfo,
) -> anyhow::Result<Vec<u8>> {
    let xml = std::str::from_utf8(keybox_xml)
        .map_err(|e| anyhow::anyhow!("keybox.xml not utf-8: {e}"))?;
    let keybox = Keybox::from_xml(xml)?;
    let alg = KeyAlgorithm::from_str(algorithm)
        .ok_or_else(|| anyhow::anyhow!("unsupported algorithm: {algorithm}"))?;

    let result = if challenge.is_empty() {
        // 无 challenge：自签单层证书（用软件生成的密钥自签）
        build_self_signed(alg, package_name)?
    } else {
        // 有 challenge：用 keybox 私钥签出完整证书链
        let kb = keybox
            .select(alg)
            .ok_or_else(|| anyhow::anyhow!("keybox 中缺少 {alg:?} 密钥"))?;
        build_attested_chain(kb, alg, challenge, package_name, device)?
    };

    // 序列化为字节流
    let mut out = Vec::new();
    out.extend_from_slice(&(result.private_key_pkcs8.len() as u32).to_be_bytes());
    out.extend_from_slice(&result.private_key_pkcs8);
    out.extend_from_slice(&(result.certificates_der.len() as u32).to_be_bytes());
    for cert in &result.certificates_der {
        out.extend_from_slice(&(cert.len() as u32).to_be_bytes());
        out.extend_from_slice(cert);
    }
    Ok(out)
}

// ===================== JNI 入口 =====================

#[cfg(feature = "jni")]
mod jni_entry {
    use super::*;
    use jni::objects::{JByteArray, JClass, JString};
    use jni::sys::{jbyteArray, jint};
    use jni::JNIEnv;

    /// `com.fktee.pki.CertGen.generateAttestedKeyPair` 的 native 实现。
    ///
    /// 签名：
    /// ```text
    /// native byte[] generateAttestedKeyPair(
    ///     byte[] keyboxXml,
    ///     String algorithm,        // "ecdsa"/"ec"/"rsa"
    ///     byte[] challenge,        // attestation challenge，可为空数组
    ///     String packageName,
    ///     int androidVersion,
    ///     byte[] deviceInfo)       // DeviceInfo 打包字节（见 DeviceInfo::unpack）
    /// ```
    #[no_mangle]
    pub extern "system" fn Java_com_fktee_pki_CertGen_generateAttestedKeyPair<'local>(
        mut env: JNIEnv<'local>,
        _class: JClass<'local>,
        keybox: JByteArray<'local>,
        algorithm: JString<'local>,
        challenge: JByteArray<'local>,
        package_name: JString<'local>,
        android_version: jint,
        device_info: JByteArray<'local>,
    ) -> jbyteArray {
        match run(
            &mut env,
            keybox,
            algorithm,
            challenge,
            package_name,
            android_version,
            device_info,
        ) {
            Ok(bytes) => match env.new_byte_array(bytes.len() as i32) {
                Ok(arr) => {
                    let sig: &[i8] = unsafe {
                        std::slice::from_raw_parts(bytes.as_ptr() as *const i8, bytes.len())
                    };
                    let _ = env.set_byte_array_region(&arr, 0, sig);
                    arr.into_raw()
                }
                Err(e) => {
                    let _ = env.throw_new(
                        "java/lang/RuntimeException",
                        &format!("new_byte_array failed: {e:?}"),
                    );
                    std::ptr::null_mut()
                }
            },
            Err(e) => {
                let _ = env.throw_new("java/lang/RuntimeException", &format!("{e:#}"));
                std::ptr::null_mut()
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn run<'local>(
        env: &mut JNIEnv<'local>,
        keybox: JByteArray<'local>,
        algorithm: JString<'local>,
        challenge: JByteArray<'local>,
        package_name: JString<'local>,
        android_version: jint,
        device_info: JByteArray<'local>,
    ) -> anyhow::Result<Vec<u8>> {
        let keybox_xml = env
            .convert_byte_array(keybox)
            .map_err(|e| anyhow::anyhow!("read keybox: {e:?}"))?;
        let algorithm = String::from(
            env.get_string(&algorithm)
                .map_err(|e| anyhow::anyhow!("read algorithm: {e:?}"))?,
        );
        let challenge = env
            .convert_byte_array(challenge)
            .map_err(|e| anyhow::anyhow!("read challenge: {e:?}"))?;
        let package_name = String::from(
            env.get_string(&package_name)
                .map_err(|e| anyhow::anyhow!("read packageName: {e:?}"))?,
        );
        let device_bytes = env
            .convert_byte_array(device_info)
            .map_err(|e| anyhow::anyhow!("read deviceInfo: {e:?}"))?;

        let mut device = DeviceInfo::unpack(&device_bytes)?;
        // JNI 侧的 androidVersion 优先（若 DeviceInfo 未填则覆盖）
        if device.android_version == 0 {
            device.android_version = android_version;
        }

        generate_attested_keypair(&keybox_xml, &algorithm, &challenge, &package_name, &device)
    }
}

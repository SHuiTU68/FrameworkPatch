//! 解析 `keybox.xml`（与硬件证明模块通用的 keybox.xml 格式一致）。
//!
//! XML 结构：
//! ```xml
//! <Keybox>
//!   <Key algorithm="ec">
//!     <PrivateKey format="pem">-----BEGIN EC PRIVATE KEY----- ... -----END EC PRIVATE KEY-----</PrivateKey>
//!     <CertificateChain>
//!       <Certificate format="pem">-----BEGIN CERTIFICATE----- ... -----END CERTIFICATE-----</Certificate>
//!       <Certificate format="pem">-----BEGIN CERTIFICATE----- ... -----END CERTIFICATE-----</Certificate>
//!     </CertificateChain>
//!   </Key>
//!   <Key algorithm="rsa"> ... </Key>
//! </Keybox>
//! ```
//!
//! 支持一个 keybox 中同时存在 EC 与 RSA 多个 Key。

use anyhow::{ensure, Result};
use serde::Deserialize;

/// 证明密钥算法。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAlgorithm {
    /// ECDSA P-256
    Ecdsa,
    /// RSA-2048
    Rsa,
}

impl KeyAlgorithm {
    /// 从字符串解析：`ec`/`ecdsa` → Ecdsa，`rsa` → Rsa。
    pub fn from_str(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "ec" | "ecdsa" | "p256" | "p-256" => Some(Self::Ecdsa),
            "rsa" => Some(Self::Rsa),
            _ => None,
        }
    }
}

impl std::fmt::Display for KeyAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ecdsa => write!(f, "ecdsa"),
            Self::Rsa => write!(f, "rsa"),
        }
    }
}

/// 单个 Keybox 条目：算法 + 私钥 PEM + 证书链 PEM（顺序：中间证书在前，根在后）。
#[derive(Debug, Clone)]
pub struct KeyboxData {
    pub algorithm: KeyAlgorithm,
    /// 私钥 PEM（`-----BEGIN EC PRIVATE KEY-----` 或 `-----BEGIN RSA PRIVATE KEY-----`）。
    pub private_key_pem: String,
    /// 证书链 PEM 列表（certificates[0] 为签发 leaf 的中间证书，最后一个为根）。
    pub certificates_pem: Vec<String>,
}

impl KeyboxData {
    /// 把证书链 PEM 解析为 DER 字节列表。
    pub fn certificates_der(&self) -> Result<Vec<Vec<u8>>> {
        self.certificates_pem
            .iter()
            .map(|p| crate::der::pem_to_der(p))
            .collect()
    }
}

/// 完整 keybox（可能包含 EC + RSA 多个 Key）。
#[derive(Debug, Clone, Default)]
pub struct Keybox {
    pub keys: Vec<KeyboxData>,
}

impl Keybox {
    /// 从 keybox.xml 文本解析。
    pub fn from_xml(xml: &str) -> Result<Self> {
        let raw: XmlKeybox = quick_xml::de::from_str(xml)
            .map_err(|e| anyhow::anyhow!("parse keybox.xml failed: {e}"))?;
        let mut keys = Vec::new();
        for k in raw.keys {
            let algorithm = KeyAlgorithm::from_str(&k.algorithm)
                .ok_or_else(|| anyhow::anyhow!("unknown keybox algorithm: {}", k.algorithm))?;
            ensure!(
                !k.private_key.text.trim().is_empty(),
                "keybox {} PrivateKey 为空",
                algorithm
            );
            let certificates_pem = k
                .certificate_chain
                .certificates
                .iter()
                .map(|c| c.text.trim().to_owned())
                .collect::<Vec<_>>();
            ensure!(
                !certificates_pem.is_empty(),
                "keybox {} CertificateChain 为空",
                algorithm
            );
            keys.push(KeyboxData {
                algorithm,
                private_key_pem: k.private_key.text.trim().to_owned(),
                certificates_pem,
            });
        }
        ensure!(!keys.is_empty(), "keybox.xml 中没有找到任何 <Key>");
        Ok(Self { keys })
    }

    /// 按算法选取 keybox。
    pub fn select(&self, alg: KeyAlgorithm) -> Option<&KeyboxData> {
        self.keys.iter().find(|k| k.algorithm == alg)
    }
}

// ===================== quick-xml 反序列化结构 =====================

#[derive(Deserialize, Debug)]
struct XmlKeybox {
    #[serde(rename = "Key", default)]
    keys: Vec<XmlKey>,
}

#[derive(Deserialize, Debug)]
struct XmlKey {
    #[serde(rename = "@algorithm")]
    algorithm: String,
    #[serde(rename = "PrivateKey")]
    private_key: XmlPemText,
    #[serde(rename = "CertificateChain")]
    certificate_chain: XmlCertificateChain,
}

/// 带 `format` 属性 + 文本内容的元素（PrivateKey / Certificate 通用）。
#[derive(Deserialize, Debug)]
struct XmlPemText {
    #[serde(rename = "@format", default)]
    #[allow(dead_code)]
    format: String,
    #[serde(rename = "$text", default)]
    text: String,
}

#[derive(Deserialize, Debug)]
struct XmlCertificateChain {
    #[serde(rename = "Certificate", default)]
    certificates: Vec<XmlPemText>,
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<Keybox>
    <Key algorithm="ec">
        <PrivateKey format="pem">-----BEGIN EC PRIVATE KEY-----
MHcCAQEEICHghkMqFRmEWc82OlD8FMnarfk19SfC39ceTW28QuVEoAoGCCqGSM49
AwEHoUQDQgAE6555+EJjWazLKpFMiYbMcK2QZpOCqXMmE/6sy/ghJ0whdJdKKv6l
uU1/ZtTgZRBmNbxTt6CjpnFYPts+Ea4QFA==
-----END EC PRIVATE KEY-----</PrivateKey>
        <CertificateChain>
            <Certificate format="pem">-----BEGIN CERTIFICATE-----
MIICeDCCAh6gAwIBAgICEAEwCgYIKoZIzj0EAwIwgZgxCzAJBgNVBAYTAlVTMRMw
EQYDVQQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1Nb3VudGFpbiBWaWV3MRUwEwYD
VQQKDAxHb29nbGUsIEluYy4xEDAOBgNVBAsMB0FuZHJvaWQxMzAxBgNVBAMMKkFu
ZHJvaWQgS2V5c3RvcmUgU29mdHdhcmUgQXR0ZXN0YXRpb24gUm9vdDAeFw0xNjAx
MTEwMDQ2MDlaFw0yNjAxMDgwMDQ2MDlaMIGIMQswCQYDVQQGEwJVUzETMBEGA1UE
CAwKQ2FsaWZvcm5pYTEVMBMGA1UECgwMR29vZ2xlLCBJbmMuMRAwDgYDVQQLDAdB
bmRyb2lkMTswOQYDVQQDDDJBbmRyb2lkIEtleXN0b3JlIFNvZnR3YXJlIEF0dGVz
dGF0aW9uIEludGVybWVkaWF0ZTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABOue
efhCY1msyyqRTImGzHCtkGaTgqlzJhP+rMv4ISdMIXSXSir+pblNf2bU4GUQZjW8
U7ego6ZxWD7bPhGuEBSjZjBkMB0GA1UdDgQWBBQ//KzWGrE6noEguNUlHMVlux6R
qTAfBgNVHSMEGDAWgBTIrel3TEXDo88NFhDkeUM6IVowzzASBgNVHRMBAf8ECDAG
AQH/AgEAMA4GA1UdDwEB/wQEAwIChDAKBggqhkjOPQQDAgNIADBFAiBLipt77oK8
wDOHri/AiZi03cONqycqRZ9pDMfDktQPjgIhAO7aAV229DLp1IQ7YkyUBO86fMy9
Xvsiu+f+uXc/WT/7
-----END CERTIFICATE-----</Certificate>
            <Certificate format="pem">-----BEGIN CERTIFICATE-----
MIICizCCAjKgAwIBAgIJAKIFntEOQ1tXMAoGCCqGSM49BAMCMIGYMQswCQYDVQQG
EwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNTW91bnRhaW4gVmll
dzEVMBMGA1UECgwMR29vZ2xlLCBJbmMuMRAwDgYDVQQLDAdBbmRyb2lkMTMwMQYD
VQQDDCpBbmRyb2lkIEtleXN0b3JlIFNvZnR3YXJlIEF0dGVzdGF0aW9uIFJvb3Qw
HhcNMTYwMTExMDA0MzUwWhcNMzYwMTA2MDA0MzUwWjCBmDELMAkGA1UEBhMCVVMx
EzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDU1vdW50YWluIFZpZXcxFTAT
BgNVBAoMDEdvb2dsZSwgSW5jLjEQMA4GA1UECwwHQW5kcm9pZDEzMDEGA1UEAwwq
QW5kcm9pZCBLZXlzdG9yZSBTb2Z0d2FyZSBBdHRlc3RhdGlvbiBSb290MFkwEwYH
KoZIzj0CAQYIKoZIzj0DAQcDQgAE7l1ex+HA220Dpn7mthvsTWpdamguD/9/SQ59
dx9EIm29sa/6FsvHrcV30lacqrewLVQBXT5DKyqO107sSHVBpKNjMGEwHQYDVR0O
BBYEFMit6XdMRcOjzw0WEOR5QzohWjDPMB8GA1UdIwQYMBaAFMit6XdMRcOjzw0W
EOR5QzohWjDPMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgKEMAoGCCqG
SM49BAMCA0cAMEQCIDUho++LNEYenNVg8x1YiSBq3KNlQfYNns6KGYxmSGB7AiBN
C/NR2TB8fVvaNTQdqEcbY6WFZTytTySn502vQX3xvw==
-----END CERTIFICATE-----</Certificate>
        </CertificateChain>
    </Key>
    <Key algorithm="rsa">
        <PrivateKey format="pem">-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQDAgyPcVogbuDAgafWwhWHG7r5/BeL1qEIEir6LR752/q7yXPKb
KvoyABQWAUKZiaFfz8aBXrNjWDwv0vIL5Jgyg92BSxbX4YVBeuVKvClqOm21wAQI
O2jFVsHwIzmRZBmGTVC3TUCuykhMdzVsiVoMJ1q/rEmdXX0jYvKcXgLocQIDAQAB
AoGBAL6GCwuZqAKm+xpZQ4p7txUGWwmjbcbpysxr88AsNNfXnpTGYGQo2Ix7f2V3
wc3qZAdKvo5yht8fCBHclygmCGjeldMu/Ja20IT/JxpfYN78xwPno45uKbqaPF/C
woB2tqiWrx0014gozpvdsfNPnJQEQweBKY4gExZyW728mTpBAkEA4cbZJ2RsCRbs
NoJtWUmDdAwh8bB0xKGlmGfGaXlchdPcRkxbkp6Uv7NODcxQFLEPEzQat/3V9gQU
0qMmytQcxQJBANpIWZd4XNVjD7D9jFJU+Y5TjhiYOq6ea35qWntdNDdVuSGOvUAy
DSg4fXifdvohi8wti2il9kGPu+ylF5qzr70CQFD+/DJklVlhbtZTThVFCTKdk6PY
ENvlvbmCKSz3i9i624Agro1X9LcdBThv/p6dsnHKNHejSZnbdvjl7OnA1J0CQBW3
TPJ8zv+Ls2vwTZ2DRrCaL3DS9EObDyasfgP36dH3fUuRX9KbKCPwOstdUgDghX/y
qAPpPu6W1iNc6VRCvCECQQCQp0XaiXCyzWSWYDJCKMX4KFb/1mW6moXI1g8bi+5x
fs0scurgHa2GunZU1M9FrbXx8rMdn4Eiz6XxpVcPmy0l
-----END RSA PRIVATE KEY-----</PrivateKey>
        <CertificateChain>
            <Certificate format="pem">-----BEGIN CERTIFICATE-----
MIICtjCCAh+gAwIBAgICEAAwDQYJKoZIhvcNAQELBQAwYzELMAkGA1UEBhMCVVMx
EzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDU1vdW50YWluIFZpZXcxFTAT
BgNVBAoMDEdvb2dsZSwgSW5jLjEQMA4GA1UECwwHQW5kcm9pZDAeFw0xNjAxMDQx
MjQwNTNaFw0zNTEyMzAxMjQwNTNaMHYxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApD
YWxpZm9ybmlhMRUwEwYDVQQKDAxHb29nbGUsIEluYy4xEDAOBgNVBAsMB0FuZHJv
aWQxKTAnBgNVBAMMIEFuZHJvaWQgU29mdHdhcmUgQXR0ZXN0YXRpb24gS2V5MIGf
MA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDAgyPcVogbuDAgafWwhWHG7r5/BeL1
qEIEir6LR752/q7yXPKbKvoyABQWAUKZiaFfz8aBXrNjWDwv0vIL5Jgyg92BSxbX
4YVBeuVKvClqOm21wAQIO2jFVsHwIzmRZBmGTVC3TUCuykhMdzVsiVoMJ1q/rEmd
XX0jYvKcXgLocQIDAQABo2YwZDAdBgNVHQ4EFgQU1AwQG/jNY7n3OVK1DhNcpteZ
k4YwHwYDVR0jBBgwFoAUKfrxrMxN0kyWQCd1trDpMuUH/i4wEgYDVR0TAQH/BAgw
BgEB/wIBADAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQELBQADgYEAni1IX4xn
M9waha2Z11Aj6hTsQ7DhnerCI0YecrUZ3GAi5KVoMWwLVcTmnKItnzpPk2sxixZ4
Fg2Iy9mLzICdhPDCJ+NrOPH90ecXcjFZNX2W88V/q52PlmEmT7K+gbsNSQQiis6f
9/VCLiVE+iEHElqDtVWtGIL4QBSbnCBjBH8=
-----END CERTIFICATE-----</Certificate>
            <Certificate format="pem">-----BEGIN CERTIFICATE-----
MIICpzCCAhCgAwIBAgIJAP+U2d2fB8gMMA0GCSqGSIb3DQEBCwUAMGMxCzAJBgNV
BAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1Nb3VudGFpbiBW
aWV3MRUwEwYDVQQKDAxHb29nbGUsIEluYy4xEDAOBgNVBAsMB0FuZHJvaWQwHhcN
MTYwMTA0MTIzMTA4WhcNMzUxMjMwMTIzMTA4WjBjMQswCQYDVQQGEwJVUzETMBEG
A1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNTW91bnRhaW4gVmVldzEVMBMGA1UE
CgwMR29vZ2xlLCBJbmMuMRAwDgYDVQQLDAdBbmRyb2lkMIGfMA0GCSqGSIb3DQEB
AQUAA4GNADCBiQKBgQCia63rbi5EYe/VDoLmt5TRdSMfd5tjkWP/96r/C3JHTsAs
Q+wzfNes7UA+jCigZtX3hwszl94OuE4TQKuvpSe/lWmgMdsGUmX4RFlXYfC78hdL
t0GAZMAoDo9Sd47b0ke2RekZyOmLw9vCkT/X11DEHTVm+Vfkl5YLCazOkjWFmwID
AQABo2MwYTAdBgNVHQ4EFgQUKfrxrMxN0kyWQCd1trDpMuUH/i4wHwYDVR0jBBgw
FoAUKfrxrMxN0kyWQCd1trDpMuUH/i4wDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8B
Af8EBAMCAoQwDQYJKoZIhvcNAQELBQADgYEAT3LzNlmNDsG5dFsxWfbwjSVJMJ6j
HBwp0kUtILlNX2S06IDHeHqcOd6os/W/L3BfRxBcxebrTQaZYdKumgf/93y4q+uc
DyQHXrF/unlx/U1bnt8Uqf7f7XzAiF343ZtkMlbVNZriE/mPzsF83O+kqrJVw4Op
Lvtc9mL1J1IXvmM=
-----END CERTIFICATE-----</Certificate>
        </CertificateChain>
    </Key>
</Keybox>"#;

    #[test]
    fn parse_sample_keybox() {
        let kb = Keybox::from_xml(SAMPLE).expect("parse");
        assert!(kb.select(KeyAlgorithm::Ecdsa).is_some());
        assert!(kb.select(KeyAlgorithm::Rsa).is_some());
        let ec = kb.select(KeyAlgorithm::Ecdsa).unwrap();
        assert_eq!(ec.certificates_pem.len(), 2);
        let ders = ec.certificates_der().expect("der");
        assert_eq!(ders.len(), 2);
        // 证书是 SEQUENCE 起头
        assert_eq!(ders[0][0], 0x30);
    }
}

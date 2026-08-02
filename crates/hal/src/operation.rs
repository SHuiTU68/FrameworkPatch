//! IKeyMintOperation 软件实现（generation 模式）。
//!
//! generation 模式下，begin() 识别出软件 keyBlob 后返回本实现而非真 HAL
//! operation。所有 update/finish 都在软件侧完成签名——不回调真 HAL，保证
//! keyBlob 内部密钥与 leaf 证书公钥一致，签名结果真实可验。
//!
//! # 支持范围
//!
//! 当前仅实现 **SIGN purpose + 任意 digest** 的最小路径（attestation 密钥的
//! 主要用途）。VERIFY / ENCRYPT / DECRYPT 返回 `UnsupportedKeyOperation`，
//! 让 keystore2 上报给应用，而非假装成功。
//!
//! update/finish 的数据累积语义：
//! - `update(input)`: 追加 input 到内部缓冲，返回空 Vec（签名操作无中间输出）。
//! - `finish(input, sig)`: 追加 input，对累积数据签名，返回签名字节。
//!   `sig` 非 None 表示 VERIFY，返回 Unsupported。
//!
//! 参考 TEESimulator 的 generation mode：软件生成密钥 + 自签 leaf + 软件签名。

use crate::android::hardware::security::keymint::IKeyMintOperation::{
    BnKeyMintOperation, IKeyMintOperation,
};
use crate::android::hardware::security::secureclock::TimeStampToken::TimeStampToken;
use crate::android::hardware::security::keymint::HardwareAuthToken::HardwareAuthToken;

use certgen::KeyPair;
use parking_lot::Mutex;

/// 软件签名 operation。
///
/// 持有生成 keyBlob 时存入的 KeyPair 副本 + 累积的待签名数据。
pub struct SoftwareOperation {
    kp: KeyPair,
    /// 累积的待签名数据（update + finish.input 拼接）。
    /// 用 Mutex 保护：binder 多线程可能并发调用 update（虽然实际单 operation 串行）。
    buf: Mutex<Vec<u8>>,
    /// operation 是否已 finish/abort（防止重复 finish）。
    finished: Mutex<bool>,
}

impl SoftwareOperation {
    pub fn new(kp: KeyPair) -> Self {
        Self {
            kp,
            buf: Mutex::new(Vec::new()),
            finished: Mutex::new(false),
        }
    }

    /// 构造 binder Strong 句柄，供 BeginResult.operation 使用。
    pub fn into_strong(self) -> rsbinder::Strong<dyn IKeyMintOperation> {
        BnKeyMintOperation::new_binder(self)
    }
}

impl rsbinder::Interface for SoftwareOperation {}

impl IKeyMintOperation for SoftwareOperation {
    fn r#updateAad(
        &self,
        _input: &[u8],
        _auth_token: Option<&HardwareAuthToken>,
        _time_stamp_token: Option<&TimeStampToken>,
    ) -> rsbinder::BinderResult<()> {
        // AAD 仅 AEAD 用，签名操作忽略。
        Ok(())
    }

    fn r#update(
        &self,
        input: &[u8],
        _auth_token: Option<&HardwareAuthToken>,
        _time_stamp_token: Option<&TimeStampToken>,
    ) -> rsbinder::BinderResult<Vec<u8>> {
        if *self.finished.lock() {
            return Err(rsbinder::StatusCode::Unknown.into());
        }
        self.buf.lock().extend_from_slice(input);
        // 签名操作无中间输出
        Ok(Vec::new())
    }

    fn r#finish(
        &self,
        input: Option<&[u8]>,
        signature: Option<&[u8]>,
        _auth_token: Option<&HardwareAuthToken>,
        _timestamp_token: Option<&TimeStampToken>,
        _confirmation_token: Option<&[u8]>,
    ) -> rsbinder::BinderResult<Vec<u8>> {
        // VERIFY purpose（signature 非 None）不支持
        if signature.is_some() {
            // 软件密钥仅支持 SIGN；VERIFY 返回 BadValue（KeyMint 语义：无效参数）。
            return Err(rsbinder::StatusCode::BadValue.into());
        }

        let mut finished = self.finished.lock();
        if *finished {
            return Err(rsbinder::StatusCode::Unknown.into());
        }
        *finished = true;

        // 追加 finish 的 input
        let data = {
            let mut buf = self.buf.lock();
            if let Some(inp) = input {
                buf.extend_from_slice(inp);
            }
            buf.clone()
        };

        // 签名：ring 内部完成 hash（ECDSA P-256 SHA-256 / RSA PKCS1 SHA-256）。
        match self.kp.sign(&data) {
            Ok(sig) => {
                log::debug!(
                    "fktee-hal: software finish signed {} bytes → {} bytes",
                    data.len(),
                    sig.len()
                );
                Ok(sig)
            }
            Err(e) => {
                log::error!("fktee-hal: software finish sign failed: {e:#}");
                Err(rsbinder::StatusCode::Unknown.into())
            }
        }
    }

    fn r#abort(&self) -> rsbinder::BinderResult<()> {
        *self.finished.lock() = true;
        self.buf.lock().clear();
        Ok(())
    }
}

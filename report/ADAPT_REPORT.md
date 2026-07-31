# FrameworkPatch smali 适配报告

由 `scripts/extract_smali.sh` 自动生成于 2026-07-31 18:47:53 UTC

## 1. 设备信息

| 项 | 值 |
|---|---|
| 型号 | PLC110 |
| 品牌/设备 | OnePlus / OP60EDL1 |
| Android 版本 | 16 (SDK 36) |
| 安全补丁 | 2026-07-01 |
| Build ID | BP2A.250605.015 |
| 增量 | V.1be4275_8cb9c6_8ac72d |
| 指纹 | `OnePlus/PLC110/OP60EDL1:16/BP2A.250605.015/V.1be4275_8cb9c6_8ac72d:user/release-keys` |

## 2. framework.jar 元信息

| 项 | 值 |
|---|---|
| 大小 | （dex 模式，无整体大小） 字节 |
| MD5 | `（dex 模式，无整体 MD5）` |
| SHA256 | `（dex 模式，无整体 SHA256）` |
| dex 数量 | 6 |

### dex 列表

```
  classes.dex
  classes2.dex
  classes3.dex
  classes4.dex
  classes5.dex
  classes6.dex
```

## 3. hook 点定位结果

| 类 | 所在 dex | 是否找到 |
|---|---|---|
| AndroidKeyStoreSpi | classes3.dex | ✓ 找到 |
| Instrumentation | classes.dex | ✓ 找到 |
| SystemProperties | classes3.dex | ✓ 找到 |

## 4. 目标方法 smali 片段（核心）

> 下面是从你 framework.jar 反编译出的真实 smali。
> 上游需要这些片段来确定：
> 1. `engineGetCertificateChain` 末尾 leaf cert / chain 数组的寄存器编号
> 2. `newApplication` 各重载里 Context 参数的寄存器编号
> 3. `SystemProperties.get` 两个重载里 `native_get` 返回值的寄存器编号
> 
> 拿到后即可给出**精确到寄存器**的 patch 指令。


### AndroidKeyStoreSpi.engineGetCertificateChain (所有重载)
方法签名匹配: `engineGetCertificateChain`
文件: `smali_classes3/android/security/keystore2/AndroidKeyStoreSpi.smali`

```smali
--- method ---
.method public whitelist test-api engineGetCertificateChain(Ljava/lang/String;)[Ljava/security/cert/Certificate;
    .registers 11
    .param p1, "alias"    # Ljava/lang/String;

    .line 181
    invoke-direct {p0, p1}, Landroid/security/keystore2/AndroidKeyStoreSpi;->getKeyMetadata(Ljava/lang/String;)Landroid/system/keystore2/KeyEntryResponse;

    move-result-object v0

    .line 183
    .local v0, "response":Landroid/system/keystore2/KeyEntryResponse;
    const/4 v1, 0x0

    if-eqz v0, :cond_49

    iget-object v2, v0, Landroid/system/keystore2/KeyEntryResponse;->metadata:Landroid/system/keystore2/KeyMetadata;

    iget-object v2, v2, Landroid/system/keystore2/KeyMetadata;->certificate:[B

    if-nez v2, :cond_e

    goto :goto_49

    .line 187
    :cond_e
    iget-object v2, v0, Landroid/system/keystore2/KeyEntryResponse;->metadata:Landroid/system/keystore2/KeyMetadata;

    iget-object v2, v2, Landroid/system/keystore2/KeyMetadata;->certificate:[B

    invoke-static {v2}, Landroid/security/keystore2/AndroidKeyStoreSpi;->toCertificate([B)Ljava/security/cert/X509Certificate;

    move-result-object v2

    .line 188
    .local v2, "leaf":Ljava/security/cert/X509Certificate;
    if-nez v2, :cond_19

    .line 189
    return-object v1

    .line 194
    :cond_19
    iget-object v1, v0, Landroid/system/keystore2/KeyEntryResponse;->metadata:Landroid/system/keystore2/KeyMetadata;

    iget-object v1, v1, Landroid/system/keystore2/KeyMetadata;->certificateChain:[B

    .line 196
    .local v1, "caBytes":[B
    const/4 v3, 0x1

    if-eqz v1, :cond_43

    .line 197
    invoke-static {v1}, Landroid/security/keystore2/AndroidKeyStoreSpi;->toCertificates([B)Ljava/util/Collection;

    move-result-object v4

    .line 199
    .local v4, "caChain":Ljava/util/Collection;, "Ljava/util/Collection<Ljava/security/cert/X509Certificate;>;"
    invoke-interface {v4}, Ljava/util/Collection;->size()I

    move-result v5

    add-int/2addr v5, v3

    new-array v3, v5, [Ljava/security/cert/Certificate;

    .line 201
    .local v3, "caList":[Ljava/security/cert/Certificate;
    invoke-interface {v4}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    move-result-object v5

    .line 202
    .local v5, "it":Ljava/util/Iterator;, "Ljava/util/Iterator<Ljava/security/cert/X509Certificate;>;"
    const/4 v6, 0x1

    .line 203
    .local v6, "i":I
    :goto_30
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    move-result v7

    if-eqz v7, :cond_42

    .line 204
    add-int/lit8 v7, v6, 0x1

    .end local v6    # "i":I
    .local v7, "i":I
    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v8

    check-cast v8, Ljava/security/cert/Certificate;

    aput-object v8, v3, v6

    move v6, v7

    goto :goto_30

    .line 206
    .end local v4    # "caChain":Ljava/util/Collection;, "Ljava/util/Collection<Ljava/security/cert/X509Certificate;>;"
    .end local v5    # "it":Ljava/util/Iterator;, "Ljava/util/Iterator<Ljava/security/cert/X509Certificate;>;"
    .end local v7    # "i":I
    :cond_42
    goto :goto_45

    .line 207
    .end local v3    # "caList":[Ljava/security/cert/Certificate;
    :cond_43
    new-array v3, v3, [Ljava/security/cert/Certificate;

    .line 210
    .restart local v3    # "caList":[Ljava/security/cert/Certificate;
    :goto_45
    const/4 v4, 0x0

    aput-object v2, v3, v4

    .line 212
    return-object v3

    .line 184
    .end local v1    # "caBytes":[B
    .end local v2    # "leaf":Ljava/security/cert/X509Certificate;
    .end local v3    # "caList":[Ljava/security/cert/Certificate;
    :cond_49
    :goto_49
    return-object v1
.end method

```

### Instrumentation.newApplication (所有重载)
方法签名匹配: `newApplication`
文件: `smali_classes/android/app/Instrumentation.smali`

```smali
--- method ---
.method public static whitelist newApplication(Ljava/lang/Class;Landroid/content/Context;)Landroid/app/Application;
    .registers 3
    .param p1, "context"    # Landroid/content/Context;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/Class<",
            "*>;",
            "Landroid/content/Context;",
            ")",
            "Landroid/app/Application;"
        }
    .end annotation

    .annotation system Ldalvik/annotation/Throws;
        value = {
            Ljava/lang/InstantiationException;,
            Ljava/lang/IllegalAccessException;,
            Ljava/lang/ClassNotFoundException;
        }
    .end annotation

    .line 1384
    .local p0, "clazz":Ljava/lang/Class;, "Ljava/lang/Class<*>;"
    invoke-virtual {p0}, Ljava/lang/Class;->newInstance()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroid/app/Application;

    .line 1385
    .local v0, "app":Landroid/app/Application;
    invoke-virtual {v0, p1}, Landroid/app/Application;->attach(Landroid/content/Context;)V

    .line 1386
    return-object v0
.end method

--- method ---
.method public whitelist newApplication(Ljava/lang/ClassLoader;Ljava/lang/String;Landroid/content/Context;)Landroid/app/Application;
    .registers 5
    .param p1, "cl"    # Ljava/lang/ClassLoader;
    .param p2, "className"    # Ljava/lang/String;
    .param p3, "context"    # Landroid/content/Context;
    .annotation system Ldalvik/annotation/Throws;
        value = {
            Ljava/lang/InstantiationException;,
            Ljava/lang/IllegalAccessException;,
            Ljava/lang/ClassNotFoundException;
        }
    .end annotation

    .line 1366
    invoke-virtual {p3}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    move-result-object v0

    invoke-direct {p0, v0}, Landroid/app/Instrumentation;->getFactory(Ljava/lang/String;)Landroid/app/AppComponentFactory;

    move-result-object v0

    .line 1367
    invoke-virtual {v0, p1, p2}, Landroid/app/AppComponentFactory;->instantiateApplication(Ljava/lang/ClassLoader;Ljava/lang/String;)Landroid/app/Application;

    move-result-object v0

    .line 1368
    .local v0, "app":Landroid/app/Application;
    invoke-virtual {v0, p3}, Landroid/app/Application;->attach(Landroid/content/Context;)V

    .line 1369
    return-object v0
.end method

```

### SystemProperties.get(String)
方法签名匹配: `get(Ljava/lang/String;)Ljava/lang/String;`
文件: `smali_classes3/android/os/SystemProperties.smali`

```smali
```

### SystemProperties.get(String, String)
方法签名匹配: `get(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;`
文件: `smali_classes3/android/os/SystemProperties.smali`

```smali
```

### SystemProperties.native_get (内部调用，确认寄存器)
方法签名匹配: `native_get`
文件: `smali_classes3/android/os/SystemProperties.smali`

```smali
--- method ---
.method static bridge synthetic blacklist -$$Nest$smnative_get(J)Ljava/lang/String;
    .registers 2

    invoke-static {p0, p1}, Landroid/os/SystemProperties;->native_get(J)Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method

--- method ---
.method static bridge synthetic blacklist -$$Nest$smnative_get_boolean(JZ)Z
    .registers 3

    invoke-static {p0, p1, p2}, Landroid/os/SystemProperties;->native_get_boolean(JZ)Z

    move-result p0

    return p0
.end method

--- method ---
.method static bridge synthetic blacklist -$$Nest$smnative_get_int(JI)I
    .registers 3

    invoke-static {p0, p1, p2}, Landroid/os/SystemProperties;->native_get_int(JI)I

    move-result p0

    return p0
.end method

--- method ---
.method static bridge synthetic blacklist -$$Nest$smnative_get_long(JJ)J
    .registers 4

    invoke-static {p0, p1, p2, p3}, Landroid/os/SystemProperties;->native_get_long(JJ)J

    move-result-wide p0

    return-wide p0
.end method

--- method ---
.method private static native blacklist native_get(J)Ljava/lang/String;
    .annotation build Ldalvik/annotation/optimization/FastNative;
    .end annotation
.end method

--- method ---
.method private static greylist native_get(Ljava/lang/String;)Ljava/lang/String;
    .registers 2
    .param p0, "key"    # Ljava/lang/String;

    .line 105
    const-string v0, ""

    invoke-static {p0, v0}, Landroid/os/SystemProperties;->native_get(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method

--- method ---
.method private static native greylist-max-p native_get(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;
    .annotation build Ldalvik/annotation/optimization/FastNative;
    .end annotation
.end method

--- method ---
.method private static native blacklist native_get_boolean(JZ)Z
    .annotation build Ldalvik/annotation/optimization/CriticalNative;
    .end annotation
.end method

--- method ---
.method private static native greylist-max-p native_get_boolean(Ljava/lang/String;Z)Z
    .annotation build Ldalvik/annotation/optimization/FastNative;
    .end annotation
.end method

--- method ---
.method private static native blacklist native_get_int(JI)I
    .annotation build Ldalvik/annotation/optimization/CriticalNative;
    .end annotation
.end method

--- method ---
.method private static native greylist-max-p native_get_int(Ljava/lang/String;I)I
    .annotation build Ldalvik/annotation/optimization/FastNative;
    .end annotation
.end method

--- method ---
.method private static native blacklist native_get_long(JJ)J
    .annotation build Ldalvik/annotation/optimization/CriticalNative;
    .end annotation
.end method

--- method ---
.method private static native greylist native_get_long(Ljava/lang/String;J)J
    .annotation build Ldalvik/annotation/optimization/FastNative;
    .end annotation
.end method

```

### KeyStore provider 类扫描（OEM 差异排查）

```
[classes3]
  android/security/AndroidKeyStoreMaintenance.smali
  android/security/KeyStore2$$ExternalSyntheticLambda0.smali
  android/security/KeyStore2$$ExternalSyntheticLambda1.smali
  android/security/KeyStore2$$ExternalSyntheticLambda2.smali
  android/security/KeyStore2$$ExternalSyntheticLambda3.smali
  android/security/KeyStore2$$ExternalSyntheticLambda4.smali
  android/security/KeyStore2$$ExternalSyntheticLambda5.smali
  android/security/KeyStore2$$ExternalSyntheticLambda6.smali
  android/security/KeyStore2$$ExternalSyntheticLambda7.smali
  android/security/KeyStore2$$ExternalSyntheticLambda8.smali
  android/security/KeyStore2$$ExternalSyntheticLambda9.smali
  android/security/KeyStore2$CheckedRemoteRequest.smali
  android/security/KeyStore2.smali
  android/security/KeyStore2HalVersion$$ExternalSyntheticLambda0.smali
  android/security/KeyStore2HalVersion.smali
  android/security/KeyStoreAuthorization.smali
  android/security/KeyStoreException$PublicErrorCode.smali
  android/security/KeyStoreException$PublicErrorInformation.smali
  android/security/KeyStoreException$RetryPolicy.smali
  android/security/KeyStoreException.smali
  android/security/KeyStoreOperation$$ExternalSyntheticLambda0.smali
  android/security/KeyStoreOperation$$ExternalSyntheticLambda1.smali
  android/security/KeyStoreOperation$$ExternalSyntheticLambda2.smali
  android/security/KeyStoreOperation$$ExternalSyntheticLambda3.smali
  android/security/KeyStoreOperation.smali
  android/security/KeyStoreParameter$Builder.smali
  android/security/KeyStoreParameter-IA.smali
  android/security/KeyStoreParameter.smali
  android/security/KeyStoreSecurityLevel$$ExternalSyntheticLambda0.smali
  android/security/KeyStoreSecurityLevel$$ExternalSyntheticLambda1.smali
  android/security/KeyStoreSecurityLevel$$ExternalSyntheticLambda2.smali
  android/security/KeyStoreSecurityLevel.smali
  android/security/keystore/AndroidKeyStoreProvider.smali
  android/security/keystore/KeyStoreConnectException.smali
  android/security/keystore/KeyStoreCryptoOperation.smali
  android/security/keystore/KeyStoreManager$SupplementaryAttestationInfoTagEnum.smali
  android/security/keystore/KeyStoreManager.smali
  android/security/keystore2/AndroidKeyStore3DESCipherSpi$CBC$NoPadding.smali
  android/security/keystore2/AndroidKeyStore3DESCipherSpi$CBC$PKCS7Padding.smali
  android/security/keystore2/AndroidKeyStore3DESCipherSpi$CBC.smali
  android/security/keystore2/AndroidKeyStore3DESCipherSpi$ECB$NoPadding.smali
  android/security/keystore2/AndroidKeyStore3DESCipherSpi$ECB$PKCS7Padding.smali
  android/security/keystore2/AndroidKeyStore3DESCipherSpi$ECB.smali
  android/security/keystore2/AndroidKeyStore3DESCipherSpi.smali
  android/security/keystore2/AndroidKeyStoreAuthenticatedAESCipherSpi$AdditionalAuthenticationDataStream.smali
  android/security/keystore2/AndroidKeyStoreAuthenticatedAESCipherSpi$BufferAllOutputUntilDoFinalStreamer.smali
  android/security/keystore2/AndroidKeyStoreAuthenticatedAESCipherSpi$GCM$NoPadding.smali
  android/security/keystore2/AndroidKeyStoreAuthenticatedAESCipherSpi$GCM.smali
  android/security/keystore2/AndroidKeyStoreAuthenticatedAESCipherSpi-IA.smali
  android/security/keystore2/AndroidKeyStoreAuthenticatedAESCipherSpi.smali
  android/security/keystore2/AndroidKeyStoreBCWorkaroundProvider.smali
  android/security/keystore2/AndroidKeyStoreCipherSpiBase.smali
  android/security/keystore2/AndroidKeyStoreECDSASignatureSpi$Ed25519.smali
  android/security/keystore2/AndroidKeyStoreECDSASignatureSpi$NONE$TruncateToFieldSizeMessageStreamer.smali
  android/security/keystore2/AndroidKeyStoreECDSASignatureSpi$NONE.smali
  android/security/keystore2/AndroidKeyStoreECDSASignatureSpi$SHA1.smali
  android/security/keystore2/AndroidKeyStoreECDSASignatureSpi$SHA224.smali
  android/security/keystore2/AndroidKeyStoreECDSASignatureSpi$SHA256.smali
  android/security/keystore2/AndroidKeyStoreECDSASignatureSpi$SHA384.smali
  android/security/keystore2/AndroidKeyStoreECDSASignatureSpi$SHA512.smali
  android/security/keystore2/AndroidKeyStoreECDSASignatureSpi-IA.smali
  android/security/keystore2/AndroidKeyStoreECDSASignatureSpi.smali
  android/security/keystore2/AndroidKeyStoreECPrivateKey.smali
  android/security/keystore2/AndroidKeyStoreECPublicKey.smali
  android/security/keystore2/AndroidKeyStoreEdECPrivateKey.smali
  android/security/keystore2/AndroidKeyStoreEdECPublicKey.smali
  android/security/keystore2/AndroidKeyStoreHmacSpi$HmacSHA1.smali
  android/security/keystore2/AndroidKeyStoreHmacSpi$HmacSHA224.smali
  android/security/keystore2/AndroidKeyStoreHmacSpi$HmacSHA256.smali
  android/security/keystore2/AndroidKeyStoreHmacSpi$HmacSHA384.smali
  android/security/keystore2/AndroidKeyStoreHmacSpi$HmacSHA512.smali
  android/security/keystore2/AndroidKeyStoreHmacSpi.smali
  android/security/keystore2/AndroidKeyStoreKey.smali
  android/security/keystore2/AndroidKeyStoreKeyAgreementSpi$ECDH.smali
  android/security/keystore2/AndroidKeyStoreKeyAgreementSpi$XDH.smali
  android/security/keystore2/AndroidKeyStoreKeyAgreementSpi.smali
  android/security/keystore2/AndroidKeyStoreKeyFactorySpi.smali
  android/security/keystore2/AndroidKeyStoreKeyGeneratorSpi$$ExternalSyntheticLambda0.smali
  android/security/keystore2/AndroidKeyStoreKeyGeneratorSpi$$ExternalSyntheticLambda1.smali
  android/security/keystore2/AndroidKeyStoreKeyGeneratorSpi$$ExternalSyntheticLambda2.smali
  android/security/keystore2/AndroidKeyStoreKeyGeneratorSpi$$ExternalSyntheticLambda3.smali
  android/security/keystore2/AndroidKeyStoreKeyGeneratorSpi$AES.smali
  android/security/keystore2/AndroidKeyStoreKeyGeneratorSpi$DESede.smali
  android/security/keystore2/AndroidKeyStoreKeyGeneratorSpi$HmacBase.smali
  android/security/keystore2/AndroidKeyStoreKeyGeneratorSpi$HmacSHA1.smali
  android/security/keystore2/AndroidKeyStoreKeyGeneratorSpi$HmacSHA224.smali
  android/security/keystore2/AndroidKeyStoreKeyGeneratorSpi$HmacSHA256.smali
  android/security/keystore2/AndroidKeyStoreKeyGeneratorSpi$HmacSHA384.smali
  android/security/keystore2/AndroidKeyStoreKeyGeneratorSpi$HmacSHA512.smali
  android/security/keystore2/AndroidKeyStoreKeyGeneratorSpi.smali
  android/security/keystore2/AndroidKeyStoreKeyPairGeneratorSpi$$ExternalSyntheticLambda0.smali
  android/security/keystore2/AndroidKeyStoreKeyPairGeneratorSpi$$ExternalSyntheticLambda1.smali
  android/security/keystore2/AndroidKeyStoreKeyPairGeneratorSpi$$ExternalSyntheticLambda2.smali
  android/security/keystore2/AndroidKeyStoreKeyPairGeneratorSpi$$ExternalSyntheticLambda3.smali
  android/security/keystore2/AndroidKeyStoreKeyPairGeneratorSpi$$ExternalSyntheticLambda4.smali
  android/security/keystore2/AndroidKeyStoreKeyPairGeneratorSpi$$ExternalSyntheticLambda5.smali
  android/security/keystore2/AndroidKeyStoreKeyPairGeneratorSpi$$ExternalSyntheticLambda6.smali
  android/security/keystore2/AndroidKeyStoreKeyPairGeneratorSpi$$ExternalSyntheticLambda7.smali
  android/security/keystore2/AndroidKeyStoreKeyPairGeneratorSpi$EC.smali
  android/security/keystore2/AndroidKeyStoreKeyPairGeneratorSpi$ED25519.smali
  android/security/keystore2/AndroidKeyStoreKeyPairGeneratorSpi$RSA.smali
  android/security/keystore2/AndroidKeyStoreKeyPairGeneratorSpi$XDH.smali
  android/security/keystore2/AndroidKeyStoreKeyPairGeneratorSpi.smali
  android/security/keystore2/AndroidKeyStoreLoadStoreParameter.smali
  android/security/keystore2/AndroidKeyStorePrivateKey.smali
  android/security/keystore2/AndroidKeyStoreProvider.smali
  android/security/keystore2/AndroidKeyStorePublicKey.smali
  android/security/keystore2/AndroidKeyStoreRSACipherSpi$NoPadding.smali
  android/security/keystore2/AndroidKeyStoreRSACipherSpi$OAEPWithMGF1Padding.smali
  android/security/keystore2/AndroidKeyStoreRSACipherSpi$OAEPWithSHA1AndMGF1Padding.smali
  android/security/keystore2/AndroidKeyStoreRSACipherSpi$OAEPWithSHA224AndMGF1Padding.smali
  android/security/keystore2/AndroidKeyStoreRSACipherSpi$OAEPWithSHA256AndMGF1Padding.smali
  android/security/keystore2/AndroidKeyStoreRSACipherSpi$OAEPWithSHA384AndMGF1Padding.smali
  android/security/keystore2/AndroidKeyStoreRSACipherSpi$OAEPWithSHA512AndMGF1Padding.smali
  android/security/keystore2/AndroidKeyStoreRSACipherSpi$PKCS1Padding.smali
  android/security/keystore2/AndroidKeyStoreRSACipherSpi.smali
  android/security/keystore2/AndroidKeyStoreRSAPrivateKey.smali
  android/security/keystore2/AndroidKeyStoreRSAPublicKey.smali
  android/security/keystore2/AndroidKeyStoreRSASignatureSpi$MD5WithPKCS1Padding.smali
  android/security/keystore2/AndroidKeyStoreRSASignatureSpi$NONEWithPKCS1Padding.smali
  android/security/keystore2/AndroidKeyStoreRSASignatureSpi$PKCS1Padding.smali
  android/security/keystore2/AndroidKeyStoreRSASignatureSpi$PSSPadding.smali
  android/security/keystore2/AndroidKeyStoreRSASignatureSpi$SHA1WithPKCS1Padding.smali
  android/security/keystore2/AndroidKeyStoreRSASignatureSpi$SHA1WithPSSPadding.smali
  android/security/keystore2/AndroidKeyStoreRSASignatureSpi$SHA224WithPKCS1Padding.smali
  android/security/keystore2/AndroidKeyStoreRSASignatureSpi$SHA224WithPSSPadding.smali
  android/security/keystore2/AndroidKeyStoreRSASignatureSpi$SHA256WithPKCS1Padding.smali
  android/security/keystore2/AndroidKeyStoreRSASignatureSpi$SHA256WithPSSPadding.smali
  android/security/keystore2/AndroidKeyStoreRSASignatureSpi$SHA384WithPKCS1Padding.smali
  android/security/keystore2/AndroidKeyStoreRSASignatureSpi$SHA384WithPSSPadding.smali
  android/security/keystore2/AndroidKeyStoreRSASignatureSpi$SHA512WithPKCS1Padding.smali
  android/security/keystore2/AndroidKeyStoreRSASignatureSpi$SHA512WithPSSPadding.smali
  android/security/keystore2/AndroidKeyStoreRSASignatureSpi.smali
  android/security/keystore2/AndroidKeyStoreSecretKey.smali
  android/security/keystore2/AndroidKeyStoreSecretKeyFactorySpi.smali
  android/security/keystore2/AndroidKeyStoreSignatureSpiBase.smali
  android/security/keystore2/AndroidKeyStoreSpi$$ExternalSyntheticLambda0.smali
  android/security/keystore2/AndroidKeyStoreSpi$$ExternalSyntheticLambda1.smali
  android/security/keystore2/AndroidKeyStoreSpi$KeyEntriesEnumerator.smali
  android/security/keystore2/AndroidKeyStoreSpi-IA.smali
  android/security/keystore2/AndroidKeyStoreSpi.smali
  android/security/keystore2/AndroidKeyStoreUnauthenticatedAESCipherSpi$CBC$NoPadding.smali
  android/security/keystore2/AndroidKeyStoreUnauthenticatedAESCipherSpi$CBC$PKCS7Padding.smali
  android/security/keystore2/AndroidKeyStoreUnauthenticatedAESCipherSpi$CBC.smali
  android/security/keystore2/AndroidKeyStoreUnauthenticatedAESCipherSpi$CTR$NoPadding.smali
  android/security/keystore2/AndroidKeyStoreUnauthenticatedAESCipherSpi$CTR.smali
  android/security/keystore2/AndroidKeyStoreUnauthenticatedAESCipherSpi$ECB$NoPadding.smali
  android/security/keystore2/AndroidKeyStoreUnauthenticatedAESCipherSpi$ECB$PKCS7Padding.smali
  android/security/keystore2/AndroidKeyStoreUnauthenticatedAESCipherSpi$ECB.smali
  android/security/keystore2/AndroidKeyStoreUnauthenticatedAESCipherSpi.smali
  android/security/keystore2/AndroidKeyStoreXDHPrivateKey.smali
  android/security/keystore2/AndroidKeyStoreXDHPublicKey.smali
  android/security/keystore2/KeyStore2ParameterUtils.smali
  android/security/keystore2/KeyStoreCryptoOperationChunkedStreamer$MainDataStream.smali
  android/security/keystore2/KeyStoreCryptoOperationChunkedStreamer$Stream.smali
  android/security/keystore2/KeyStoreCryptoOperationChunkedStreamer.smali
  android/security/keystore2/KeyStoreCryptoOperationStreamer.smali
  android/security/keystore2/KeyStoreCryptoOperationUtils.smali
  android/security/net/config/KeyStoreCertificateSource.smali
  android/security/net/config/KeyStoreConfigSource.smali
```

## 5. 重新打包参数

- 反编译命令: `java -jar baksmali.jar d <dex> -o <out_dir>`
- 重新打包命令: `java -jar smali.jar a -a <API_LEVEL> <out_dir> -o <dex>`
- API level 参考: Android 15 = 35, Android 16 = 36
- 你的设备 SDK: 36

## 6. 下一步

1. 把本报告 (`report/ADAPT_REPORT.md`) 内容发给上游
2. 上游根据第 4 节 smali 片段，给出每个 hook 点的精确 patch 代码
3. 按 README 流程：baksmali → 改 smali → smali a 重打包 → 注入 framework.jar

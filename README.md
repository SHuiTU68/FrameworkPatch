# Framework Patch
Modify framework.jar to build a valid certificate chain.

> 适配 Android 15 / 16（compileSdk 35，AGP 8.7.3 / Gradle 8.9）。
> Keybox 改为从 `keybox.xml` 自动生成，构建指纹内置 OnePlus 13 / Pixel 9 Pro XL + 自定义占位。

## Requirements
- Intermediate Windows and Linux knowledge.
- Intermediate Java and Smali knowledge.
- WSL (only in Windows).
- Java 17.
- 7zip.

In GNU/Linux distro, install this packages (I use Ubuntu in WSL2):
```
sudo apt update
sudo apt full-upgrade -y
sudo apt install -y default-jdk zipalign
```

## Keybox 配置（重要）
本项目的 `Keybox.java` 不再硬编码在源码里，而是由 Gradle 任务 `generateKeybox` 在编译时从 XML 自动生成。

1. 准备你的 `keybox.xml`（硬件证明模块通用的格式，含 EC/RSA 私钥与证书链）。
2. 把它放到**项目根目录**（与 `settings.gradle.kts` 同级）。
3. 构建时会自动解析并生成 `Keybox.java`。

- `keybox.xml` 已被 `.gitignore` 忽略，**不会被提交**，避免泄露私钥。
- 若根目录没有 `keybox.xml`，会回退到 `keybox.xml.example`（仅测试密钥，无法通过 STRONG_INTEGRITY）。
- 也可手动触发：`./gradlew generateKeybox`。

`keybox.xml` 格式：
```xml
<?xml version="1.0"?>
<Keybox>
    <Key algorithm="ec">
        <PrivateKey format="pem">-----BEGIN EC PRIVATE KEY----- ... -----END EC PRIVATE KEY-----</PrivateKey>
        <CertificateChain>
            <Certificate format="pem">-----BEGIN CERTIFICATE----- ... -----END CERTIFICATE-----</Certificate>
            <Certificate format="pem">-----BEGIN CERTIFICATE----- ... -----END CERTIFICATE-----</Certificate>
        </CertificateChain>
    </Key>
    <Key algorithm="rsa"> ... </Key>
</Keybox>
```

## 设备指纹切换
`Android.java` 顶部 `ACTIVE_PROFILE` 控制对 GMS unstable 进程伪装的指纹：
- `0` — OnePlus 13 (Android 16)（默认）
- `1` — Pixel 9 Pro XL (Android 16)
- `2` — 占位，填入你自己的指纹

修改该常量后重新构建即可。

## CI 自动构建
`.github/workflows/build.yml` 在推送到 `main` 分支（或手动触发）时：
1. 从仓库 secret `KEYBOX_XML`（如有配置）恢复真实 `keybox.xml`；
2. 构建 release APK，解出 `classes.dex`；
3. 把 `release/`（含 `classes.dex`、`app-release.apk`、说明）**直接 commit 到 `main` 分支**（不提 PR）。

配置真实密钥：仓库 Settings → Secrets and variables → Actions → 新增 `KEYBOX_XML`（整个 XML 文件内容）。
未配置时使用测试密钥构建。

## SystemRW
To make system rw you can use @lebigmac scripts: https://systemrw.com/download.php

For my vayu, I used this: https://mega.nz/file/TQ42WApL#ky3OzPwEKQeKrFGJYygqEr07zsidEqYAd7lSu9-ceEM

FLASH IN CUSTOM RECOVERY.
AFTER FLASHING; REBOOT TO RECOVERY AGAIN TO START MODIFYING SYSTEM.

## Tutorial
First, cd to a working (and clean) directory.

Pull framework.jar from your device:
```
adb pull /system/framework/framework.jar
```

Now, compile [smali](https://github.com/google/smali):
(Use WSL if you are in Windows)
```
git clone --depth=1 https://github.com/google/smali.git
cd smali
./gradlew build
```

Then pick smali and baksmali fatJars and paste to working dir.

Using 7zip extract framework.jar to framework/ directory.

Now using [jadx](https://github.com/skylot/jadx) open framework.jar and check these classes:
- android.security.keystore2.AndroidKeyStoreSpi
- android.app.Instrumentation

You must check in where .dex they are, you can know by checking upper text in class declaration, something like this:
```
/* loaded from: classes3.dex */
public class AndroidKeyStoreSpi extends KeyStoreSpi

/* loaded from: classes.dex */
public class Instrumentation 
````

Now using baksmali.jar, decompile that .dex files:
```
java -jar baksmali.jar d framework/classes3.dex -o classes3
java -jar baksmali.jar d framework/classes.dex -o classes
```

After .dex files are decompiled, you must search in folders for this files and modify like this:

- AndroidKeyStoreSpi.smali:

Search for method "engineGetCertificateChain" and near the end should be a line like this:
```
const/4 v4, 0x0
aput-object v2, v3, v4
return-object v3
```

In this example:

v2 -> leaf cert.
v3 -> certificate chain.
v4 -> 0, the position to insert the leaf cert in certificate chain.

It may be different in your .smali file. Do not copy and paste...

After aput operation, you must add this:
```
invoke-static {XX}, Lcom/android/internal/util/framework/Android;->engineGetCertificateChain([Ljava/security/cert/Certificate;)[Ljava/security/cert/Certificate;
move-result-object XX
```

Replace XX with the leaf certificate register.

So the final code (in this example) should be this:
```
const/4 v4, 0x0
aput-object v2, v3, v4
invoke-static {v3}, Lcom/android/internal/util/framework/Android;->engineGetCertificateChain([Ljava/security/cert/Certificate;)[Ljava/security/cert/Certificate;
move-result-object v3
return-object v3
```

- Instrumentation.smali:

Search for "newApplication" methods and before the return operation, add this:
```
invoke-static {XX}, Lcom/android/internal/util/framework/Android;->newApplication(Landroid/content/Context;)V
```

Replace XX with the Context register.

- SystemProperties.smali (prop 级隐藏，可选但强烈推荐):

> 这一步在 GMS unstable 进程内伪装 `ro.boot.verifiedbootstate` / `ro.boot.flash.locked` / `ro.boot.vbmeta.device_state` 等 BL 锁相关 prop，避免 DroidGuard 直接 `getprop` 暴露真实解锁状态。

SystemProperties 通常和 Instrumentation 在同一个 .dex（`classes.dex`）。找到 `android.os.SystemProperties` 里的两个 `get` 方法，在 `native_get` 返回后、`return-object` 前，插入后置 hook：

`get(Ljava/lang/String;)Ljava/lang/String;` 形如：
```
invoke-static {v0}, Landroid/os/SystemProperties;->native_get(Ljava/lang/String;)Ljava/lang/String;
move-result-object v1
invoke-static {v0, v1}, Lcom/android/internal/util/framework/Android;->systemPropertiesGet(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;
move-result-object v1
return-object v1
```
（`v0` = key 寄存器，`v1` = native_get 返回值寄存器；以你实际 smali 为准）

`get(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;` 形如：
```
invoke-static {v0, v1}, Landroid/os/SystemProperties;->native_get(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;
move-result-object v2
invoke-static {v0, v1, v2}, Lcom/android/internal/util/framework/Android;->systemPropertiesGet(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;
move-result-object v2
return-object v2
```
（`v0` = key，`v1` = def，`v2` = native_get 返回值；以你实际 smali 为准）

> 仅在 GMS unstable 进程生效，其他进程零开销（hook 内部用 `spoofEnabled` 短路）。

Now compile again the files:
```
java -jar smali.jar a -a {API_LEVEL} classes3 -o framework/classes3.dex
java -jar smali.jar a -a {API_LEVEL} classes -o framework/classes.dex
```

Replace {API_LEVEL} with the Android version you are running (Android 15 = 35, Android 16 = 36).

Then build the patch dex. 你不再需要手动改源码里的密钥——把你的 `keybox.xml` 放到项目根目录后：
```
./gradlew :app:assembleRelease
```
编译产物在 `app/build/outputs/apk/release/`，从中取出 `classes.dex`（也可直接用 CI 自动产出的 `release/classes.dex`）。

Now add a number greater than the one that already exists in the framework/.

For example, if the greatest number is classes5.dex, you must copy it as classes6.dex

Using 7zip recompile as .zip all framework/ files without compression.

After you have the framework.zip use zipalign:
```
zipalign -f -p -v -z 4 framework.zip framework.jar
```

Now move framework.jar to /system/framework, you can use Magisk module to replace it or mount /system as read-write and replace it.

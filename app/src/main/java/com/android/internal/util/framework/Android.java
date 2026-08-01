package com.android.internal.util.framework;

import android.app.Application;
import android.content.Context;
import android.os.Build;
import android.security.keystore.KeyProperties;
import android.util.Log;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.lsposed.lsparanoid.Obfuscate;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.StringReader;
import java.lang.reflect.Field;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;

@Obfuscate
public final class Android {
    private static final String TAG = "chiteroman";
    private static volatile boolean isGmsUnstable = false;

    // 设备指纹候选表。索引由编译期 -PactiveProfile=N 决定（见 ProfileConfig）。
    private static final int ACTIVE_PROFILE = ProfileConfig.ACTIVE_PROFILE;
    private static final List<HashMap<String, String>> PROFILES = new ArrayList<>();

    /**
     * BouncyCastle 懒加载 holder。
     *
     * 关键设计：Android.<clinit> 不引用 BCHolder，因此 JVM 不会在 Android 类初始化时
     * 触发 BCHolder.<clinit>。只有 attestation 方法（certificate / certificateChain /
     * engineGetCertificateChain）首次调用时才会访问 BCHolder.xxx，此时才加载 BouncyCastle。
     *
     * 背景：frameworkpatch.dex 在 boot classpath，Instrumentation.newApplication 被 hook
     * 后，每个进程启动都会触发 Android.<clinit>。若 <clinit> 内有 BouncyCastle 类引用，
     * 会导致百毫秒级重活或 ExceptionInInitializerError，直接卡死系统进程
     * （负一屏卡死 → system_server watchdog → 重启即此症状）。
     */
    private static final class BCHolder {
        static final ASN1ObjectIdentifier OID = new ASN1ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17");
        static final CertificateFactory certificateFactory;
        static final JcaX509CertificateConverter CERT_CONVERTER = new JcaX509CertificateConverter();
        static final JcaPEMKeyConverter KEY_CONVERTER = new JcaPEMKeyConverter();
        static PEMKeyPair EC, RSA;
        static final List<Certificate> EC_CERTS = new ArrayList<>();
        static final List<Certificate> RSA_CERTS = new ArrayList<>();
        static X509CertificateHolder EC_ROOT_HOLDER;
        static X509CertificateHolder RSA_ROOT_HOLDER;
        static volatile boolean ready = false;
        static volatile boolean failed = false;

        static {
            try {
                EC = parseKeyPair(Keybox.EC.PRIVATE_KEY);
                for (String c : Keybox.EC.CERTIFICATES) EC_CERTS.add(parseCert(c));

                RSA = parseKeyPair(Keybox.RSA.PRIVATE_KEY);
                for (String c : Keybox.RSA.CERTIFICATES) RSA_CERTS.add(parseCert(c));

                EC_ROOT_HOLDER = new X509CertificateHolder(EC_CERTS.get(0).getEncoded());
                RSA_ROOT_HOLDER = new X509CertificateHolder(RSA_CERTS.get(0).getEncoded());
                certificateFactory = CertificateFactory.getInstance("X.509");
                ready = true;
            } catch (Throwable t) {
                Log.e("chiteroman", "keybox init failed: " + t);
                failed = true;
                // 不 throw：类在 boot classpath，<clinit> 抛异常会让调用方进程崩溃
            }
        }

        private static PEMKeyPair parseKeyPair(String key) throws Throwable {
            try (PEMParser parser = new PEMParser(new StringReader(key))) {
                return (PEMKeyPair) parser.readObject();
            }
        }

        private static Certificate parseCert(String cert) throws Throwable {
            PemObject pemObject;
            try (PemReader reader = new PemReader(new StringReader(cert))) {
                pemObject = reader.readPemObject();
            }
            return CERT_CONVERTER.getCertificate(new X509CertificateHolder(pemObject.getContent()));
        }
    }

    static {
        // Profile 0 — OnePlus Ace 5 至尊版 (PLC110, Android 16)
        PROFILES.add(buildProfile(
                "OnePlus", "OnePlus", "PLC110", "OP60EDL1", "PLC110",
                "OnePlus/PLC110/OP60EDL1:16/BP2A.250605.015/V.1be4275_8cb9c6_8ac72d:user/release-keys",
                "16", "BP2A.250605.015", "V.1be4275_8cb9c6_8ac72d",
                "2025-06-05", "user", "release-keys",
                "",  // BOARD
                "",  // BOOTLOADER
                "",  // HARDWARE
                "",  // HOST
                "")); // RADIO

        // Profile 1 — Pixel 9 Pro XL (Android 16)
        PROFILES.add(buildProfile(
                "Google", "google", "komodo", "komodo", "Pixel 9 Pro XL",
                "google/komodo/komodo:16/BP2A.250605.031/13740072:user/release-keys",
                "16", "BP2A.250605.031", "13740072",
                "2025-06-05", "user", "release-keys",
                "komodo", "sl-2.1-9528787", "zuma", "", "g5300q"));

        // Profile 2 — 占位：填入你自己的设备指纹
        PROFILES.add(buildProfile(
                "", "", "", "", "",
                "",
                "", "", "",
                "", "", "",
                "", "", "", "", ""));
    }

    private static HashMap<String, String> buildProfile(
            String manufacturer, String brand, String device, String product, String model,
            String fingerprint, String release, String id, String incremental,
            String securityPatch, String type, String tags,
            String board, String bootloader, String hardware, String host, String radio) {
        HashMap<String, String> m = new HashMap<>();
        m.put("MANUFACTURER", manufacturer);
        m.put("BRAND", brand);
        m.put("DEVICE", device);
        m.put("PRODUCT", product);
        m.put("MODEL", model);
        m.put("FINGERPRINT", fingerprint);
        m.put("RELEASE", release);
        m.put("ID", id);
        m.put("INCREMENTAL", incremental);
        m.put("SECURITY_PATCH", securityPatch);
        m.put("TYPE", type);
        m.put("TAGS", tags);
        m.put("BOARD", board);
        m.put("BOOTLOADER", bootloader);
        m.put("HARDWARE", hardware);
        m.put("HOST", host);
        m.put("RADIO", radio);
        return m;
    }

    public static byte[] certificateChain(byte[] bytes) {
        if (bytes == null) return null;
        if (BCHolder.failed) return bytes;
        try {
            LinkedList<Certificate> certificates = new LinkedList<>(BCHolder.certificateFactory.generateCertificates(new ByteArrayInputStream(bytes)));

            X509Certificate x509Certificate = (X509Certificate) certificates.getFirst();

            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

            if (KeyProperties.KEY_ALGORITHM_EC.equals(x509Certificate.getPublicKey().getAlgorithm())) {
                for (Certificate c : BCHolder.EC_CERTS) {
                    byteArrayOutputStream.write(c.getEncoded());
                }
            } else {
                for (Certificate c : BCHolder.RSA_CERTS) {
                    byteArrayOutputStream.write(c.getEncoded());
                }
            }

            return byteArrayOutputStream.toByteArray();

        } catch (Throwable t) {
            Log.e(TAG, t.toString());
        }
        return bytes;
    }

    public static byte[] certificate(byte[] bytes) {
        if (bytes == null) return null;
        if (BCHolder.failed) return bytes;
        try {
            X509CertificateHolder holder = new X509CertificateHolder(bytes);

            if (!"CN=Android Keystore Key".equals(holder.getSubject().toString())) return bytes;

            X509Certificate leaf = BCHolder.CERT_CONVERTER.getCertificate(holder);

            Extension ext = holder.getExtension(BCHolder.OID);

            if (ext == null) return bytes;

            ASN1Sequence sequence = ASN1Sequence.getInstance(ext.getExtnValue().getOctets());

            ASN1Encodable[] encodables = sequence.toArray();

            ASN1Sequence teeEnforced = (ASN1Sequence) encodables[7];

            ASN1EncodableVector vector = buildHackedEnforced(teeEnforced);

            encodables[7] = new DERSequence(vector);

            ASN1Sequence hackedSeq = new DERSequence(encodables);

            ASN1OctetString hackedSeqOctets = new DEROctetString(hackedSeq);

            Extension hackedExt = new Extension(BCHolder.OID, false, hackedSeqOctets);

            X509v3CertificateBuilder builder;
            ContentSigner signer;

            if (!isGmsUnstable && KeyProperties.KEY_ALGORITHM_EC.equals(leaf.getPublicKey().getAlgorithm())) {
                builder = new X509v3CertificateBuilder(BCHolder.EC_ROOT_HOLDER.getSubject(), holder.getSerialNumber(), holder.getNotBefore(), holder.getNotAfter(), holder.getSubject(), BCHolder.EC.getPublicKeyInfo());
                signer = new JcaContentSignerBuilder(leaf.getSigAlgName()).build(BCHolder.KEY_CONVERTER.getPrivateKey(BCHolder.EC.getPrivateKeyInfo()));
            } else {
                builder = new X509v3CertificateBuilder(BCHolder.RSA_ROOT_HOLDER.getSubject(), holder.getSerialNumber(), holder.getNotBefore(), holder.getNotAfter(), holder.getSubject(), BCHolder.RSA.getPublicKeyInfo());
                signer = new JcaContentSignerBuilder("SHA256withRSA").build(BCHolder.KEY_CONVERTER.getPrivateKey(BCHolder.RSA.getPrivateKeyInfo()));
            }

            for (ASN1ObjectIdentifier extensionOID : holder.getExtensions().getExtensionOIDs()) {
                if (BCHolder.OID.getId().equals(extensionOID.getId())) continue;
                builder.addExtension(holder.getExtension(extensionOID));
            }

            builder.addExtension(hackedExt);

            return builder.build(signer).getEncoded();

        } catch (Throwable t) {
            Log.e(TAG, t.toString());
        }
        return bytes;
    }

    public static Certificate[] engineGetCertificateChain(Certificate[] caList) {
        if (caList == null) return null;
        if (caList.length < 4) return caList;
        if (BCHolder.failed) return caList;
        try {
            X509CertificateHolder holder = new X509CertificateHolder(caList[0].getEncoded());

            if (!"CN=Android Keystore Key".equals(holder.getSubject().toString())) return caList;

            X509Certificate leaf = BCHolder.CERT_CONVERTER.getCertificate(holder);

            Extension ext = holder.getExtension(BCHolder.OID);

            if (ext == null) return caList;

            ASN1Sequence sequence = ASN1Sequence.getInstance(ext.getExtnValue().getOctets());

            ASN1Encodable[] encodables = sequence.toArray();

            ASN1Sequence teeEnforced = (ASN1Sequence) encodables[7];

            ASN1EncodableVector vector = buildHackedEnforced(teeEnforced);

            encodables[7] = new DERSequence(vector);

            ASN1Sequence hackedSeq = new DERSequence(encodables);

            ASN1OctetString hackedSeqOctets = new DEROctetString(hackedSeq);

            Extension hackedExt = new Extension(BCHolder.OID, false, hackedSeqOctets);

            X509v3CertificateBuilder builder;
            ContentSigner signer;

            LinkedList<Certificate> certs;

            if (!isGmsUnstable && KeyProperties.KEY_ALGORITHM_EC.equals(leaf.getPublicKey().getAlgorithm())) {
                certs = new LinkedList<>(BCHolder.EC_CERTS);
                builder = new X509v3CertificateBuilder(BCHolder.EC_ROOT_HOLDER.getSubject(), holder.getSerialNumber(), holder.getNotBefore(), holder.getNotAfter(), holder.getSubject(), BCHolder.EC.getPublicKeyInfo());
                signer = new JcaContentSignerBuilder(leaf.getSigAlgName()).build(BCHolder.KEY_CONVERTER.getPrivateKey(BCHolder.EC.getPrivateKeyInfo()));
            } else {
                certs = new LinkedList<>(BCHolder.RSA_CERTS);
                builder = new X509v3CertificateBuilder(BCHolder.RSA_ROOT_HOLDER.getSubject(), holder.getSerialNumber(), holder.getNotBefore(), holder.getNotAfter(), holder.getSubject(), BCHolder.RSA.getPublicKeyInfo());
                signer = new JcaContentSignerBuilder("SHA256withRSA").build(BCHolder.KEY_CONVERTER.getPrivateKey(BCHolder.RSA.getPrivateKeyInfo()));
            }

            for (ASN1ObjectIdentifier extensionOID : holder.getExtensions().getExtensionOIDs()) {
                if (BCHolder.OID.getId().equals(extensionOID.getId())) continue;
                builder.addExtension(holder.getExtension(extensionOID));
            }

            builder.addExtension(hackedExt);

            certs.addFirst(BCHolder.CERT_CONVERTER.getCertificate(builder.build(signer)));

            return certs.toArray(Certificate[]::new);

        } catch (Throwable t) {
            Log.e(TAG, t.toString());
        }
        return caList;
    }

    /**
     * 重建 teeEnforced：移除真实 rootOfTrust(704) 与 GMS 不稳定的特征 tag，
     * 注入伪造的 rootOfTrust（deviceLocked=true, verifiedBootState=0=Verified）。
     *
     * verifiedBootKey / verifiedBootHash 用确定性值而非每次随机：
     * 服务端有真实设备 VB key 数据库，纯随机值永不匹配且自身不稳定，是已知检测向量。
     * 这里用全零（部分设备在 Verified 状态下报告此值），保证一致性。
     */
    private static ASN1EncodableVector buildHackedEnforced(ASN1Sequence teeEnforced) {
        ASN1EncodableVector vector = new ASN1EncodableVector(teeEnforced.size());
        for (ASN1Encodable asn1Encodable : teeEnforced) {
            ASN1TaggedObject taggedObject = (ASN1TaggedObject) asn1Encodable;

            int tag = taggedObject.getTagNo();

            if (isGmsUnstable)
                if (tag == 710 || tag == 711 || tag == 712 || tag == 716 || tag == 717)
                    continue;

            if (tag == 704) continue;
            vector.add(taggedObject);
        }

        // 确定性 verifiedBootKey/Hash，避免随机值被服务端识别
        byte[] verifiedBootKey = new byte[32];
        byte[] verifiedBootHash = new byte[32];
        // 全零表示「无自定义 key 验证」，部分 Verified 设备报告此值，一致性优先

        ASN1Encodable[] rootOfTrustEnc = {new DEROctetString(verifiedBootKey), ASN1Boolean.TRUE, new ASN1Enumerated(0), new DEROctetString(verifiedBootHash)};

        ASN1Sequence rootOfTrustSeq = new DERSequence(rootOfTrustEnc);

        ASN1TaggedObject rootOfTrustTagObj = new DERTaggedObject(704, rootOfTrustSeq);

        vector.add(rootOfTrustTagObj);
        return vector;
    }

    private static Field getFieldByName(String name) {
        Field field;
        try {
            field = Build.class.getDeclaredField(name);
        } catch (NoSuchFieldException e) {
            try {
                field = Build.VERSION.class.getDeclaredField(name);
            } catch (NoSuchFieldException ex) {
                return null;
            }
        }
        field.setAccessible(true);
        return field;
    }

    public static void newApplication(Context context) {
        if (context == null) return;

        final String packageName = context.getPackageName();
        final String processName = Application.getProcessName();

        if (packageName != null && processName != null && packageName.equals("com.google.android.gms") && processName.equals("com.google.android.gms.unstable")) {
            isGmsUnstable = true;
            try {
                HashMap<String, String> profile = PROFILES.get(ACTIVE_PROFILE);
                if (profile.get("FINGERPRINT").isEmpty()) {
                    // 当前激活的指纹为空（占位），不进行 spoof，避免写入空值导致异常
                    return;
                }
                profile.forEach((s, s2) -> {
                    if (s2 == null || s2.isEmpty()) return;
                    Field field = getFieldByName(s);
                    if (field == null) return;
                    try {
                        field.set(null, s2);
                    } catch (Throwable t) {
                        Log.e(TAG, t.toString());
                    }
                });
            } catch (Throwable t) {
                Log.e(TAG, t.toString());
            }
        }
    }

    public static void onEngineGetCertificateChain() {
        isGmsUnstable = Arrays.stream(Thread.currentThread().getStackTrace()).anyMatch(e -> e.getClassName().toLowerCase(Locale.US).contains("droidguard"));
    }

    /**
     * PackageManager.hasSystemFeature 后置 hook。
     *
     * 不再强制对 FEATURE_KEYSTORE_APP_ATTEST_KEY 返回 false：
     * 现代 Pixel 9 / OnePlus 13 真机均具备该特性，返回 false 反而是
     * 与伪装机型不一致的检测向量。改为返回真机值，由证书链 hook 兜底。
     */
    public static boolean hasSystemFeature(boolean ret, String feature) {
        return ret;
    }
}

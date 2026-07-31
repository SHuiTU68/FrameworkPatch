import org.gradle.api.DefaultTask
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.tasks.InputFile
import org.gradle.api.tasks.OutputDirectory
import org.gradle.api.tasks.PathSensitive
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.TaskAction
import org.w3c.dom.Element
import javax.xml.parsers.DocumentBuilderFactory

plugins {
    id("com.android.application")
    id("org.lsposed.lsparanoid")
}

android {
    namespace = "com.android.internal.util.framework"
    compileSdk = 35

    packaging {
        resources {
            excludes += "META-INF/**"
        }
    }

    defaultConfig {
        applicationId = "com.android.internal.util.framework"
        minSdk = 35
        targetSdk = 35
        versionCode = 2
        versionName = "2.0"
        multiDexEnabled = false
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            multiDexEnabled = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    sourceSets {
        getByName("main") {
            // Keybox.java 由 generateKeybox 任务生成，仓库里不硬编码真实私钥
            java.srcDir(layout.buildDirectory.dir("generated/source/keybox"))
        }
    }
}

dependencies {
    implementation("org.bouncycastle:bcpkix-jdk18on:1.78.1")
}

/**
 * 解析项目根目录的 keybox.xml（硬件证明 Keybox，PEM 内嵌 XML），
 * 生成 Keybox.java（含 EC/RSA 私钥与证书链）。
 *
 * 若不存在 keybox.xml，则回退到 keybox.xml.example（仅测试密钥）。
 *
 * keybox.xml 格式：
 * <Keybox>
 *   <Key algorithm="ec">
 *     <PrivateKey format="pem">-----BEGIN EC PRIVATE KEY----- ... -----END EC PRIVATE KEY-----</PrivateKey>
 *     <CertificateChain>
 *       <Certificate format="pem">-----BEGIN CERTIFICATE----- ... -----END CERTIFICATE-----</Certificate>
 *       ...
 *     </CertificateChain>
 *   </Key>
 *   <Key algorithm="rsa"> ... </Key>
 * </Keybox>
 */
abstract class GenerateKeyboxTask : DefaultTask() {

    @get:InputFile
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val source: RegularFileProperty

    @get:OutputDirectory
    abstract val outputDir: DirectoryProperty

    @TaskAction
    fun generate() {
        val src = source.get().asFile
        if (!src.exists()) {
            throw GradleException("Neither keybox.xml nor keybox.xml.example found in project root.")
        }

        val dbf = DocumentBuilderFactory.newInstance().apply {
            try { setFeature("http://apache.org/xml/features/disallow-doctype-decl", true) } catch (_: Throwable) {}
            isExpandEntityReferences = false
        }
        val doc = dbf.newDocumentBuilder().parse(src)
        doc.documentElement.normalize()

        var ecPriv = ""
        val ecCerts = mutableListOf<String>()
        var rsaPriv = ""
        val rsaCerts = mutableListOf<String>()

        val keys = doc.getElementsByTagName("Key")
        for (i in 0 until keys.length) {
            val keyEl = keys.item(i) as Element
            val algo = keyEl.getAttribute("algorithm").trim().lowercase()
            val priv = keyEl.getElementsByTagName("PrivateKey").item(0).textContent.trim().trimIndent().trim()
            val certNodes = keyEl.getElementsByTagName("Certificate")
            val certs = mutableListOf<String>()
            for (j in 0 until certNodes.length) {
                certs.add(certNodes.item(j).textContent.trim().trimIndent().trim())
            }
            when (algo) {
                "ec" -> { ecPriv = priv; ecCerts.clear(); ecCerts.addAll(certs) }
                "rsa" -> { rsaPriv = priv; rsaCerts.clear(); rsaCerts.addAll(certs) }
            }
        }

        if (ecPriv.isBlank() || rsaPriv.isBlank() || ecCerts.isEmpty() || rsaCerts.isEmpty()) {
            throw GradleException("keybox.xml must contain both EC and RSA keys with at least one certificate each.")
        }

        val out = outputDir.get().asFile.apply { mkdirs() }
        out.resolve("Keybox.java").writeText(buildJava(ecPriv, ecCerts, rsaPriv, rsaCerts))
    }

    private fun textBlock(content: String): String = "\"\"\"\n" + content + "\n\"\"\""

    private fun certsArray(certs: List<String>): String =
        certs.joinToString(",\n        ") { textBlock(it) }

    private fun buildJava(ecPriv: String, ecCerts: List<String>, rsaPriv: String, rsaCerts: List<String>): String = buildString {
        appendLine("package com.android.internal.util.framework;")
        appendLine()
        appendLine("import org.lsposed.lsparanoid.Obfuscate;")
        appendLine()
        appendLine("@Obfuscate")
        appendLine("public final class Keybox {")
        appendLine("    public static final class EC {")
        appendLine("        public static final String PRIVATE_KEY = ${textBlock(ecPriv)};")
        appendLine("        public static final String[] CERTIFICATES = {")
        appendLine("            ${certsArray(ecCerts)}")
        appendLine("        };")
        appendLine("    }")
        appendLine("    public static final class RSA {")
        appendLine("        public static final String PRIVATE_KEY = ${textBlock(rsaPriv)};")
        appendLine("        public static final String[] CERTIFICATES = {")
        appendLine("            ${certsArray(rsaCerts)}")
        appendLine("        };")
        appendLine("    }")
        appendLine("}")
    }.trimIndent() + "\n"
}

val generateKeybox by tasks.registering(GenerateKeyboxTask::class) {
    val keyboxXml = rootProject.layout.projectDirectory.file("keybox.xml")
    val exampleXml = rootProject.layout.projectDirectory.file("keybox.xml.example")
    source.set(project.providers.provider {
        if (keyboxXml.get().asFile.exists()) keyboxXml.get() else exampleXml.get()
    })
    outputDir.set(layout.buildDirectory.dir("generated/source/keybox/com/android/internal/util/framework"))
}

// 编译前先生成 Keybox.java
tasks.matching { it.name.startsWith("compile") && it.name.contains("JavaWithJavac", ignoreCase = true) }
    .configureEach { dependsOn(generateKeybox) }

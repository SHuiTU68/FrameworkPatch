// build.rs — 用 rsbinder-aidl 把 vendored 的 AOSP KeyMint 冻结快照编译成 Rust 绑定。
//
// AIDL 来源（frozen，IMMUTABLE，勿改）：
//   hardware/interfaces/security/keymint/aidl/aidl_api/
//     android.hardware.security.keymint/3/   (KeyMint V3，Android 12-14)
//     android.hardware.security.secureclock/1/  (TimeStampToken/Timestamp 依赖)
//
// 冻结快照里类型全部用全限定名（FQCN），无 import 语句；rsbinder-aidl 在所有已
// 解析文档里按 FQCN 解析引用，因此只要把 keymint + secureclock 两个包都 source
// 进来即可。secureclock 仅作为 parcelable 依赖被引用（IKeyMintOperation 的
// update/finish 形参），不注册其 service。
//
// @VintfStability 接口必须带版本号与 hash：keystore2 启动时调用
// getInterfaceVersion()/getInterfaceHash() 做版本协商。各接口的版本 = 它最后一次
// 被冻结的版本号（不是包版本），hash 取自 AOSP aidl_api/<pkg>/<ver>/.hash：
//   aidl_api/.../keymint/3/.hash      → 仅 1 行（V3 只改了 IKeyMintDevice）
//   aidl_api/.../keymint/2/.hash      → 2 行（line1=IKeyMintDevice, line2=IKeyMintOperation）
// 故：
//   IKeyMintDevice    : version 3, hash 74a53863...（V3 新增 AttestationKey/attestKey）
//   IKeyMintOperation : version 2, hash 70c734fb...（V3 未改，沿用 V2）
// 其余 parcelable/enum 无 getInterfaceVersion 元方法，不加版本/hash。
//
// rsbinder-aidl 的 .version()/.hash() 作用于“最近一次 .source() 加入的单个文件”
// （对目录 source 会 panic），因此下面按文件逐个加入，紧跟对应接口文件后链式调用。
use std::fs;
use std::path::PathBuf;

const KM_DIR: &str = "aidl/android/hardware/security/keymint";
const SC_DIR: &str = "aidl/android/hardware/security/secureclock";

const KMD_VERSION: i32 = 3;
const KMD_HASH: &str = "74a538630d5d90f732f361a2313cbb69b09eb047";
const KMO_VERSION: i32 = 2;
const KMO_HASH: &str = "70c734fbd5cac5b36676d66d8d9aa941967e1e7b";

fn collect_aidl(dir: &str) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("read_dir({dir}) failed: {e}"))
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("aidl"))
        .collect();
    v.sort();
    v
}

fn main() {
    let mut builder = rsbinder_aidl::Builder::new()
        .output(PathBuf::from("keymint.rs"))
        .set_async_support(false)
        // 冻结快照无 import 语句，include_dir 仅作兜底（解析器会按 FQCN 跨文档匹配）。
        .include_dir(PathBuf::from(KM_DIR))
        .include_dir(PathBuf::from(SC_DIR));

    for path in collect_aidl(KM_DIR) {
        builder = builder.source(&path);
        match path.file_name().and_then(|s| s.to_str()) {
            Some("IKeyMintDevice.aidl") => {
                builder = builder.version(KMD_VERSION).hash(KMD_HASH);
            }
            Some("IKeyMintOperation.aidl") => {
                builder = builder.version(KMO_VERSION).hash(KMO_HASH);
            }
            _ => {}
        }
    }

    for path in collect_aidl(SC_DIR) {
        builder = builder.source(&path);
    }

    if let Err(err) = builder.generate() {
        eprintln!("rsbinder-aidl error: {:?}", err);
        std::process::exit(1);
    }
    println!("cargo:rerun-if-changed=aidl");
    println!("cargo:rerun-if-changed=build.rs");
}

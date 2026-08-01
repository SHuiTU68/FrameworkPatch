// build.rs — 用 rsbinder-aidl 把 AIDL 编译成 Rust binder 绑定。
//
// 当前 aidl/ 下是占位骨架（仅 getHardwareInfo），用于验证工具链与注册样板。
// 真正可用前必须用 AOSP 冻结快照整体替换：
//   hardware/interfaces/security/keymint/aidl/aidl_api/android.hardware.security.keymint/<ver>/
// 该冻结快照带 @VintfStability 版本号与接口 hash，keystore2 启动时会做版本
// 协商——手写 AIDL 不带这些戳记会被拒绝。替换后 Builder 上需链式调用
//   .version(<ver>).hash("<frozen hash>")
// 以生成 getInterfaceVersion()/getInterfaceHash() 元方法。
use std::path::PathBuf;

fn main() {
    if let Err(err) = rsbinder_aidl::Builder::new()
        .source(PathBuf::from("aidl"))
        .output(PathBuf::from("keymint.rs"))
        .set_async_support(false)
        .generate()
    {
        eprintln!("rsbinder-aidl error: {:?}", err);
        std::process::exit(1);
    }
    println!("cargo:rerun-if-changed=aidl");
}

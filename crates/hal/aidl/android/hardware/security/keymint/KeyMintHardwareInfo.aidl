// 占位骨架 AIDL —— 仅用于验证 rsbinder-aidl 工具链与 service 注册样板。
// 真正可用前必须整体替换为 AOSP 冻结快照（带 @VintfStability 版本/hash）：
//   hardware/interfaces/security/keymint/aidl/aidl_api/
//     android.hardware.security.keymint/<version>/
// 该目录含 IKeyMintDevice / IKeyMintOperation / IRemotelyProvisionedComponent
// 及全部 parcelable（KeyParameter、KeyCreationResult、Tag、SecurityLevel、
// ErrorCode 等），互相 import，必须整体 vendoring。
package android.hardware.security.keymint;

parcelable KeyMintHardwareInfo {
    int keyMintVersion;
    int keyMintSecurityLevel;
    boolean isHwAttestationSupported;
}

// 占位骨架 —— 仅 getHardwareInfo，证明 descriptor 字符串
// `android.hardware.security.keymint.IKeyMintDevice` 正确、可被
// servicemanager 注册。完整接口见上方注释。
package android.hardware.security.keymint;

interface IKeyMintDevice {
    KeyMintHardwareInfo getHardwareInfo();
}

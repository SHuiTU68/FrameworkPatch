// FKTee-rs WebUI 常量
// 模块 ID 与 KernelSU webroot 挂钩（/data/adb/modules/<MOD_ID>/webroot）

// 模块 ID（与 module.prop 的 id 一致）
export const MOD_ID = 'fktee_rs'
// localStorage 键前缀
export const LOCAL_STORAGE_PREFIX = `FKTee`

// 在线更新源（module.prop updateJson 指向的仓库）
export const GITHUB_REPO = 'SHuiTU68/FrameworkPatch'
export const TELEGRAM_CHANNEL = 'https://t.me/kowchannel'
// keybox 在线仓库
export const KEYBOX_REPO_URL = 'https://keybox.kowx712.cc'

// FKTee 配置根目录（daemon 读取的所有配置文件均在此目录下）
export const CONFIG_PATH = '/data/adb/Tee-rs'

// 各配置文件路径
export const CONFIG_FILE = `${CONFIG_PATH}/config.toml`
export const INJECTOR_FILE = `${CONFIG_PATH}/injector.toml`
export const HAL_FILE = `${CONFIG_PATH}/hal.toml`
export const DENY_FILE = `${CONFIG_PATH}/deny.list`
export const PROPS_FILE = `${CONFIG_PATH}/props.conf`
export const USB_FILE = `${CONFIG_PATH}/usb.conf`
export const KEYBOX_FILE = `${CONFIG_PATH}/keybox.xml`
export const HAL_ENABLED_FILE = `${CONFIG_PATH}/hal.enabled`

// PID 文件（service.sh 写入 $TEERS_DIR/data/*.pid）
export const PID_FKTEE = `${CONFIG_PATH}/data/fktee.pid`
export const PID_INJECTOR = `${CONFIG_PATH}/data/injector.pid`
export const PID_HAL = `${CONFIG_PATH}/data/hal.pid`

// 重启信号文件路径（service.sh 主循环检测并消费 restart.<name>）
export function restartSignalPath(name: string): string {
  return `${CONFIG_PATH}/restart.${name}`
}

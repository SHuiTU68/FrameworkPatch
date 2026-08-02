// FKTee-rs 常量
export const MOD_ID = 'fktee_rs'
export const LOCAL_STORAGE_PREFIX = `FKTee`
export const CONFIG_PATH = '/data/adb/Tee-rs'
export const GITHUB_REPO = 'SHuiTU68/FrameworkPatch'

// 各配置文件路径（与 daemon / service.sh 硬编码路径一致）
export const CONFIG_FILE = `${CONFIG_PATH}/config.toml`
export const INJECTOR_FILE = `${CONFIG_PATH}/injector.toml`
export const HAL_FILE = `${CONFIG_PATH}/hal.toml`
export const DENY_FILE = `${CONFIG_PATH}/deny.list`
export const PROPS_FILE = `${CONFIG_PATH}/props.conf`
export const USB_FILE = `${CONFIG_PATH}/usb.conf`
export const KEYBOX_FILE = `${CONFIG_PATH}/keybox.xml`
export const HAL_ENABLED_FILE = `${CONFIG_PATH}/hal.enabled`

// pid 文件（service.sh 写入）
export const PID_DIR = `${CONFIG_PATH}/data`
export const PID_FKTEE = `${PID_DIR}/fktee.pid`
export const PID_INJECTOR = `${PID_DIR}/injector.pid`
export const PID_HAL = `${PID_DIR}/hal.pid`

// 重启信号前缀（service.sh 主循环消费）
export const RESTART_PREFIX = `${CONFIG_PATH}/restart.`

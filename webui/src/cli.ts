// KSU bridge 调用封装
// 保留对外的过程式 API（exec/readFile/writeFile/fileExists/restartDaemon/showToast/escapeHtml），
// 供历史模块与新增模块共用；同时提供 Cli 类承载 FKTee 专用辅助方法。
import { exec as ksuExec, toast } from 'kernelsu-alt'
import { CONFIG_PATH, HAL_ENABLED_FILE, MOD_ID, RESTART_PREFIX, USB_FILE } from './constant'

export interface ExecResult {
  errno: number
  stdout: string
  stderr: string
}

// HTML 转义，避免注入
export function escapeHtml(s: string): string {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}

// 执行 shell 命令
export async function exec(cmd: string): Promise<ExecResult> {
  const r = await ksuExec(cmd)
  return {
    errno: r?.errno ?? -1,
    stdout: r?.stdout ?? '',
    stderr: r?.stderr ?? '',
  }
}

// 读取文件（cat）
export async function readFile(path: string): Promise<string> {
  const safe = path.replace(/'/g, "'\\''")
  const r = await exec(`cat '${safe}' 2>/dev/null`)
  return r.stdout
}

// 判断文件是否存在
export async function fileExists(path: string): Promise<boolean> {
  const safe = path.replace(/'/g, "'\\''")
  const r = await exec(`test -f '${safe}' && echo yes || echo no`)
  return r.stdout.trim() === 'yes'
}

// 写入文件（heredoc，避免转义问题）
export async function writeFile(path: string, content: string): Promise<void> {
  const safe = path.replace(/'/g, "'\\''")
  const dir = path.substring(0, path.lastIndexOf('/'))
  if (dir) {
    await exec(`mkdir -p '${dir.replace(/'/g, "'\\''")}'`)
  }
  const cmd = `cat > '${safe}' <<'FKTEE_EOF'\n${content}\nFKTEE_EOF`
  const r = await exec(cmd)
  if (r.errno !== 0) {
    throw new Error(`写入失败 ${path}: ${r.stderr}`)
  }
}

// 重启 daemon（touch restart 信号文件），service.sh 主循环消费
export async function restartDaemon(name: string): Promise<void> {
  const r = await exec(`touch ${RESTART_PREFIX}${name}`)
  if (r.errno !== 0) {
    throw new Error(`重启失败: ${r.stderr}`)
  }
  showToast(`已发送重启信号: ${name}`)
}

// 弹出 toast（兼容非 KSU 环境）
export function showToast(msg: string): void {
  try {
    toast(msg)
  } catch {
    console.log('[toast]', msg)
  }
}

export class Cli {
  static #basePathPromise: Promise<string> | null = null
  static #managerPromise: Promise<string> | null = null

  constructor() {
    if (!Cli.#basePathPromise) {
      Cli.#basePathPromise = this.#resolveBasePath()
    }
    if (!Cli.#managerPromise) {
      Cli.#managerPromise = this.#resolveManager()
    }
  }

  async getBasePath(): Promise<string> {
    return Cli.#basePathPromise!
  }

  async getManager(): Promise<string> {
    return Cli.#managerPromise!
  }

  async getManagerPath(): Promise<string> {
    const manager = await this.getManager()
    switch (manager) {
      case 'MAGISK':
        return '/data/adb/magisk'
      case 'KSU':
        return '/data/adb/ksu/bin'
      case 'APATCH':
        return '/data/adb/ap/bin'
      default:
        return '/data/adb/ap/bin:/data/adb/ksu/bin:/data/adb/magisk'
    }
  }

  async #resolveBasePath(): Promise<string> {
    const disabled = await fileExists(`/data/adb/modules/.${MOD_ID}`)
    return disabled ? `/data/adb/modules/.${MOD_ID}` : `/data/adb/modules/${MOD_ID}`
  }

  async #resolveManager(): Promise<string> {
    const basePath = await this.getBasePath()
    return (await this.grepProp('MANAGER', `${basePath}/common/manager.sh`)) || ''
  }

  async grepProp(key: string, filePath: string): Promise<string | null> {
    const safe = filePath.replace(/'/g, "'\\''")
    const r = await exec(`grep '^${key}=' '${safe}' | cut -d'=' -f2`)
    return r.errno === 0 ? r.stdout.trim() : null
  }

  // 用系统浏览器打开外链
  async linkRedirect(url: string): Promise<void> {
    const result = await exec(`am start -a android.intent.action.VIEW -d '${url}'`)
    if (result.errno !== 0) window.open(url, '_blank')
  }

  async reboot(): Promise<void> {
    const result = await exec('svc power reboot || reboot')
    if (result.errno !== 0) throw new Error(`reboot failed (${result.errno})`)
  }

  // 读取 /data/adb/Tee-rs/usb.conf 的 adb_enabled
  async getUsbAdb(): Promise<boolean> {
    try {
      const raw = await readFile(USB_FILE)
      for (const line of raw.split('\n')) {
        const t = line.trim()
        if (!t || t.startsWith('#')) continue
        if (t.startsWith('adb_enabled=')) {
          return t.split('=')[1]?.trim() === '1'
        }
      }
    } catch {
      /* ignore */
    }
    return true
  }

  // 写 usb.conf + settings 持久化
  async setUsbAdb(enabled: boolean): Promise<void> {
    const val = enabled ? '1' : '0'
    await writeFile(USB_FILE, `adb_enabled=${val}\n`)
    await exec(`settings put global adb_enabled ${val}`)
  }

  // HAL 模式：hal.enabled 文件是否存在
  async getHalEnabled(): Promise<boolean> {
    return fileExists(HAL_ENABLED_FILE)
  }

  // 切换 HAL/inject 模式（touch / rm hal.enabled），需重启生效
  async toggleHal(enable: boolean): Promise<void> {
    if (enable) {
      await exec(`touch ${HAL_ENABLED_FILE}`)
    } else {
      await exec(`rm -f ${HAL_ENABLED_FILE}`)
    }
  }

  get configPath(): string {
    return CONFIG_PATH
  }
}

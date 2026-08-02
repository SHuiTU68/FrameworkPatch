// FKTee-rs WebUI CLI 桥接层
// 保留参考项目的 Cli 类（getBasePath / downloadFile / installModule / setBootHash 等），
// 并新增 FKTee 特有辅助：USB 调试开关、HAL 模式切换、重启信号。
// 同时导出独立函数 exec / restartDaemon / showToast / escapeHtml 供对话框使用。
import { exec as ksuExec, spawn, toast } from 'kernelsu-alt'
import { File } from './file'
import { MOD_ID, USB_FILE, HAL_ENABLED_FILE, PROPS_FILE, restartSignalPath } from './constant'

export type ExecResult = Awaited<ReturnType<typeof ksuExec>>

// 重新导出 exec，供 status.ts 等独立调用
export async function exec(cmd: string, options?: { env?: Record<string, string> }): Promise<ExecResult> {
  return ksuExec(cmd, options)
}

// 弹出 Android Toast
export function showToast(msg: string): void {
  try {
    toast(msg)
  } catch {
    /* 非 KSU 环境忽略 */
  }
}

// HTML 转义（用于在 innerHTML 中安全插入用户输入）
export function escapeHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}

// 发送重启信号（service.sh 主循环会消费 restart.<name> 文件）
// name 取值：all | fktee | injector | hal
export async function restartDaemon(name: string): Promise<void> {
  const path = restartSignalPath(name)
  await File.createFile(path)
}

// 读取 *.conf 文件中的 key=value 行（# 与空行忽略），返回 Map
async function readConfKeys(path: string): Promise<Map<string, string>> {
  const map = new Map<string, string>()
  let raw = ''
  try {
    raw = await File.read(path)
  } catch {
    return map
  }
  for (const line of raw.split('\n')) {
    const trimmed = line.trim()
    if (trimmed === '' || trimmed.startsWith('#')) continue
    const eq = trimmed.indexOf('=')
    if (eq <= 0) continue
    map.set(trimmed.slice(0, eq).trim(), trimmed.slice(eq + 1).trim())
  }
  return map
}

// 把 key=value 行写回 conf 文件（保留 # 注释与空行）
async function writeConfKey(path: string, key: string, value: string): Promise<void> {
  let raw = ''
  try {
    raw = await File.read(path)
  } catch {
    raw = ''
  }
  const lines = raw.split('\n')
  let found = false
  for (let i = 0; i < lines.length; i++) {
    const trimmed = lines[i].trim()
    if (trimmed === '' || trimmed.startsWith('#')) continue
    const eq = trimmed.indexOf('=')
    if (eq > 0 && trimmed.slice(0, eq).trim() === key) {
      lines[i] = `${key}=${value}`
      found = true
      break
    }
  }
  if (!found) lines.push(`${key}=${value}`)
  await File.write(path, lines.join('\n'))
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
    const exists = await File.exist(`/data/adb/modules/.${MOD_ID}`)
    return exists ? `/data/adb/modules/.${MOD_ID}` : `/data/adb/modules/${MOD_ID}`
  }

  async #resolveManager(): Promise<string> {
    const basePath = await this.getBasePath()
    return (await this.grepProp('MANAGER', `${basePath}/common/manager.sh`)) || ''
  }

  async grepProp(key: string, filePath: string): Promise<string | null> {
    const result = await exec(`grep '^${key}=' '${filePath}' | cut -d'=' -f2`)
    return result.errno === 0 ? result.stdout.trim() : null
  }

  async linkRedirect(url: string): Promise<void> {
    const result = await exec(`am start -a android.intent.action.VIEW -d '${url}'`)
    if (result.errno !== 0) window.open(url, '_blank')
  }

  async getAospKey(): Promise<string> {
    const basePath = await Cli.#basePathPromise
    const { stdout, errno } = await exec(`xxd -r -p ${basePath}/common/.default | base64 -d`)
    if (errno !== 0 || !stdout.trim()) throw new Error('getAospKey failed')
    return stdout
  }

  async downloadFile(url: string, destPath: string): Promise<void> {
    const managerPath = await this.getManagerPath()
    return new Promise((resolve, reject) => {
      const tryCurl = () => {
        const curl = spawn('curl', ['--connect-timeout', '10', '-L', '-s', '-o', destPath, url],
          { env: { PATH: `$PATH:${managerPath}:/data/data/com.termux/files/usr/bin` }})
        curl.on('exit', (code) => {
          if (code === 0) resolve()
          else tryWget()
        })
        curl.on('error', () => tryWget())
      }
      const tryWget = () => {
        const wget = spawn('busybox', ['wget', '-T', '10', '--no-check-certificate', '-qO', destPath, url],
          { env: { PATH: `$PATH:${managerPath}:/data/data/com.termux/files/usr/bin` }})
        wget.on('exit', (code) => {
          if (code === 0) resolve()
          else reject(new Error(`downloadFile failed: wget exit(${code})`))
        })
        wget.on('error', (err) => reject(new Error(`downloadFile failed: wget error(${err.message})`)))
      }
      tryCurl()
    })
  }

  async unzip(zipPath: string, dest: string): Promise<void> {
    await File.createDirectory(dest)
    const result = await exec(`unzip -o '${zipPath}' -d '${dest}'`)
    if (result.errno !== 0) {
      throw new Error(`unzip failed (${result.errno}): ${result.stderr}`)
    }
  }

  async installModule(zipPath: string): Promise<boolean> {
    return this.#manageModule('install', zipPath)
  }

  async uninstallModule(modId: string): Promise<boolean> {
    return this.#manageModule('uninstall', modId)
  }

  async #manageModule(option: 'install' | 'uninstall', module: string): Promise<boolean> {
    const basePath = await this.getBasePath()
    const manager = await this.getManager()
    const managerPath = await this.getManagerPath()

    return new Promise((resolve, reject) => {
      let cmd: [string, string[]]

      const cleanup = () => File.delete(`${basePath}/common/tmp`).catch(() => {})

      switch (manager) {
        case 'APATCH':
          if (option == 'uninstall') File.copy(`${basePath}/update/module.prop`, `${basePath}/module.prop`)
          cmd = ['apd', ['module', option, module]]
          break
        case 'KSU':
          if (option == 'uninstall') File.copy(`${basePath}/update/module.prop`, `${basePath}/module.prop`)
          cmd = ['ksud', ['module', option, module]]
          break
        case 'MAGISK':
          if (option == 'uninstall') File.copy(`${basePath}/update`, `/data/adb/modules/${MOD_ID}`)
          cmd = ['magisk', [`--${option}-module`, module]]
          break
        default:
          if (option == 'uninstall') {
            cmd = ['false', []]
            break
          }
          cleanup().then(() => reject(new Error(`Failed to ${option} module: unknown manager '${manager}'`)))
          return
      }

      let stdout = ''
      const proc = spawn(cmd[0], cmd[1], { env: { PATH: `$PATH:${managerPath}` } })
      proc.stdout.on('data', (chunk: string) => stdout += chunk)
      proc.on('exit', (code: number | null) => {
        if (code === 0) {
          cleanup().then(() => {
            if (stdout.includes('No need to reboot')) location.reload()
            resolve(true)
          })
        } else {
          if (option == 'uninstall') {
            File.createFile(`/data/adb/modules/${MOD_ID}/remove`).catch(() => {})
            resolve(true)
          } else {
            cleanup().then(() => reject(new Error(`Failed to ${option} module: exit(${code})`)))
          }
        }
      })
      proc.on('error', (err: Error) => {
        cleanup().then(() => reject(new Error(`Failed to ${option} module: ${err.message}`)))
      })
    })
  }

  // 设置 ro.boot.vbmeta.digest（修复异常启动状态）
  async setBootHash(hash: string): Promise<void> {
    const managerPath = await this.getManagerPath()
    const result = await exec(`
      resetprop -n ro.boot.vbmeta.digest "${hash}"
      resetprop -c $(resetprop -Z ro.boot.vbmeta.digest) >/dev/null 2>&1 || true
      resetprop -c >/dev/null 2>&1 || true`,
      { env: { PATH: `$PATH:${managerPath}` } })
    if (result.errno !== 0) throw new Error(`setBootHash failed (${result.errno})`)
  }

  async getMagiskDenyList(): Promise<string[]> {
    if (import.meta.env.DEV) {
      return [
        'com.example.game',
        'com.example.streaming',
        'io.github.vvb2060.keyattestation',
      ]
    }
    const result = await exec(`magisk --denylist ls 2>/dev/null | awk -F'|' '{print $1}' | grep -v "isolated"`)
    if (result.errno !== 0) return []
    return result.stdout.split('\n')
      .map(line => line.trim())
      .filter(line => line.length > 0)
  }

  async reboot(): Promise<void> {
    const result = await exec("svc power reboot || reboot")
    if (result.errno !== 0) throw new Error(`reboot failed (${result.errno})`)
  }

  async getXposedList(): Promise<string[]> {
    if (import.meta.env.DEV) {
      return [
        'org.lsposed.manager',
        'com.example.xposedmod1',
        'com.example.xposedmod2',
      ]
    }
    const basePath = await this.getBasePath()
    return new Promise((resolve) => {
      let stdout = ''
      const proc = spawn('sh', [`${basePath}/common/get_extra.sh`, '--xposed'])
      proc.stdout.on('data', (chunk: string) => stdout += chunk + '\n')
      proc.on('exit', (code: number | null) => {
        if (code === 0) {
          resolve(stdout.split('\n')
            .map(line => line.trim())
            .filter(line => line.length > 0))
        } else {
          resolve([])
        }
      })
      proc.on('error', () => resolve([]))
    })
  }

  // ---------- FKTee 特有辅助 ----------

  // 读取 usb.conf 的 adb_enabled 值（默认 1）
  async getUsbAdb(): Promise<boolean> {
    if (import.meta.env.DEV) return true
    const map = await readConfKeys(USB_FILE)
    return map.get('adb_enabled') !== '0'
  }

  // 写入 usb.conf 并立即通过 settings 生效
  async setUsbAdb(enabled: boolean): Promise<void> {
    const val = enabled ? '1' : '0'
    await writeConfKey(USB_FILE, 'adb_enabled', val)
    // 立即生效（无需重启）
    await exec(`settings put global adb_enabled ${val}`)
  }

  // HAL 模式是否启用（hal.enabled 文件存在即启用）
  async getHalEnabled(): Promise<boolean> {
    if (import.meta.env.DEV) return false
    return File.exist(HAL_ENABLED_FILE)
  }

  // 切换 HAL 模式（创建/删除 hal.enabled，需重启生效）
  async toggleHal(enable: boolean): Promise<void> {
    if (enable) {
      await File.createFile(HAL_ENABLED_FILE)
    } else {
      await File.delete(HAL_ENABLED_FILE)
    }
  }

  // 读取 props.conf 的 enabled 标志（缺省视为 1）
  async getPropsEnabled(): Promise<boolean> {
    if (import.meta.env.DEV) return true
    const map = await readConfKeys(PROPS_FILE)
    return map.get('enabled') !== '0'
  }

  // 写入 props.conf 的 enabled 标志
  async setPropsEnabled(enabled: boolean): Promise<void> {
    await writeConfKey(PROPS_FILE, 'enabled', enabled ? '1' : '0')
  }
}

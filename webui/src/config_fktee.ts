// FKTee 配置：覆盖基类 Config 的 read/write，把 allowPackages 映射到
// /data/adb/Tee-rs/allow.list（纯包名列表），把 default_policy + per-app
// 策略映射到 config.toml 的 [trust] / [<package>] 段。
// injector.toml / hal.toml 的直接编辑由 ConfigDialog / HalDialog 处理。
import { parse, stringify } from 'smol-toml'
import { File } from './file'
import { Config, type ConfigData, type Policy } from './config'
import { CONFIG_FILE, ALLOW_FILE, HAL_FILE, INJECTOR_FILE, KEYBOX_FILE, CONFIG_PATH } from './constant'

export type Toml = Record<string, unknown>

// 已知的 config.toml 顶层段名（不属于 per-app 策略）
const KNOWN_TOP_SECTIONS = new Set(['backend', 'trust', 'crypto', 'log'])

export class FkteeConfig extends Config {
  override readonly identity: string = 'FKTee'

  override get configPath(): string {
    return CONFIG_PATH
  }

  // 读取 allow.list + config.toml，合并到 ConfigData
  override async read(): Promise<void> {
    if (import.meta.env.DEV) {
      this.set({
        default_policy: { verified_boot_state: 'green', device_locked: true, vb_key: 'auto', vb_hash: 'auto', security_patch: 'auto' },
        allowPackages: [
          'io.github.vvb2060.keyattestation',
          'io.github.vvb2060.mahoshojo?',
          'com.google.android.gms!',
          'com.example.banking',
          'com.example.wallet!',
          'com.example.social?',
        ],
        'com.google.android.gms': { vb_key: 'auto', vb_hash: '241890bd44131d34c077cb01a0c3ea1ff68533b21e9d83b3f3adca6663c3d443', security_patch: '2026-05-05' },
        'com.example.banking': { vb_key: 'auto', vb_hash: 'auto', security_patch: 'auto' },
      })
      return
    }

    const allowPackages = await readAllowList()
    const cfg = await readToml(CONFIG_FILE)

    const data: ConfigData = { allowPackages }

    // [trust] -> default_policy
    const trust = cfg.trust as Toml | undefined
    if (trust && typeof trust === 'object') {
      data.default_policy = { ...(trust as Policy) }
    }

    // 其余对象段视为 per-app 策略 [<package>]
    for (const [key, val] of Object.entries(cfg)) {
      if (KNOWN_TOP_SECTIONS.has(key)) continue
      if (val && typeof val === 'object' && !Array.isArray(val)) {
        data[key] = { ...(val as Policy) }
      }
    }

    this.set(data)
  }

  // 写入 allow.list + config.toml
  override async write(): Promise<void> {
    const data = this.get()

    // 1. 写 allow.list
    await writeAllowList(data.allowPackages ?? [])

    // 2. 写 config.toml：先读现有内容（保留 [backend]/[crypto]/[log] 等段）
    const cfg = await readToml(CONFIG_FILE)

    // [trust] <- default_policy
    if (data.default_policy && Object.keys(data.default_policy).length > 0) {
      cfg.trust = { ...data.default_policy }
    } else {
      delete cfg.trust
    }

    // 清除旧的 per-app 段，再写入当前 per-app 策略
    for (const key of Object.keys(cfg)) {
      if (KNOWN_TOP_SECTIONS.has(key)) continue
      delete cfg[key]
    }
    for (const [key, val] of Object.entries(data)) {
      if (key === 'allowPackages' || key === 'default_policy') continue
      if (val && typeof val === 'object' && !Array.isArray(val)) {
        cfg[key] = { ...(val as Policy) }
      }
    }

    await writeToml(CONFIG_FILE, cfg)
  }
}

// 读取一个 toml 文件，缺失/解析失败返回空对象
export async function readToml(path: string): Promise<Toml> {
  if (import.meta.env.DEV) return {}
  try {
    const raw = await File.read(path)
    return parse(raw) as Toml
  } catch {
    return {}
  }
}

// 写回 toml（stringify 会丢失注释，可接受）
export async function writeToml(path: string, data: Toml): Promise<void> {
  const raw = stringify(data as Record<string, unknown>)
  await File.write(path, raw)
}

// 便捷：直接读取三类配置文件
export const readConfigToml = (): Promise<Toml> => readToml(CONFIG_FILE)
export const readInjectorToml = (): Promise<Toml> => readToml(INJECTOR_FILE)
export const readHalToml = (): Promise<Toml> => readToml(HAL_FILE)

// 读取 allow.list：每行一个包名，# 与空行忽略（可能带 ! / ? 后缀表示模式）
export async function readAllowList(): Promise<string[]> {
  if (import.meta.env.DEV) return []
  try {
    const raw = await File.read(ALLOW_FILE)
    return raw.split('\n')
      .map(line => line.trim())
      .filter(line => line.length > 0 && !line.startsWith('#'))
  } catch {
    return []
  }
}

// 写入 allow.list：每行一个条目
export async function writeAllowList(packages: string[]): Promise<void> {
  const raw = packages.length > 0 ? packages.join('\n') + '\n' : ''
  await File.write(ALLOW_FILE, raw)
}

// keybox.xml 状态：是否存在 + 字节数
export async function keyboxStat(): Promise<{ exists: boolean; size: number }> {
  try {
    const r = await File.read(KEYBOX_FILE)
    return { exists: true, size: r.length }
  } catch {
    return { exists: false, size: 0 }
  }
}
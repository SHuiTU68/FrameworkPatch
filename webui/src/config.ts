import type { MdOutlinedTextField } from '@material/web/all'
import { File } from './file'
import { CONFIG_PATH, ALLOW_FILE } from './constant'

export interface Policy {
  verified_boot_state?: string
  device_locked?: boolean
  vb_key?: string
  vb_hash?: string
  security_patch?: string
  [key: string]: string | boolean | undefined
}

export interface TextFieldMeta {
  type?: 'text'
  label?: string
  required?: boolean
  defaultValue?: string
  options?: string[]
  maxlength?: number
  placeholder?: string
  textarea?: boolean
  validate: (value: string) => boolean | string
}

export interface BooleanFieldMeta {
  type: 'boolean'
  label: string
  defaultValue?: boolean
}

export interface ButtonFieldMeta {
  type: 'button'
  label: string
  onClick: () => void
}

export type PolicyFieldMeta = TextFieldMeta | BooleanFieldMeta | ButtonFieldMeta

export function snakeToLabel(key: string): string {
  return key
    .replace(/_/g, ' ')
    .replace(/\b\w/g, c => c.toUpperCase())
}

export class PolicySchema {
  readonly #fields: Map<string, PolicyFieldMeta>

  constructor(fields: Record<string, PolicyFieldMeta>) {
    this.#fields = new Map(Object.entries(fields))
  }

  getField(key: string): PolicyFieldMeta | undefined {
    return this.#fields.get(key)
  }

  getFields(): [string, PolicyFieldMeta][] {
    return [...this.#fields.entries()]
  }

  validate(values: Record<string, string>): Record<string, boolean | string> {
    const result: Record<string, boolean | string> = {}
    for (const [key, meta] of this.#fields) {
      if (meta.type === 'button') continue
      if (meta.type === 'boolean') {
        result[key] = true
        continue
      }
      const value = values[key] ?? ''
      if (!value && !meta.required) {
        result[key] = true
      } else {
        result[key] = meta.validate(value)
      }
    }
    return result
  }
}

// FKTee [trust] 段策略 schema（对应 config.toml [trust] 字段）
export const DEFAULT_POLICY_SCHEMA = new PolicySchema({
  verified_boot_state: {
    defaultValue: 'green',
    options: ['green', 'yellow', 'orange', 'red'],
    placeholder: 'green | yellow | orange | red',
    validate: (v) => !v || ['green', 'yellow', 'orange', 'red'].includes(v) || 'green | yellow | orange | red',
  },
  device_locked: {
    type: 'boolean',
    label: 'config_device_locked',
    defaultValue: true,
  },
  vb_key: {
    defaultValue: 'auto',
    options: ['auto', 'random'],
    placeholder: 'auto | random | <hex>',
    validate: (v) => !v || v === 'auto' || v === 'random' || /^[0-9a-fA-F]+$/.test(v) || 'auto | random | <hex>',
  },
  vb_hash: {
    defaultValue: 'auto',
    options: ['auto', 'random'],
    placeholder: 'auto | random | <hex>',
    validate: (v) => !v || v === 'auto' || v === 'random' || /^[0-9a-fA-F]+$/.test(v) || 'auto | random | <hex>',
  },
  security_patch: {
    defaultValue: 'auto',
    options: ['auto', 'latest'],
    placeholder: 'auto | latest | YYYY-MM-DD',
    validate: (v) => !v || v === 'auto' || v === 'latest' || /^\d{4}-\d{2}-\d{2}$/.test(v) || 'auto | latest | YYYY-MM-DD',
  },
  _today: {
    type: 'button',
    label: 'functional_button_today',
    onClick: () => {
      const today = new Date().toISOString().slice(0, 10)
      const el = document.querySelector<MdOutlinedTextField>('.policy-security_patch')
      if (el) el.value = today
    },
  },
})

export interface ConfigData {
  default_policy?: Policy
  allowPackages?: string[]
  [section: string]: Policy | string[] | undefined
}

// 解析 config.ini 风格的配置（基类兼容用，FkteeConfig 重写了 read/write）
function parseConfig(raw: string): ConfigData {
  const config: ConfigData = {}
  let section: string | null = null

  for (const line of raw.split('\n')) {
    const trimmed = line.trim()
    if (trimmed === '' || trimmed.startsWith('#')) continue

    const sectionMatch = trimmed.match(/^\[(.+)\]$/)
    if (sectionMatch) {
      section = sectionMatch[1]
      config[section] = section === 'allowPackages' ? [] : {}
      continue
    }

    if (!section) continue

    if (section === 'allowPackages') {
      (config.allowPackages as string[]).push(trimmed)
    } else {
      const eqIdx = trimmed.indexOf('=')
      if (eqIdx > 0) {
        const key = trimmed.slice(0, eqIdx).trim()
        const value = trimmed.slice(eqIdx + 1).trim()
        const sectionData = config[section] as Record<string, string>
        sectionData[key] = value
      }
    }
  }

  return config
}

function serializeConfig(config: ConfigData): string {
  const lines: string[] = []

  for (const [section, data] of Object.entries(config)) {
    if (data === undefined) continue
    lines.push(`[${section}]`)

    if (section === 'allowPackages' && Array.isArray(data)) {
      for (const entry of data) {
        lines.push(entry)
      }
    } else if (typeof data === 'object') {
      for (const [key, value] of Object.entries(data as Record<string, string | boolean>)) {
        lines.push(`${key} = ${value}`)
      }
    }
  }

  return lines.join('\n')
}

export class Config {
  readonly identity: string = 'TS'

  protected readonly CONFIG_PATH: string = CONFIG_PATH
  protected readonly CONFIG_FILE: string = ALLOW_FILE

  protected readonly perAppConfig: boolean = true
  protected readonly appMode: boolean = true

  #data: ConfigData = {}
  readonly policySchema: PolicySchema = DEFAULT_POLICY_SCHEMA

  async read(): Promise<void> {
    if (import.meta.env.DEV) {
      this.#data = {
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
      }
      return
    }
    try {
      const raw = await File.read(this.CONFIG_FILE)
      this.#data = parseConfig(raw)
    } catch {
      this.#data = {
        default_policy: { verified_boot_state: 'green', device_locked: true, vb_key: 'auto', vb_hash: 'auto', security_patch: 'auto' },
        allowPackages: [],
      }
    }
  }

  async write(): Promise<void> {
    const raw = serializeConfig(this.#data)
    await File.write(this.CONFIG_FILE, raw)
  }

  get(): ConfigData
  get(section: string): Policy | string[] | undefined
  get(section?: string): ConfigData | Policy | string[] | undefined {
    if (section === undefined) return this.#data
    return this.#data[section]
  }

  set(data: ConfigData): void
  set(section: string, key: string, value: string): void
  set(section: string, value: string[] | Policy | undefined): void
  set(section: string | ConfigData, key?: string | string[] | Policy, value?: string): void {
    if (typeof section === 'object') {
      this.#data = section
    } else if (value !== undefined) {
      if (!(section in this.#data) || Array.isArray(this.#data[section])) {
        this.#data[section] = {}
      }
      (this.#data[section] as Record<string, string>)[key as string] = value
    } else if (key === undefined) {
      delete this.#data[section]
    } else {
      this.#data[section] = key as string[] | Policy
    }
  }

  removeMatch(section: string, predicate: (value: string) => boolean): string[] {
    const arr = this.#data[section]
    if (!Array.isArray(arr)) return []
    const removed = arr.filter(predicate)
    this.#data[section] = arr.filter(v => !predicate(v))
    return removed
  }

  replaceMatch(section: string, predicate: (value: string) => boolean, newValue: string): boolean {
    const arr = this.#data[section]
    if (!Array.isArray(arr)) return false
    const idx = arr.findIndex(predicate)
    if (idx === -1) return false
    arr[idx] = newValue
    return true
  }

  push(section: string, value: string): void {
    if (!(section in this.#data) || !Array.isArray(this.#data[section])) {
      this.#data[section] = []
    }
    (this.#data[section] as string[]).push(value)
  }

  pop(section: string, value?: string): string | undefined {
    const arr = this.#data[section]
    if (!Array.isArray(arr)) return undefined

    let removed: string | undefined
    if (value === undefined) {
      removed = arr.pop()
    } else {
      const idx = arr.indexOf(value)
      if (idx !== -1) {
        removed = arr.splice(idx, 1)[0]
      }
    }

    // 清理孤立的 per-app 策略
    if (removed && section === 'allowPackages') {
      const pkgName = removed.replace(/[!?]$/, '')
      delete this.#data[pkgName]
    }

    return removed
  }

  get configPath(): string {
    return this.CONFIG_PATH
  }

  get supportsPerAppConfig(): boolean {
    return this.perAppConfig
  }

  get supportsAppMode(): boolean {
    return this.appMode
  }
}
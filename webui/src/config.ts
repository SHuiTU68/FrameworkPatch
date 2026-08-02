// 配置抽象：schema 驱动表单元数据 + deny.list 读写基类
import { File } from './file'
import { DENY_FILE } from './constant'

export interface Policy {
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

// snake_case → Title Case 标签
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

export interface ConfigData {
  denyPackages?: string[]
  [section: string]: string[] | undefined
}

// deny.list 解析：每行一个包名，# 与空行跳过
function parseDenyList(raw: string): string[] {
  const list: string[] = []
  for (const line of raw.split('\n')) {
    const t = line.trim()
    if (!t || t.startsWith('#')) continue
    list.push(t)
  }
  return list
}

export class Config {
  readonly identity: string = 'FKTee'

  protected readonly CONFIG_PATH: string = '/data/adb/Tee-rs'
  protected readonly DENY_FILE: string = DENY_FILE

  #data: ConfigData = {}

  async read(): Promise<void> {
    if (import.meta.env.DEV) {
      this.#data = {
        denyPackages: [
          'io.github.vvb2060.keyattestation',
          'com.example.banking',
        ],
      }
      return
    }
    try {
      const raw = await File.read(this.DENY_FILE)
      this.#data = { denyPackages: parseDenyList(raw) }
    } catch {
      this.#data = { denyPackages: [] }
    }
  }

  async write(): Promise<void> {
    const list = this.#data.denyPackages ?? []
    // 去重并排序，保留可读性
    const uniq = [...new Set(list)]
    const raw = uniq.join('\n') + (uniq.length ? '\n' : '')
    await File.write(this.DENY_FILE, raw)
  }

  get(): ConfigData
  get(section: string): string[] | undefined
  get(section?: string): ConfigData | string[] | undefined {
    if (section === undefined) return this.#data
    return this.#data[section]
  }

  set(data: ConfigData): void
  set(section: string, value: string[] | undefined): void
  set(section: string | ConfigData, value?: string[] | undefined): void {
    if (typeof section === 'object') {
      this.#data = section
    } else if (value === undefined) {
      delete this.#data[section]
    } else {
      this.#data[section] = value
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
    if (!Array.isArray(this.#data[section])) {
      this.#data[section] = []
    }
    ;(this.#data[section] as string[]).push(value)
  }

  pop(section: string, value?: string): string | undefined {
    const arr = this.#data[section]
    if (!Array.isArray(arr)) return undefined
    if (value === undefined) return arr.pop()
    const idx = arr.indexOf(value)
    if (idx !== -1) return arr.splice(idx, 1)[0]
    return undefined
  }

  get configPath(): string {
    return this.CONFIG_PATH
  }
}

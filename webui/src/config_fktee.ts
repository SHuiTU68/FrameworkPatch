// FKTee 配置：deny.list 由基类 Config 处理；此处提供 config.toml /
// injector.toml / hal.toml 的 smol-toml 读写辅助，供配置/HAL 对话框使用。
import { parse, stringify } from 'smol-toml'
import { File } from './file'
import { Config } from './config'
import { CONFIG_FILE, HAL_FILE, INJECTOR_FILE, KEYBOX_FILE } from './constant'

export type Toml = Record<string, unknown>

export class FkteeConfig extends Config {
  override readonly identity: string = 'FKTee'
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

// keybox.xml 状态：是否存在 + 字节数
export async function keyboxStat(): Promise<{ exists: boolean; size: number }> {
  try {
    const r = await File.read(KEYBOX_FILE)
    return { exists: true, size: r.length }
  } catch {
    return { exists: false, size: 0 }
  }
}

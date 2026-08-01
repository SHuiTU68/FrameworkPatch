// 配置读写：injector.toml / config.toml
//
// **全局 hook 模型**：injector.toml 只有一个 [hook].enabled 全局开关，
// 不再有 scoop 白名单 / 每应用模式。所有走 keystore2 的应用都受影响。
import { readFile, writeFile } from './cli';

export const INJECTOR_PATH = '/data/adb/fktee/injector.toml';
export const CONFIG_PATH = '/data/adb/fktee/config.toml';
export const KEYBOX_PATH = '/data/adb/fktee/keybox.xml';

export interface InjectorConfig {
  enabled: boolean; // 全局总开关
  keyboxPath: string;
}

export interface DaemonConfig {
  logLevel: string;
  autoStart: boolean;
}

// 去除行内注释（仅在裸值时调用）
function stripInlineComment(s: string): string {
  const idx = s.indexOf(' #');
  return (idx >= 0 ? s.substring(0, idx) : s).trim();
}

// 简易 TOML 解析器（正则实现，不依赖额外库）
// 支持：[section]、key = "str" / 'str' / 数字 / 布尔
export function parseToml(text: string): Record<string, any> {
  const root: Record<string, any> = {};
  let current: Record<string, any> = root;
  const lines = text.split('\n');
  for (const raw of lines) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;

    const sectionMatch = line.match(/^\[(.+)\]$/);
    if (sectionMatch) {
      const sec = sectionMatch[1].trim();
      current = root[sec] = root[sec] || {};
      continue;
    }

    const kvMatch = line.match(/^([^\s=]+)\s*=\s*(.*)$/);
    if (!kvMatch) continue;
    const key = kvMatch[1].trim();
    let valRaw = kvMatch[2].trim();

    // 字符串
    if (valRaw.startsWith('"') || valRaw.startsWith("'")) {
      const q = valRaw[0];
      const end = valRaw.indexOf(q, 1);
      current[key] = end >= 0 ? valRaw.substring(1, end) : valRaw.replace(/^["']|["']$/g, '');
      continue;
    }

    // 布尔
    if (valRaw === 'true' || valRaw === 'false') {
      current[key] = valRaw === 'true';
      continue;
    }

    // 数字
    if (/^-?\d+(\.\d+)?$/.test(valRaw)) {
      current[key] = Number(valRaw);
      continue;
    }

    // 裸字符串
    current[key] = stripInlineComment(valRaw);
  }
  return root;
}

// 读取 injector.toml（全局配置）
export async function readInjectorToml(): Promise<InjectorConfig> {
  const text = await readFile(INJECTOR_PATH);
  const data = parseToml(text);
  const hook = data.hook || {};
  const keybox = data.keybox || {};
  return {
    enabled: hook.enabled !== false, // 缺省视为启用
    keyboxPath: keybox.path ? String(keybox.path) : KEYBOX_PATH,
  };
}

// 序列化并写入 injector.toml（全局配置）
export async function writeInjectorToml(cfg: InjectorConfig): Promise<void> {
  let out = '# FKTee-rs injector.toml — 全局 hook 配置\n\n';
  out += '# 全局总开关：true = 所有应用的 keystore2 attestation 都用 keybox 伪造\n';
  out += '[hook]\n';
  out += `enabled = ${cfg.enabled ? 'true' : 'false'}\n\n`;
  out += '[keybox]\n';
  out += `path = "${cfg.keyboxPath}"\n`;
  await writeFile(INJECTOR_PATH, out);
}

// 读取 config.toml
export async function readConfigToml(): Promise<DaemonConfig> {
  const text = await readFile(CONFIG_PATH);
  const data = parseToml(text);
  const d = data.daemon || {};
  return {
    logLevel: String(d.log_level || 'info'),
    autoStart: d.auto_start === true,
  };
}


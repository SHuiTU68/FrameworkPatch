// 配置读写：injector.toml / config.toml
import { readFile, writeFile } from './cli';

export const INJECTOR_PATH = '/data/adb/fktee/injector.toml';
export const CONFIG_PATH = '/data/adb/fktee/config.toml';
export const KEYBOX_PATH = '/data/adb/fktee/keybox.xml';

export type InjectMode = 'auto' | 'generate' | 'hack';

export const ALL_MODES: InjectMode[] = ['auto', 'generate', 'hack'];

export interface InjectorConfig {
  scoop: string[];                       // 目标包名列表
  modes: Record<string, InjectMode>;     // 包名 -> 注入模式
  keyboxPath: string;                    // keybox.xml 路径
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

// 解析 TOML 数组字面量，提取字符串/数字/布尔元素
function parseArray(buf: string): unknown[] {
  const inner = buf.replace(/^\[/, '').replace(/\][\s\S]*$/, '');
  const items: unknown[] = [];
  const re = /"([^"]*)"|'([^']*)'|(\d+(?:\.\d+)?)|true|false/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(inner)) !== null) {
    if (m[1] !== undefined) items.push(m[1]);
    else if (m[2] !== undefined) items.push(m[2]);
    else if (m[3] !== undefined) items.push(Number(m[3]));
    else items.push(m[0] === 'true');
  }
  return items;
}

// 简易 TOML 解析器（正则实现，不依赖额外库）
// 支持：[section]、key = "str" / 'str' / 数字 / 布尔 / 多行数组
// 注：[modes] 段中以点号分隔的包名键按原样作为键名存储
export function parseToml(text: string): Record<string, any> {
  const root: Record<string, any> = {};
  let current: Record<string, any> = root;
  const lines = text.split('\n');
  let i = 0;
  while (i < lines.length) {
    const line = lines[i].trim();
    i++;
    if (!line || line.startsWith('#')) continue;

    // 区段 [section]
    const sectionMatch = line.match(/^\[(.+)\]$/);
    if (sectionMatch) {
      const sec = sectionMatch[1].trim();
      current = root[sec] = root[sec] || {};
      continue;
    }

    // 键值对
    const kvMatch = line.match(/^([^\s=]+)\s*=\s*(.*)$/);
    if (!kvMatch) continue;
    const key = kvMatch[1].trim();
    let valRaw = kvMatch[2].trim();

    // 多行数组
    if (valRaw.startsWith('[') && !valRaw.includes(']')) {
      let buf = valRaw;
      while (i < lines.length && !buf.includes(']')) {
        buf += '\n' + lines[i];
        i++;
      }
      current[key] = parseArray(buf);
      continue;
    }
    if (valRaw.startsWith('[')) {
      current[key] = parseArray(valRaw);
      continue;
    }

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

// 读取 injector.toml
export async function readInjectorToml(): Promise<InjectorConfig> {
  const text = await readFile(INJECTOR_PATH);
  const data = parseToml(text);
  const scoop: string[] = Array.isArray(data.scoop) ? data.scoop.map(String) : [];
  const modesRaw = data.modes || {};
  const modes: Record<string, InjectMode> = {};
  for (const k of Object.keys(modesRaw)) {
    const v = String(modesRaw[k]).toLowerCase();
    if (v === 'auto' || v === 'generate' || v === 'hack') {
      modes[k] = v;
    }
  }
  const keyboxPath = data.keybox && data.keybox.path ? String(data.keybox.path) : KEYBOX_PATH;
  return { scoop, modes, keyboxPath };
}

// 序列化并写入 injector.toml
export async function writeInjectorToml(cfg: InjectorConfig): Promise<void> {
  let out = '# FKTee-rs injector.toml\n\n';
  out += '# 注入目标包名列表\n';
  out += 'scoop = [\n';
  for (const p of cfg.scoop) out += `  "${p}",\n`;
  out += ']\n\n';
  out += '# 注入模式：auto / generate / hack\n';
  out += '[modes]\n';
  for (const p of cfg.scoop) {
    out += `${p} = "${cfg.modes[p] || 'auto'}"\n`;
  }
  out += '\n[keybox]\n';
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

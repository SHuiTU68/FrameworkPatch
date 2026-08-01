// 配置读写：injector.toml / config.toml / deny.list / props.conf / usb.conf
//
// **全局 hook + 黑名单模型**：injector.toml 只有 [hook].enabled 全局开关，
// 黑名单放在独立的 deny.list（每行一个包名）。所有走 keystore2 的应用都受影响，
// 黑名单里的包名豁免。props.conf / usb.conf 由 service.sh 应用。
import { readFile, writeFile } from './cli';

export const INJECTOR_PATH = '/data/adb/Tee-rs/injector.toml';
export const CONFIG_PATH = '/data/adb/Tee-rs/config.toml';
export const KEYBOX_PATH = '/data/adb/Tee-rs/keybox.xml';
export const DENY_LIST_PATH = '/data/adb/Tee-rs/deny.list';
export const PROPS_CONF_PATH = '/data/adb/Tee-rs/props.conf';
export const USB_CONF_PATH = '/data/adb/Tee-rs/usb.conf';

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

// ===================== 黑名单 deny.list =====================
// 每行一个包名，跳过空行与 # 注释。
export async function readDenyList(): Promise<string[]> {
  const text = await readFile(DENY_LIST_PATH);
  return text
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith('#'));
}

export async function writeDenyList(packages: string[]): Promise<void> {
  const header =
    '# FKTee-rs 黑名单（deny.list）— 由 WebUI 维护\n' +
    '# 列出的包名豁免伪造，保留真实 attestation。每行一个包名。\n';
  const body = packages.filter((p) => p && !p.startsWith('#')).join('\n');
  await writeFile(DENY_LIST_PATH, header + (body ? body + '\n' : ''));
}

// ===================== prop 属性隐藏 props.conf =====================
// 每行 key=value，# 与空行忽略；特殊键 enabled=1/0 控制总开关。
export interface PropsConfig {
  enabled: boolean;
  entries: { key: string; value: string }[];
}

export async function readPropsConf(): Promise<PropsConfig> {
  const text = await readFile(PROPS_CONF_PATH);
  const cfg: PropsConfig = { enabled: true, entries: [] };
  for (const raw of text.split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const idx = line.indexOf('=');
    if (idx < 0) continue;
    const key = line.slice(0, idx).trim();
    const value = line.slice(idx + 1).trim();
    if (key === 'enabled') {
      cfg.enabled = value !== '0';
    } else {
      cfg.entries.push({ key, value });
    }
  }
  return cfg;
}

export async function writePropsConf(cfg: PropsConfig): Promise<void> {
  let out = '# FKTee-rs prop 属性隐藏配置 — 由 WebUI 维护\n';
  out += `enabled=${cfg.enabled ? '1' : '0'}\n`;
  for (const e of cfg.entries) {
    out += `${e.key}=${e.value}\n`;
  }
  await writeFile(PROPS_CONF_PATH, out);
}

// ===================== USB 调试开关 usb.conf =====================
export async function readUsbConf(): Promise<boolean> {
  const text = await readFile(USB_CONF_PATH);
  for (const raw of text.split('\n')) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const idx = line.indexOf('=');
    if (idx < 0) continue;
    if (line.slice(0, idx).trim() === 'adb_enabled') {
      return line.slice(idx + 1).trim() !== '0';
    }
  }
  return true; // 缺省开启
}

export async function writeUsbConf(adbEnabled: boolean): Promise<void> {
  const out =
    '# FKTee-rs USB 调试开关配置 — 由 WebUI 维护\n' +
    `adb_enabled=${adbEnabled ? '1' : '0'}\n`;
  await writeFile(USB_CONF_PATH, out);
}


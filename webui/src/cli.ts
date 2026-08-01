// KSU bridge 调用封装
import { exec as ksuExec, listPackages as ksuListPackages, getPackagesInfo, toast } from 'kernelsu-alt';

export interface ExecResult {
  errno: number;
  stdout: string;
  stderr: string;
}

export interface AppInfo {
  packageName: string;
  label: string;
  versionName: string;
  versionCode: number;
  system: boolean;
  enabled: boolean;
}

// HTML 转义，避免注入
export function escapeHtml(s: string): string {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// 执行 shell 命令
export async function exec(cmd: string): Promise<ExecResult> {
  const r = await ksuExec(cmd);
  return {
    errno: r?.errno ?? -1,
    stdout: r?.stdout ?? '',
    stderr: r?.stderr ?? '',
  };
}

// 读取文件（cat）
export async function readFile(path: string): Promise<string> {
  const safe = path.replace(/'/g, "'\\''");
  const r = await exec(`cat '${safe}' 2>/dev/null`);
  return r.stdout;
}

// 判断文件是否存在
export async function fileExists(path: string): Promise<boolean> {
  const safe = path.replace(/'/g, "'\\''");
  const r = await exec(`test -f '${safe}' && echo yes || echo no`);
  return r.stdout.trim() === 'yes';
}

// 写入文件（heredoc，避免转义问题）
export async function writeFile(path: string, content: string): Promise<void> {
  const safe = path.replace(/'/g, "'\\''");
  const dir = path.substring(0, path.lastIndexOf('/'));
  if (dir) {
    await exec(`mkdir -p '${dir.replace(/'/g, "'\\''")}'`);
  }
  const cmd = `cat > '${safe}' <<'FKTEE_EOF'\n${content}\nFKTEE_EOF`;
  const r = await exec(cmd);
  if (r.errno !== 0) {
    throw new Error(`写入失败 ${path}: ${r.stderr}`);
  }
}

// 列出全部已安装应用（listPackages + getPackagesInfo）
export async function listApps(): Promise<AppInfo[]> {
  const names = await ksuListPackages();
  // 兼容部分实现返回字符串的情况
  const list: string[] = Array.isArray(names)
    ? names
    : String(names || '').split('\n').map((s) => s.trim()).filter(Boolean);
  if (!list.length) return [];
  const infos = await getPackagesInfo(list);
  return (infos || []).map((p: any) => ({
    packageName: p?.name || p?.packageName || '',
    label: p?.label || p?.name || '',
    versionName: p?.versionName || '',
    versionCode: p?.versionCode || 0,
    system: !!p?.system,
    enabled: p?.enabled !== false,
  }));
}

// 重启 daemon（touch restart 信号文件）
export async function restartDaemon(name: string): Promise<void> {
  const r = await exec(`touch /data/adb/fktee/restart.${name}`);
  if (r.errno !== 0) {
    throw new Error(`重启失败: ${r.stderr}`);
  }
  showToast(`已发送重启信号: ${name}`);
}

// 弹出 toast（兼容非 KSU 环境）
export function showToast(msg: string): void {
  try {
    toast(msg);
  } catch {
    console.log('[toast]', msg);
  }
}

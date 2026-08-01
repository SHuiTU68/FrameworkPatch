// 状态面板：daemon 运行状态、keystore2 注入状态、重启按钮
import { exec, restartDaemon, escapeHtml, showToast } from './cli';

interface StatusInfo {
  fkteePid: string;
  injectorPid: string;
  keystore2Pid: string;
  injected: boolean;
  targetCount: number;
}

// 获取 pidof（取首个 pid）
async function pidOf(name: string): Promise<string> {
  const r = await exec(`pidof '${name.replace(/'/g, "'\\''")}' 2>/dev/null`);
  const out = r.stdout.trim();
  return out ? out.split(/\s+/)[0] : '';
}

// 采集状态
async function fetchStatus(): Promise<StatusInfo> {
  const [fkteePid, injectorPid, keystore2Pid, scoopRaw, injectRaw] = await Promise.all([
    pidOf('fktee'),
    pidOf('fktee-injector'),
    pidOf('keystore2'),
    exec(`cat /data/adb/fktee/injector.toml 2>/dev/null | grep -c '"'`),
    exec(`test -f /data/adb/fktee/injected && echo yes || echo no`),
  ]);
  // 简单估算目标数量（双引号出现次数 / 2）
  const n = parseInt(scoopRaw.stdout.trim(), 10);
  const targetCount = isNaN(n) ? 0 : Math.floor(n / 2);
  return {
    fkteePid,
    injectorPid,
    keystore2Pid,
    injected: injectRaw.stdout.trim() === 'yes',
    targetCount,
  };
}

// 渲染状态面板
export async function renderStatus(container: HTMLElement): Promise<void> {
  container.innerHTML = '<div class="hint">采集状态中…</div>';
  let s: StatusInfo;
  try {
    s = await fetchStatus();
  } catch (e: any) {
    container.innerHTML = `<div class="hint error">采集失败：${escapeHtml(e?.message || e)}</div>`;
    return;
  }

  const row = (label: string, value: string, ok: boolean) => `
    <div class="info-row">
      <span>${escapeHtml(label)}</span>
      <b class="${ok ? 'ok' : 'warn'}">${escapeHtml(value)}</b>
    </div>`;

  container.innerHTML = `
    <div class="status">
      <h2 class="section-title">运行状态</h2>
      <div class="info-card">
        ${row('FKTee daemon', s.fkteePid ? `运行中 (PID ${s.fkteePid})` : '未运行', !!s.fkteePid)}
        ${row('Injector', s.injectorPid ? `运行中 (PID ${s.injectorPid})` : '未运行', !!s.injectorPid)}
        ${row('Keystore2', s.keystore2Pid ? `PID ${s.keystore2Pid}` : '未运行', !!s.keystore2Pid)}
        ${row('注入状态', s.injected ? '已注入' : '未注入', s.injected)}
        ${row('目标数量', String(s.targetCount), s.targetCount > 0)}
      </div>

      <h2 class="section-title">重启 Daemon</h2>
      <div class="actions">
        <md-filled-tonal-button id="r-fktee">
          <span class="material-symbols-outlined" slot="icon">restart_alt</span>
          重启 FKTee
        </md-filled-tonal-button>
        <md-filled-tonal-button id="r-injector">
          <span class="material-symbols-outlined" slot="icon">restart_alt</span>
          重启 Injector
        </md-filled-tonal-button>
        <md-filled-button id="r-all">
          <span class="material-symbols-outlined" slot="icon">power_settings_new</span>
          全部重启
        </md-filled-button>
        <md-outlined-button id="refresh">
          <span class="material-symbols-outlined" slot="icon">refresh</span>
          刷新
        </md-outlined-button>
      </div>
      <p class="tip">重启通过向 <code>/data/adb/fktee/restart.*</code> 写入信号文件触发。</p>
    </div>
  `;

  const bind = (id: string, name: string) => {
    container.querySelector(id)?.addEventListener('click', async () => {
      try {
        await restartDaemon(name);
        setTimeout(() => renderStatus(container), 1500);
      } catch (e: any) {
        showToast(e?.message || String(e));
      }
    });
  };
  bind('#r-fktee', 'fktee');
  bind('#r-injector', 'injector');
  bind('#r-all', 'all');
  container.querySelector('#refresh')?.addEventListener('click', () => renderStatus(container));
}

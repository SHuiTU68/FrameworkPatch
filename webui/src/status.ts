// 状态面板：daemon 运行状态、keystore2 注入状态、全局开关、重启按钮
import { exec, restartDaemon, escapeHtml, showToast } from './cli';
import { readInjectorToml } from './config';

interface StatusInfo {
  fkteePid: string;
  injectorPid: string;
  keystore2Pid: string;
  injected: boolean;
  hookEnabled: boolean;
}

// 获取 pidof（取首个 pid）
async function pidOf(name: string): Promise<string> {
  const r = await exec(`pidof '${name.replace(/'/g, "'\\''")}' 2>/dev/null`);
  const out = r.stdout.trim();
  return out ? out.split(/\s+/)[0] : '';
}

// 采集状态
async function fetchStatus(): Promise<StatusInfo> {
  const [fkteePid, injectorPid, keystore2Pid, injectRaw, cfg] = await Promise.all([
    pidOf('fktee'),
    pidOf('fktee-injector'),
    pidOf('keystore2'),
    exec(`test -f /data/adb/Tee-rs/injected && echo yes || echo no`),
    readInjectorToml().catch(() => ({ enabled: false, keyboxPath: '' })),
  ]);
  return {
    fkteePid,
    injectorPid,
    keystore2Pid,
    injected: injectRaw.stdout.trim() === 'yes',
    hookEnabled: cfg.enabled,
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

  const hookText = s.hookEnabled ? '已启用（全局，所有应用）' : '已禁用（透传）';

  container.innerHTML = `
    <div class="status">
      <h2 class="section-title">运行状态</h2>
      <div class="info-card">
        ${row('FKTee daemon', s.fkteePid ? `运行中 (PID ${s.fkteePid})` : '未运行', !!s.fkteePid)}
        ${row('Injector', s.injectorPid ? `运行中 (PID ${s.injectorPid})` : '未运行', !!s.injectorPid)}
        ${row('Keystore2', s.keystore2Pid ? `PID ${s.keystore2Pid}` : '未运行', !!s.keystore2Pid)}
        ${row('注入状态', s.injected ? '已注入' : '未注入', s.injected)}
        ${row('全局 Hook', hookText, s.hookEnabled)}
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
        </md-filled-button>
      </div>
      <p class="tip">重启通过向 <code>/data/adb/Tee-rs/restart.*</code> 写入信号文件触发。</p>
      <p class="tip">切换“全局”开关后需重启 Injector 才能让 keystore2 重新读取配置。</p>
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

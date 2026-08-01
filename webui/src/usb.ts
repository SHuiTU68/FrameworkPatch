// USB 调试开关面板
//
// 读写 /data/adb/fktee/usb.conf（service.sh apply_usb 读取），
// 同时直接调用 settings put global adb_enabled 实现「立即生效」，
// 不必等 service.sh 下一轮轮询。
import { escapeHtml, exec, showToast } from './cli';
import { readUsbConf, writeUsbConf } from './config';

let confAdb = true; // usb.conf 中持久化的目标值
let liveAdb = true; // settings global adb_enabled 的实时值
let liveRead = false;

// 读取实时 adb_enabled 状态
async function fetchLive(): Promise<boolean> {
  const r = await exec(`settings get global adb_enabled 2>/dev/null`);
  liveRead = true;
  return r.stdout.trim() === '1';
}

export async function renderUsb(container: HTMLElement): Promise<void> {
  container.innerHTML = '<div class="hint">读取 USB 配置…</div>';
  try {
    confAdb = await readUsbConf();
    liveAdb = await fetchLive();
  } catch (e: any) {
    container.innerHTML = `<div class="hint error">读取失败：${escapeHtml(e?.message || e)}</div>`;
    return;
  }
  draw(container);
  bind(container);
}

function draw(container: HTMLElement): void {
  const statusText = liveAdb
    ? 'USB 调试已开启（adb 可连接）'
    : 'USB 调试已关闭（adb 不可连接）';
  const statusClass = liveAdb ? 'ok' : 'warn';

  const targetText = confAdb
    ? '开机/重启后保持开启'
    : '开机/重启后保持关闭';

  container.innerHTML = `
    <div class="usb">
      <h2 class="section-title">USB 调试开关</h2>
      <div class="info-card">
        <div class="info-row">
          <span>当前状态</span>
          <b class="${statusClass}">${escapeHtml(statusText)}</b>
        </div>
        <div class="info-row">
          <span>持久化目标</span>
          <b>${escapeHtml(targetText)}</b>
        </div>
        <div class="info-row">
          <span>配置文件</span>
          <b>
            <md-switch id="usb-switch" ${confAdb ? 'selected' : ''}></md-switch>
          </b>
        </div>
      </div>
      <p class="tip">
        切换开关会写入 <code>usb.conf</code>，<b>并立即</b>通过
        <code>settings put global adb_enabled</code> 应用——无需重启。
      </p>
      <p class="tip">
        service.sh 在开机与每轮轮询时也会读取此文件，保证状态持久。
      </p>
      <div class="actions">
        <md-outlined-button id="usb-refresh">
          <span class="material-symbols-outlined" slot="icon">refresh</span>
          刷新实时状态
        </md-outlined-button>
      </div>
    </div>
  `;
}

function bind(container: HTMLElement): void {
  const sw = container.querySelector('#usb-switch') as HTMLElement | null;
  if (sw) {
    sw.addEventListener('change', async () => {
      confAdb = (sw as any).hasAttribute('selected');
      try {
        // 1) 持久化到 usb.conf
        await writeUsbConf(confAdb);
        // 2) 立即应用到 settings global
        const r = await exec(`settings put global adb_enabled ${confAdb ? '1' : '0'} 2>&1`);
        if (r.errno !== 0) {
          showToast(`配置已保存，但立即生效失败：${r.stderr || '未知错误'}`);
        } else {
          showToast(confAdb ? 'USB 调试已开启' : 'USB 调试已关闭');
        }
        // 重新读取实时状态
        liveAdb = await fetchLive();
      } catch (e: any) {
        showToast(`保存失败: ${e?.message || e}`);
      }
      draw(container);
      bind(container);
    });
  }

  container.querySelector('#usb-refresh')?.addEventListener('click', async () => {
    try {
      liveAdb = await fetchLive();
      showToast(liveAdb ? '当前 USB 调试：开启' : '当前 USB 调试：关闭');
    } catch (e: any) {
      showToast(`刷新失败: ${e?.message || e}`);
    }
    draw(container);
    bind(container);
  });
}

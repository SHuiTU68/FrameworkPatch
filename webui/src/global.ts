// 全局开关面板：FKTee-rs 全局 hook 总开关
//
// 取代旧的“勾选应用”列表。全局模型下没有 per-app 选择——
// 开关一开，所有走 keystore2 的应用 attestation 都用本模块 keybox 伪造。
import { escapeHtml, showToast, fileExists } from './cli';
import { readInjectorToml, writeInjectorToml, KEYBOX_PATH } from './config';

let enabled = true;
let keyboxReady = false;

async function refresh(): Promise<void> {
  const cfg = await readInjectorToml();
  enabled = cfg.enabled;
  keyboxReady = await fileExists(KEYBOX_PATH);
}

export async function renderGlobal(container: HTMLElement): Promise<void> {
  container.innerHTML = '<div class="hint">读取全局配置…</div>';
  try {
    await refresh();
  } catch (e: any) {
    container.innerHTML = `<div class="hint error">读取失败：${escapeHtml(e?.message || e)}</div>`;
    return;
  }
  draw(container);
  bind(container);
}

function draw(container: HTMLElement): void {
  const statusText = enabled
    ? keyboxReady
      ? '已启用 · 所有应用的 keystore2 attestation 将使用本模块 keybox'
      : '已启用 · 但 keybox.xml 缺失，请先在 Keybox 标签导入'
    : '已禁用 · 所有事务透传，不伪造任何证书';
  const statusClass = enabled ? (keyboxReady ? 'ok' : 'warn') : 'warn';

  container.innerHTML = `
    <div class="global">
      <h2 class="section-title">全局 Hook</h2>
      <div class="info-card">
        <div class="info-row">
          <span>总开关</span>
          <b>
            <md-switch id="master-switch" ${enabled ? 'selected' : ''}></md-switch>
          </b>
        </div>
        <div class="info-row">
          <span>状态</span>
          <b class="${statusClass}">${escapeHtml(statusText)}</b>
        </div>
        <div class="info-row">
          <span>作用范围</span>
          <b>所有应用（keystore2 全局）</b>
        </div>
        <div class="info-row">
          <span>keybox</span>
          <b class="${keyboxReady ? 'ok' : 'warn'}">${keyboxReady ? '已就绪' : '未导入'}</b>
        </div>
      </div>
      <p class="tip">
        开启后，FKTee-rs 注入 keystore2 并全局拦截 attestation 事务，
        <b>所有应用</b>读到的证书链都由本模块 keybox 签发——无需逐个勾选应用。
        关闭则所有事务透传，恢复系统原始行为。
      </p>
      <p class="tip">
        切换开关后需重启 Injector 生效（见“状态”标签）。
      </p>
    </div>
  `;
}

function bind(container: HTMLElement): void {
  const sw = container.querySelector('#master-switch') as HTMLElement | null;
  if (sw) {
    sw.addEventListener('change', async () => {
      // md-switch 的 selected 属性在 change 事件触发时已反映新状态
      enabled = (sw as any).hasAttribute('selected');
      try {
        await writeInjectorToml({ enabled, keyboxPath: KEYBOX_PATH });
        showToast(enabled ? '全局 hook 已启用' : '全局 hook 已禁用');
      } catch (e: any) {
        showToast(`保存失败: ${e?.message || e}`);
      }
      draw(container);
      bind(container);
    });
  }
}


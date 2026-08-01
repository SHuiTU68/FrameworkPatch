// FKTee-rs KSU WebUI 主入口
import '@material/web/all.js';
import { fullScreen, toast } from 'kernelsu-alt';
import { renderGlobal } from './global';
import { renderKeybox } from './keybox';
import { renderStatus } from './status';

type Tab = 'global' | 'keybox' | 'status';

const app = document.getElementById('app')!;
let currentTab: Tab = 'global';

// 检查 WebView 版本 >= 120
function checkWebViewVersion(): boolean {
  const m = navigator.userAgent.match(/Chrome\/(\d+)/);
  const ver = m ? parseInt(m[1], 10) : 0;
  if (ver && ver < 120) {
    try {
      toast(`WebView 版本过低 (${ver})，建议升级至 120+`);
    } catch {
      /* ignore */
    }
    console.warn(`WebView version ${ver} < 120`);
    return false;
  }
  return true;
}

// 全局 MD3 样式
const STYLE = `
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined&family=Roboto:wght@400;500;700&display=swap" />
<style>
:root {
  --md-sys-color-primary: #4f60bc;
  --md-sys-color-on-primary: #ffffff;
  --md-sys-color-primary-container: #dde0ff;
  --md-sys-color-on-primary-container: #00164e;
  --md-sys-color-surface: #fefcff;
  --md-sys-color-on-surface: #1b1b1f;
  --md-sys-color-surface-variant: #e3e1ec;
  --md-sys-color-on-surface-variant: #46464f;
  --md-sys-color-outline: #777680;
  --md-sys-color-secondary-container: #e1e0f9;
  --md-sys-color-error: #ba1a1a;
  --md-sys-color-on-error: #ffffff;
  --md-sys-color-error-container: #ffdad6;
  --md-sys-color-outline-variant: #c7c5d0;
  color-scheme: light;
}
@media (prefers-color-scheme: dark) {
  :root {
    --md-sys-color-primary: #bbc3ff;
    --md-sys-color-on-primary: #212a60;
    --md-sys-color-primary-container: #384278;
    --md-sys-color-on-primary-container: #dde0ff;
    --md-sys-color-surface: #131318;
    --md-sys-color-on-surface: #e5e1e9;
    --md-sys-color-surface-variant: #46464f;
    --md-sys-color-on-surface-variant: #c7c5d0;
    --md-sys-color-outline: #90909a;
    --md-sys-color-secondary-container: #3a3a4c;
    --md-sys-color-error: #ffb4ab;
    --md-sys-color-on-error: #690005;
    --md-sys-color-error-container: #93000a;
    --md-sys-color-outline-variant: #46464f;
    color-scheme: dark;
  }
}
* { box-sizing: border-box; }
html, body { margin: 0; padding: 0; }
body {
  font-family: 'Roboto', system-ui, sans-serif;
  background: var(--md-sys-color-surface);
  color: var(--md-sys-color-on-surface);
  min-height: 100vh;
}
.material-symbols-outlined { font-family: 'Material Symbols Outlined'; font-weight: normal; font-style: normal; line-height: 1; }
#app { max-width: 760px; margin: 0 auto; padding: 16px; }
.appbar { display: flex; align-items: center; gap: 12px; margin-bottom: 8px; }
.appbar h1 { font-size: 22px; margin: 0; flex: 1; }
.appbar .logo { width: 36px; height: 36px; border-radius: 10px; background: var(--md-sys-color-primary); color: var(--md-sys-color-on-primary); display: flex; align-items: center; justify-content: center; font-weight: 700; }
.subtitle { color: var(--md-sys-color-on-surface-variant); font-size: 13px; margin: 0 0 12px; }
.tabs { display: flex; gap: 8px; margin-bottom: 16px; flex-wrap: wrap; }
.tabs md-text-button, .tabs md-filled-tonal-button { flex: 1; min-width: 96px; }
#content { display: block; }
.section-title { font-size: 16px; margin: 18px 0 10px; color: var(--md-sys-color-on-surface-variant); }
.toolbar { display: flex; align-items: center; gap: 12px; margin-bottom: 12px; }
.toolbar md-outlined-text-field { flex: 1; }
.counter { font-size: 13px; color: var(--md-sys-color-on-surface-variant); white-space: nowrap; }
.cards { display: flex; flex-direction: column; gap: 8px; }
.card {
  display: flex; align-items: center; gap: 12px;
  background: var(--md-sys-color-secondary-container);
  border-radius: 16px; padding: 10px 14px; cursor: pointer;
  border: 2px solid transparent; transition: border-color .15s;
}
.card.selected { border-color: var(--md-sys-color-primary); }
.card-body { flex: 1; min-width: 0; }
.card-title { font-weight: 500; font-size: 15px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.card-sub { font-size: 12px; color: var(--md-sys-color-on-surface-variant); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.card-meta { font-size: 11px; color: var(--md-sys-color-outline); margin-top: 2px; }
.info-card { background: var(--md-sys-color-secondary-container); border-radius: 16px; padding: 14px 16px; }
.info-row { display: flex; justify-content: space-between; padding: 6px 0; border-bottom: 1px solid var(--md-sys-color-outline-variant); font-size: 14px; }
.info-row:last-child { border-bottom: none; }
.info-row .ok { color: #2e7d32; }
.info-row .warn { color: var(--md-sys-color-error); }
.mono { font-family: ui-monospace, monospace; font-size: 12px; }
.actions { display: flex; gap: 10px; flex-wrap: wrap; margin: 14px 0; }
.tip { font-size: 12px; color: var(--md-sys-color-outline); }
.hint { padding: 24px; text-align: center; color: var(--md-sys-color-on-surface-variant); }
.hint.error { color: var(--md-sys-color-error); }
.mode-pkg { font-family: ui-monospace, monospace; font-size: 12px; color: var(--md-sys-color-on-surface-variant); margin-bottom: 8px; }
code { background: var(--md-sys-color-surface-variant); padding: 1px 5px; border-radius: 4px; font-size: 12px; }
md-checkbox { flex: none; }
</style>
`;

// 顶部外壳
function shell(): string {
  const tabBtn = (id: Tab, label: string) =>
    currentTab === id
      ? `<md-filled-tonal-button data-tab="${id}">${label}</md-filled-tonal-button>`
      : `<md-text-button data-tab="${id}">${label}</md-text-button>`;
  return `
    ${STYLE}
    <div class="appbar">
      <div class="logo">F</div>
      <h1>FKTee-rs</h1>
    </div>
    <p class="subtitle">Play Integrity 全局密钥链 Hook · KernelSU WebUI</p>
    <div class="tabs">
      ${tabBtn('global', '全局')}
      ${tabBtn('keybox', 'Keybox')}
      ${tabBtn('status', '状态')}
    </div>
    <div id="content"></div>
  `;
}

// 切换标签
function switchTab(tab: Tab): void {
  if (tab === currentTab) return;
  currentTab = tab;
  render();
}

// 渲染当前标签内容
function renderContent(): void {
  const content = document.getElementById('content')!;
  if (currentTab === 'global') renderGlobal(content);
  else if (currentTab === 'keybox') renderKeybox(content);
  else renderStatus(content);
}

function render(): void {
  app.innerHTML = shell();
  app.querySelectorAll<HTMLElement>('[data-tab]').forEach((btn) => {
    btn.addEventListener('click', () => switchTab(btn.dataset.tab as Tab));
  });
  renderContent();
}

// 启动
function boot(): void {
  checkWebViewVersion();
  try {
    fullScreen(true);
  } catch {
    /* 非 KSU 环境忽略 */
  }
  render();
}

boot();

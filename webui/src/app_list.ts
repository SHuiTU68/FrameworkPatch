// 应用列表渲染：勾选 target、模式对话框（Auto/Generate/Hack）
import { AppInfo, listApps, escapeHtml, showToast } from './cli';
import {
  InjectorConfig,
  InjectMode,
  ALL_MODES,
  readInjectorToml,
  writeInjectorToml,
} from './config';

let apps: AppInfo[] = [];
let config: InjectorConfig;
let keyword = '';
let modeTarget = ''; // 当前正在配置模式的目标包名

const MODE_DESC: Record<InjectMode, string> = {
  auto: '自动（优先 keybox）',
  generate: '生成（运行时生成）',
  hack: 'Hack（强制）',
};

// 渲染应用列表
export async function renderAppList(container: HTMLElement): Promise<void> {
  container.innerHTML = '<div class="hint">加载应用列表中…</div>';
  try {
    const [allApps, cfg] = await Promise.all([listApps(), readInjectorToml()]);
    apps = allApps;
    config = cfg;
  } catch (e: any) {
    container.innerHTML = `<div class="hint error">加载失败：${escapeHtml(e?.message || String(e))}</div>`;
    return;
  }
  draw(container);
  bindEvents(container);
}

// 排序：已选排前面，再按名称
function sortedApps(): AppInfo[] {
  const selected = new Set(config.scoop);
  return [...apps].sort((a, b) => {
    const as = selected.has(a.packageName) ? 0 : 1;
    const bs = selected.has(b.packageName) ? 0 : 1;
    if (as !== bs) return as - bs;
    return (a.label || a.packageName).localeCompare(b.label || b.packageName);
  });
}

function draw(container: HTMLElement): void {
  const selectedCount = config.scoop.length;
  const filtered = sortedApps().filter((a) => {
    if (!keyword) return true;
    const k = keyword.toLowerCase();
    return a.packageName.toLowerCase().includes(k) || (a.label || '').toLowerCase().includes(k);
  });

  const cards = filtered
    .map((a) => {
      const checked = config.scoop.includes(a.packageName);
      const mode = config.modes[a.packageName] || 'auto';
      const sub = [
        a.versionName ? `v${a.versionName}` : '',
        a.system ? '系统' : '第三方',
        a.enabled ? '' : '已禁用',
      ].filter(Boolean).join(' · ');
      return `
      <div class="card${checked ? ' selected' : ''}" data-pkg="${escapeHtml(a.packageName)}">
        <md-checkbox touch-target="wrap" ${checked ? 'selected' : ''}></md-checkbox>
        <div class="card-body">
          <div class="card-title">${escapeHtml(a.label || a.packageName)}</div>
          <div class="card-sub">${escapeHtml(a.packageName)}</div>
          <div class="card-meta">${escapeHtml(sub)} · 模式: ${escapeHtml(MODE_DESC[mode])}</div>
        </div>
        <md-icon-button class="mode-btn" data-pkg="${escapeHtml(a.packageName)}" title="注入模式">
          <span class="material-symbols-outlined">tune</span>
        </md-icon-button>
      </div>`;
    })
    .join('');

  container.innerHTML = `
    <div class="toolbar">
      <md-outlined-text-field id="search" label="搜索应用" value="${escapeHtml(keyword)}"></md-outlined-text-field>
      <span class="counter">已选 ${selectedCount} / 共 ${apps.length}</span>
    </div>
    <div class="cards">${cards || '<div class="hint">无匹配应用</div>'}</div>
    <md-dialog id="mode-dialog">
      <div slot="headline">注入模式</div>
      <div slot="content" id="mode-content"></div>
      <div slot="actions">
        <md-text-button id="mode-cancel">取消</md-text-button>
        <md-text-button id="mode-ok">确定</md-text-button>
      </div>
    </md-dialog>
  `;
}

function bindEvents(container: HTMLElement): void {
  // 搜索
  const search = container.querySelector('#search') as HTMLElement | null;
  if (search) {
    search.addEventListener('input', (e: Event) => {
      const t = e.target as any;
      keyword = t?.value || '';
      draw(container);
      bindEvents(container);
    });
  }

  // 卡片点击切换选中
  container.querySelectorAll<HTMLElement>('.card').forEach((card) => {
    let longPressTimer: number | undefined;
    const pkg = card.dataset.pkg || '';

    const toggle = () => toggleSelect(container, pkg);
    card.addEventListener('click', (e) => {
      // 点击模式按钮不触发切换
      if ((e.target as HTMLElement).closest('.mode-btn')) return;
      toggle();
    });

    // 长按 / 右键 -> 模式对话框
    card.addEventListener('contextmenu', (e) => {
      e.preventDefault();
      openModeDialog(container, pkg);
    });
    card.addEventListener('touchstart', () => {
      longPressTimer = window.setTimeout(() => openModeDialog(container, pkg), 600);
    });
    card.addEventListener('touchend', () => {
      if (longPressTimer) clearTimeout(longPressTimer);
    });
    card.addEventListener('touchmove', () => {
      if (longPressTimer) clearTimeout(longPressTimer);
    });
  });

  // 模式按钮
  container.querySelectorAll<HTMLElement>('.mode-btn').forEach((btn) => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      openModeDialog(container, btn.dataset.pkg || '');
    });
  });
}

// 切换某个应用的选中状态并写回 injector.toml
async function toggleSelect(container: HTMLElement, pkg: string): Promise<void> {
  const idx = config.scoop.indexOf(pkg);
  if (idx >= 0) {
    config.scoop.splice(idx, 1);
  } else {
    config.scoop.push(pkg);
    if (!config.modes[pkg]) config.modes[pkg] = 'auto';
  }
  try {
    await writeInjectorToml(config);
    showToast(idx >= 0 ? `已移除: ${pkg}` : `已添加: ${pkg}`);
  } catch (e: any) {
    showToast(`保存失败: ${e?.message || e}`);
  }
  draw(container);
  bindEvents(container);
}

// 打开模式选择对话框
function openModeDialog(container: HTMLElement, pkg: string): void {
  if (!pkg) return;
  modeTarget = pkg;
  const current = config.modes[pkg] || 'auto';
  const content = container.querySelector('#mode-content') as HTMLElement;
  if (content) {
    content.innerHTML = `
      <div class="mode-pkg">${escapeHtml(pkg)}</div>
      <md-list>
        ${ALL_MODES.map(
          (m) => `
          <md-list-item type="button" data-mode="${m}">
            <div slot="headline">${escapeHtml(m.toUpperCase())}</div>
            <div slot="supporting-text">${escapeHtml(MODE_DESC[m])}</div>
            ${m === current ? '<md-icon slot="end">check</md-icon>' : ''}
          </md-list-item>`,
        ).join('')}
      </md-list>`;
    content.querySelectorAll<HTMLElement>('md-list-item').forEach((item) => {
      item.addEventListener('click', () => {
        const m = item.dataset.mode as InjectMode;
        if (m) chooseMode(container, m);
      });
    });
  }
  const dialog = container.querySelector('#mode-dialog') as any;
  dialog?.show?.();

  const cancel = container.querySelector('#mode-cancel');
  const ok = container.querySelector('#mode-ok');
  cancel?.addEventListener('click', () => dialog?.close?.());
  ok?.addEventListener('click', () => dialog?.close?.());
}

// 选定模式
async function chooseMode(container: HTMLElement, mode: InjectMode): Promise<void> {
  if (!modeTarget) return;
  // 若该应用未在 scoop 中，配置模式时自动加入
  if (!config.scoop.includes(modeTarget)) {
    config.scoop.push(modeTarget);
  }
  config.modes[modeTarget] = mode;
  try {
    await writeInjectorToml(config);
    showToast(`${modeTarget} -> ${mode}`);
  } catch (e: any) {
    showToast(`保存失败: ${e?.message || e}`);
  }
  const dialog = container.querySelector('#mode-dialog') as any;
  dialog?.close?.();
  draw(container);
  bindEvents(container);
}

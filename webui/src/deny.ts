// 黑名单（deny list）应用选择器
//
// 移植自 Tricky-Addon-Update-Target-List 的 app_list 设计：
// 用 kernelsu-alt 的 listPackages / getPackagesInfo 列出已安装应用，
// 卡片展示图标 + 应用名 + 包名 + 勾选框。勾选 = 加入黑名单（豁免伪造）。
// 与 Tricky 的差异：黑名单是二态（无 ! / ? 模式），持久化到 deny.list
// （每行一个包名），而非 target.txt。
import { listPackages, getPackagesInfo, type PackagesInfo } from 'kernelsu-alt';
import { escapeHtml, exec, showToast } from './cli';
import { readDenyList, writeDenyList } from './config';

interface AppEntry {
  packageName: string;
  appName: string;
  isSystem: boolean;
}

let allEntries: AppEntry[] = [];
let denySet: Set<string> = new Set();
let filter = '';
let loaded = false;

// 获取已安装应用列表（KSU 原生 API，失败回退 pm list packages）
async function fetchApps(): Promise<AppEntry[]> {
  let pkgs: string[] = [];
  try {
    pkgs = await listPackages('all');
  } catch {
    pkgs = [];
  }
  if (!pkgs.length) {
    // 回退：pm list packages（兼容旧版 KSU / 无 listPackages 的环境）
    const r = await exec(`pm list packages`);
    pkgs = r.stdout
      .split('\n')
      .map((l) => l.replace(/^package:/, '').trim())
      .filter(Boolean);
  }
  if (!pkgs.length) return [];

  let infos: PackagesInfo[] = [];
  try {
    infos = (await getPackagesInfo(pkgs)) as PackagesInfo[];
  } catch {
    infos = [];
  }
  return pkgs.map((pkg, i) => ({
    packageName: pkg,
    appName: infos[i]?.appLabel || pkg,
    isSystem: infos[i]?.isSystem ?? false,
  }));
}

export async function renderDeny(container: HTMLElement): Promise<void> {
  container.innerHTML = '<div class="hint">加载应用列表…</div>';
  if (!loaded) {
    try {
      const [apps, deny] = await Promise.all([fetchApps(), readDenyList().catch(() => [] as string[])]);
      allEntries = apps.sort((a, b) => a.appName.localeCompare(b.appName, 'zh-CN'));
      denySet = new Set(deny);
      loaded = true;
    } catch (e: any) {
      container.innerHTML = `<div class="hint error">加载失败：${escapeHtml(e?.message || e)}</div>`;
      return;
    }
  }
  draw(container);
  bind(container);
}

function draw(container: HTMLElement): void {
  const visible = allEntries.filter(
    (a) =>
      !filter ||
      a.packageName.toLowerCase().includes(filter) ||
      a.appName.toLowerCase().includes(filter)
  );
  const denyCount = denySet.size;

  const cards = visible
    .map((a) => {
      const checked = denySet.has(a.packageName);
      const sysTag = a.isSystem ? '<span class="card-meta">系统</span>' : '';
      return `
      <div class="card deny-card${checked ? ' selected' : ''}" data-pkg="${escapeHtml(a.packageName)}">
        <md-ripple></md-ripple>
        <label class="name">
          <div class="app-icon-container">
            <img class="app-icon" data-pkg="${escapeHtml(a.packageName)}" alt="${escapeHtml(a.appName)}" />
            <span class="app-icon-fallback material-symbols-outlined" data-pkg="${escapeHtml(a.packageName)}">android</span>
          </div>
          <div class="app-info">
            <div class="card-title">${escapeHtml(a.appName)}</div>
            <div class="card-sub">${escapeHtml(a.packageName)}</div>
            ${sysTag}
          </div>
        </label>
        <md-checkbox touch-target="wrapper" ${checked ? 'checked' : ''}></md-checkbox>
      </div>`;
    })
    .join('');

  container.innerHTML = `
    <div class="deny">
      <h2 class="section-title">黑名单（豁免伪造）</h2>
      <p class="tip">勾选的应用保留真实 attestation（透传），其余所有应用一律用 keybox 伪造。当前已勾选 <b>${denyCount}</b> 个。</p>
      <div class="toolbar">
        <md-outlined-text-field id="deny-search" label="搜索应用 / 包名" value="${escapeHtml(filter)}">
          <span class="material-symbols-outlined" slot="leading-icon">search</span>
        </md-outlined-text-field>
        <md-outlined-button id="deny-clear" title="清空黑名单">
          <span class="material-symbols-outlined" slot="icon">delete_sweep</span>
        </md-outlined-button>
      </div>
      <div class="counter">${visible.length} / ${allEntries.length} 个应用${filter ? '（已过滤）' : ''}</div>
      <div class="cards">${cards || '<div class="hint">无匹配应用</div>'}</div>
      <div class="actions">
        <md-filled-button id="deny-save">
          <span class="material-symbols-outlined" slot="icon">save</span>
          保存黑名单
        </md-filled-button>
        <md-outlined-button id="deny-refresh">
          <span class="material-symbols-outlined" slot="icon">refresh</span>
          刷新列表
        </md-outlined-button>
      </div>
      <p class="tip">保存后需重启 Injector 生效（见「状态」标签）。</p>
    </div>
  `;
  loadIcons(container);
}

// 图标用 KSU 拦截的 ksu://icon/ 协议；加载失败显示兜底图标。
function loadIcons(container: HTMLElement): void {
  container.querySelectorAll<HTMLImageElement>('.app-icon').forEach((img) => {
    const pkg = img.dataset.pkg || '';
    img.onload = () => {
      img.style.opacity = '1';
      img.parentElement?.querySelector('.app-icon-fallback')?.classList.remove('visible');
    };
    img.onerror = () => {
      img.style.display = 'none';
      img.parentElement?.querySelector('.app-icon-fallback')?.classList.add('visible');
    };
    img.src = `ksu://icon/${pkg}`;
  });
}

function bind(container: HTMLElement): void {
  // 卡片点击 / 勾选切换
  container.querySelectorAll<HTMLElement>('.deny-card').forEach((card) => {
    card.addEventListener('click', (e) => {
      // 点击 checkbox 自身时让 md-checkbox 处理，避免双切换
      if ((e.target as HTMLElement).tagName === 'MD-CHECKBOX') return;
      const pkg = card.dataset.pkg || '';
      const cb = card.querySelector('md-checkbox') as any;
      const now = !cb.checked;
      cb.checked = now;
      toggle(card, pkg, now);
    });
    card.querySelector('md-checkbox')?.addEventListener('change', () => {
      const pkg = card.dataset.pkg || '';
      const cb = card.querySelector('md-checkbox') as any;
      toggle(card, pkg, !!cb.checked);
    });
  });

  // 搜索
  const search = container.querySelector('#deny-search') as any;
  search?.addEventListener('input', () => {
    filter = String(search?.value || '').toLowerCase();
    draw(container);
    bind(container);
  });

  // 清空
  container.querySelector('#deny-clear')?.addEventListener('click', () => {
    denySet.clear();
    draw(container);
    bind(container);
    showToast('已清空勾选（需保存生效）');
  });

  // 保存
  container.querySelector('#deny-save')?.addEventListener('click', async () => {
    try {
      await writeDenyList(Array.from(denySet));
      showToast(`黑名单已保存（${denySet.size} 个）`);
    } catch (e: any) {
      showToast(`保存失败: ${e?.message || e}`);
    }
  });

  // 刷新
  container.querySelector('#deny-refresh')?.addEventListener('click', async () => {
    loaded = false;
    await renderDeny(container);
  });
}

function toggle(card: HTMLElement, pkg: string, on: boolean): void {
  if (on) {
    denySet.add(pkg);
    card.classList.add('selected');
  } else {
    denySet.delete(pkg);
    card.classList.remove('selected');
  }
  // 更新顶部计数
  const tip = document.querySelector('.deny .tip b');
  if (tip) tip.textContent = String(denySet.size);
}

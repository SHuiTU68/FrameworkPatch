// Prop 属性隐藏面板
//
// 读写 /data/adb/Tee-rs/props.conf（service.sh apply_props 读取）。
// 总开关控制 enabled=1/0；其余 key=value 通过 resetprop 覆盖，
// 让 Play Integrity / 反作弊检测看到伪造的 verified boot 状态等。
import { escapeHtml, exec, showToast } from './cli';
import { readPropsConf, writePropsConf, type PropsConfig } from './config';

let cfg: PropsConfig = { enabled: true, entries: [] };

// 读取某个 prop 当前实际值（getprop，便于对比隐藏前后）
async function readPropLive(key: string): Promise<string> {
  const safe = key.replace(/'/g, "'\\''");
  const r = await exec(`getprop '${safe}' 2>/dev/null`);
  return r.stdout.trim();
}

export async function renderProps(container: HTMLElement): Promise<void> {
  container.innerHTML = '<div class="hint">读取 prop 配置…</div>';
  try {
    cfg = await readPropsConf();
  } catch (e: any) {
    container.innerHTML = `<div class="hint error">读取失败：${escapeHtml(e?.message || e)}</div>`;
    return;
  }
  draw(container);
  bind(container);
}

function draw(container: HTMLElement): void {
  const rows = cfg.entries
    .map((e, i) => {
      return `
      <div class="card prop-card" data-idx="${i}">
        <md-ripple></md-ripple>
        <div class="prop-body">
          <md-outlined-text-field class="prop-key" label="属性名" value="${escapeHtml(e.key)}"></md-outlined-text-field>
          <md-outlined-text-field class="prop-val" label="伪造值" value="${escapeHtml(e.value)}"></md-outlined-text-field>
        </div>
        <md-icon-button class="prop-del" title="删除">
          <span class="material-symbols-outlined">delete</span>
        </md-icon-button>
      </div>`;
    })
    .join('');

  const statusText = cfg.enabled
    ? `已启用 · ${cfg.entries.length} 条 prop 将通过 resetprop 覆盖`
    : '已禁用 · 不修改任何系统属性';

  container.innerHTML = `
    <div class="props">
      <h2 class="section-title">Prop 属性隐藏</h2>
      <div class="info-card">
        <div class="info-row">
          <span>总开关</span>
          <b>
            <md-switch id="props-switch" ${cfg.enabled ? 'selected' : ''}></md-switch>
          </b>
        </div>
        <div class="info-row">
          <span>状态</span>
          <b class="${cfg.enabled ? 'ok' : 'warn'}">${escapeHtml(statusText)}</b>
        </div>
      </div>
      <p class="tip">
        通过 <code>resetprop --delete</code> + <code>resetprop set</code> 覆盖系统属性，
        让 Play Integrity / 反作弊读到伪造的 verified boot 状态。需要 Magisk/KernelSU 提供的 resetprop。
      </p>
      <p class="tip">
        支持条件语法 <code>key~match=value</code>：仅当 <code>getprop(key)</code> 包含
        <code>match</code> 时才覆盖（用于隐藏 recovery 启动模式等，避免误改正常值）。
      </p>
      <p class="tip">
        支持 <code>once:</code> 前缀：该条目仅在开机时执行一次，主循环轮询时跳过
        （用于 <code>sys.boot_completed=0</code> 等“一次性”项，避免持续压回导致系统误判未开机）。
      </p>

      <h2 class="section-title">属性条目（key = value）</h2>
      <div class="cards">${rows || '<div class="hint">暂无属性条目</div>'}</div>
      <div class="actions">
        <md-filled-tonal-button id="props-add">
          <span class="material-symbols-outlined" slot="icon">add</span>
          新增属性
        </md-filled-tonal-button>
        <md-filled-button id="props-save">
          <span class="material-symbols-outlined" slot="icon">save</span>
          保存
        </md-filled-button>
        <md-outlined-button id="props-apply-now">
          <span class="material-symbols-outlined" slot="icon">bolt</span>
          立即应用
        </md-outlined-button>
        <md-outlined-button id="props-refresh">
          <span class="material-symbols-outlined" slot="icon">refresh</span>
          重新载入
        </md-outlined-button>
      </div>
      <p class="tip">保存仅写 props.conf；「立即应用」会立刻对每条 prop 跑一次 resetprop（无需等 service.sh 轮询）。</p>
    </div>
  `;
}

function bind(container: HTMLElement): void {
  // 总开关
  const sw = container.querySelector('#props-switch') as HTMLElement | null;
  if (sw) {
    sw.addEventListener('change', async () => {
      cfg.enabled = (sw as any).hasAttribute('selected');
      try {
        await writePropsConf(cfg);
        showToast(cfg.enabled ? 'prop 隐藏已启用（已保存）' : 'prop 隐藏已禁用（已保存）');
      } catch (e: any) {
        showToast(`保存失败: ${e?.message || e}`);
      }
      draw(container);
      bind(container);
    });
  }

  // 编辑 key/value（实时同步到内存）
  container.querySelectorAll<HTMLElement>('.prop-card').forEach((card) => {
    const idx = Number(card.dataset.idx);
    const keyEl = card.querySelector('.prop-key') as any;
    const valEl = card.querySelector('.prop-val') as any;
    keyEl?.addEventListener('input', () => {
      if (cfg.entries[idx]) cfg.entries[idx].key = String(keyEl.value || '');
    });
    valEl?.addEventListener('input', () => {
      if (cfg.entries[idx]) cfg.entries[idx].value = String(valEl.value || '');
    });
    // 删除
    card.querySelector('.prop-del')?.addEventListener('click', () => {
      cfg.entries.splice(idx, 1);
      draw(container);
      bind(container);
    });
  });

  // 新增
  container.querySelector('#props-add')?.addEventListener('click', () => {
    cfg.entries.push({ key: 'ro.boot.', value: '' });
    draw(container);
    bind(container);
  });

  // 保存
  container.querySelector('#props-save')?.addEventListener('click', async () => {
    // 过滤空 key
    cfg.entries = cfg.entries.filter((e) => e.key.trim());
    try {
      await writePropsConf(cfg);
      showToast(`已保存 ${cfg.entries.length} 条 prop`);
    } catch (e: any) {
      showToast(`保存失败: ${e?.message || e}`);
    }
    draw(container);
    bind(container);
  });

  // 立即应用
  container.querySelector('#props-apply-now')?.addEventListener('click', async () => {
    if (!cfg.enabled) {
      showToast('prop 隐藏已禁用，无法应用');
      return;
    }
    if (!cfg.entries.length) {
      showToast('没有可应用的 prop 条目');
      return;
    }
    // 检查 resetprop 可用性
    const chk = await exec(`command -v resetprop >/dev/null 2>&1 && echo yes || echo no`);
    if (chk.stdout.trim() !== 'yes') {
      showToast('未找到 resetprop，无法应用（需 Magisk/KernelSU）');
      return;
    }
    let ok = 0;
    for (const e of cfg.entries) {
      let key = e.key;
      const value = e.value;
      // 去掉 once: 前缀（立即应用时按需执行一次）
      if (key.startsWith('once:')) {
        key = key.slice(5);
      }
      // 支持 key~match=value：仅当 getprop(key) 包含 match 才覆盖
      const tilde = key.indexOf('~');
      if (tilde >= 0) {
        const realKey = key.slice(0, tilde);
        const match = key.slice(tilde + 1);
        const cur = await exec(`getprop '${realKey.replace(/'/g, "'\\''")}' 2>/dev/null`);
        if (!cur.stdout.includes(match)) {
          ok++; // 当前值不匹配，无需修改，视为已满足
          continue;
        }
        key = realKey;
      }
      const k = key.replace(/'/g, "'\\''");
      const v = value.replace(/'/g, "'\\''");
      const r = await exec(
        `resetprop --delete '${k}' 2>/dev/null; resetprop '${k}' '${v}' 2>/dev/null; echo done`
      );
      if (r.errno === 0) ok++;
    }
    showToast(`已应用 ${ok}/${cfg.entries.length} 条 prop`);
  });

  // 重新载入
  container.querySelector('#props-refresh')?.addEventListener('click', async () => {
    try {
      cfg = await readPropsConf();
      showToast('已重新载入配置');
    } catch (e: any) {
      showToast(`载入失败: ${e?.message || e}`);
    }
    draw(container);
    bind(container);
  });
}

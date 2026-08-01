// Keybox 管理：导入 keybox.xml、显示算法/有效期/证书数
import { readFile, writeFile, fileExists, escapeHtml, showToast, exec } from './cli';
import { KEYBOX_PATH } from './config';

interface KeyboxInfo {
  algorithm: string;
  certCount: number;
  chainLength: number;
  notBefore: string;
  notAfter: string;
  hasKey: boolean;
}

// base64 -> ArrayBuffer
function b64ToArrayBuffer(b64: string): ArrayBuffer {
  const bin = atob(b64.replace(/\s+/g, ''));
  const len = bin.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}

// 用 asn1js + pkijs 解码证书有效期（动态导入，失败不影响 UI）
async function decodeCertValidity(b64: string): Promise<{ notBefore: string; notAfter: string }> {
  try {
    const asn1js = await import('asn1js');
    const { Certificate } = await import('pkijs');
    const buf = b64ToArrayBuffer(b64);
    const asn1 = (asn1js as any).fromBER(buf);
    const cert = new Certificate({ schema: asn1.result });
    const fmt = (d: any) => {
      try {
        return new Date(d.value?.valueOf?.() ?? d.value).toLocaleString('zh-CN');
      } catch {
        return String(d);
      }
    };
    return { notBefore: fmt(cert.notBefore), notAfter: fmt(cert.notAfter) };
  } catch {
    return { notBefore: '—', notAfter: '—' };
  }
}

// 解析 keybox.xml 信息
async function parseKeybox(xml: string): Promise<KeyboxInfo> {
  const info: KeyboxInfo = {
    algorithm: '—',
    certCount: 0,
    chainLength: 0,
    notBefore: '—',
    notAfter: '—',
    hasKey: false,
  };
  try {
    const doc = new DOMParser().parseFromString(xml, 'application/xml');
    const keys = doc.querySelectorAll('Key');
    info.certCount = keys.length;
    if (keys.length > 0) {
      info.algorithm = keys[0].getAttribute('algorithm') || 'RSA';
      info.hasKey = !!keys[0].querySelector('PrivateKey');
      const cert = keys[0].querySelector('Certificate');
      info.chainLength = cert ? Number(cert.getAttribute('chainLength') || '1') : 1;
      // 提取第一个 Sequence（通常为证书 DER base64）
      const seq = cert?.querySelector('Sequence');
      if (seq?.textContent) {
        const v = await decodeCertValidity(seq.textContent.trim());
        info.notBefore = v.notBefore;
        info.notAfter = v.notAfter;
      }
    }
  } catch {
    // 忽略解析错误
  }
  return info;
}

// 渲染 keybox 管理界面
export async function renderKeybox(container: HTMLElement): Promise<void> {
  container.innerHTML = '<div class="hint">读取 keybox…</div>';

  const exists = await fileExists(KEYBOX_PATH);
  let info: KeyboxInfo | null = null;
  if (exists) {
    try {
      const xml = await readFile(KEYBOX_PATH);
      info = await parseKeybox(xml);
    } catch (e: any) {
      info = null;
    }
  }

  const card = info
    ? `
    <div class="info-card">
      <div class="info-row"><span>算法</span><b>${escapeHtml(info.algorithm)}</b></div>
      <div class="info-row"><span>Key 数量</span><b>${info.certCount}</b></div>
      <div class="info-row"><span>证书链长度</span><b>${info.chainLength}</b></div>
      <div class="info-row"><span>私钥</span><b>${info.hasKey ? '已包含' : '缺失'}</b></div>
      <div class="info-row"><span>生效时间</span><b>${escapeHtml(info.notBefore)}</b></div>
      <div class="info-row"><span>失效时间</span><b>${escapeHtml(info.notAfter)}</b></div>
      <div class="info-row"><span>路径</span><b class="mono">${escapeHtml(KEYBOX_PATH)}</b></div>
    </div>`
    : `<div class="hint">未发现 keybox.xml，请导入</div>`;

  container.innerHTML = `
    <div class="keybox">
      <h2 class="section-title">Keybox 管理</h2>
      ${card}
      <div class="actions">
        <input type="file" id="keybox-file" accept=".xml,text/xml" hidden />
        <md-filled-button id="import-btn">
          <span class="material-symbols-outlined" slot="icon">upload_file</span>
          导入 keybox.xml
        </md-filled-button>
        <md-outlined-button id="refresh-btn">
          <span class="material-symbols-outlined" slot="icon">refresh</span>
          刷新
        </md-outlined-button>
      </div>
      <p class="tip">导入后将保存到 <code>${escapeHtml(KEYBOX_PATH)}</code>，daemon 会自动加载。</p>
    </div>
  `;

  const fileInput = container.querySelector('#keybox-file') as HTMLInputElement;
  container.querySelector('#import-btn')?.addEventListener('click', () => fileInput?.click());
  container.querySelector('#refresh-btn')?.addEventListener('click', () => renderKeybox(container));
  if (fileInput) {
    fileInput.addEventListener('change', () => onImport(container, fileInput));
  }
}

// 处理导入
async function onImport(container: HTMLElement, input: HTMLInputElement): Promise<void> {
  const file = input.files?.[0];
  if (!file) return;
  try {
    const text = await file.text();
    if (!text.includes('<keybox') && !text.includes('<Key')) {
      showToast('文件内容不像 keybox.xml');
      return;
    }
    await writeFile(KEYBOX_PATH, text);
    // 设置权限，确保 daemon 可读
    await exec(`chmod 644 '${KEYBOX_PATH.replace(/'/g, "'\\''")}'`);
    showToast('keybox 已导入');
    await renderKeybox(container);
  } catch (e: any) {
    showToast(`导入失败: ${e?.message || e}`);
  }
}

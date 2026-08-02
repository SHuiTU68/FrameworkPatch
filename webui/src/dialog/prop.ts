// props.conf 列表编辑器
// 语法：enabled=N（首行总开关）、key=value、key~match=value（条件覆盖）、once:key=value（仅开机）
import type { MdDialog, MdFilledButton, MdOutlinedButton, MdOutlinedTextField, MdSwitch, MdIconButton } from '@material/web/all'
import { i18n } from '../i18n'
import { File } from '../file'
import type { Snackbar } from '../snackbar/snackbar'
import { PROPS_FILE } from '../constant'
import { applyDialogAnimation } from './animation'

interface PropRule {
  key: string
  match: string   // 为空表示无 ~ 条件
  value: string
  once: boolean
}

export class PropDialog {
  #dialog: MdDialog | null = null
  #snackbar: Snackbar
  #rules: PropRule[] = []
  #enabled = true

  constructor(_cli: unknown, _config: unknown, snackbar: Snackbar) {
    this.#snackbar = snackbar
  }

  getElement(): DocumentFragment {
    const template = document.createElement('template')
    template.innerHTML = /* html */ `
      <md-dialog id="prop-dialog">
        <div slot="headline">${i18n.t('prop_dialog_title')}</div>
        <div slot="content">
          <label class="switch-item contrast" for="prop-enabled-switch">
            <md-ripple></md-ripple>
            <span>${i18n.t('prop_enabled')}</span>
            <md-switch icons="true" id="prop-enabled-switch"></md-switch>
          </label>
          <md-divider></md-divider>
          <div id="prop-rules" class="prop-rules"></div>
          <md-outlined-button id="prop-add-rule" class="full-width-button">
            <md-icon slot="icon">add</md-icon>
            ${i18n.t('prop_add_rule')}
          </md-outlined-button>
        </div>
        <div slot="actions">
          <md-outlined-button id="close-prop">${i18n.t('functional_button_close')}</md-outlined-button>
          <md-filled-button id="save-prop">${i18n.t('functional_button_save')}</md-filled-button>
        </div>
      </md-dialog>
    `

    const fragment = template.content
    this.#dialog = fragment.querySelector<MdDialog>('#prop-dialog')

    fragment.querySelector<MdOutlinedButton>('#prop-add-rule')!.onclick = () => {
      this.#rules.push({ key: '', match: '', value: '', once: false })
      this.#renderRules()
    }
    fragment.querySelector<MdOutlinedButton>('#close-prop')!.onclick = () => this.close()
    fragment.querySelector<MdFilledButton>('#save-prop')!.onclick = () => this.#save()

    return fragment
  }

  initAnimation(): void {
    if (this.#dialog) applyDialogAnimation(this.#dialog)
  }

  async show(): Promise<void> {
    await this.#load()
    this.#dialog?.show()
  }

  close(): void {
    this.#dialog?.close()
  }

  async #load(): Promise<void> {
    this.#rules = []
    this.#enabled = true
    try {
      const raw = await File.read(PROPS_FILE)
      for (const line of raw.split('\n')) {
        const t = line.trim()
        if (!t || t.startsWith('#')) continue
        const eqIdx = t.indexOf('=')
        if (eqIdx <= 0) continue
        const spec = t.slice(0, eqIdx)
        const value = t.slice(eqIdx + 1)
        if (spec === 'enabled') {
          this.#enabled = value.trim() === '1'
          continue
        }
        let once = false
        let rest = spec
        if (rest.startsWith('once:')) {
          once = true
          rest = rest.slice(5)
        }
        let key = rest
        let match = ''
        const tilde = rest.indexOf('~')
        if (tilde > 0) {
          key = rest.slice(0, tilde)
          match = rest.slice(tilde + 1)
        }
        this.#rules.push({ key, match, value, once })
      }
    } catch {
      /* 文件不存在时留空 */
    }
    this.#renderRules()
    const sw = this.#dialog?.querySelector<MdSwitch>('#prop-enabled-switch')
    if (sw) sw.selected = this.#enabled
  }

  #renderRules(): void {
    const container = this.#dialog?.querySelector<HTMLElement>('#prop-rules')
    if (!container) return
    container.innerHTML = ''
    this.#rules.forEach((rule, idx) => {
      const row = document.createElement('div')
      row.className = 'prop-rule'
      row.innerHTML = /* html */ `
        <div class="prop-rule-fields">
          <md-outlined-text-field class="prop-key" label="${i18n.t('prop_key')}" placeholder="ro.build.tags" value="${this.#escAttr(rule.key)}"></md-outlined-text-field>
          <md-outlined-text-field class="prop-match" label="${i18n.t('prop_match')}" placeholder="keys" value="${this.#escAttr(rule.match)}"></md-outlined-text-field>
          <md-outlined-text-field class="prop-value" label="${i18n.t('prop_value')}" placeholder="release-keys" value="${this.#escAttr(rule.value)}"></md-outlined-text-field>
        </div>
        <div class="prop-rule-actions">
          <label class="prop-once-label">
            <md-switch class="prop-once" icons="true"${rule.once ? ' selected' : ''}></md-switch>
            <span>${i18n.t('prop_once')}</span>
          </label>
          <md-icon-button class="prop-del" data-idx="${idx}">
            <md-icon>delete</md-icon>
          </md-icon-button>
        </div>
      `
      row.querySelector<MdIconButton>('.prop-del')!.onclick = () => {
        this.#rules.splice(idx, 1)
        this.#renderRules()
      }
      container.appendChild(row)
    })
  }

  #escAttr(s: string): string {
    return String(s).replace(/"/g, '&quot;')
  }

  #collect(): { enabled: boolean; rules: PropRule[] } {
    const container = this.#dialog?.querySelector<HTMLElement>('#prop-rules')
    const sw = this.#dialog?.querySelector<MdSwitch>('#prop-enabled-switch')
    const enabled = sw?.selected ?? true
    const rules: PropRule[] = []
    container?.querySelectorAll<HTMLElement>('.prop-rule').forEach(row => {
      const key = (row.querySelector<MdOutlinedTextField>('.prop-key')?.value ?? '').trim()
      const match = (row.querySelector<MdOutlinedTextField>('.prop-match')?.value ?? '').trim()
      const value = (row.querySelector<MdOutlinedTextField>('.prop-value')?.value ?? '')
      const once = row.querySelector<MdSwitch>('.prop-once')?.selected ?? false
      if (key) rules.push({ key, match, value, once })
    })
    return { enabled, rules }
  }

  async #save(): Promise<void> {
    const { enabled, rules } = this.#collect()
    const lines: string[] = [`enabled=${enabled ? '1' : '0'}`]
    for (const r of rules) {
      const spec = (r.once ? 'once:' : '') + r.key + (r.match ? `~${r.match}` : '')
      lines.push(`${spec}=${r.value}`)
    }
    const raw = lines.join('\n') + '\n'
    try {
      await File.write(PROPS_FILE, raw)
      this.#rules = rules
      this.#enabled = enabled
      this.close()
      this.#snackbar.show(i18n.t('prompt_prop_saved'))
    } catch {
      this.#snackbar.show(i18n.t('prompt_prop_save_error'), false)
    }
  }
}

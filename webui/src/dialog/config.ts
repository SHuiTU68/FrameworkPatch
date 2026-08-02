// config.toml + injector.toml 编辑器
import type { MdDialog, MdFilledButton, MdOutlinedButton, MdOutlinedTextField, MdSwitch, MdOutlinedSelect } from '@material/web/all'
import { i18n } from '../i18n'
import type { Snackbar } from '../snackbar/snackbar'
import { CONFIG_FILE, INJECTOR_FILE } from '../constant'
import { readConfigToml, readInjectorToml, writeToml, type Toml } from '../config_fktee'
import { applyDialogAnimation } from './animation'

// 布尔字段描述
interface BoolField {
  id: string
  section: string
  key: string
  label: string
}
// 文本字段描述
interface TextField {
  id: string
  section: string
  key: string
  label: string
  placeholder?: string
}
// 选择字段描述
interface SelectField {
  id: string
  section: string
  key: string
  label: string
  options: string[]
}

const CONFIG_BOOLS: BoolField[] = [
  { id: 'cfg-device_locked', section: 'trust', key: 'device_locked', label: 'config_device_locked' },
  { id: 'cfg-to_kmsg', section: 'log', key: 'to_kmsg', label: 'config_log_to_kmsg' },
  { id: 'cfg-verbose', section: 'log', key: 'verbose', label: 'config_log_verbose' },
]
const CONFIG_TEXTS: TextField[] = [
  { id: 'cfg-vb_key', section: 'trust', key: 'vb_key', label: 'config_vb_key', placeholder: 'auto | random | <hex>' },
  { id: 'cfg-vb_hash', section: 'trust', key: 'vb_hash', label: 'config_vb_hash', placeholder: 'auto | random | <hex>' },
  { id: 'cfg-security_patch', section: 'trust', key: 'security_patch', label: 'config_security_patch', placeholder: 'auto | latest | YYYY-MM-DD' },
  { id: 'cfg-root_kek_seed', section: 'crypto', key: 'root_kek_seed', label: 'config_root_kek_seed', placeholder: 'hex（空=自动生成）' },
  { id: 'cfg-kak_seed', section: 'crypto', key: 'kak_seed', label: 'config_kak_seed', placeholder: 'hex' },
  { id: 'cfg-shared_secret_seed', section: 'crypto', key: 'shared_secret_seed', label: 'config_shared_secret_seed', placeholder: 'hex' },
  { id: 'cfg-shared_secret_nonce', section: 'crypto', key: 'shared_secret_nonce', label: 'config_shared_secret_nonce', placeholder: 'hex' },
]
const CONFIG_SELECTS: SelectField[] = [
  { id: 'cfg-mode', section: 'backend', key: 'mode', label: 'config_backend_mode', options: ['injector', 'hal'] },
  { id: 'cfg-verified_boot_state', section: 'trust', key: 'verified_boot_state', label: 'config_verified_boot_state', options: ['green', 'yellow', 'orange', 'red'] },
  { id: 'cfg-log_level', section: 'log', key: 'level', label: 'config_log_level', options: ['debug', 'info', 'warn', 'error'] },
]
const INJECTOR_BOOLS: BoolField[] = [
  { id: 'inj-hook_enabled', section: 'hook', key: 'enabled', label: 'config_hook_enabled' },
  { id: 'inj-get_key_entry', section: 'intercept', key: 'get_key_entry', label: 'get_key_entry' },
  { id: 'inj-generate_key', section: 'intercept', key: 'generate_key', label: 'generate_key' },
  { id: 'inj-import_key', section: 'intercept', key: 'import_key', label: 'import_key' },
  { id: 'inj-create_operation', section: 'intercept', key: 'create_operation', label: 'create_operation' },
  { id: 'inj-delete_key', section: 'intercept', key: 'delete_key', label: 'delete_key' },
  { id: 'inj-list_entries', section: 'intercept', key: 'list_entries', label: 'list_entries' },
  { id: 'inj-grant', section: 'intercept', key: 'grant', label: 'grant' },
]

function selectHtml(id: string, label: string, options: string[]): string {
  const opts = options.map(o => `<md-select-option value="${o}"><div slot="headline">${o}</div></md-select-option>`).join('')
  return `<md-outlined-select id="${id}" label="${i18n.t(label)}" menu-positioning="popover" clamp-menu-width>${opts}</md-outlined-select>`
}

function boolHtml(id: string, label: string): string {
  return `<label class="switch-item outlined" for="${id}">
    <md-ripple></md-ripple>
    <span>${i18n.t(label)}</span>
    <md-switch icons="true" id="${id}"></md-switch>
  </label>`
}

function textHtml(id: string, label: string, placeholder?: string): string {
  const ph = placeholder ? ` placeholder="${placeholder}"` : ''
  return `<md-outlined-text-field id="${id}" label="${i18n.t(label)}" autocapitalize="none"${ph}></md-outlined-text-field>`
}

export class ConfigDialog {
  #dialog: MdDialog | null = null
  #snackbar: Snackbar

  constructor(_cli: unknown, _config: unknown, snackbar: Snackbar) {
    this.#snackbar = snackbar
  }

  getElement(): DocumentFragment {
    const template = document.createElement('template')
    template.innerHTML = /* html */ `
      <md-dialog id="config-dialog" class="text-field-dialog">
        <div slot="headline">${i18n.t('config_dialog_title')}</div>
        <div slot="content">
          <div class="cfg-section-title">${i18n.t('config_section_backend')}</div>
          ${selectHtml('cfg-mode', 'config_backend_mode', ['injector', 'hal'])}
          <div class="cfg-section-title">${i18n.t('config_section_trust')}</div>
          ${selectHtml('cfg-verified_boot_state', 'config_verified_boot_state', ['green', 'yellow', 'orange', 'red'])}
          ${boolHtml('cfg-device_locked', 'config_device_locked')}
          ${textHtml('cfg-vb_key', 'config_vb_key', 'auto | random | <hex>')}
          ${textHtml('cfg-vb_hash', 'config_vb_hash', 'auto | random | <hex>')}
          ${textHtml('cfg-security_patch', 'config_security_patch', 'auto | latest | YYYY-MM-DD')}
          <div class="cfg-section-title">${i18n.t('config_section_crypto')}</div>
          ${textHtml('cfg-root_kek_seed', 'config_root_kek_seed', 'hex')}
          ${textHtml('cfg-kak_seed', 'config_kak_seed', 'hex')}
          ${textHtml('cfg-shared_secret_seed', 'config_shared_secret_seed', 'hex')}
          ${textHtml('cfg-shared_secret_nonce', 'config_shared_secret_nonce', 'hex')}
          <div class="cfg-section-title">${i18n.t('config_section_log')}</div>
          ${selectHtml('cfg-log_level', 'config_log_level', ['debug', 'info', 'warn', 'error'])}
          ${boolHtml('cfg-to_kmsg', 'config_log_to_kmsg')}
          ${boolHtml('cfg-verbose', 'config_log_verbose')}
          <md-divider></md-divider>
          <div class="cfg-section-title">${i18n.t('config_section_injector')}</div>
          ${boolHtml('inj-hook_enabled', 'config_hook_enabled')}
          ${boolHtml('inj-get_key_entry', 'get_key_entry')}
          ${boolHtml('inj-generate_key', 'generate_key')}
          ${boolHtml('inj-import_key', 'import_key')}
          ${boolHtml('inj-create_operation', 'create_operation')}
          ${boolHtml('inj-delete_key', 'delete_key')}
          ${boolHtml('inj-list_entries', 'list_entries')}
          ${boolHtml('inj-grant', 'grant')}
        </div>
        <div slot="actions">
          <md-outlined-button id="close-config">${i18n.t('functional_button_close')}</md-outlined-button>
          <md-filled-button id="save-config">${i18n.t('functional_button_save')}</md-filled-button>
        </div>
      </md-dialog>
    `

    const fragment = template.content
    this.#dialog = fragment.querySelector<MdDialog>('#config-dialog')

    fragment.querySelector<MdOutlinedButton>('#close-config')!.onclick = () => this.close()
    fragment.querySelector<MdFilledButton>('#save-config')!.onclick = () => this.#save()

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
    const cfg = await readConfigToml()
    const inj = await readInjectorToml()

    for (const f of CONFIG_SELECTS) {
      const el = this.#dialog?.querySelector<MdOutlinedSelect>(`#${f.id}`)
      const val = String((cfg[f.section] as Toml | undefined)?.[f.key] ?? f.options[0])
      if (el) el.value = f.options.includes(val) ? val : f.options[0]
    }
    for (const f of CONFIG_TEXTS) {
      const el = this.#dialog?.querySelector<MdOutlinedTextField>(`#${f.id}`)
      const val = (cfg[f.section] as Toml | undefined)?.[f.key]
      if (el) el.value = val === undefined ? '' : String(val)
    }
    for (const f of CONFIG_BOOLS) {
      const el = this.#dialog?.querySelector<MdSwitch>(`#${f.id}`)
      const val = (cfg[f.section] as Toml | undefined)?.[f.key]
      if (el) el.selected = val === undefined ? true : Boolean(val)
    }
    for (const f of INJECTOR_BOOLS) {
      const el = this.#dialog?.querySelector<MdSwitch>(`#${f.id}`)
      const val = (inj[f.section] as Toml | undefined)?.[f.key]
      if (el) el.selected = val === undefined ? true : Boolean(val)
    }
  }

  async #save(): Promise<void> {
    const cfg = await readConfigToml()
    const inj = await readInjectorToml()

    for (const f of CONFIG_SELECTS) {
      const el = this.#dialog?.querySelector<MdOutlinedSelect>(`#${f.id}`)
      const val = el?.value ?? f.options[0]
      if (!cfg[f.section]) cfg[f.section] = {}
      ;(cfg[f.section] as Toml)[f.key] = val
    }
    for (const f of CONFIG_TEXTS) {
      const el = this.#dialog?.querySelector<MdOutlinedTextField>(`#${f.id}`)
      const val = el?.value.trim() ?? ''
      if (!cfg[f.section]) cfg[f.section] = {}
      ;(cfg[f.section] as Toml)[f.key] = val
    }
    for (const f of CONFIG_BOOLS) {
      const el = this.#dialog?.querySelector<MdSwitch>(`#${f.id}`)
      const val = el?.selected ?? true
      if (!cfg[f.section]) cfg[f.section] = {}
      ;(cfg[f.section] as Toml)[f.key] = val
    }
    for (const f of INJECTOR_BOOLS) {
      const el = this.#dialog?.querySelector<MdSwitch>(`#${f.id}`)
      const val = el?.selected ?? true
      if (!inj[f.section]) inj[f.section] = {}
      ;(inj[f.section] as Toml)[f.key] = val
    }

    try {
      await writeToml(CONFIG_FILE, cfg)
      await writeToml(INJECTOR_FILE, inj)
      this.close()
      this.#snackbar.show(i18n.t('prompt_config_saved'))
    } catch {
      this.#snackbar.show(i18n.t('prompt_config_save_error'), false)
    }
  }
}

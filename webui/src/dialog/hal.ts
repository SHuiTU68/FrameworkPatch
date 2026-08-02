// HAL 模式对话框：模式切换 + forge_mode + device 字段
import type { MdDialog, MdFilledButton, MdOutlinedButton, MdOutlinedTextField, MdSwitch, MdOutlinedSelect } from '@material/web/all'
import { i18n } from '../i18n'
import type { Cli } from '../cli'
import type { Snackbar } from '../snackbar/snackbar'
import { HAL_FILE } from '../constant'
import { readHalToml, writeToml, type Toml } from '../config_fktee'
import { applyDialogAnimation } from './animation'

const DEVICE_FIELDS = [
  'android_version', 'os_version', 'os_patch_level', 'vendor_patch_level',
  'boot_patch_level', 'keymaster_version', 'attestation_version', 'security_level',
] as const

const SECURITY_LEVELS = ['0', '1', '2']

export class HalDialog {
  #dialog: MdDialog | null = null
  #cli: Cli
  #snackbar: Snackbar

  constructor(cli: Cli, snackbar: Snackbar) {
    this.#cli = cli
    this.#snackbar = snackbar
  }

  getElement(): DocumentFragment {
    const template = document.createElement('template')
    template.innerHTML = /* html */ `
      <md-dialog id="hal-dialog" class="text-field-dialog">
        <div slot="headline">${i18n.t('hal_dialog_title')}</div>
        <div slot="content">
          <label class="switch-item contrast" for="hal-enabled-switch">
            <md-ripple></md-ripple>
            <span>${i18n.t('hal_mode_enable')}</span>
            <md-switch icons="true" id="hal-enabled-switch"></md-switch>
          </label>
          <div class="hal-hint">${i18n.t('hal_mode_hint')}</div>
          <md-divider></md-divider>
          <div class="cfg-section-title">${i18n.t('hal_forge_mode')}</div>
          <md-outlined-select id="hal-forge_mode" label="${i18n.t('hal_forge_mode')}" menu-positioning="popover" clamp-menu-width>
            <md-select-option value="auto"><div slot="headline">auto</div></md-select-option>
            <md-select-option value="generation"><div slot="headline">generation</div></md-select-option>
            <md-select-option value="leaf_hack"><div slot="headline">leaf_hack</div></md-select-option>
          </md-outlined-select>
          <label class="switch-item outlined" for="hal-hook_enabled">
            <md-ripple></md-ripple>
            <span>${i18n.t('hal_hook_enabled')}</span>
            <md-switch icons="true" id="hal-hook_enabled"></md-switch>
          </label>
          <md-outlined-text-field id="hal-real_hal_instance" label="${i18n.t('hal_real_hal_instance')}" autocapitalize="none"></md-outlined-text-field>
          <md-outlined-text-field id="hal-keybox_path" label="${i18n.t('hal_keybox_path')}" autocapitalize="none"></md-outlined-text-field>
          <md-outlined-text-field id="hal-deny_list_path" label="${i18n.t('hal_deny_list_path')}" autocapitalize="none"></md-outlined-text-field>
          <md-divider></md-divider>
          <div class="cfg-section-title">${i18n.t('hal_device')}</div>
          ${DEVICE_FIELDS.map(f => {
            if (f === 'security_level') {
              return `<md-outlined-select id="hal-${f}" label="${i18n.t('hal_' + f)}" menu-positioning="popover" clamp-menu-width>
                <md-select-option value="0"><div slot="headline">0 (Software)</div></md-select-option>
                <md-select-option value="1"><div slot="headline">1 (TEE)</div></md-select-option>
                <md-select-option value="2"><div slot="headline">2 (StrongBox)</div></md-select-option>
              </md-outlined-select>`
            }
            return `<md-outlined-text-field id="hal-${f}" label="${i18n.t('hal_' + f)}" type="number" placeholder="0"></md-outlined-text-field>`
          }).join('\n')}
        </div>
        <div slot="actions">
          <md-outlined-button id="close-hal">${i18n.t('functional_button_close')}</md-outlined-button>
          <md-filled-button id="save-hal">${i18n.t('functional_button_save')}</md-filled-button>
        </div>
      </md-dialog>
    `

    const fragment = template.content
    this.#dialog = fragment.querySelector<MdDialog>('#hal-dialog')

    fragment.querySelector<MdOutlinedButton>('#close-hal')!.onclick = () => this.close()
    fragment.querySelector<MdFilledButton>('#save-hal')!.onclick = () => this.#save()

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
    const hal = await readHalToml()
    const enabled = await this.#cli.getHalEnabled()

    const enSw = this.#dialog?.querySelector<MdSwitch>('#hal-enabled-switch')
    if (enSw) enSw.selected = enabled

    const forge = this.#dialog?.querySelector<MdOutlinedSelect>('#hal-forge_mode')
    const forgeVal = String((hal.hook as Toml | undefined)?.forge_mode ?? 'auto')
    if (forge) forge.value = forgeVal

    const hookSw = this.#dialog?.querySelector<MdSwitch>('#hal-hook_enabled')
    const hookVal = (hal.hook as Toml | undefined)?.enabled
    if (hookSw) hookSw.selected = hookVal === undefined ? true : Boolean(hookVal)

    const setText = (id: string, val: unknown) => {
      const el = this.#dialog?.querySelector<MdOutlinedTextField>(`#${id}`)
      if (el) el.value = val === undefined ? '' : String(val)
    }
    setText('hal-real_hal_instance', hal.real_hal_instance)
    setText('hal-keybox_path', hal.keybox_path)
    setText('hal-deny_list_path', hal.deny_list_path)

    const device = (hal.device as Toml | undefined) ?? {}
    for (const f of DEVICE_FIELDS) {
      if (f === 'security_level') {
        const el = this.#dialog?.querySelector<MdOutlinedSelect>(`#hal-${f}`)
        const v = String(device[f] ?? '0')
        if (el) el.value = SECURITY_LEVELS.includes(v) ? v : '0'
      } else {
        setText(`hal-${f}`, device[f] ?? '')
      }
    }
  }

  async #save(): Promise<void> {
    const hal = await readHalToml()

    // hook 段
    if (!hal.hook) hal.hook = {}
    const hook = hal.hook as Toml
    const forge = this.#dialog?.querySelector<MdOutlinedSelect>('#hal-forge_mode')
    hook.forge_mode = forge?.value ?? 'auto'
    const hookSw = this.#dialog?.querySelector<MdSwitch>('#hal-hook_enabled')
    hook.enabled = hookSw?.selected ?? true

    // 顶层字段
    const getText = (id: string): string => this.#dialog?.querySelector<MdOutlinedTextField>(`#${id}`)?.value.trim() ?? ''
    hal.real_hal_instance = getText('hal-real_hal_instance') || 'fktee-real'
    hal.keybox_path = getText('hal-keybox_path') || '/data/adb/Tee-rs/keybox.xml'
    hal.deny_list_path = getText('hal-deny_list_path') || '/data/adb/Tee-rs/deny.list'

    // device 段
    if (!hal.device) hal.device = {}
    const device = hal.device as Toml
    for (const f of DEVICE_FIELDS) {
      if (f === 'security_level') {
        const el = this.#dialog?.querySelector<MdOutlinedSelect>(`#hal-${f}`)
        device[f] = parseInt(el?.value ?? '0', 10) || 0
      } else {
        const v = getText(`hal-${f}`)
        device[f] = v ? parseInt(v, 10) : 0
      }
    }

    // 模式切换
    const enSw = this.#dialog?.querySelector<MdSwitch>('#hal-enabled-switch')
    const wantEnabled = enSw?.selected ?? false
    const wasEnabled = await this.#cli.getHalEnabled()
    let modeChanged = false
    if (wantEnabled !== wasEnabled) {
      try {
        await this.#cli.toggleHal(wantEnabled)
        modeChanged = true
      } catch {
        /* ignore */
      }
    }

    try {
      await writeToml(HAL_FILE, hal)
      this.close()
      this.#snackbar.show(i18n.t(modeChanged ? 'prompt_hal_mode_changed' : 'prompt_hal_saved'))
    } catch {
      this.#snackbar.show(i18n.t('prompt_hal_save_error'), false)
    }
  }
}

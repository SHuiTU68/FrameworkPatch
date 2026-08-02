// Prop 设置对话框：boot_hash 写入 config.toml [trust].vb_hash，
// prop_handler 开关映射到 props.conf 的 enabled=1/0 标志。
import type { MdDialog, MdFilledButton, MdOutlinedButton, MdOutlinedTextField, MdSwitch } from '@material/web/all'
import { i18n } from '../i18n'
import type { Cli } from '../cli'
import { Config } from '../config'
import type { Snackbar } from '../snackbar/snackbar'
import { applyDialogAnimation } from './animation'

export class PropDialog {
  #dialog: MdDialog | null = null
  #cli: Cli
  #config: Config
  #snackbar: Snackbar

  constructor(cli: Cli, config: Config, snackbar: Snackbar) {
    this.#cli = cli
    this.#config = config
    this.#snackbar = snackbar
  }

  getElement(): DocumentFragment {
    const template = document.createElement('template')
    template.innerHTML = /* html */ `
      <md-dialog id="prop-dialog">
        <div slot="headline">${i18n.t('menu_prop_setting')}</div>
        <div slot="content">
          <label class="switch-item contrast" for="prop-setting-switch">
            <md-ripple></md-ripple>
            <span>${i18n.t('prop_handler')}</span>
            <md-switch icons="true" id="prop-setting-switch"></md-switch>
          </label>
          <md-divider></md-divider>
          <md-outlined-text-field id="boot-hash-input" label="${i18n.t('boot_hash_title')}" type="textarea" rows="4" placeholder="241890bd44131d34c077cb01a0c3ea1ff68533b21e9d83b3f3adca6663c3d443"></md-outlined-text-field>
        </div>
        <div slot="actions">
          <md-outlined-button id="close-prop">${i18n.t('functional_button_close')}</md-outlined-button>
          <md-filled-button id="save-prop">${i18n.t('functional_button_save')}</md-filled-button>
        </div>
      </md-dialog>
    `

    const fragment = template.content
    this.#dialog = fragment.querySelector<MdDialog>('#prop-dialog')

    const switchItem = fragment.querySelector<MdSwitch>('#prop-setting-switch')
    switchItem?.addEventListener('change', async () => {
      try {
        await this.#cli.setPropsEnabled(switchItem.selected)
      } catch (error) {
        switchItem.selected = !switchItem.selected
        console.error(error)
      }
    })

    const bootHashInput = fragment.querySelector<MdOutlinedTextField>('#boot-hash-input')
    bootHashInput?.addEventListener('input', (e) => {
      const input = e.target as HTMLInputElement
      input.value = input.value.toLowerCase()
    })

    fragment.querySelector<MdOutlinedButton>('#close-prop')!.onclick = () => this.close()
    fragment.querySelector<MdFilledButton>('#save-prop')!.onclick = () => this.#save()

    return fragment
  }

  initAnimation(): void {
    if (this.#dialog) applyDialogAnimation(this.#dialog)
  }

  async show(): Promise<void> {
    const bootHashInput = this.#dialog?.querySelector<MdOutlinedTextField>('#boot-hash-input')
    if (bootHashInput) {
      // 从 config.toml [trust].vb_hash 读取当前值
      const data = this.#config.get()
      const vbHash = data.default_policy?.vb_hash
      bootHashInput.value = (vbHash && vbHash !== 'auto' && vbHash !== 'random') ? String(vbHash) : ''
    }

    const disableSwitch = this.#dialog?.querySelector<MdSwitch>('#prop-setting-switch')
    if (disableSwitch) {
      try {
        disableSwitch.selected = await this.#cli.getPropsEnabled()
      } catch {
        disableSwitch.selected = false
      }
    }

    this.#dialog?.show()
  }

  close(): void {
    this.#dialog?.close()
  }

  async #save(): Promise<void> {
    this.close()
    try {
      const bootHashInput = document.querySelector<MdOutlinedTextField>('#boot-hash-input')
      const hash = bootHashInput?.value?.trim() ?? ''

      if (hash) {
        // 通过 resetprop 立即设置 ro.boot.vbmeta.digest
        await this.#cli.setBootHash(hash)
      }

      // 写入 config.toml [trust].vb_hash（由 FkteeConfig.write 落盘）
      const data = this.#config.get()
      if (!data.default_policy) {
        data.default_policy = { verified_boot_state: 'green', device_locked: true, vb_key: 'auto', vb_hash: 'auto', security_patch: 'auto' }
      }
      data.default_policy.vb_hash = hash || 'auto'
      await this.#config.write()

      this.#snackbar.show(i18n.t('prompt_boot_hash_set'))
    } catch {
      this.#snackbar.show(i18n.t('prompt_boot_hash_set_error'), false)
    }
  }
}

// USB 调试开关对话框
import type { MdDialog, MdSwitch } from '@material/web/all'
import { i18n } from '../i18n'
import type { Cli } from '../cli'
import type { Snackbar } from '../snackbar/snackbar'
import { applyDialogAnimation } from './animation'

export class UsbDialog {
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
      <md-dialog id="usb-dialog">
        <div slot="headline">${i18n.t('usb_dialog_title')}</div>
        <div slot="content">
          <label class="switch-item contrast" for="usb-adb-switch">
            <md-ripple></md-ripple>
            <span>${i18n.t('usb_adb_enabled')}</span>
            <md-switch icons="true" id="usb-adb-switch"></md-switch>
          </label>
        </div>
        <div slot="actions">
          <md-text-button id="close-usb">${i18n.t('functional_button_close')}</md-text-button>
        </div>
      </md-dialog>
    `

    const fragment = template.content
    this.#dialog = fragment.querySelector<MdDialog>('#usb-dialog')

    const sw = fragment.querySelector<MdSwitch>('#usb-adb-switch')!
    sw.addEventListener('change', async () => {
      try {
        await this.#cli.setUsbAdb(sw.selected)
        this.#snackbar.show(i18n.t('prompt_usb_set'))
      } catch {
        sw.selected = !sw.selected
        this.#snackbar.show(i18n.t('prompt_usb_set_error'), false)
      }
    })

    fragment.querySelector<HTMLElement>('#close-usb')!.onclick = () => this.close()

    return fragment
  }

  initAnimation(): void {
    if (this.#dialog) applyDialogAnimation(this.#dialog)
  }

  async show(): Promise<void> {
    const sw = this.#dialog?.querySelector<MdSwitch>('#usb-adb-switch')
    if (sw) sw.selected = await this.#cli.getUsbAdb()
    this.#dialog?.show()
  }

  close(): void {
    this.#dialog?.close()
  }
}

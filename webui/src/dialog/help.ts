import type { MdDialog, MdTextButton } from '@material/web/all'
import { i18n } from '../i18n'
import type { Cli } from '../cli'
import { applyDialogAnimation } from './animation'
import { renderMarkdown } from './markdown'

export class HelpDialog {
  #dialog: MdDialog | null = null
  #cli: Cli

  constructor(cli: Cli) {
    this.#cli = cli
  }

  getElement(): DocumentFragment {
    const template = document.createElement('template')
    template.innerHTML = /* html */ `
      <md-dialog id="help-dialog" class="markdown-content">
        <div slot="headline">${i18n.t('help_help_instructions')}</div>
        <div slot="content" class="help-content">
          <div class="instruction">
            <h3 data-i18n="functional_button_save"></h3>
            <p data-i18n="help_save_description"></p>
          </div>
          <div class="instruction">
            <h3 data-i18n="help_add_system_app"></h3>
            <p data-i18n="help_add_system_app_description"></p>
          </div>
          <div class="instruction">
            <h3 data-i18n="help_set_keybox"></h3>
            <p data-i18n="help_set_keybox_description"></p>
            <ul>
              <li data-i18n="help_set_keybox_local"></li>
              <li data-i18n="help_set_keybox_paste"></li>
            </ul>
          </div>
          <div class="instruction">
            <h3 data-i18n="help_prop_settings"></h3>
            <p data-i18n="help_prop_settings_description"></p>
          </div>
          <div class="instruction">
            <h3 data-i18n="help_config"></h3>
            <p data-i18n="help_config_description"></p>
          </div>
          <div class="instruction">
            <h3 data-i18n="help_hal"></h3>
            <p data-i18n="help_hal_description"></p>
          </div>
          <div class="instruction">
            <h3 data-i18n="help_usb"></h3>
            <p data-i18n="help_usb_description"></p>
          </div>
        </div>
        <div slot="actions">
          <md-text-button id="close-help">${i18n.t('functional_button_close')}</md-text-button>
        </div>
      </md-dialog>
    `

    const fragment = template.content
    this.#dialog = fragment.querySelector<MdDialog>('#help-dialog')

    fragment.querySelector<MdTextButton>('#close-help')!.onclick = () => this.close()

    return fragment
  }

  initAnimation(): void {
    if (this.#dialog) applyDialogAnimation(this.#dialog)
  }

  show(): void {
    if (!this.#dialog) return

    this.#dialog.querySelectorAll<HTMLElement>('[data-i18n]').forEach(el => {
      const key = el.getAttribute('data-i18n')
      if (key) {
        let text = i18n.t(key)
        if (el.tagName === 'H3') {
          text = '### ' + text
        }
        renderMarkdown(text, el, this.#cli)
      }
    })

    this.#dialog.show()
  }

  close(): void {
    this.#dialog?.close()
  }
}

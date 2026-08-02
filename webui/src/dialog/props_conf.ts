// props.conf 编辑器：直接编辑 prop 隐藏规则的原始文本
// 格式：key=value / key~match=value / once:key=value / # 注释 / enabled=1|0
import type { MdDialog, MdFilledButton, MdOutlinedButton, MdOutlinedTextField } from '@material/web/all'
import { i18n } from '../i18n'
import { File } from '../file'
import type { Snackbar } from '../snackbar/snackbar'
import { PROPS_FILE } from '../constant'
import { applyDialogAnimation } from './animation'

export class PropsConfDialog {
  #dialog: MdDialog | null = null
  #snackbar: Snackbar

  constructor(snackbar: Snackbar) {
    this.#snackbar = snackbar
  }

  getElement(): DocumentFragment {
    const template = document.createElement('template')
    template.innerHTML = /* html */ `
      <md-dialog id="props-conf-dialog" class="text-field-dialog">
        <div slot="headline">${i18n.t('props_conf_title')}</div>
        <div slot="content">
          <div class="props-conf-hint">${i18n.t('props_conf_hint')}</div>
          <md-outlined-text-field id="props-conf-editor" type="textarea" rows="16" placeholder="key=value&#10;key~match=value&#10;once:key=value"></md-outlined-text-field>
        </div>
        <div slot="actions">
          <md-outlined-button id="close-props-conf">${i18n.t('functional_button_close')}</md-outlined-button>
          <md-filled-button id="save-props-conf">${i18n.t('functional_button_save')}</md-filled-button>
        </div>
      </md-dialog>
    `

    const fragment = template.content
    this.#dialog = fragment.querySelector<MdDialog>('#props-conf-dialog')

    fragment.querySelector<MdOutlinedButton>('#close-props-conf')!.onclick = () => this.close()
    fragment.querySelector<MdFilledButton>('#save-props-conf')!.onclick = () => this.#save()

    return fragment
  }

  initAnimation(): void {
    if (this.#dialog) applyDialogAnimation(this.#dialog)
  }

  async show(): Promise<void> {
    const editor = this.#dialog?.querySelector<MdOutlinedTextField>('#props-conf-editor')
    if (editor) {
      try {
        editor.value = await File.read(PROPS_FILE)
      } catch {
        editor.value = 'enabled=1\n'
      }
    }
    this.#dialog?.show()
  }

  close(): void {
    this.#dialog?.close()
  }

  async #save(): Promise<void> {
    const editor = this.#dialog?.querySelector<MdOutlinedTextField>('#props-conf-editor')
    if (!editor) return
    try {
      await File.write(PROPS_FILE, editor.value)
      this.close()
      this.#snackbar.show(i18n.t('prompt_props_conf_saved'))
    } catch {
      this.#snackbar.show(i18n.t('prompt_props_conf_save_error'), false)
    }
  }
}

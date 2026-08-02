// Keybox 管理：本地文件导入 + 粘贴文本，写入前备份到 .bak
import type { MdDialog, MdTextButton, MdFilledButton, MdOutlinedTextField } from '@material/web/all'
import { i18n } from '../i18n'
import { File } from '../file'
import { FileSelector } from '../file_selector/file_selector'
import type { Snackbar } from '../snackbar/snackbar'
import { KEYBOX_FILE } from '../constant'
import { applyDialogAnimation } from '../dialog/animation'
import './keybox.scss'

export class Keybox {
  readonly #fileSelector: FileSelector
  #snackbar: Snackbar

  constructor(_cli: unknown, _config: unknown, fileSelector: FileSelector, snackbar: Snackbar) {
    this.#fileSelector = fileSelector
    this.#snackbar = snackbar
  }

  get keyboxPath(): string {
    return KEYBOX_FILE
  }

  appendTo(container: HTMLElement): void {
    container.appendChild(this.#getElement())
    container.querySelectorAll<MdDialog>('md-dialog').forEach(d => applyDialogAnimation(d))
  }

  #getElement(): DocumentFragment {
    const template = document.createElement('template')
    template.innerHTML = /* html */ `
      <md-dialog id="keybox-paste-dialog" class="text-field-dialog">
        <div slot="headline">${i18n.t('keybox_paste_title')}</div>
        <div slot="content">
          <md-outlined-text-field id="keybox-paste-input" type="textarea" rows="8" label="${i18n.t('keybox_paste_title')}" placeholder="${i18n.t('keybox_paste_placeholder')}"></md-outlined-text-field>
        </div>
        <div slot="actions">
          <md-text-button id="cancel-keybox-paste">${i18n.t('functional_button_cancel')}</md-text-button>
          <md-filled-button id="save-keybox-paste">${i18n.t('functional_button_import')}</md-filled-button>
        </div>
      </md-dialog>
    `

    const fragment = template.content
    const dialog = fragment.querySelector<MdDialog>('#keybox-paste-dialog')!

    fragment.querySelector<MdTextButton>('#cancel-keybox-paste')!.onclick = () => dialog.close()
    fragment.querySelector<MdFilledButton>('#save-keybox-paste')!.onclick = async () => {
      const input = dialog.querySelector<MdOutlinedTextField>('#keybox-paste-input')!
      const content = input.value.trim()
      dialog.close()
      if (!content) {
        this.#snackbar.show(i18n.t('prompt_keybox_invalid'), false)
        return
      }
      await this.#apply(content)
    }

    return fragment
  }

  // 从本地文件选择导入
  async setLocalKey(): Promise<void> {
    try {
      const content = await this.#fileSelector.getFileContent('xml')
      if (!content) return
      await this.#apply(content)
    } catch {
      this.#snackbar.show(i18n.t('prompt_key_set_error'), false)
    }
  }

  // 打开粘贴对话框
  showPasteDialog(): void {
    const input = document.querySelector<MdOutlinedTextField>('#keybox-paste-input')
    if (input) input.value = ''
    document.querySelector<MdDialog>('#keybox-paste-dialog')?.show()
  }

  // 写入 keybox.xml，先备份 .bak
  async #apply(content: string): Promise<void> {
    try {
      await File.copy(this.keyboxPath, `${this.keyboxPath}.bak`).catch(() => {})
      await File.write(this.keyboxPath, content)
      this.#snackbar.show(i18n.t('prompt_key_set'))
    } catch {
      this.#snackbar.show(i18n.t('prompt_key_set_error'), false)
    }
  }
}

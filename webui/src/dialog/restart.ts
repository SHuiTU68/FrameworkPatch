// 重启守护进程对话框：4 个按钮发送 restart.{all,fktee,injector,hal} 信号
import type { MdDialog, MdTextButton } from '@material/web/all'
import { i18n } from '../i18n'
import type { Snackbar } from '../snackbar/snackbar'
import { restartDaemon } from '../cli'
import { applyDialogAnimation } from './animation'

const TARGETS: Array<[string, string]> = [
  ['restart-all', 'all'],
  ['restart-fktee', 'fktee'],
  ['restart-injector', 'injector'],
  ['restart-hal', 'hal'],
]

export class RestartDialog {
  #dialog: MdDialog | null = null
  #snackbar: Snackbar

  constructor(snackbar: Snackbar) {
    this.#snackbar = snackbar
  }

  getElement(): DocumentFragment {
    const template = document.createElement('template')
    template.innerHTML = /* html */ `
      <md-dialog id="restart-dialog">
        <div slot="headline">${i18n.t('restart_dialog_title')}</div>
        <div slot="content">
          <p class="restart-hint">${i18n.t('restart_dialog_hint')}</p>
          <div class="restart-actions">
            <md-filled-button id="restart-all"><md-icon slot="icon">restart_alt</md-icon>${i18n.t('restart_all')}</md-filled-button>
            <md-filled-tonal-button id="restart-fktee">${i18n.t('restart_fktee')}</md-filled-tonal-button>
            <md-filled-tonal-button id="restart-injector">${i18n.t('restart_injector')}</md-filled-tonal-button>
            <md-filled-tonal-button id="restart-hal">${i18n.t('restart_hal')}</md-filled-tonal-button>
          </div>
        </div>
        <div slot="actions">
          <md-text-button id="close-restart">${i18n.t('functional_button_close')}</md-text-button>
        </div>
      </md-dialog>
    `

    const fragment = template.content
    this.#dialog = fragment.querySelector<MdDialog>('#restart-dialog')

    for (const [id, name] of TARGETS) {
      fragment.querySelector<MdTextButton>(`#${id}`)!.onclick = async () => {
        try {
          await restartDaemon(name)
          this.#snackbar.show(i18n.t('prompt_restart_sent', name))
        } catch {
          this.#snackbar.show(i18n.t('prompt_restart_error'), false)
        }
      }
    }

    fragment.querySelector<MdTextButton>('#close-restart')!.onclick = () => this.close()

    return fragment
  }

  initAnimation(): void {
    if (this.#dialog) applyDialogAnimation(this.#dialog)
  }

  show(): void {
    this.#dialog?.show()
  }

  close(): void {
    this.#dialog?.close()
  }
}

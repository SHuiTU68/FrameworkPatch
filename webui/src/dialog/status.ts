// 状态页：显示模式、daemon/injector/hal 进程、keybox 与各配置文件状态
import type { MdDialog, MdTextButton } from '@material/web/all'
import { i18n } from '../i18n'
import type { Cli } from '../cli'
import { File } from '../file'
import { exec } from '../cli'
import { HAL_ENABLED_FILE, INJECTOR_FILE, CONFIG_FILE, ALLOW_FILE, PROPS_FILE, USB_FILE, KEYBOX_FILE, HAL_FILE, PID_FKTEE, PID_INJECTOR, PID_HAL } from '../constant'
import { keyboxStat } from '../config_fktee'
import { applyDialogAnimation } from './animation'

interface Row { label: string; value: string; ok: boolean }

export class StatusDialog {
  #dialog: MdDialog | null = null
  #cli: Cli

  constructor(cli: Cli) {
    this.#cli = cli
  }

  getElement(): DocumentFragment {
    const template = document.createElement('template')
    template.innerHTML = /* html */ `
      <md-dialog id="status-dialog" class="status-dialog">
        <div slot="headline">${i18n.t('status_title')}</div>
        <div slot="content">
          <div id="status-rows" class="status-rows"></div>
        </div>
        <div slot="actions">
          <md-text-button id="close-status">${i18n.t('functional_button_close')}</md-text-button>
        </div>
      </md-dialog>
    `

    const fragment = template.content
    this.#dialog = fragment.querySelector<MdDialog>('#status-dialog')

    fragment.querySelector<MdTextButton>('#close-status')!.onclick = () => this.close()

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
    const container = this.#dialog?.querySelector<HTMLElement>('#status-rows')
    if (!container) return

    const rows: Row[] = []

    // 模式
    const halEnabled = await this.#cli.getHalEnabled()
    rows.push({
      label: i18n.t('status_mode'),
      value: halEnabled ? i18n.t('status_mode_hal') : i18n.t('status_mode_inject'),
      ok: true,
    })

    // 进程状态
    rows.push({ label: i18n.t('status_daemon'), value: await this.#pidAlive(PID_FKTEE) ? i18n.t('status_running') : i18n.t('status_stopped'), ok: await this.#pidAlive(PID_FKTEE) })
    rows.push({ label: i18n.t('status_injector'), value: await this.#pidAlive(PID_INJECTOR) ? i18n.t('status_running') : i18n.t('status_stopped'), ok: await this.#pidAlive(PID_INJECTOR) })
    rows.push({ label: i18n.t('status_hal_proc'), value: await this.#pidAlive(PID_HAL) ? i18n.t('status_running') : i18n.t('status_stopped'), ok: await this.#pidAlive(PID_HAL) })

    // keybox
    const kb = await keyboxStat()
    rows.push({
      label: i18n.t('status_keybox'),
      value: kb.exists ? `${i18n.t('status_present')} (${kb.size}B)` : i18n.t('status_absent'),
      ok: kb.exists,
    })

    // 配置文件
    const files: Array<[string, string]> = [
      [i18n.t('status_config_files') + ' config.toml', CONFIG_FILE],
      [i18n.t('status_config_files') + ' injector.toml', INJECTOR_FILE],
      [i18n.t('status_config_files') + ' hal.toml', HAL_FILE],
      [i18n.t('status_config_files') + ' allow.list', ALLOW_FILE],
      [i18n.t('status_config_files') + ' props.conf', PROPS_FILE],
      [i18n.t('status_config_files') + ' usb.conf', USB_FILE],
      [i18n.t('status_config_files') + ' keybox.xml', KEYBOX_FILE],
      [i18n.t('status_config_files') + ' hal.enabled', HAL_ENABLED_FILE],
    ]
    for (const [label, path] of files) {
      const exists = await File.exist(path)
      rows.push({ label, value: exists ? i18n.t('status_present') : i18n.t('status_absent'), ok: exists })
    }

    container.innerHTML = rows.map(r => `
      <div class="status-row">
        <span class="status-label">${r.label}</span>
        <span class="status-value ${r.ok ? 'ok' : 'warn'}">${r.value}</span>
      </div>
    `).join('')
  }

  // 读取 pid 文件并测试 /proc/<pid> 是否存在
  async #pidAlive(pidFile: string): Promise<boolean> {
    try {
      const pid = (await File.read(pidFile)).trim()
      if (!pid) return false
      const r = await exec(`test -d /proc/${pid} && echo yes || echo no`)
      return r.stdout.trim() === 'yes'
    } catch {
      return false
    }
  }
}

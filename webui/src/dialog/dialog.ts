// 对话框聚合控制器
import type { Cli } from '../cli'
import type { Config } from '../config'
import type { Snackbar } from '../snackbar/snackbar'
import type { AppList } from '../app_list/app_list'
import { AboutDialog } from './about'
import { HelpDialog } from './help'
import { SystemAppDialog } from './system_app'
import { PropDialog } from './prop'
import { ConfigDialog } from './config'
import { HalDialog } from './hal'
import { UsbDialog } from './usb'
import { RestartDialog } from './restart'
import { StatusDialog } from './status'
import './dialog.scss'

export class DialogController {
  readonly about: AboutDialog
  readonly help: HelpDialog
  readonly systemApp: SystemAppDialog
  readonly prop: PropDialog
  readonly configDialog: ConfigDialog
  readonly hal: HalDialog
  readonly usb: UsbDialog
  readonly restart: RestartDialog
  readonly status: StatusDialog

  constructor(cli: Cli, _config: Config, snackbar: Snackbar, appList: AppList) {
    this.about = new AboutDialog(cli)
    this.help = new HelpDialog(cli)
    this.systemApp = new SystemAppDialog(appList)
    this.prop = new PropDialog(cli, _config, snackbar)
    this.configDialog = new ConfigDialog(cli, _config, snackbar)
    this.hal = new HalDialog(cli, snackbar)
    this.usb = new UsbDialog(cli, snackbar)
    this.restart = new RestartDialog(snackbar)
    this.status = new StatusDialog(cli)
  }

  appendAll(container: HTMLElement): void {
    const dialogs = [
      this.about, this.help, this.systemApp, this.prop,
      this.configDialog, this.hal, this.usb, this.restart, this.status,
    ]
    for (const d of dialogs) container.appendChild(d.getElement())
    for (const d of dialogs) d.initAnimation()
  }

  showAbout(): void { this.about.show() }
  showHelp(): void { this.help.show() }
  showSystemApp(): void { this.systemApp.show() }
  showProp(): void { this.prop.show() }
  showConfig(): void { this.configDialog.show() }
  showHal(): void { this.hal.show() }
  showUsb(): void { this.usb.show() }
  showRestart(): void { this.restart.show() }
  showStatus(): void { this.status.show() }
}

import { Cli } from '../cli'
import type { UpdateManager } from '../update'
import type { Snackbar } from '../snackbar/snackbar'
import { Config } from '../config'
import { AppList } from '../app_list/app_list'
import { DefaultPolicyDialog } from './policy'
import { AboutDialog } from './about'
import { HelpDialog } from './help'
import { UninstallDialog } from './uninstall'
import { SystemAppDialog } from './system_app'
import { PropDialog } from './prop'
import { UpdateDialog } from './update'
import { I18nDialog } from './i18n'
// FKTee 特有对话框
import { ConfigDialog } from './config'
import { HalDialog } from './hal'
import { UsbDialog } from './usb'
import { RestartDialog } from './restart'
import { StatusDialog } from './status'
import { PropsConfDialog } from './props_conf'
import './dialog.scss'

export class DialogController {
  readonly about: AboutDialog
  readonly help: HelpDialog
  readonly uninstall: UninstallDialog
  readonly defaultPolicy: DefaultPolicyDialog
  readonly systemApp: SystemAppDialog
  readonly prop: PropDialog
  readonly update: UpdateDialog
  readonly i18nDialog: I18nDialog
  // FKTee 特有
  readonly fkteeConfig: ConfigDialog
  readonly hal: HalDialog
  readonly usb: UsbDialog
  readonly propsConf: PropsConfDialog
  readonly status: StatusDialog
  readonly restart: RestartDialog

  constructor(cli: Cli, config: Config, updateManager: UpdateManager, snackbar: Snackbar, appList: AppList) {
    this.about = new AboutDialog(cli, updateManager, snackbar, config)
    this.help = new HelpDialog(cli)
    this.uninstall = new UninstallDialog(cli, snackbar)
    this.defaultPolicy = new DefaultPolicyDialog(config)
    this.systemApp = new SystemAppDialog(appList)
    this.prop = new PropDialog(cli, config, snackbar)
    this.update = new UpdateDialog(cli, updateManager, snackbar)
    this.i18nDialog = new I18nDialog(cli)
    // FKTee 特有
    this.fkteeConfig = new ConfigDialog(cli, config, snackbar)
    this.hal = new HalDialog(cli, snackbar)
    this.usb = new UsbDialog(cli, snackbar)
    this.propsConf = new PropsConfDialog(snackbar)
    this.status = new StatusDialog(cli)
    this.restart = new RestartDialog(snackbar)
  }

  appendAll(container: HTMLElement): void {
    container.appendChild(this.about.getElement())
    container.appendChild(this.help.getElement())
    container.appendChild(this.uninstall.getElement())
    container.appendChild(this.defaultPolicy.getElement())
    container.appendChild(this.systemApp.getElement())
    container.appendChild(this.prop.getElement())
    container.appendChild(this.update.getElement())
    container.appendChild(this.i18nDialog.getElement())
    // FKTee 特有
    container.appendChild(this.fkteeConfig.getElement())
    container.appendChild(this.hal.getElement())
    container.appendChild(this.usb.getElement())
    container.appendChild(this.propsConf.getElement())
    container.appendChild(this.status.getElement())
    container.appendChild(this.restart.getElement())

    this.about.initAnimation()
    this.help.initAnimation()
    this.uninstall.initAnimation()
    this.defaultPolicy.initAnimation()
    this.systemApp.initAnimation()
    this.prop.initAnimation()
    this.update.initAnimation()
    this.i18nDialog.initAnimation()
    this.fkteeConfig.initAnimation()
    this.hal.initAnimation()
    this.usb.initAnimation()
    this.propsConf.initAnimation()
    this.status.initAnimation()
    this.restart.initAnimation()
  }

  showAbout(): void {
    this.about.show()
  }

  showUpdate(changelog: string): void {
    this.update.show(changelog)
  }

  showHelp(): void {
    this.help.show()
  }

  showUninstall(): void {
    this.uninstall.show()
  }

  showDefaultPolicy(): void {
    this.defaultPolicy.show()
  }

  showSystemApp(): void {
    this.systemApp.show()
  }

  showProp(): void {
    this.prop.show()
  }

  showI18nDialog(): void {
    this.i18nDialog.show()
  }

  // FKTee 特有
  showFkteeConfig(): void {
    this.fkteeConfig.show()
  }

  showHal(): void {
    this.hal.show()
  }

  showUsb(): void {
    this.usb.show()
  }

  showPropsConf(): void {
    this.propsConf.show()
  }

  showStatus(): void {
    this.status.show()
  }

  showRestart(): void {
    this.restart.show()
  }
}

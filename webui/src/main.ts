// FKTee-rs WebUI 主入口
import '@material/web/all'
import type { MdOutlinedTextField, MdDialog, MdFab, MdIconButton } from '@material/web/all'
import { i18n } from './i18n'
import { MainMenu } from './main_menu/main_menu'
import { Cli } from './cli'
import { FkteeConfig } from './config_fktee'
import { AppList } from './app_list/app_list'
import { Snackbar } from './snackbar/snackbar'
import { FileSelector } from './file_selector/file_selector'
import { History } from './history'
import { Keybox } from './keybox/keybox'
import { DialogController } from './dialog/dialog'
import { SearchBar } from './search_bar/search_bar'
import { Keybind } from './keybind'
import './style.scss'

await i18n.init()

const snackbar = new Snackbar()
const fileSelector = new FileSelector()
const cli = new Cli()
const history = new History()
const keybind = new Keybind()
const config = new FkteeConfig()

document.querySelector<HTMLDivElement>('#app')!.innerHTML = /* html */ `
  <section class="header">
    <div id="title" class="search-hide">
      <div class="title-main">${i18n.t('header_title')}</div>
      <div class="title-sub">${i18n.t('header_subtitle')}</div>
    </div>
    <div class="spacer"></div>
    <md-icon-button id="search-button" class="search-hide"><md-icon>search</md-icon></md-icon-button>
    <md-outlined-text-field class="search-bar hide">
      <md-icon-button slot="trailing-icon" id="search-close"><md-icon>close</md-icon></md-icon-button>
    </md-outlined-text-field>
    <div class="main-menu">
      <md-icon-button id="menu-button">
        <md-icon>more_vert</md-icon>
      </md-icon-button>
    </div>
  </section>

  <section class="body-content">
    <div class="deny-hint">${i18n.t('app_list_deny_hint')}</div>
    <div class="app-list">
      <div class="loading"><md-circular-progress indeterminate></md-circular-progress></div>
    </div>
    <div class="bottom-safe-inset"></div>
  </section>

  <section class="floating-content fab-hide">
    ${snackbar.html()}
    <div class="fab-container">
      <md-fab variant="primary" class="fab fab-hide" id="save" label="${i18n.t('functional_button_save')}">
        <md-icon slot="icon">edit_note</md-icon>
      </md-fab>
    </div>
  </section>

  <section class="dialog-content"></section>
`

// 应用列表
const appList = new AppList(config)
await config.read()
await appList.fetch()
appList.syncSystemAppsWithConfig()
const appListContainer = document.querySelector<HTMLElement>('.app-list')!
appList.renderAppList(appListContainer)
float(false)

// 搜索栏
const searchBar = new SearchBar(history)
const searchBarEl = document.querySelector<MdOutlinedTextField>('.search-bar')!
const searchHide = document.querySelectorAll<HTMLElement>('.search-hide')
const searchButton = document.getElementById('search-button') as MdIconButton
searchBar.init(searchBarEl, searchHide, appListContainer)
searchButton.onclick = () => searchBar.show()

// 保存黑名单
const saveFab = document.getElementById('save') as MdFab
saveFab.onclick = () => saveDeny()
async function saveDeny(): Promise<void> {
  try {
    await appList.save()
    await appList.refresh()
    snackbar.show(i18n.t('prompt_saved_target'))
  } catch {
    snackbar.show(i18n.t('prompt_save_error'), false)
  }
}

// 浮动元素显隐
function float(hide: boolean): void {
  document.querySelectorAll('.floating-content, .fab').forEach(el => el.classList.toggle('fab-hide', hide))
}

// 菜单事件
const mainMenu = new MainMenu()
const keybox = new Keybox(cli, config, fileSelector, snackbar)
const mainMenuContainer = document.querySelector<HTMLElement>('.main-menu')!
mainMenu.appendTo(mainMenuContainer)
mainMenu.on('menu-open', () => appList.menuOpen = true)
mainMenu.on('menu-close', () => appList.menuOpen = false)
mainMenu.on('menu-refresh', async () => await appList.refresh())
mainMenu.on('menu-select-all', () => appList.selectAll())
mainMenu.on('menu-deselect-all', () => appList.deselectAll())
mainMenu.on('menu-add-system-app', () => dialogController.showSystemApp())
mainMenu.on('menu-keybox-local', async () => await keybox.setLocalKey())
mainMenu.on('menu-keybox-paste', () => keybox.showPasteDialog())
mainMenu.on('menu-prop-setting', () => dialogController.showProp())
mainMenu.on('menu-config', () => dialogController.showConfig())
mainMenu.on('menu-hal', () => dialogController.showHal())
mainMenu.on('menu-usb', () => dialogController.showUsb())
mainMenu.on('menu-status', () => dialogController.showStatus())
mainMenu.on('menu-restart', () => dialogController.showRestart())
mainMenu.on('menu-help', () => dialogController.showHelp())
mainMenu.on('menu-about', () => dialogController.showAbout())

// 快捷键
keybind.on('keybind-select-all', () => appList.selectAll())
keybind.on('keybind-deselect-all', () => appList.deselectAll())
keybind.on('keybind-search', () => searchBar.show())
keybind.on('keybind-save', () => saveDeny())
keybind.on('keybind-esc', () => history.back())

// 对话框
const dialogController = new DialogController(cli, config, snackbar, appList)
const dialogContent = document.querySelector<HTMLElement>('.dialog-content')!
fileSelector.appendTo(dialogContent)
keybox.appendTo(dialogContent)
dialogController.appendAll(dialogContent)
dialogContent.querySelectorAll<MdDialog>('md-dialog').forEach((dialog, i) => {
  const id = dialog.id || `md-dialog-${i}`
  dialog.addEventListener('open', () => history.push(id, () => dialog.close()))
  dialog.addEventListener('closed', () => history.consume(id))
})

// 滚动时收起 FAB / 菜单
let lastScrollY = window.scrollY
window.onscroll = () => {
  document.querySelectorAll('md-menu').forEach(menu => menu.close())
  float(window.scrollY > lastScrollY && window.scrollY > 48)
  document.querySelector('.header')?.classList.toggle('scroll', window.scrollY > 10)
  lastScrollY = window.scrollY
}

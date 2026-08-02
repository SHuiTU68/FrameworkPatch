// 顶部主菜单
import type { MdIconButton, MdMenuItem, MdMenu, MdSubMenu } from '@material/web/all'
import { i18n } from '../i18n'
import './main_menu.scss'

export class MainMenu {
  #callbacks = new Map<string, Array<() => void>>()

  appendTo(container: HTMLElement): void {
    container.appendChild(this.#getElement(container))
  }

  #getElement(el: HTMLElement): DocumentFragment {
    const template = document.createElement('template')
    template.innerHTML = /* html */ `
      <md-menu id="menu-options" anchor="menu-button">
        <div class="menu-item-button-container">
          <md-filled-tonal-icon-button id="select-all"><md-icon>select_all</md-icon></md-filled-tonal-icon-button>
          <md-filled-tonal-icon-button id="deselect-all"><md-icon>deselect</md-icon></md-filled-tonal-icon-button>
          <md-filled-tonal-icon-button id="refresh"><md-icon>refresh</md-icon></md-filled-tonal-icon-button>
        </div>
        <md-divider role="separator" tabindex="-1"></md-divider>
        <md-menu-item id="add-system-app">
          <div slot="headline">${i18n.t('menu_add_system_app')}</div>
        </md-menu-item>
        <md-sub-menu hover-close-delay="0" id="keybox-menu">
          <md-menu-item slot="item" class="sub-menu-entry">
            <div slot="headline">${i18n.t('menu_keybox')}</div>
            <md-icon slot="end">key</md-icon>
          </md-menu-item>
          <md-menu positioning="popover" slot="menu" x-offset="2">
            <md-menu-item id="keybox-local">
              <div slot="headline">${i18n.t('menu_keybox_import')}</div>
            </md-menu-item>
            <md-menu-item id="keybox-paste">
              <div slot="headline">${i18n.t('menu_keybox_paste')}</div>
            </md-menu-item>
          </md-menu>
        </md-sub-menu>
        <md-menu-item id="prop-setting">
          <div slot="headline">${i18n.t('menu_prop_setting')}</div>
        </md-menu-item>
        <md-menu-item id="config">
          <div slot="headline">${i18n.t('menu_config')}</div>
        </md-menu-item>
        <md-menu-item id="hal">
          <div slot="headline">${i18n.t('menu_hal')}</div>
        </md-menu-item>
        <md-menu-item id="usb">
          <div slot="headline">${i18n.t('menu_usb')}</div>
        </md-menu-item>
        <md-menu-item id="status">
          <div slot="headline">${i18n.t('menu_status')}</div>
        </md-menu-item>
        <md-menu-item id="restart">
          <div slot="headline">${i18n.t('menu_restart')}</div>
          <md-icon slot="end">restart_alt</md-icon>
        </md-menu-item>
        <md-divider role="separator" tabindex="-1"></md-divider>
        <md-menu-item id="help">
          <div slot="headline">${i18n.t('menu_help')}</div>
        </md-menu-item>
        <md-sub-menu hover-close-delay="0">
          <md-menu-item slot="item" class="sub-menu-entry">
            <div slot="headline">${i18n.t('menu_language')}</div>
            <md-icon slot="end">language</md-icon>
          </md-menu-item>
          <md-menu positioning="popover" slot="menu" id="language-menu" x-offset="2"></md-menu>
        </md-sub-menu>
        <md-menu-item id="about">
          <div slot="headline">${i18n.t('menu_about')}</div>
        </md-menu-item>
      </md-menu>
    `

    const fragment = template.content
    const menuOptions = fragment.querySelector('#menu-options') as MdMenu

    el.querySelector<MdIconButton>('#menu-button')!.onclick = () => {
      menuOptions.open = !menuOptions.open
    }

    menuOptions.addEventListener('opened', () => this.#emit('menu-open'))
    menuOptions.addEventListener('closed', () => this.#emit('menu-close'))

    const items: Array<[string, string]> = [
      ['select-all', 'menu-select-all'],
      ['deselect-all', 'menu-deselect-all'],
      ['refresh', 'menu-refresh'],
      ['add-system-app', 'menu-add-system-app'],
      ['keybox-local', 'menu-keybox-local'],
      ['keybox-paste', 'menu-keybox-paste'],
      ['prop-setting', 'menu-prop-setting'],
      ['config', 'menu-config'],
      ['hal', 'menu-hal'],
      ['usb', 'menu-usb'],
      ['status', 'menu-status'],
      ['restart', 'menu-restart'],
      ['help', 'menu-help'],
      ['about', 'menu-about'],
    ]

    items.forEach(([id, event]) => {
      const itemEl = fragment.querySelector<MdMenuItem>(`#${id}`)
      if (itemEl) {
        itemEl.onclick = () => {
          this.#emit(event)
          menuOptions.open = false
        }
      }
    })

    // 子菜单点击切换（覆盖默认 hover 行为，移动端更顺手）
    let menuOpen = false
    fragment.querySelectorAll('.sub-menu-entry').forEach(entry => {
      const item = entry as MdMenuItem
      const subMenu = item.parentElement as MdSubMenu
      item.onclick = (e) => {
        e.stopPropagation()
        menuOpen = !menuOpen
        menuOpen ? subMenu.show() : subMenu.close()
      }
      subMenu.querySelector('md-menu')?.addEventListener('opening', () => menuOpen = true)
      subMenu.querySelector('md-menu')?.addEventListener('closing', () => menuOpen = false)
    })

    // 生成语言菜单（仅 en + zh-CN）
    const languageMenu = fragment.querySelector('#language-menu')
    if (languageMenu) {
      languageMenu.innerHTML = ''
      const currentSaved = i18n.lang
      const langs = { default: i18n.t('system_default'), ...i18n.languages }
      for (const [code, name] of Object.entries(langs)) {
        const item = document.createElement('md-menu-item')
        item.id = `lang-${code}`
        if (currentSaved === code) {
          item.setAttribute('selected', '')
        }
        item.innerHTML = `<div slot="headline">${name}</div>`
        item.onclick = () => {
          i18n.setLanguage(code)
        }
        languageMenu.appendChild(item)
      }
    }

    return fragment
  }

  on(event: string, callback: () => void): void {
    const cbs = this.#callbacks.get(event) ?? []
    cbs.push(callback)
    this.#callbacks.set(event, cbs)
  }

  #emit(event: string): void {
    this.#callbacks.get(event)?.forEach(cb => cb())
  }
}

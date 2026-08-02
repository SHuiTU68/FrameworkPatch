// 黑名单 app picker：列出全部应用，勾选 = 写入 deny.list（豁免 attestation hook）
import { listPackages, getPackagesInfo } from 'kernelsu-alt'
import type { PackagesInfo } from 'kernelsu-alt'
import { Config } from '../config'
import { LOCAL_STORAGE_PREFIX } from '../constant'
import './app_list.scss'

const SYSTEM_APPS_KEY = `${LOCAL_STORAGE_PREFIX}AdditionalApps`
// 默认额外显示的系统应用（play 服务/商店等常需加入黑名单）
const DEFAULT_ADDITIONAL_APPS = [
  'com.google.android.gms', // Play Service
  'com.android.vending',    // Play Store
  'com.google.android.gsf', // Google Services Framework
]

export interface AppEntry {
  packageName: string
  appName: string
  isSystem: boolean
}

export class AppList {
  #entries: AppEntry[] = []
  #config: Config
  #iconObserver: IntersectionObserver | null = null
  #systemAppIconObserver: IntersectionObserver | null = null
  #container: HTMLElement | null = null
  menuOpen = false

  constructor(config: Config) {
    this.#config = config
  }

  async fetch(): Promise<void> {
    if (import.meta.env.DEV) {
      this.#initDevMode()
      return
    }

    const pkgs = await listPackages('all').catch(() => [])

    let infos: PackagesInfo[]
    try {
      infos = await getPackagesInfo(pkgs) as PackagesInfo[]
    } catch {
      infos = pkgs.map((pkg: string) => ({
        packageName: pkg,
        versionName: '',
        versionCode: 0,
        appLabel: pkg,
        isSystem: false,
        uid: 0,
      }))
    }

    this.#entries = pkgs.map((pkg: string, i: number) => ({
      packageName: pkg,
      appName: infos[i]?.appLabel || pkg,
      isSystem: infos[i]?.isSystem ?? false,
    }))
  }

  getEntries(): AppEntry[] {
    return this.#entries
  }

  async save(): Promise<void> {
    if (import.meta.env.DEV) return
    await this.#config.write()
  }

  async refresh(force: boolean = true): Promise<void> {
    if (force) {
      await this.#config.read()
      await this.fetch()
      if (this.#container) {
        this.renderAppList(this.#container)
        window.scrollTo(0, 0)
      }
    } else {
      if (this.#container) {
        this.renderAppList(this.#container)
      }
    }
  }

  // 把已存在于黑名单中的系统应用同步进 additionalApps，使其可见
  syncSystemAppsWithConfig(): void {
    const deny = (this.#config.get('denyPackages') as string[]) || []
    const additionalApps = this.getAdditionalApps()
    let changed = false

    for (const pkg of deny) {
      const entry = this.#entries.find(e => e.packageName === pkg)
      if (entry?.isSystem && !additionalApps.includes(pkg)) {
        additionalApps.push(pkg)
        changed = true
      }
    }

    if (changed) {
      this.saveAdditionalApps(additionalApps)
    }
  }

  selectAll(): void {
    if (!this.#container) return
    const additionalApps = this.getAdditionalApps()
    const deny = (this.#config.get('denyPackages') as string[]) || []
    this.#container.querySelectorAll<HTMLElement>('.card').forEach(card => {
      const pkg = card.dataset.package!
      // 仅当前可见的应用参与全选
      if (!deny.includes(pkg)) this.#config.push('denyPackages', pkg)
      card.querySelector('md-checkbox')!.checked = true
      card.classList.add('selected')
    })
    void additionalApps
  }

  deselectAll(): void {
    if (!this.#container) return
    this.#config.set('denyPackages', [])
    this.#container.querySelectorAll<HTMLElement>('.card').forEach(card => {
      const checkbox = card.querySelector('md-checkbox')!
      checkbox.checked = false
      card.classList.remove('selected')
    })
  }

  renderAppList(container: HTMLElement): void {
    this.#container = container
    container.innerHTML = ''

    const additionalApps = this.getAdditionalApps()
    const displayed = this.#entries.filter(
      e => !e.isSystem || additionalApps.includes(e.packageName),
    )

    const deny = (this.#config.get('denyPackages') as string[]) || []

    // 已勾选（在黑名单中）的排前
    displayed.sort((a, b) => {
      const aDenied = deny.includes(a.packageName)
      const bDenied = deny.includes(b.packageName)
      if (aDenied !== bDenied) return aDenied ? -1 : 1
      return (a.appName || '').localeCompare(b.appName || '')
    })

    const fragment = document.createDocumentFragment()
    for (const entry of displayed) {
      const denied = deny.includes(entry.packageName)
      fragment.appendChild(this.#createCard(entry, denied))
    }
    container.appendChild(fragment)

    this.#iconObserver?.disconnect()
    this.#iconObserver = this.#setupIconObserver(container)
    this.#setupCardListeners(container)
  }

  renderSystemAppList(container: HTMLElement): void {
    container.innerHTML = ''

    const additionalApps = this.getAdditionalApps()
    const systemEntries = this.#entries.filter(e => e.isSystem)

    systemEntries.sort((a, b) => {
      const aChecked = additionalApps.includes(a.packageName)
      const bChecked = additionalApps.includes(b.packageName)
      if (aChecked !== bChecked) return aChecked ? -1 : 1
      return (a.appName || '').localeCompare(b.appName || '')
    })

    const fragment = document.createDocumentFragment()
    for (const entry of systemEntries) {
      const cardBox = this.#createCard(entry, false)
      const checkbox = cardBox.querySelector('md-checkbox')!
      if (additionalApps.includes(entry.packageName)) {
        checkbox.checked = true
        cardBox.querySelector('.card')!.classList.add('selected')
      }
      fragment.appendChild(cardBox)
    }
    container.appendChild(fragment)

    this.#systemAppIconObserver?.disconnect()
    this.#systemAppIconObserver = this.#setupIconObserver(container)
    this.#setupSystemAppListeners(container)
  }

  getAdditionalApps(): string[] {
    try {
      const raw = localStorage.getItem(SYSTEM_APPS_KEY)
      return raw ? JSON.parse(raw) as string[] : [...DEFAULT_ADDITIONAL_APPS]
    } catch {
      return [...DEFAULT_ADDITIONAL_APPS]
    }
  }

  saveAdditionalApps(apps: string[]): void {
    localStorage.setItem(SYSTEM_APPS_KEY, JSON.stringify(apps))
  }

  #createCard(entry: AppEntry, denied: boolean): HTMLElement {
    const selectedClass = denied ? ' selected' : ''
    const checkedAttr = denied ? 'checked' : ''

    const wrapper = document.createElement('div')
    wrapper.innerHTML = /* html */ `
      <div class="card-box">
        <div class="card card-alpha content${selectedClass}" data-package="${entry.packageName}">
          <md-ripple></md-ripple>
          <label class="name" for="checkbox-${entry.packageName}">
            <div class="app-icon-container">
              <div class="loader" data-package="${entry.packageName}"></div>
              <img class="app-icon" data-package="${entry.packageName}" alt="${entry.appName}" draggable="false" />
              <div class="app-icon-fallback" data-package="${entry.packageName}">
                <svg viewBox="0 -960 960 960" xmlns="http://www.w3.org/2000/svg"><path d="M40-240q9-107 65.5-197T256-580l-74-128q-6-9-3-19t13-15q8-5 18-2t16 12l74 128q86-36 180-36t180 36l74-128q6-9 16-12t18 2q10 5 13 15t-3 19l-74 128q94 53 150.5 143T920-240H40Zm275.5-124.5Q330-379 330-400t-14.5-35.5Q301-450 280-450t-35.5 14.5Q230-421 230-400t14.5 35.5Q259-350 280-350t35.5-14.5Zm400 0Q730-379 730-400t-14.5-35.5Q701-450 680-450t-35.5 14.5Q630-421 630-400t14.5 35.5Q659-350 680-350t35.5-14.5Z"/></svg>
              </div>
            </div>
            <div class="app-info">
              <div class="app-name">${entry.appName}</div>
              <div class="package-name">${entry.packageName}</div>
            </div>
          </label>
          <md-checkbox class="checkbox" id="checkbox-${entry.packageName}" touch-target="wrapper" ${checkedAttr}></md-checkbox>
        </div>
      </div>`
    return wrapper.firstElementChild as HTMLElement
  }

  #setupCardListeners(container: HTMLElement): void {
    const cards = container.querySelectorAll<HTMLElement>('.card')
    cards.forEach(card => {
      card.onclick = () => {
        if (this.menuOpen) return
        const pkg = card.dataset.package!
        const checkbox = card.querySelector('md-checkbox')!
        const deny = (this.#config.get('denyPackages') as string[]) || []

        if (checkbox.checked) {
          // 取消勾选：从黑名单移除
          this.#config.removeMatch('denyPackages', t => t === pkg)
          checkbox.checked = false
          card.classList.remove('selected')
        } else {
          // 勾选：加入黑名单
          this.#config.push('denyPackages', pkg)
          checkbox.checked = true
          card.classList.add('selected')
        }
      }
    })
  }

  #setupSystemAppListeners(container: HTMLElement): void {
    const cards = container.querySelectorAll<HTMLElement>('.card')
    cards.forEach(card => {
      card.onclick = () => {
        const checkbox = card.querySelector('md-checkbox')!
        checkbox.checked = !checkbox.checked
        card.classList.toggle('selected')
      }
    })
  }

  // 系统应用对话框保存：仅更新可见集合（additionalApps），不直接改 deny.list
  async saveSystemAppSelection(checkedApps: string[]): Promise<void> {
    this.saveAdditionalApps(checkedApps)
    await this.refresh(false)
  }

  #setupIconObserver(container: HTMLElement): IntersectionObserver {
    const observer = new IntersectionObserver((entries) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          const el = entry.target as HTMLElement
          const pkg = el.querySelector('.app-icon')?.getAttribute('data-package')
          if (pkg) {
            this.#loadIcon(pkg, el)
            observer.unobserve(el)
          }
        }
      })
    }, { rootMargin: '100px', threshold: 0.1 })

    container.querySelectorAll('.app-icon-container').forEach(el => {
      observer.observe(el)
    })

    return observer
  }

  #loadIcon(packageName: string, scopeEl?: HTMLElement): void {
    const root = scopeEl ?? document
    const img = root.querySelector<HTMLImageElement>(`.app-icon[data-package="${packageName}"]`)
    const loader = root.querySelector<HTMLElement>(`.loader[data-package="${packageName}"]`)
    if (!img) return
    img.onload = () => {
      if (loader) loader.style.display = 'none'
      img.style.opacity = '1'
    }
    img.onerror = () => {
      img.style.display = 'none'
      const fallback = root.querySelector<HTMLElement>(`.app-icon-fallback[data-package="${packageName}"]`)
      if (fallback) fallback.classList.add('visible')
      if (loader) loader.style.display = 'none'
    }
    img.src = `ksu://icon/${packageName}`
  }

  // 调试用：模拟应用列表与黑名单
  #initDevMode(): void {
    const data = this.#config.get()
    if (!data.denyPackages || data.denyPackages.length === 0) {
      data.denyPackages = [
        'io.github.vvb2060.keyattestation',
        'com.example.banking',
      ]
    }

    this.#entries = [
      { packageName: 'io.github.vvb2060.keyattestation', appName: 'Key Attestation', isSystem: false },
      { packageName: 'io.github.vvb2060.mahoshojo', appName: 'Mahoshojo', isSystem: false },
      { packageName: 'com.example.app', appName: 'Example App', isSystem: false },
      { packageName: 'com.example.banking', appName: 'My Banking App', isSystem: false },
      { packageName: 'com.example.social', appName: 'Social Media', isSystem: false },
      { packageName: 'com.example.game', appName: 'Awesome Game', isSystem: false },
      { packageName: 'com.example.wallet', appName: 'Digital Wallet', isSystem: false },
      { packageName: 'com.example.streaming', appName: 'Video Streaming', isSystem: false },
      { packageName: 'com.google.android.gms', appName: 'Google Play Services', isSystem: true },
      { packageName: 'com.android.vending', appName: 'Google Play Store', isSystem: true },
      { packageName: 'com.google.android.gsf', appName: 'Google Services Framework', isSystem: true },
      { packageName: 'com.qualcomm.qti', appName: 'Qualcomm Technologies', isSystem: true },
    ]
  }
}

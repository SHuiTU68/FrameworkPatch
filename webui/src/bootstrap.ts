// FKTee-rs WebUI 启动入口
// 先检查 WebView 版本是否满足要求，满足则动态加载 main.ts
import { exec } from 'kernelsu-alt'
import { isSupported, renderBlockingPage, UPDATE_URL } from './webview/webview'

if (!isSupported()) {
  document.querySelector<HTMLDivElement>('#app')!.innerHTML = renderBlockingPage()
  document.getElementById('update-webview')!.onclick = async () => {
    const result = await exec(`am start -a android.intent.action.VIEW -d '${UPDATE_URL}'`)
    if (result.errno !== 0) window.open(UPDATE_URL, '_blank')
  }
} else {
  try {
    await import('./main')
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e)
    document.querySelector<HTMLDivElement>('#app')!.innerHTML = `<p id="load-error">Failed to load app: ${msg}</p>`
  }
}

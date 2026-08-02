import { defineConfig } from 'vite'

// FKTee-rs WebUI 构建配置
// 产物输出到模块的 webroot 目录，供 KernelSU/KSU WebUI 加载
export default defineConfig({
  base: '',
  build: {
    outDir: '../module/webroot',
    emptyOutDir: true,
    cssCodeSplit: false,
    target: 'es2020',
  },
  server: {
    port: 5173,
  },
})

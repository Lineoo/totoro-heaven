/**
 * `POST /api/local/logs/open` —— 在系统文件管理器里打开日志目录（仅本机）
 *
 * 为什么需要它：日志写在 `os.tmpdir()/totoro-heaven-runtime/logs`（Windows 下是 `%TEMP%`），
 * 用户很难自己找到；这个端点在**本机**调用系统命令打开该目录
 * （不安全输入：路径由服务端拼，不由调用方给）。
 *
 * ⚠️ 跨平台纪律（2026-10-18）：这里**绝不能**写死 `explorer.exe` ——
 *    Linux/macOS 没有它，`spawn` 会异步抛 `ENOENT`；若没有 `error` 监听，
 *    Node 会把它当**未捕获异常**直接结束整个 Nitro 进程（点一下按钮就把后端打崩）。
 *    现在：按平台选 opener + 等 `spawn` 成功再返回 + 兜住 `error`。
 */
import { spawn } from 'node:child_process'
import { mkdirSync } from 'node:fs'
import { assertLocalRequest } from '../../../utils/tokenScanState'
import { LOG_DIR, logInfo, logWarn } from '../../../utils/logger'

/** 当前平台对应的“打开目录”命令（不导出：这是路由文件，避免被当成 handler 之外的 API） */
function logOpener(): string {
  if (process.platform === 'win32') return 'explorer.exe'
  if (process.platform === 'darwin') return 'open'
  return 'xdg-open'
}

export default defineEventHandler(async (event) => {
  assertLocalRequest(event)
  const opener = logOpener()
  try {
    mkdirSync(LOG_DIR, { recursive: true })
    /**
     * ⚠️ 必须等 `spawn` 成功（而不是 spawn 完就 return）：
     *    `spawn` 的失败是**异步事件**，try/catch 抓不到；不等它就会把“没打开”报成 `ok: true`，
     *    更糟的是没有 error 监听时进程会被未捕获的 'error' 直接带走。
     */
    const child = spawn(opener, [LOG_DIR], { detached: true, stdio: 'ignore' })
    await new Promise<void>((resolve, reject) => {
      child.once('spawn', resolve)
      child.once('error', reject)
    })
    child.unref()
    logInfo('ui', '打开日志文件夹', { dir: LOG_DIR, opener })
    return { ok: true, dir: LOG_DIR }
  } catch (err) {
    const message = err instanceof Error ? err.message : '打开失败'
    logWarn('ui', '打开日志文件夹失败', { dir: LOG_DIR, opener, error: message })
    return { ok: false, dir: LOG_DIR, message }
  }
})

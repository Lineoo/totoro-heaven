/**
 * 启动「内存扫描器」
 *
 * 平台分支：
 *   - Windows：PowerShell + Add-Type P/Invoke，源码内嵌见 `tokenScanScript.ts`；
 *   - Linux：Node 直接只读 `/proc/<pid>/mem`，见 `tokenScanLinux.ts`。
 *
 * Windows 为什么这样起：
 *   - 发布物是 **Node SEA 单文件 EXE**，外部 .ps1 不会被打进去 → 运行时把内嵌源码写到临时目录再执行；
 *   - **纯 ASCII 写入、无 BOM**（本机 PS 5.1 读无 BOM 非 ASCII 会按 ANSI 误解码，见 ERROR.md E14）；
 *   - `windowsHide` 不弹窗；结果通过它 POST 回本地端点，不靠解析 stdout。
 *
 * 🔴 2026-10-14 重写（E80，起因：26H2 用户报"扫描器未回传结果（退出码 4294967295）"）：
 *   老实现是 `stdio: 'ignore'` —— **PowerShell 吐出来的每一个字都被丢掉**，
 *   于是界面上、日志里都只剩一个数字，谁也说不清是"参数不认识"还是"被安全软件杀了"。
 *   现在：**收输出（utf8，失败再按 GBK 兜底解一次）+ 落一份 sidecar 诊断文件 + 写运行日志 +
 *   把真实原因渲染进界面文案**，并且**不写任何没有证据的归因**（老文案直接断言"可能是杀软拦截"，
 *   而补丁版又反过来断言"是 `-Endpoint` 的锅" —— 两种都是猜）。
 */

import { spawn } from 'node:child_process'
import { mkdirSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { redactFreeText } from '../../utils/mp/logFormat'
import { logInfo, logWarn } from './logger'
import { TOKEN_SCAN_PS1, tokenScannerArgs } from './tokenScanScript'
import { runLinuxTokenScan } from './tokenScanLinux'
import { getScan, patchScan } from './tokenScanState'

/** 扫描器落点目录（固定名，便于排错；脚本与诊断日志都在这儿，用户可整目录发回来） */
export function scannerDir(): string {
  const dir = join(tmpdir(), 'totoro-heaven-token')
  mkdirSync(dir, { recursive: true })
  return dir
}

/** 内嵌脚本在临时目录里的落点（内容每次覆盖写） */
function scriptPath(): string {
  const p = join(scannerDir(), 'scan-memory.ps1')
  writeFileSync(p, TOKEN_SCAN_PS1, 'utf8') // 内容为纯 ASCII → 无 BOM 也安全（有单测盯着）
  return p
}

/** 最近一次扫描的子进程输出留档（**只在本机 %TEMP%，不入库**） */
export function scannerLogPath(): string {
  return join(scannerDir(), 'last-scan.log')
}

/** 收集子进程输出时的上限（字节）：够看清一条 PowerShell 错误，又不会把内存/日志撑爆 */
export const SCAN_OUTPUT_LIMIT = 4000

/**
 * 解码子进程输出（纯函数，有单测）。
 *
 * ⚠️ 为什么要两层：脚本第一件事就想把控制台输出设成 UTF-8，但**语法错误发生在它前面** ——
 *    那种情况下 PowerShell 按**系统 ANSI（中文机 = 936/GBK）**吐错误信息，
 *    按 utf8 解会得到一串替换字符（实测：GBK 的"中文"两字节按 utf8 解 = 4 个替换字符）。
 *    判据：utf8 解出替换字符（U+FFFD）就重来一次 GBK；Node 24 自带 full-icu，`TextDecoder('gbk')` 可用。
 */
export function decodeScannerOutput(buf: Buffer): string {
  const utf8 = buf.toString('utf8')
  if (!utf8.includes('\uFFFD')) return utf8
  try {
    const gbk = new TextDecoder('gbk').decode(buf)
    // 只有当 GBK 解的替换字符更少时才采用它（避免把"本来就含 U+FFFD 的 utf8 文本"改坏）
    return gbk.split('\uFFFD').length < utf8.split('\uFFFD').length ? gbk : utf8
  } catch {
    return utf8
  }
}

/** 把输出收敛成可直接展示/落盘的一段文本（去空行、截断；纯函数，有单测） */
export function condenseScanOutput(out: string): string {
  const text = String(out ?? '')
    .replace(/\r\n/g, '\n')
    .split('\n')
    .map((l) => l.trimEnd())
    .filter((l) => l.trim().length > 0)
    .join('\n')
  if (text.length <= SCAN_OUTPUT_LIMIT) return text
  return `${text.slice(0, SCAN_OUTPUT_LIMIT)}\n…（输出过长，已截断；完整内容见 last-scan.log）`
}

/**
 * 「退出码 + 输出」→ 给用户看的一句话（纯函数，有单测）。
 *
 * 🔒 文案纪律（E80）：**只陈述观测到的事实**，不做没有证据的归因。
 *    背景：`-File` 模式下 `powershell.exe` 只可能退 `0` / `1` / 脚本里 `exit N` 的那个 N
 *    （官方文档 + 本机实测），所以"退了一个别的数"本身就是一个**事实**：进程没走到脚本出口。
 *    老文案据此断言"可能是杀软拦截"，补丁版又断言"是 `-Endpoint` 的锅" —— 两者都是猜；
 *    现在改成"有输出就报输出，没输出就如实说没输出"，让证据自己说话。
 */
export function describeScanFailure(code: number | null, output: string, logPath: string): string {
  const codeText = code === null ? '进程没有正常退出（可能被外部强制结束）' : `退出码 ${code}`
  const text = condenseScanOutput(output)
  if (text) return `扫描器未回传结果（${codeText}）：\n${text}\n（诊断日志：${logPath}）`
  return (
    `扫描器未回传结果（${codeText}），且子进程**没有留下任何输出** —— 常见于刚开始就被安全软件/系统策略结束，` +
    `或本机 PowerShell 不可用。可改用抓包路线：Fiddler 抓一条 wxxcx.xtotoro.com 请求，` +
    `把 Authorization: Bearer … 粘到输入框。\n（诊断日志：${logPath}）`
  )
}

/**
 * 把扫描器现场文本**脱敏后再留档**（写入 sidecar 与进包前都跑它；幂等）。
 *
 * 🔴 为什么需要（2026-10-14 自查发现的漏洞）：上一版 `writeScannerLog()` 是**原样写盘**的 ——
 *    子进程输出里若出现 token 样式串或学号，就会以明文躺在 `%TEMP%` 里、还会随诊断包发出去。
 *    现在统一过 `redactFreeText()`（token 样式串 + 自述人名 + 8~18 位数字串）。
 *
 * ⚠️ **唯一豁免：`exitCode:` 那一行**。退出码本身是 10 位数字（`4294967295`），
 *    数字串掩码会把它变成 `42****95` —— 而**这个数正是 E80 那次报障里唯一的线索**，
 *    掩掉它等于把证据毁了。这一行由本文件自己写、不含任何用户数据，所以按行豁免；
 *    其余每一行（包括子进程原话）都照常掩码。
 */
export function maskScannerRecord(text: string): string {
  return String(text ?? '')
    .split('\n')
    .map((line) => (/^exitCode\s*:/.test(line) ? line : redactFreeText(line)))
    .join('\n')
}

/**
 * 把这次扫描的现场写成 sidecar 文件（**尽力而为**，失败不影响业务）。
 * ⚠️ 不写 nonce（一次性凭据，没必要落盘）；写盘前过 `maskScannerRecord()` 脱敏。
 */
function writeScannerLog(code: number | null, output: string): string {
  const p = scannerLogPath()
  try {
    const shown = condenseScanOutput(output)
    const body = [
      `time    : ${new Date().toISOString()}`,
      `exitCode: ${code === null ? '(null：被强制结束)' : code}`,
      `script  : ${join(scannerDir(), 'scan-memory.ps1')}`,
      'output  :',
      shown || '(子进程没有留下任何输出)',
      '',
    ].join('\n')
    writeFileSync(p, maskScannerRecord(body), 'utf8')
  } catch {
    /* 留档失败不影响业务 */
  }
  return p
}

/**
 * 非 Windows 平台下「一键获取 token」的统一说明（`start` 端点与 runner 共用同一句，避免两处文案漂移）。
 * 口径：只说“当前平台不支持 + 可替代路线”，不假装扫描器还能工作。
 */
export const TOKEN_SCAN_UNSUPPORTED_MESSAGE =
  '「一键获取 token」目前支持 Windows 与 Linux（只读扫描微信小程序进程内存）。' +
  '当前平台请改用「抓包粘贴 token」：用 mitmproxy/Charles 抓一条 wxxcx.xtotoro.com 请求，' +
  '把 Authorization: Bearer … 粘到输入框。'

/**
 * 启动扫描器。**不等待**其完成（结果由扫描器 POST 回 `/api/local/token-import`）。
 * 若它异常退出且状态仍是 scanning，则把状态置为 error（避免前端一直转圈）。
 */
export function launchTokenScanner(endpoint: string, nonce: string): void {
  /**
   * Linux（2026-10-18 实测）：微信 4.x AppImage 里的 WMPF 运行时也是 `WeChatAppEx`，
   * 内存里能找到 `WXXCX` 候选。实现放在 `tokenScanLinux.ts`：
   * 只读 `/proc/<pid>/mem`，不写内存/不注入；结果仍 POST 回 token-import 验活。
   *
   * ⚠️ 与 Windows 不同：Linux 受 ptrace/Yama 限制，默认 `ptrace_scope=1` 会 EACCES；
   * 由 `tokenScanLinux` 返回 `NO_PERMISSION`，界面再给用户命令，不在这里自动提权。
   */
  if (process.platform === 'linux') {
    logInfo('token-scan', 'Linux 内存扫描器已启动', {
      endpoint: endpoint.replace(/\/api\/local\/.*$/, ''),
    })
    void runLinuxTokenScan(endpoint, nonce)
    return
  }

  /**
   * 🔒 其它平台闸门：Windows 走 PowerShell；macOS 等没有 `/proc` 扫描实现。
   * 不假装能工作，直接把状态推进到 `error` 并说明可替代路线。
   */
  if (process.platform !== 'win32') {
    const logPath = writeScannerLog(null, `unsupported platform: ${process.platform} (${process.arch})`)
    logWarn('token-scan', '当前平台不支持内存扫描，已跳过', {
      platform: process.platform,
      arch: process.arch,
      log: logPath,
    })
    const cur = getScan()
    if (cur && cur.nonce === nonce && cur.phase === 'scanning') {
      patchScan({ phase: 'error', message: TOKEN_SCAN_UNSUPPORTED_MESSAGE })
    }
    return
  }

  const ps = 'powershell.exe'
  const script = scriptPath()
  const chunks: Buffer[] = []
  let collected = 0

  const child = spawn(ps, tokenScannerArgs(script, endpoint, nonce), {
    windowsHide: true,
    // 🔴 原来是 'ignore'：故障时连一个字都不剩。现在 stdin 仍然不看，stdout/stderr 全收。
    stdio: ['ignore', 'pipe', 'pipe'],
  })

  const onData = (buf: Buffer) => {
    if (collected >= SCAN_OUTPUT_LIMIT * 2) return // 继续消费但不留（防病态输出撑爆内存）
    chunks.push(buf)
    collected += buf.length
  }
  child.stdout?.on('data', onData)
  child.stderr?.on('data', onData)

  logInfo('token-scan', '扫描器已启动', { ps, script })

  child.on('error', (err) => {
    const logPath = writeScannerLog(null, `spawn 失败：${err.message}`)
    logWarn('token-scan', '扫描器启动失败', { error: err.message, log: logPath })
    const cur = getScan()
    if (cur && cur.nonce === nonce && cur.phase === 'scanning') {
      patchScan({ phase: 'error', message: `无法启动扫描器：${err.message}（本机需有 PowerShell）` })
    }
  })

  child.on('exit', (code) => {
    const output = decodeScannerOutput(Buffer.concat(chunks))
    const logPath = writeScannerLog(code, output)
    const text = condenseScanOutput(output)
    /** 🆕 脱敏后的现场文本：**界面文案、日志行、诊断包都用它**（退出码那一行豁免掩码） */
    const masked = maskScannerRecord(text)
    // 给它 3 秒把 POST 发出来；仍停在 scanning 就认为失败。
    // ⚠️ 必须再比对 nonce（E80 顺手修的老 bug）：只判 phase 时，**上一轮**扫描器迟到退出
    //    会把**新一轮**的 scanning 状态打成 error。
    setTimeout(() => {
      const cur = getScan()
      if (cur && cur.nonce === nonce && cur.phase === 'scanning') {
        /**
         * ⚠️ 两处口径（2026-10-14 实测踩到，写下来免得后人改回去）：
         *   ① **退出码必须写进 `msg`**：`msg` 只过 token 掩码；而放进 `data.code` 会被
         *      `redactValue` 的"8~18 位整数当学号"兜底掩成 `42****95` —— 证据直接没了。
         *      结构化那一路另给 `codeHex`（形如 `0xffffffff`，不含 8~18 位数字串 ⇒ 掩码不动它）。
         *   ② **输出必须是脱敏后的 `masked`**：原文只允许留在 sidecar 的 `output` 段里，
         *      而且那份 sidecar 也已经过 `maskScannerRecord()`。
         */
        logWarn(
          'token-scan',
          `扫描器未回传结果（退出码 ${code === null ? 'null' : code}）${
            masked ? `：${masked.slice(0, 300)}` : '，且子进程没有留下任何输出'
          }`,
          {
            codeHex: code === null ? '' : `0x${(code >>> 0).toString(16)}`,
            hasOutput: masked.length > 0,
            log: logPath,
          },
        )
        patchScan({ phase: 'error', message: describeScanFailure(code, masked, logPath) })
      } else if (code !== 0) {
        logWarn('token-scan', '扫描器非零退出（状态已推进，不覆盖界面）', {
          codeHex: code === null ? '' : `0x${(code >>> 0).toString(16)}`,
          log: logPath,
        })
      } else {
        logInfo('token-scan', '扫描器正常退出', { code, log: logPath })
      }
    }, 3000)
  })
}

/**
 * Linux 版「一键获取 token」：只读扫描 WMPF 进程内存
 *
 * 实测环境（2026-10-18，Linux 微信 4.1.4 AppImage）：
 *   - 主进程 `wechat` 没有 token；
 *   - `RadiumWMPF/runtime/WeChatAppEx`（无 `--type=` 的宿主）里有 token；
 *   - `--type=utility --utility-sub-type=network.mojom.NetworkService` 里也有同一条；
 *   - renderer / gpu / zygote / broker 里没有（而且很大，跳过）。
 *
 * 实现边界：
 *   - 只读 `/proc/<pid>/mem`（`open(..., 'r')` + `read`），**不写内存、不注入、不 hook**；
 *   - token 候选只回传给本机 `/api/local/token-import`，由现有逻辑**逐个验活**；
 *   - 不把 token 写日志、不写盘；日志只有 pid / 字节数 / 候选数。
 *
 * ⚠️ Linux 与 Windows 最大的区别：`/proc/<pid>/mem` 受 ptrace 权限约束。
 *    默认 `kernel.yama.ptrace_scope=1` 时，普通同用户进程读别人内存会 `EACCES`；
 *    需要用户临时 `sudo sysctl kernel.yama.ptrace_scope=0`，或给扫描器 CAP_SYS_PTRACE。
 *    本模块只负责**如实报 NO_PERMISSION**，不自动改系统设置。
 */
import { open, readFile, readdir, readlink } from 'node:fs/promises'
import { TOKEN_MAX_CANDIDATES } from '../../utils/mp/tokenScan'
import {
  LINUX_SCAN_CHUNK_BYTES,
  LINUX_SCAN_MAX_REGION_BYTES,
  LINUX_SCAN_OVERLAP_BYTES,
  candidateTokens,
  classifyWmpfProcess,
  findTokenCandidatesInBuffer,
  mergeTokenCandidates,
  parseMapsLine,
  shouldScanMapRange,
  wmpfRoleRank,
  type MapRange,
  type TokenCandidate,
  type WmpfProcessInfo,
} from '../../utils/mp/tokenScanLinux'
import { logInfo, logWarn } from './logger'

export type LinuxScanError = '' | 'NO_PROCESS' | 'NO_PERMISSION' | 'NO_TOKEN' | 'SCAN_FAILED'

export interface LinuxTokenScanResult {
  error: LinuxScanError
  tokens: string[]
  /** 找到的 WMPF 进程数（不是扫描成功的进程数） */
  processes: number
  /** 实际尝试扫过的 pid（排障用；不含 token） */
  scannedPids: number[]
  bytesRead: number
  detail: string
}

/** `/proc/<pid>/mem` 打开失败 = 权限问题，单独区分，不混进 SCAN_FAILED */
class LinuxMemoryPermissionError extends Error {
  readonly kind = 'NO_PERMISSION' as const
  constructor(message: string) {
    super(message)
    this.name = 'LinuxMemoryPermissionError'
  }
}

async function readText(path: string): Promise<string> {
  try {
    return await readFile(path, 'utf8')
  } catch {
    return ''
  }
}

/** 列出值得扫描的 WMPF 进程：host → network → utility */
export async function listWmpfProcesses(): Promise<WmpfProcessInfo[]> {
  let names: string[]
  try {
    names = await readdir('/proc')
  } catch (err) {
    throw new Error(`无法读取 /proc：${err instanceof Error ? err.message : String(err)}`)
  }

  const out: WmpfProcessInfo[] = []
  for (const name of names) {
    if (!/^\d+$/.test(name)) continue
    const pid = Number(name)
    const comm = (await readText(`/proc/${pid}/comm`)).trim()
    /**
     * 先按 comm 粗筛，避免对几百个无关进程逐个读 cmdline。
     * 用 `includes` 而不是严格相等：comm 可能被内核截断/大小写变化；
     * 真正的角色判定仍在 classifyWmpfProcess 里。
     */
    if (!comm.toLowerCase().includes('wechatappex')) continue

    const cmdline = (await readText(`/proc/${pid}/cmdline`)).replace(/\0/g, ' ').trim()
    const role = classifyWmpfProcess(comm, cmdline)
    if (role === 'skip') continue

    let exe = ''
    try {
      exe = await readlink(`/proc/${pid}/exe`)
    } catch {
      /* exe 只是排障信息，读不到不影响扫描 */
    }
    out.push({ pid, comm, cmdline, exe, role })
  }

  return out.sort((a, b) => wmpfRoleRank(a.role) - wmpfRoleRank(b.role) || a.pid - b.pid)
}

async function readMapRanges(pid: number): Promise<MapRange[]> {
  const text = await readFile(`/proc/${pid}/maps`, 'utf8')
  const out: MapRange[] = []
  for (const line of text.split('\n')) {
    const range = parseMapsLine(line)
    if (range) out.push(range)
  }
  return out
}

interface PidScanResult {
  candidates: TokenCandidate[]
  bytesRead: number
  regions: number
}

/**
 * 扫描单个 pid 的可读内存区。
 *
 * 只读、分块、块间重叠；某个区读失败（EIO/ENXIO）就跳过该区，
 * 不因为一个 guard page 把整次扫描判失败。
 */
async function scanPid(pid: number, maxRegionBytes: number): Promise<PidScanResult> {
  const ranges = await readMapRanges(pid)
  let handle
  try {
    handle = await open(`/proc/${pid}/mem`, 'r')
  } catch (err) {
    const code = (err as NodeJS.ErrnoException)?.code
    if (code === 'EACCES' || code === 'EPERM') {
      throw new LinuxMemoryPermissionError(
        `读取 /proc/${pid}/mem 被拒绝（${code}）。Linux 默认 ptrace_scope=1 会禁止同用户非父子进程读内存。`,
      )
    }
    throw err
  }

  const buf = Buffer.alloc(LINUX_SCAN_CHUNK_BYTES)
  let candidates: TokenCandidate[] = []
  let bytesRead = 0
  let regions = 0

  try {
    for (const range of ranges) {
      if (!shouldScanMapRange(range, maxRegionBytes)) continue
      regions += 1
      let pos = range.start
      while (pos < range.end) {
        const want = Math.min(LINUX_SCAN_CHUNK_BYTES, range.end - pos)
        let n = 0
        try {
          const res = await handle.read(buf, 0, want, pos)
          n = res.bytesRead
        } catch (err) {
          const code = (err as NodeJS.ErrnoException)?.code
          if (code === 'EACCES' || code === 'EPERM') {
            throw new LinuxMemoryPermissionError(
              `读取 /proc/${pid}/mem 被拒绝（${code}）。Linux 默认 ptrace_scope=1 会禁止同用户非父子进程读内存。`,
            )
          }
          // 未映射/guard page 的 EIO 很常见：跳过本区，继续下一个
          break
        }
        if (!n) break
        bytesRead += n
        candidates = mergeTokenCandidates(
          candidates,
          findTokenCandidatesInBuffer(buf.subarray(0, n)),
        )
        if (candidates.length >= TOKEN_MAX_CANDIDATES) break

        // token 可能跨块：回退 256 字节再读
        const step = n - LINUX_SCAN_OVERLAP_BYTES
        if (step <= 0) break
        pos += step
      }
      if (candidates.length >= TOKEN_MAX_CANDIDATES) break
    }
  } finally {
    await handle.close().catch(() => {
      /* 关闭失败不影响结果 */
    })
  }

  return { candidates, bytesRead, regions }
}

/**
 * 扫描所有 WMPF 进程。**所有进程都尝试**（host 有 token 时 network 里通常也有一条，
 * 去重后候选仍只有 1~2 条）；这样不会因为某个进程是旧快照就漏掉新 token。
 */
export async function scanLinuxToken(
  maxRegionBytes: number = LINUX_SCAN_MAX_REGION_BYTES,
): Promise<LinuxTokenScanResult> {
  const processes = await listWmpfProcesses()
  if (processes.length === 0) {
    return {
      error: 'NO_PROCESS',
      tokens: [],
      processes: 0,
      scannedPids: [],
      bytesRead: 0,
      detail: '',
    }
  }

  let candidates: TokenCandidate[] = []
  let bytesRead = 0
  const scannedPids: number[] = []
  let permissionDetail = ''
  let lastError = ''

  for (const proc of processes) {
    if (candidates.length >= TOKEN_MAX_CANDIDATES) break
    scannedPids.push(proc.pid)
    try {
      const res = await scanPid(proc.pid, maxRegionBytes)
      bytesRead += res.bytesRead
      candidates = mergeTokenCandidates(candidates, res.candidates)
      logInfo('token-scan', 'Linux 已扫描 WMPF 进程', {
        pid: proc.pid,
        role: proc.role,
        regions: res.regions,
        bytes: res.bytesRead,
        candidates: res.candidates.length,
      })
    } catch (err) {
      if (err instanceof LinuxMemoryPermissionError) {
        permissionDetail = err.message
        logWarn('token-scan', 'Linux 读取进程内存被拒绝', { pid: proc.pid, role: proc.role, error: err.message })
      } else {
        lastError = err instanceof Error ? err.message : String(err)
        logWarn('token-scan', 'Linux 扫描进程失败', { pid: proc.pid, role: proc.role, error: lastError })
      }
    }
  }

  const base = { processes: processes.length, scannedPids, bytesRead }
  if (candidates.length > 0) {
    return { ...base, error: '', tokens: candidateTokens(candidates), detail: '' }
  }
  if (permissionDetail) {
    return { ...base, error: 'NO_PERMISSION', tokens: [], detail: permissionDetail }
  }
  if (lastError) {
    return { ...base, error: 'SCAN_FAILED', tokens: [], detail: lastError }
  }
  return { ...base, error: 'NO_TOKEN', tokens: [], detail: '' }
}

/**
 * 扫描并把结果 POST 回本机 `/api/local/token-import`（不等待用户、不阻塞启动端点）。
 * 与 Windows 扫描器保持同一套回传协议；验活仍在 token-import 端点里做。
 */
export async function runLinuxTokenScan(endpoint: string, nonce: string): Promise<void> {
  const started = Date.now()
  let result: LinuxTokenScanResult
  try {
    result = await scanLinuxToken()
  } catch (err) {
    result = {
      error: 'SCAN_FAILED',
      tokens: [],
      processes: 0,
      scannedPids: [],
      bytesRead: 0,
      detail: err instanceof Error ? err.message : String(err),
    }
  }

  const payload = {
    nonce,
    tokens: result.tokens,
    error: result.error,
    processes: result.processes,
    phase: 'scan',
    detail: result.detail,
    platform: 'linux',
    psVersion: process.version,
    bytesRead: result.bytesRead,
    scannedPids: result.scannedPids,
    elapsedMs: Date.now() - started,
  }

  try {
    const res = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    })
    if (!res.ok) {
      logWarn('token-scan', 'Linux 扫描结果回传失败', { http: res.status })
    }
  } catch (err) {
    logWarn('token-scan', 'Linux 扫描结果回传失败', {
      error: err instanceof Error ? err.message : String(err),
    })
  }

  logInfo('token-scan', 'Linux 扫描结束', {
    error: result.error,
    processes: result.processes,
    candidates: result.tokens.length,
    bytes: result.bytesRead,
    elapsedMs: Date.now() - started,
  })
}

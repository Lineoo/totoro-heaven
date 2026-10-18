/**
 * Linux 微信 WMPF 内存扫描的**纯逻辑**（零第三方依赖，可单测）
 *
 * 背景（2026-10-18 实测）：
 *   - Linux 微信 4.x 的 AppImage 里带有独立的 WMPF 运行时
 *     `RadiumWMPF/runtime/WeChatAppEx`（Chromium/XWeb 架构）；
 *   - token 以 ASCII `WXXCX` + base64、101 字符的形式存在于
 *     **WMPF 宿主进程**和 **NetworkService 进程**的内存里；
 *   - 主进程 `wechat`、renderer、zygote 里没有。
 *
 * 本文件只做「怎么认进程 / 怎么认内存区 / 怎么从 Buffer 里找候选」这类纯计算；
 * 真正的 `/proc/<pid>/mem` 读取在 `server/utils/tokenScanLinux.ts`。
 *
 * ⚠️ 纪律：候选的清洗/去重/限量统一复用 `utils/mp/tokenScan.ts`；
 *    token 本体不打印、不落盘，日志只留指纹。
 */
import { TOKEN_MAX_CANDIDATES, TOKEN_MIN_LEN, TOKEN_PREFIX, isTokenShape } from './tokenScan'

/** WMPF 进程角色：host = 主进程；network = NetworkService；utility = 其它 utility */
export type WmpfRole = 'host' | 'network' | 'utility' | 'skip'

export interface WmpfProcessInfo {
  pid: number
  comm: string
  cmdline: string
  exe: string
  role: WmpfRole
}

/** `/proc/<pid>/maps` 的一行 */
export interface MapRange {
  start: number
  end: number
  perms: string
  path: string
}

/** 从内存 Buffer 里找到的候选 */
export interface TokenCandidate {
  token: string
  encoding: 'ascii' | 'utf16le'
}

/**
 * 单个可读内存区的上限（默认 1 GiB）。
 * 理由：WMPF 是 Chromium，存在很大的堆；但超过 1 GiB 的区多半是 GPU/大缓存，
 * 扫完收益低、耗时高。实测 token 所在的 `[anon:partition_alloc]` 远小于这个值。
 */
export const LINUX_SCAN_MAX_REGION_BYTES = 1024 * 1024 * 1024
/** 每次读取的块大小 */
export const LINUX_SCAN_CHUNK_BYTES = 1024 * 1024
/** 块间重叠：token 最长约 101 字符，256 足够覆盖跨块 */
export const LINUX_SCAN_OVERLAP_BYTES = 256

const ROLE_ORDER: Record<WmpfRole, number> = { host: 0, network: 1, utility: 2, skip: 9 }

/**
 * 判断一个进程是不是值得扫描的 WMPF 进程。
 *
 * 判据全部来自实测命令行：
 *   - 主进程：`.../RadiumWMPF/runtime/WeChatAppEx --log-level=2 ...`（没有 `--type=`）
 *   - 网络：`--type=utility --utility-sub-type=network.mojom.NetworkService`
 *   - 跳过：`--type=renderer` / `gpu-process` / `zygote` / `broker`
 *
 * 注意：主进程 `wechat` 的 `comm` 不是 `WeChatAppEx`，本函数会 skip —— 它没有 token。
 */
export function classifyWmpfProcess(comm: string, cmdline: string): WmpfRole {
  const c = String(comm ?? '').trim().toLowerCase()
  if (c !== 'wechatappex') return 'skip'
  const cmd = String(cmdline ?? '')

  // Chromium 子进程：renderer / GPU / zygote / broker 都实测没有 token，且体积很大
  if (/--type=(?:renderer|gpu-process|zygote|broker)\b/.test(cmd)) return 'skip'

  if (/--type=utility\b/.test(cmd)) {
    // 实测 NetworkService 里有 token（与宿主同一条）；ILink utility 里没有
    return /--utility-sub-type=network\.mojom\.NetworkService\b/.test(cmd) ? 'network' : 'utility'
  }

  // 没有 --type= 的 WeChatAppEx 就是 WMPF 宿主
  if (!/--type=/.test(cmd)) return 'host'
  return 'skip'
}

/** 进程扫描优先级：host → network → utility */
export function wmpfRoleRank(role: WmpfRole): number {
  return ROLE_ORDER[role] ?? ROLE_ORDER.skip
}

/**
 * 解析 `/proc/<pid>/maps` 的一行。
 * 例：`7f00-7f10 r--p 00000000 08:01 123 /usr/lib/libx.so`
 * pathname 可能含空格，所以第 6 段起要整体拼回。
 */
export function parseMapsLine(line: string): MapRange | null {
  const parts = String(line ?? '').trim().split(/\s+/)
  if (parts.length < 2) return null
  const [range, perms] = parts
  const [a, b] = range.split('-')
  if (!a || !b) return null
  const start = Number.parseInt(a, 16)
  const end = Number.parseInt(b, 16)
  if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end) || end <= start) return null
  return {
    start,
    end,
    perms,
    path: parts.length >= 6 ? parts.slice(5).join(' ') : '',
  }
}

/** 这个内存区值不值得读：可读、非空、不要太大、跳过 vvar/vsyscall */
export function shouldScanMapRange(
  range: MapRange,
  maxRegionBytes: number = LINUX_SCAN_MAX_REGION_BYTES,
): boolean {
  if (!range.perms.includes('r')) return false
  if (range.end <= range.start) return false
  if (range.end - range.start > maxRegionBytes) return false
  if (range.path === '[vvar]' || range.path === '[vsyscall]') return false
  return true
}

/**
 * 在一个 Buffer 里找 `WXXCX` 候选。
 *
 * 同时支持两种编码：
 *   - ASCII：普通 C/C++ string、Chromium 的 one-byte V8 string；
 *   - UTF-16LE：如果 token 被存成 JS 宽字符串（实测 Linux 这里是 ASCII，但留着更稳）。
 *
 * ⚠️ 用 `latin1` 把 Buffer 变成字符串再跑正则：这样二进制里的 `\0` 不会被 UTF-8 解码弄丢，
 *    UTF-16LE 的 `W\0X\0...` 也能被第二个正则直接匹配。
 */
export function findTokenCandidatesInBuffer(
  buf: Buffer,
  max: number = TOKEN_MAX_CANDIDATES,
): TokenCandidate[] {
  if (!buf || buf.length < TOKEN_MIN_LEN) return []
  const text = buf.toString('latin1')
  const out: TokenCandidate[] = []
  const seen = new Set<string>()

  // ASCII：WXXCX + 至少 (TOKEN_MIN_LEN - 5) 个 base64 字符
  const asciiRe = new RegExp(`${TOKEN_PREFIX}[A-Za-z0-9+/=]{${TOKEN_MIN_LEN - TOKEN_PREFIX.length},}`, 'g')
  for (const m of text.matchAll(asciiRe)) {
    const token = m[0]
    if (!isTokenShape(token) || seen.has(token)) continue
    seen.add(token)
    out.push({ token, encoding: 'ascii' })
    if (out.length >= max) return out
  }

  // UTF-16LE：W\0X\0X\0C\0X\0 + base64 字符 + \0 交替
  const utf16Re = new RegExp(
    `${TOKEN_PREFIX.split('').map((ch) => `${ch}\\x00`).join('')}(?:[A-Za-z0-9+/=]\\x00){${TOKEN_MIN_LEN - TOKEN_PREFIX.length},}`,
    'g',
  )
  for (const m of text.matchAll(utf16Re)) {
    const token = Buffer.from(m[0], 'latin1').toString('utf16le')
    if (!isTokenShape(token) || seen.has(token)) continue
    seen.add(token)
    out.push({ token, encoding: 'utf16le' })
    if (out.length >= max) return out
  }

  return out
}

/** 合并候选：过滤非 token 形状、去重、限量；保持先出现顺序 */
export function mergeTokenCandidates(
  existing: TokenCandidate[],
  next: TokenCandidate[],
  max: number = TOKEN_MAX_CANDIDATES,
): TokenCandidate[] {
  const out: TokenCandidate[] = []
  const seen = new Set<string>()
  for (const c of [...existing, ...next]) {
    if (!c || !isTokenShape(c.token) || seen.has(c.token)) continue
    seen.add(c.token)
    out.push({ token: c.token, encoding: c.encoding })
    if (out.length >= max) break
  }
  return out
}

/** 候选 → 纯 token 字符串（给 HTTP 回传/清洗用） */
export function candidateTokens(candidates: TokenCandidate[]): string[] {
  return candidates.map((c) => c.token)
}

/**
 * Linux WMPF token 扫描的纯逻辑测试
 *
 * 依据（2026-10-18 实测，Linux 微信 4.1.4 AppImage）：
 *   - 主进程 `wechat` 没有 token；
 *   - `WeChatAppEx`（无 --type=）有 token；
 *   - `--type=utility --utility-sub-type=network.mojom.NetworkService` 有同一条；
 *   - renderer / gpu / zygote / broker 没有，且体积大。
 *
 * 这里只测纯函数：真实 `/proc/<pid>/mem` 读取在 `server/utils/tokenScanLinux.ts`。
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  LINUX_SCAN_MAX_REGION_BYTES,
  candidateTokens,
  classifyWmpfProcess,
  findTokenCandidatesInBuffer,
  mergeTokenCandidates,
  parseMapsLine,
  shouldScanMapRange,
  wmpfRoleRank,
  type MapRange,
  type TokenCandidate,
} from '../../utils/mp/tokenScanLinux.ts'
import { TOKEN_MAX_CANDIDATES, TOKEN_PREFIX } from '../../utils/mp/tokenScan.ts'

const makeToken = (len = 101): string => `${TOKEN_PREFIX}${'A'.repeat(Math.max(0, len - TOKEN_PREFIX.length))}`

const hostCmd =
  '/tmp/.mount_WeChatfNdink/opt/wechat/RadiumWMPF/runtime/WeChatAppEx --log-level=2 --lang=zh-CN --wmpf_root_dir=/home/lineo/.xwechat/radium --enable-applet-v3'
const networkCmd =
  '/tmp/.mount_WeChatfNdink/opt/wechat/RadiumWMPF/runtime/WeChatAppEx --type=utility --utility-sub-type=network.mojom.NetworkService --lang=zh-CN'
const utilityCmd =
  '/tmp/.mount_WeChatfNdink/opt/wechat/RadiumWMPF/runtime/WeChatAppEx --type=utility --utility-sub-type=flue.mojom.ILinkServiceHost --lang=zh-CN'
const rendererCmd =
  '/tmp/.mount_WeChatfNdink/opt/wechat/RadiumWMPF/runtime/WeChatAppEx --type=renderer --wmpf-render-type=7'
const gpuCmd =
  '/tmp/.mount_WeChatfNdink/opt/wechat/RadiumWMPF/runtime/WeChatAppEx --type=gpu-process'
const zygoteCmd =
  '/tmp/.mount_WeChatfNdink/opt/wechat/RadiumWMPF/runtime/WeChatAppEx --type=zygote --no-zygote-sandbox'
const brokerCmd =
  '/tmp/.mount_WeChatfNdink/opt/wechat/RadiumWMPF/runtime/WeChatAppEx --type=broker'

test('进程角色：host / network / utility 要识别，renderer/gpu/zygote/broker 要跳过', () => {
  assert.equal(classifyWmpfProcess('WeChatAppEx', hostCmd), 'host')
  assert.equal(classifyWmpfProcess('WeChatAppEx', networkCmd), 'network')
  assert.equal(classifyWmpfProcess('WeChatAppEx', utilityCmd), 'utility')
  assert.equal(classifyWmpfProcess('WeChatAppEx', rendererCmd), 'skip')
  assert.equal(classifyWmpfProcess('WeChatAppEx', gpuCmd), 'skip')
  assert.equal(classifyWmpfProcess('WeChatAppEx', zygoteCmd), 'skip')
  assert.equal(classifyWmpfProcess('WeChatAppEx', brokerCmd), 'skip')
})

test('进程角色：非 WeChatAppEx 一律 skip（主进程 wechat 没有 token）', () => {
  assert.equal(classifyWmpfProcess('wechat', hostCmd), 'skip')
  assert.equal(classifyWmpfProcess('WeChatLinux_x86', hostCmd), 'skip')
  assert.equal(classifyWmpfProcess('crashpad_handler', hostCmd), 'skip')
  // comm 大小写/变体：仍按 WeChatAppEx 认
  assert.equal(classifyWmpfProcess('wechatappex', hostCmd), 'host')
})

test('扫描优先级：host → network → utility', () => {
  assert.ok(wmpfRoleRank('host') < wmpfRoleRank('network'))
  assert.ok(wmpfRoleRank('network') < wmpfRoleRank('utility'))
  assert.ok(wmpfRoleRank('utility') < wmpfRoleRank('skip'))
})

test('parseMapsLine：标准行 / path 含空格 / 无 path / 坏行', () => {
  const a = parseMapsLine('7f0000000000-7f0000001000 r--p 00000000 08:01 1234 /usr/lib/libx.so')
  assert.deepEqual(a, {
    start: 0x7f0000000000,
    end: 0x7f0000001000,
    perms: 'r--p',
    path: '/usr/lib/libx.so',
  })

  const b = parseMapsLine('7f00-7f10 rw-p 00000000 00:00 0 [anon:partition_alloc]')
  assert.equal(b?.path, '[anon:partition_alloc]')

  // 路径含空格：第 6 段起整体拼回
  const c = parseMapsLine('1000-2000 r--s 00000000 08:01 9 /tmp/a b c.so')
  assert.equal(c?.path, '/tmp/a b c.so')

  assert.equal(parseMapsLine(''), null)
  assert.equal(parseMapsLine('not-a-range r--p'), null)
  assert.equal(parseMapsLine('1000-1000 r--p 0 0 0'), null)
})

test('shouldScanMapRange：只读、非空、不超上限、跳过 vvar/vsyscall', () => {
  const base: MapRange = { start: 0x1000, end: 0x2000, perms: 'r--p', path: '' }
  assert.equal(shouldScanMapRange(base), true)
  assert.equal(shouldScanMapRange({ ...base, perms: '-w-p' }), false)
  assert.equal(shouldScanMapRange({ ...base, end: 0x1000 }), false)
  assert.equal(shouldScanMapRange({ ...base, end: base.start + LINUX_SCAN_MAX_REGION_BYTES + 1 }), false)
  assert.equal(shouldScanMapRange({ ...base, path: '[vvar]' }), false)
  assert.equal(shouldScanMapRange({ ...base, path: '[vsyscall]' }), false)
  // 上限是参数（测试用小值）
  assert.equal(shouldScanMapRange({ ...base, end: base.start + 100 }, 50), false)
})

test('findTokenCandidatesInBuffer：ASCII token 能找到', () => {
  const token = makeToken()
  const buf = Buffer.concat([Buffer.from('prefix '), Buffer.from(token), Buffer.from(' suffix')])
  const found = findTokenCandidatesInBuffer(buf)
  assert.equal(found.length, 1)
  assert.equal(found[0].token, token)
  assert.equal(found[0].encoding, 'ascii')
})

test('findTokenCandidatesInBuffer：UTF-16LE token 能找到，且不会被 ASCII 规则误判', () => {
  const token = makeToken()
  // 用非 base64 的 `!` 分隔，否则 `y` 会被贪婪地算进 token
  const buf = Buffer.from(`x${token}!y`, 'utf16le')
  const found = findTokenCandidatesInBuffer(buf)
  assert.equal(found.length, 1)
  assert.equal(found[0].token, token)
  assert.equal(found[0].encoding, 'utf16le')
})

test('findTokenCandidatesInBuffer：太短 / 非 base64 / 普通文本不产生候选', () => {
  assert.deepEqual(findTokenCandidatesInBuffer(Buffer.from(makeToken(79))), [])
  // 前缀后面只有 50 个连续 base64 字符（<75）⇒ 不能当候选
  assert.deepEqual(
    findTokenCandidatesInBuffer(Buffer.from(`${TOKEN_PREFIX}${'A'.repeat(50)}-${'A'.repeat(40)}`)),
    [],
  )
  assert.deepEqual(findTokenCandidatesInBuffer(Buffer.from('WXXCX is a prefix, not a token')), [])
})

test('findTokenCandidatesInBuffer：去重 + 限量', () => {
  const a = makeToken()
  const b = `${TOKEN_PREFIX}${'B'.repeat(96)}`
  const buf = Buffer.from(`${a}\n${a}\n${b}`)
  const found = findTokenCandidatesInBuffer(buf, 1)
  assert.equal(found.length, 1)
  assert.equal(found[0].token, a)

  const all = findTokenCandidatesInBuffer(buf, TOKEN_MAX_CANDIDATES)
  assert.equal(all.length, 2)
  assert.deepEqual(all.map((c) => c.token), [a, b])
})

test('mergeTokenCandidates：过滤非形状、去重、保序、限量', () => {
  const a = makeToken()
  const b = `${TOKEN_PREFIX}${'B'.repeat(96)}`
  const bad = 'not-a-token'
  const existing: TokenCandidate[] = [{ token: a, encoding: 'ascii' }]
  const next: TokenCandidate[] = [
    { token: a, encoding: 'utf16le' },
    { token: bad, encoding: 'ascii' },
    { token: b, encoding: 'ascii' },
  ]
  const merged = mergeTokenCandidates(existing, next)
  assert.deepEqual(merged.map((c) => c.token), [a, b])
  assert.equal(merged[0].encoding, 'ascii', '同 token 保留先出现的那条')

  const limited = mergeTokenCandidates(existing, next, 1)
  assert.deepEqual(limited.map((c) => c.token), [a])
  assert.deepEqual(candidateTokens(merged), [a, b])
})

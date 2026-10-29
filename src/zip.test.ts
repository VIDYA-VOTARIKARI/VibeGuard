import JSZip from 'jszip'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { readZip, scanTextFiles, scanZip, type ScanChecks } from './scanner'
import { readSourceZip } from './zip'
import { MAX_ARCHIVE_BYTES, MAX_ARCHIVE_ENTRIES, MAX_EXTRACTED_BYTES, MAX_SOURCE_FILE_BYTES } from './limits'
import { dependencyKey, type OsvLookup } from './intelligence'

afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals() })
const uploaded = (bytes: Uint8Array) => new File([new Uint8Array(bytes).buffer], 'project.zip')
async function archive(entries: Record<string, string | Uint8Array>, options: JSZip.JSZipGeneratorOptions<'uint8array'> = {}) {
  const zip = new JSZip()
  for (const [path, content] of Object.entries(entries)) zip.file(path, content, { createFolders: false })
  return zip.generateAsync({ type: 'uint8array', compression: 'DEFLATE', ...options })
}
function headers(bytes: Uint8Array) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
  const end = bytes.length - 22, central = view.getUint32(end + 16, true)
  const local = view.getUint32(central + 42, true)
  const data = local + 30 + view.getUint16(local + 26, true) + view.getUint16(local + 28, true)
  return { view, central, local, end, data }
}
const noMatches: OsvLookup = async (dependencies) => ({ advisories: new Map(dependencies.map((dep) => [dependencyKey(dep.packageName, dep.ecosystem, dep.version), []])), checkedAt: new Date().toISOString(), responseCount: dependencies.length, source: 'OSV.dev' })
const allDisabled: ScanChecks = { secrets: false, configuration: false, authorization: false, codeSafety: false, dependencies: false }

const shop = [
  "const express = require('express')",
  "const cors = require('cors')",
  'const app = express()',
  'app.use(express.json())',
  'app.use(cors({ credentials: true, origin: true }))',
  "app.get('/api/orders/:id', requireAuth, async (req, res) => {",
  '  const order = orders.find(item => item.id === req.params.id)',
  '  return res.json(order)',
  '})',
  "app.get('/api/my-orders', requireAuth, async (req, res) => {",
  '  return res.json(orders.filter(item => item.ownerId === req.user.id))',
  '})',
  "app.post('/api/checkout', requireAuth, async (req, res) => {",
  '  const { productId, quantity, unitPrice } = req.body',
  '  const product = catalog.find(item => item.id === productId)',
  '  const total = Number(quantity) * Number(unitPrice)',
  '  return res.json({ total, product })',
  '})',
  "throw new Error('Uploaded code must never run')",
].join('\n')

describe('generated e-commerce ZIP flow', () => {
  it('finds all three rules at the actual nested files/lines, with options, provenance and phases', async () => {
    const bytes = await archive({
      'shop/api/server.cjs': shop,
      'shop/api/payment.mjs': 'export const connected = true',
      'shop/package.json': JSON.stringify({ engines: { node: '>=20' }, dependencies: { express: '^4.18.2' } }),
      'shop/package-lock.json': JSON.stringify({ packages: { '': { dependencies: { express: '^4.18.2' } }, 'node_modules/express': { version: '4.18.2' } } }),
      'shop/.env.production.local': '# deploy\nDATABASE_PASSWORD=unquoted-sensitive-value',
      'shop/.nvmrc': '20.19.0',
      'shop/Dockerfile': 'FROM node:20-alpine',
    }, { streamFiles: true })
    const phases: string[] = []
    const scanId = crypto.randomUUID()
    const result = await scanZip(uploaded(bytes), 'E-commerce source', {}, noMatches, { scanId, onProgress: (phase) => phases.push(phase) })
    expect(result.findings.filter((finding) => finding.rule.startsWith('VG-JS')).map(({ rule, file, line }) => ({ rule, file, line }))).toEqual([
      { rule: 'VG-JS-001', file: 'shop/api/server.cjs', line: 7 },
      { rule: 'VG-JS-002', file: 'shop/api/server.cjs', line: 16 },
      { rule: 'VG-JS-003', file: 'shop/api/server.cjs', line: 5 },
    ])
    expect(result.findings.every((finding) => finding.scanId === scanId)).toBe(true)
    expect(new Set(result.findings.map((finding) => finding.id)).size).toBe(result.findings.length)
    expect(result.scanId).toBe(scanId)
    expect(result.scanType).toBe('Source upload')
    expect(result.scanStatus).toBe('Completed')
    expect(result.sourceFiles).toHaveLength(7)
    expect(result.dependencies).toEqual([expect.objectContaining({ packageName: 'express', declaredVersion: '^4.18.2', resolvedVersion: '4.18.2', lookupStatus: 'no-match' })])
    expect(result.runtimes).toEqual(expect.arrayContaining([expect.objectContaining({ sourceFile: 'shop/.nvmrc', version: '20.19.0' }), expect.objectContaining({ sourceFile: 'shop/Dockerfile', version: '20-alpine' })]))
    expect([...new Set(phases)]).toEqual([
      'Validating archive headers and safety limits', 'Reading the ZIP central directory',
      'Extracting supported text with streamed byte and CRC checks', 'Archive extraction complete',
      'Running selected static source checks', 'Inventorying nested manifests and lockfiles',
      'Matching exact dependency versions against OSV', 'Detecting runtime declarations and finalizing coverage',
      'Scan complete',
    ])
  })

  it.each(['authorization', 'configuration', 'codeSafety'] as const)('respects the %s rule option', (option) => {
    const rules = { authorization: 'VG-JS-001', configuration: 'VG-JS-003', codeSafety: 'VG-JS-002' }
    const result = scanTextFiles([{ path: 'shop/server.mjs', content: shop }], 'options', { [option]: false })
    expect(result.findings.some((finding) => finding.rule === rules[option])).toBe(false)
    for (const key of Object.keys(rules) as Array<keyof typeof rules>) if (key !== option) expect(result.findings.some((finding) => finding.rule === rules[key])).toBe(true)
    expect(result.coverage.find((check) => check.id === option)?.status).toBe('not-run')
  })

  it('does not use ownership guards from another handler, helper or comment', () => {
    const text = [
      "app.get('/safe', (req, res) => { const order = orders.find(x => x.id === req.params.id && x.ownerId === req.user.id) })",
      "app.get('/bad', (req, res) => {",
      '  // ownerId === req.user.id is not enforced',
      '  const order = orders.find(x => x.id === req.params.id)',
      '  return res.json(order)',
      '})',
      "app.get('/also-bad', function(req, res) {",
      '  const order = orders.find(x => x.id === req.params.id)',
      '  return res.json(order)',
      '})',
      'const guard = (ownerId, req) => ownerId === req.user.id',
    ].join('\n')
    const result = scanTextFiles([{ path: 'server.js', content: text }], 'handlers')
    expect(result.findings.filter((finding) => finding.rule === 'VG-JS-001').map((finding) => finding.line)).toEqual([4, 8])
  })

  it('does not flag local trusted price arithmetic or examples in comments/strings', () => {
    const content = 'const quantity = 2; const unitPrice = 5; const total = Number(quantity) * Number(unitPrice)\n// cors({origin: true})\nconst sample = "orders.find(x => x.id === req.params.id)"'
    expect(scanTextFiles([{ path: 'trusted.cjs', content }], 'trusted').findings.filter((finding) => finding.rule.startsWith('VG-JS'))).toEqual([])
  })

  it('does not suppress a generic query using another handler’s ownership check or order lookup', () => {
    const content = [
      "app.get('/safe', (req, res) => { return db.from('orders').select('*').eq('owner_id', req.user.id) })",
      "app.get('/orders', (req, res) => { return orders.find(x => x.id === req.params.id && x.ownerId === req.user.id) })",
      "app.get('/unsafe', (req, res) => { return db.from('invoices').select('*') })",
    ].join('\n')
    expect(scanTextFiles([{ path: 'server.js', content }], 'generic handlers').findings.filter((finding) => finding.rule === 'AUTHZ-001').map((finding) => finding.line)).toEqual([3])
  })

  it('reports skipped content and disabled/dependency-less checks as limitations', async () => {
    const bytes = await archive({ 'src/index.js': 'export const ok = true', 'node_modules/pkg/index.js': 'eval(userInput)', 'photo.png': new Uint8Array([0, 1]), 'code.js': new Uint8Array([0xff, 0xfe]) })
    const result = await scanZip(uploaded(bytes), 'coverage', { dependencies: false }, noMatches)
    expect(result.scanStatus).toBe('Completed with limitations')
    expect(result.sourceFiles).toEqual(['src/index.js'])
    expect(result.coverage.find((check) => check.id === 'source')?.skippedCount).toBe(3)
    expect(result.limitations?.join(' ')).toMatch(/node_modules.*photo\.png.*code\.js/)
    expect(result.limitations?.join(' ')).toContain('Disabled by the scan options')
  })

  it('fails honestly when no supported files or no meaningful checks are available', async () => {
    const unsupported = await scanZip(uploaded(await archive({ 'image.png': 'not source' })), 'unsupported', {}, noMatches)
    expect(unsupported.scanStatus).toBe('Failed')
    expect(unsupported.errorCode).toBe('NO_SUPPORTED_CHECKS')
    const disabled = await scanZip(uploaded(await archive({ 'server.js': shop, 'package.json': '{}' })), 'disabled', allDisabled, noMatches)
    expect(disabled.scanStatus).toBe('Failed')
    expect(disabled.findings).toEqual([])
  })

  it('keeps dependency inventory when advisory matching is disabled', async () => {
    const lookup = vi.fn(noMatches)
    const result = await scanZip(uploaded(await archive({ 'package.json': '{"dependencies":{"express":"4.18.2"}}' })), 'disabled', { dependencies: false }, lookup)
    expect(lookup).not.toHaveBeenCalled()
    expect(result.dependencies[0]).toMatchObject({ packageName: 'express', lookupStatus: 'unavailable' })
    expect(result.scanStatus).toBe('Completed with limitations')
  })

  it('scans nested independent projects and lockfiles without collapsing package or runtime evidence', async () => {
    const bytes = await archive({
      'a/package.json': '{"engines":{"node":"20"},"dependencies":{"lodash":"^4.17.0"}}',
      'a/package-lock.json': '{"packages":{"node_modules/lodash":{"version":"4.17.20"}}}',
      'b/package.json': '{"engines":{"node":"22"},"dependencies":{"lodash":"^4.17.21"}}',
      'b/package-lock.json': '{"packages":{"node_modules/lodash":{"version":"4.17.21"}}}',
      'c/package.json': '{"dependencies":{"lodash":"^4.0.0"}}',
      'python/requirements.txt': 'requests>=2.31.0',
    })
    const result = await scanZip(uploaded(bytes), 'independent projects', {}, noMatches)
    expect(result.dependencies).toHaveLength(4)
    expect(result.dependencies).toEqual(expect.arrayContaining([
      expect.objectContaining({ declarationFile: 'a/package.json', version: '4.17.20', declaredVersion: '^4.17.0', lookupStatus: 'no-match' }),
      expect.objectContaining({ declarationFile: 'b/package.json', version: '4.17.21', declaredVersion: '^4.17.21', lookupStatus: 'no-match' }),
      expect.objectContaining({ manifest: 'c/package.json', version: '^4.0.0', lookupStatus: 'unknown-version' }),
      expect.objectContaining({ manifest: 'python/requirements.txt', version: '>=2.31.0', lookupStatus: 'unknown-version' }),
    ]))
    expect(result.runtimes.filter((runtime) => runtime.component === 'Node.js').map((runtime) => runtime.sourceFile)).toEqual(['a/package.json', 'b/package.json', 'c/package.json'])
    expect(result.scanStatus).toBe('Completed with limitations')
  })
})

describe('ZIP safety before and during decompression', () => {
  it.each(['STORE', 'DEFLATE'] as const)('accepts normal %s ZIPs with Unicode paths', async (compression) => {
    expect(await readZip(uploaded(await archive({ 'src/café.js': 'export const café = "☕"' }, { compression })))).toEqual([{ path: 'src/café.js', content: 'export const café = "☕"' }])
  })

  it.each(['../escape.js', 'a/../../escape.js', '..\\escape.js', '/absolute.js', 'C:\\drive.js', 'src/file.js:stream', 'nul\0.js', './ambiguous.js'])('rejects raw unsafe path %s before inflating', async (path) => {
    const bytes = await archive({ [path]: 'source' })
    const inflater = vi.fn()
    vi.stubGlobal('DecompressionStream', inflater)
    await expect(readZip(uploaded(bytes))).rejects.toThrow('Unsafe archive path rejected')
    expect(inflater).not.toHaveBeenCalled()
  })

  it('rejects unsafe directory records even when they contain no files', async () => {
    const zip = new JSZip(); zip.folder('../unsafe')
    await expect(readZip(uploaded(await zip.generateAsync({ type: 'uint8array' })))).rejects.toThrow('Unsafe archive path')
  })

  it('rejects duplicates before any library can collapse them', async () => {
    await expect(readZip(uploaded(await archive({ 'a.js': 'a', 'A.js': 'b' })))).rejects.toThrow('duplicate or ambiguous')
    const bytes = await archive({ 'a.js': 'a', 'b.js': 'b' }, { compression: 'STORE' })
    const { view, central } = headers(bytes)
    const second = central + 46 + view.getUint16(central + 28, true)
    const local = view.getUint32(second + 42, true)
    bytes[second + 46] = 97; bytes[local + 30] = 97
    await expect(readZip(uploaded(bytes))).rejects.toThrow('duplicate or ambiguous')
  })

  it('validates local raw names instead of trusting safe central names', async () => {
    const bytes = await archive({ 'abc.js': 'source' })
    const { local } = headers(bytes)
    bytes.set(new TextEncoder().encode('../bad'), local + 30)
    await expect(readZip(uploaded(bytes))).rejects.toThrow('Unsafe archive path')
  })

  it('rejects a symlink', async () => {
    const zip = new JSZip(); zip.file('link.js', '../../secret', { unixPermissions: 0o120777 })
    await expect(readZip(uploaded(await zip.generateAsync({ type: 'uint8array', platform: 'UNIX' })))).rejects.toThrow('symlinks and special files')
  })

  it('rejects archive size and raw entry count limits before decompression', async () => {
    await expect(readZip({ size: MAX_ARCHIVE_BYTES + 1, name: 'big.zip' } as File)).rejects.toThrow('100 MB')
    const bytes = await archive({ 'source.js': 'a' })
    const { view, end } = headers(bytes)
    view.setUint16(end + 8, MAX_ARCHIVE_ENTRIES + 1, true); view.setUint16(end + 10, MAX_ARCHIVE_ENTRIES + 1, true)
    const inflater = vi.fn(); vi.stubGlobal('DecompressionStream', inflater)
    await expect(readZip(uploaded(bytes))).rejects.toThrow('50,000')
    expect(inflater).not.toHaveBeenCalled()
  })

  it('accepts and scans an archive between the former 10 MB cap and the 100 MB limit', async () => {
    const bytes = await archive({ 'data.bin': new Uint8Array(12 * 1024 * 1024), 'src/index.js': 'export const ok = true' }, { compression: 'STORE' })
    expect(bytes.length).toBeGreaterThan(10 * 1024 * 1024)
    expect((await readSourceZip(uploaded(bytes))).files).toEqual([{ path: 'src/index.js', content: 'export const ok = true' }])
    const result = await scanZip(uploaded(bytes), 'large archive', {}, noMatches)
    expect(result.sourceFiles).toEqual(['src/index.js'])
    expect(result.scanStatus).not.toBe('Failed')
  })

  it.each([
    ['source.js', MAX_SOURCE_FILE_BYTES + 1, '10 MB per-file'],
    ['bomb.bin', 2 * 1024 * 1024, 'compression ratio'],
  ] as const)('rejects size/ratio metadata for %s without constructing an inflater', async (name, size, message) => {
    const bytes = await archive({ [name]: new Uint8Array(size) })
    const inflater = vi.fn(); vi.stubGlobal('DecompressionStream', inflater)
    await expect(readZip(uploaded(bytes))).rejects.toThrow(message)
    expect(inflater).not.toHaveBeenCalled()
  })

  it('rejects total extracted size metadata above 500 MB before decompression', async () => {
    const bytes = await archive({ 'data.bin': new Uint8Array([1, 2, 3]) })
    const { view, central } = headers(bytes)
    view.setUint32(central + 24, MAX_EXTRACTED_BYTES + 1, true)
    const inflater = vi.fn(); vi.stubGlobal('DecompressionStream', inflater)
    await expect(readZip(uploaded(bytes))).rejects.toThrow('500 MB safety limit')
    expect(inflater).not.toHaveBeenCalled()
  })

  it('cancels actual streaming output when forged sizes hide a compression bomb', async () => {
    const bytes = await archive({ 'bomb.js': 'a'.repeat(4_000_000) })
    const { view, central, local } = headers(bytes)
    view.setUint32(local + 22, 900_000, true); view.setUint32(central + 24, 900_000, true)
    const cancel = vi.spyOn(ReadableStreamDefaultReader.prototype, 'cancel')
    await expect(readZip(uploaded(bytes))).rejects.toThrow('Actual streamed output exceeds')
    expect(cancel).toHaveBeenCalled()
  })

  it('counts UTF-8 output bytes rather than JavaScript characters', async () => {
    let seed = 1
    const chars = Array.from({ length: 3_500_000 }, () => { seed = (seed * 1664525 + 1013904223) >>> 0; return String.fromCodePoint(0x4e00 + (seed % 20992)) })
    const bytes = await archive({ 'wide.js': chars.join('') })
    const { view, central, local } = headers(bytes)
    view.setUint32(local + 22, 3_500_000, true); view.setUint32(central + 24, 3_500_000, true)
    await expect(readZip(uploaded(bytes))).rejects.toThrow('Actual streamed output exceeds')
  })

  it('checks streamed CRC after applying limits', async () => {
    const bytes = await archive({ 'source.js': 'const value = 1' }, { compression: 'STORE' })
    const { data } = headers(bytes); bytes[data] ^= 1
    await expect(readZip(uploaded(bytes))).rejects.toThrow('CRC integrity')
  })

  it.each(['encrypted', 'ZIP64', 'count', 'overlap', 'compression', 'size'] as const)('rejects malformed/unsupported %s records', async (kind) => {
    const bytes = await archive({ 'source.js': 'const value = 1' })
    const { view, central, local, end } = headers(bytes)
    if (kind === 'encrypted') view.setUint16(central + 8, 1, true)
    if (kind === 'ZIP64') view.setUint32(central + 24, 0xffffffff, true)
    if (kind === 'count') { view.setUint16(end + 8, 0, true); view.setUint16(end + 10, 0, true) }
    if (kind === 'overlap') view.setUint32(central + 42, local + 1, true)
    if (kind === 'compression') view.setUint16(central + 10, 99, true)
    if (kind === 'size') view.setUint32(local + 22, 0, true)
    await expect(readSourceZip(uploaded(bytes))).rejects.toThrow('archive could not be opened')
  })

  it('rejects truncation, invalid deflate data and unavailable native streaming support', async () => {
    const bytes = await archive({ 'source.js': 'const value = 1' })
    await expect(readZip(uploaded(bytes.subarray(0, bytes.length - 3)))).rejects.toThrow('archive could not be opened')
    const { data } = headers(bytes); bytes[data] = 0xff
    await expect(readZip(uploaded(bytes))).rejects.toThrow('Archive extraction failed')
    vi.stubGlobal('DecompressionStream', undefined)
    await expect(readZip(uploaded(await archive({ 'source.js': 'content' })))).rejects.toThrow('bounded deflate-raw')
  })
})

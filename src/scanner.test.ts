import { describe, expect, it, vi } from 'vitest'
import JSZip from 'jszip'
import { fixedFixture, runAuthorizationCheck, vulnerableFixture } from './demo'
import { readZip, scanTextFiles, scanZip } from './scanner'
import { discoverDependencies, lookupOsvAdvisories, scanDependencies } from './intelligence'

describe('controlled authorization demo', () => {
  it('reproduces cross-user access in the vulnerable fixture', () => {
    const results = runAuthorizationCheck(false)
    expect(results[0].passed).toBe(false)
    expect(results[1].passed).toBe(true)
    expect(results[2].passed).toBe(true)
    expect(results[3].passed).toBe(true)
  })

  it('blocks cross-user access while preserving legitimate access after correction', () => {
    const results = runAuthorizationCheck(true)
    expect(results.every((result) => result.passed)).toBe(true)
  })
})

describe('deterministic source checks', () => {
  const vulnerableExpressSource = [
    "const cors = require('cors')",
    'app.use(cors({ origin: true }))',
    "app.get('/api/orders/:id', requireAuth, async (req, res) => {",
    '  const order = orders.find(item => item.id === req.params.id)',
    '  return res.json(order)',
    '})',
    "app.post('/api/checkout', async (req, res) => {",
    '  const { quantity, unitPrice } = req.body',
    '  const total = Number(quantity) * Number(unitPrice)',
    '  return res.json({ total })',
    '})',
  ].join('\n')

  it('detects the three JavaScript Express fixture rules in a nested project ZIP', async () => {
    const zip = new JSZip()
    zip.file('vibeguard-vulnerable-shop/server.js', vulnerableExpressSource)
    const bytes = await zip.generateAsync({ type: 'uint8array' })
    const result = await scanZip(new File([bytes.buffer as ArrayBuffer], 'vulnerable-shop.zip', { type: 'application/zip' }), 'vulnerable express fixture')
    expect(result.findings.map((finding) => finding.rule)).toEqual(expect.arrayContaining(['VG-JS-001', 'VG-JS-002', 'VG-JS-003']))
    expect(result.findings.find((finding) => finding.rule === 'VG-JS-001')?.confidence).toBe('Likely')
    expect(result.findings.find((finding) => finding.rule === 'VG-JS-001')?.line).toBe(4)
    expect(result.findings.find((finding) => finding.rule === 'VG-JS-002')?.line).toBe(9)
    expect(result.findings.find((finding) => finding.rule === 'VG-JS-003')?.line).toBe(2)
    expect(result.findings.every((finding) => finding.file === 'vibeguard-vulnerable-shop/server.js')).toBe(true)
    expect(result.findings.every((finding) => finding.scanId === result.scanId)).toBe(true)
  })

  it('does not flag corrected authorization, trusted pricing, or explicit CORS', () => {
    const corrected = [
      "const cors = require('cors')",
      "app.use(cors({ origin: ['https://shop.example'] }))",
      "app.get('/api/orders/:id', requireAuth, async (req, res) => {",
      '  const order = orders.find(item => item.id === req.params.id && item.ownerId === req.user.id)',
      '  return res.json(order)',
      '})',
      "app.post('/api/checkout', async (req, res) => {",
      '  const { productId, quantity } = req.body',
      '  const product = await catalog.findById(productId)',
      '  const total = Number(quantity) * Number(product.price)',
      '  return res.json({ total })',
      '})',
    ].join('\n')
    const result = scanTextFiles([{ path: 'vibeguard-vulnerable-shop/server.js', content: corrected }], 'corrected express fixture')
    expect(result.findings.some((finding) => finding.rule === 'VG-JS-001')).toBe(false)
    expect(result.findings.some((finding) => finding.rule === 'VG-JS-002')).toBe(false)
    expect(result.findings.some((finding) => finding.rule === 'VG-JS-003')).toBe(false)
  })

  it('does not label an unrelated identifier lookup as the order authorization rule', () => {
    const result = scanTextFiles([{ path: 'server.js', content: 'const user = users.find(item => item.id === req.params.id)' }], 'unrelated lookup')
    expect(result.findings.some((finding) => finding.rule === 'VG-JS-001')).toBe(false)
  })

  it('discovers nested JavaScript files from the uploaded ZIP', async () => {
    const zip = new JSZip()
    zip.file('vibeguard-vulnerable-shop/server.js', vulnerableExpressSource)
    const bytes = await zip.generateAsync({ type: 'uint8array' })
    const files = await readZip(new File([bytes.buffer as ArrayBuffer], 'vulnerable-shop.zip', { type: 'application/zip' }))
    expect(files).toEqual([{ path: 'vibeguard-vulnerable-shop/server.js', content: vulnerableExpressSource }])
  })

  it('flags an ownership-free query and does not flag the corrected query', () => {
    const vulnerable = scanTextFiles([{ path: 'api/orders.ts', content: vulnerableFixture }], 'vulnerable')
    const corrected = scanTextFiles([{ path: 'api/orders.ts', content: fixedFixture }], 'corrected')
    expect(vulnerable.findings.some((item) => item.rule === 'AUTHZ-001')).toBe(true)
    expect(corrected.findings.some((item) => item.rule === 'AUTHZ-001')).toBe(false)
  })

  it('redacts secret-like evidence', () => {
    const secret = 'const apiKey = "sk_live_1234567890abcdef"'
    const result = scanTextFiles([{ path: 'src/config.ts', content: secret }], 'secret fixture')
    expect(result.findings.length).toBeGreaterThan(0)
    expect(result.findings[0].evidence).not.toContain('sk_live_1234567890abcdef')
    expect(result.findings[0].evidence).toContain('••••')
  })

  it('runs the real ZIP source workflow and returns redacted evidence', async () => {
    const zip = new JSZip()
    zip.file('src/config.ts', 'const apiKey = "sk_live_1234567890abcdef"')
    const bytes = await zip.generateAsync({ type: 'uint8array' })
    const fixture = new File([bytes.buffer as ArrayBuffer], 'source.zip', { type: 'application/zip' })
    const result = await scanZip(fixture, 'source fixture', { dependencies: false })
    expect(result.fileCount).toBe(1)
    expect(result.findings.some((finding) => finding.evidence.includes('••••'))).toBe(true)
    expect(result.findings.some((finding) => finding.evidence.includes('sk_live_1234567890abcdef'))).toBe(false)
  })

  it('rejects non-ZIP uploads before attempting to scan them', async () => {
    const invalid = new File(['not a zip'], 'project.tar', { type: 'application/x-tar' })
    await expect(readZip(invalid)).rejects.toThrow('Upload a .zip archive')
  })

  it('rejects malformed ZIP content honestly', async () => {
    const malformed = new File(['not a real archive'], 'project.zip', { type: 'application/zip' })
    await expect(readZip(malformed)).rejects.toThrow('archive could not be opened')
    await expect(scanZip(malformed, 'failed fixture')).rejects.toThrow('archive could not be opened')
  })

  it('rejects archive traversal using the original ZIP entry name', async () => {
    const zip = new JSZip()
    zip.file('../escape.js', 'const apiKey = "sk_live_1234567890abcdef"')
    const bytes = await zip.generateAsync({ type: 'uint8array' })
    const unsafe = new File([bytes.buffer as ArrayBuffer], 'project.zip', { type: 'application/zip' })
    await expect(readZip(unsafe)).rejects.toThrow('Unsafe archive path rejected')
  })

  it('matches dependency advisories against exact lockfile versions', async () => {
    const zip = new JSZip()
    zip.file('package-lock.json', JSON.stringify({ lockfileVersion: 3, packages: { '': { name: 'fixture' }, 'node_modules/lodash': { version: '4.17.20' } } }))
    const bytes = await zip.generateAsync({ type: 'uint8array' })
    const fixture = new File([bytes.buffer as ArrayBuffer], 'dependencies.zip', { type: 'application/zip' })
    const discovered = discoverDependencies([{ path: 'package-lock.json', content: JSON.stringify({ packages: { 'node_modules/lodash': { version: '4.17.20' } } }) }])
    expect(discovered).toEqual([expect.objectContaining({ packageName: 'lodash', ecosystem: 'npm', version: '4.17.20', manifest: 'package-lock.json', versionSource: 'resolved', resolvedVersion: '4.17.20' })])
    const result = await scanZip(fixture, 'dependency fixture', {}, async () => ({
      advisories: new Map([
        ['npm:lodash:4.17.20', [{ id: 'GHSA-35jh-r3h4-6jhm', packageName: 'lodash', ecosystem: 'npm', version: '4.17.20', severity: 'High', summary: 'Prototype pollution advisory for the test fixture.', affectedRange: '< 4.17.21', fixedVersion: '4.17.21', sourceUrl: 'https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm', source: 'OSV.dev', checkedAt: new Date().toISOString() }]],
      ]),
      source: 'OSV.dev',
      checkedAt: new Date().toISOString(),
      responseCount: 1,
    }))
    expect(result.findings.some((finding) => finding.advisoryId === 'GHSA-35jh-r3h4-6jhm')).toBe(true)
    expect(result.coverage.find((check) => check.id === 'dependencies')?.status).toBe('passed')
    expect(result.coverage.find((check) => check.id === 'dependencies')?.matchedCount).toBe(1)
  })

  it('reports an unavailable advisory service instead of claiming clean dependencies', async () => {
    const zip = new JSZip()
    zip.file('package-lock.json', JSON.stringify({ lockfileVersion: 3, packages: { 'node_modules/lodash': { version: '4.17.20' } } }))
    const bytes = await zip.generateAsync({ type: 'uint8array' })
    const fixture = new File([bytes.buffer as ArrayBuffer], 'dependencies.zip', { type: 'application/zip' })
    const result = await scanZip(fixture, 'unavailable fixture', {}, async () => { throw new Error('service unavailable') })
    expect(result.coverage.find((check) => check.id === 'dependencies')?.status).toBe('unavailable')
    expect(result.findings.some((finding) => finding.category === 'Dependencies')).toBe(false)
  })

  it('shows extracted dependency entries and keeps the deployed Node runtime unknown without engines evidence', async () => {
    const zip = new JSZip()
    zip.file('vibeguard-vulnerable-shop/package.json', JSON.stringify({ dependencies: { express: '4.18.2', cors: '2.8.5' } }))
    zip.file('vibeguard-vulnerable-shop/package-lock.json', JSON.stringify({ lockfileVersion: 3, packages: {
      '': { name: 'vibeguard-vulnerable-shop' },
      'node_modules/express': { version: '4.18.2' },
      'node_modules/cors': { version: '2.8.5' },
    } }))
    const bytes = await zip.generateAsync({ type: 'uint8array' })
    const result = await scanZip(new File([bytes.buffer as ArrayBuffer], 'runtime-fixture.zip', { type: 'application/zip' }), 'runtime fixture', {}, async () => ({ advisories: new Map([['npm:express:4.18.2', []], ['npm:cors:2.8.5', []]]), source: 'OSV.dev', checkedAt: new Date().toISOString(), responseCount: 2 }))
    expect(result.dependencies.map((dependency) => `${dependency.ecosystem}:${dependency.packageName}@${dependency.version}`)).toEqual(expect.arrayContaining(['npm:express@4.18.2', 'npm:cors@2.8.5']))
    expect(result.dependencies.find((dependency) => dependency.packageName === 'express')).toMatchObject({ versionSource: 'resolved', declaredVersion: '4.18.2', resolvedVersion: '4.18.2' })
    expect(result.runtimes.some((runtime) => runtime.component === 'Express' && runtime.evidence === 'resolved' && runtime.version === '4.18.2')).toBe(true)
    expect(result.runtimes.some((runtime) => runtime.component === 'Node.js' && runtime.evidence === 'unknown' && runtime.version === undefined && runtime.details?.includes('no engines.node'))).toBe(true)
    expect(result.coverage.find((check) => check.id === 'dependencies')).toMatchObject({ status: 'passed', matchedCount: 0 })
    expect(result.coverage.find((check) => check.id === 'dependencies')?.details).toContain('0 matching advisory records')
  })

  it('preserves scoped names and parses supported pnpm and Yarn lockfile entries', () => {
    const dependencies = discoverDependencies([
      { path: 'package-lock.json', content: JSON.stringify({ packages: { 'node_modules/@acme/shop-sdk': { version: '1.2.3' } } }) },
      { path: 'pnpm-lock.yaml', content: 'packages:\n  /express@4.18.2:\n    resolution: {integrity: sha512-test}\n' },
      { path: 'yarn.lock', content: 'cors@^2.8.5:\n  version "2.8.5"\n' },
    ])
    expect(dependencies).toEqual(expect.arrayContaining([
      expect.objectContaining({ packageName: '@acme/shop-sdk', ecosystem: 'npm', version: '1.2.3' }),
      expect.objectContaining({ packageName: 'express', ecosystem: 'npm', version: '4.18.2' }),
      expect.objectContaining({ packageName: 'cors', ecosystem: 'npm', version: '2.8.5' }),
    ]))
  })
})

describe('OSV advisory response handling', () => {
  const advisory = {
    id: 'GHSA-35jh-r3h4-6jhm',
    summary: 'Prototype pollution advisory for lodash.',
    database_specific: { severity: 'HIGH' },
    affected: [{ package: { ecosystem: 'npm', name: 'lodash' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.17.21' }] }] }],
    references: [{ type: 'ADVISORY', url: 'https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm' }],
  }

  it('sends an exact ecosystem/name/version query and parses the full advisory response', async () => {
    const fetchMock = vi.fn().mockImplementation(async () => Response.json({ vulns: [advisory] }))
    vi.stubGlobal('fetch', fetchMock)
    try {
      const result = await lookupOsvAdvisories([{ packageName: 'lodash', ecosystem: 'npm', version: '4.17.20', manifest: 'package-lock.json' }])
      const requestBody = JSON.parse(fetchMock.mock.calls[0][1].body as string)
      expect(fetchMock.mock.calls[0][0]).toBe('https://api.osv.dev/v1/query')
      expect(requestBody).toEqual({ package: { name: 'lodash', ecosystem: 'npm' }, version: '4.17.20' })
      expect(result.source).toBe('OSV.dev')
      expect(result.responseCount).toBe(1)
      expect(result.advisories.get('npm:lodash:4.17.20')).toHaveLength(1)
      expect(result.advisories.get('npm:lodash:4.17.20')?.[0].fixedVersion).toBe('4.17.21')
    } finally {
      vi.unstubAllGlobals()
    }
  })

  it('uses the OSV zero-match response for a fixed exact version', async () => {
    const fetchMock = vi.fn().mockImplementation(async () => Response.json({}))
    vi.stubGlobal('fetch', fetchMock)
    try {
      const result = await lookupOsvAdvisories([{ packageName: 'lodash', ecosystem: 'npm', version: '4.17.21', manifest: 'package-lock.json' }])
      expect(result.advisories.get('npm:lodash:4.17.21')).toEqual([])
    } finally {
      vi.unstubAllGlobals()
    }
  })

  it('preserves HTTP errors as unavailable coverage instead of clean results', async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: false, status: 429, json: async () => ({}) })
    vi.stubGlobal('fetch', fetchMock)
    try {
      const result = await scanDependencies([{ path: 'package-lock.json', content: JSON.stringify({ packages: { 'node_modules/lodash': { version: '4.17.20' } } }) }])
      expect(result.coverage.status).toBe('unavailable')
      expect(result.coverage.error).toContain('429')
      expect(result.coverage.source).toBe('OSV.dev')
    } finally {
      vi.unstubAllGlobals()
    }
  })
})

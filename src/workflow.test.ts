import JSZip from 'jszip'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { ApiRequestError, runUrlScan } from './api'
import { scanZip } from './scanner'
import { actualRecords, associateSource, dependencyLabel, dependencyOutcome, executeScan, pendingScan, scanRecord, upsertScan } from './workflow'
import { createHtmlReport, createReportPayload } from './report'
import type { ScanSummary } from './types'

afterEach(() => vi.unstubAllGlobals())

async function archive(files: Record<string, string>) {
  const zip = new JSZip()
  Object.entries(files).forEach(([path, content]) => zip.file(path, content))
  return new File([await zip.generateAsync({ type: 'arraybuffer', compression: 'DEFLATE' })], 'project.zip')
}

const completeUrl = (scanId: string): ScanSummary => ({ ...pendingScan('https://site.example', 'Website URL'), scanId, scanStatus: 'Completed with limitations', coverage: [
  { id: 'headers', label: 'Headers', status: 'passed', details: 'Controlled response inspected' },
  { id: 'dependencies', label: 'Dependency advisory matching', status: 'unavailable', details: 'Dependency advisory check unavailable: exact dependency versions could not be established.' },
] })

describe('shared scan lifecycle and record isolation', () => {
  it('runs the real ZIP pipeline through lifecycle, Patch Intelligence and both reports', async () => {
    const file = await archive({
      'shop/api/server.js': [
        'app.use(cors({ origin: true }))',
        'app.get("/orders/:id", (req, res) => {',
        ' const order = orders.find(o => o.id === req.params.id)',
        ' return res.json(order)',
        '})',
        'app.post("/checkout", (req, res) => {',
        ' const { quantity, unitPrice } = req.body',
        ' const total = Number(quantity) * Number(unitPrice)',
        ' return res.json({ total })',
        '})',
      ].join('\n'),
      'shop/package.json': JSON.stringify({ dependencies: { express: '^4.18.0' }, engines: { node: '>=20' } }),
      'shop/package-lock.json': JSON.stringify({ lockfileVersion: 3, packages: { '': { dependencies: { express: '^4.18.0' } }, 'node_modules/express': { version: '4.18.2' } } }),
    })
    const states: ScanSummary[] = [], phases: string[] = []
    const zipService: typeof scanZip = (file, target, checks, _lookup, options) => scanZip(file, target, checks, async () => ({ advisories: new Map([['npm:express:4.18.2', []]]), source: 'Controlled OSV response', checkedAt: new Date().toISOString(), responseCount: 1 }), options)
    const { scan } = await executeScan({ type: 'Source upload', target: 'shop', file, authorized: true }, (snapshot, phase) => { states.push(snapshot); phases.push(phase) }, { zip: zipService, url: runUrlScan })
    expect(states[0].scanStatus).toBe('Pending')
    expect(states[1].scanStatus).toBe('Running')
    expect(scan.scanStatus).toBe('Completed')
    expect(new Set(states.map((state) => state.scanId)).size).toBe(1)
    expect(states.filter((state) => ['Pending', 'Running'].includes(state.scanStatus)).every((state) => !state.findings.length)).toBe(true)
    expect(phases.some((phase) => /OSV/.test(phase))).toBe(true)
    expect(scan.findings.filter((finding) => finding.rule.startsWith('VG-JS-'))).toHaveLength(3)
    expect(scan.findings.find((finding) => finding.rule === 'VG-JS-001')).toMatchObject({ file: 'shop/api/server.js', line: 3, scanId: scan.scanId })
    expect(scan.findings.find((finding) => finding.rule === 'VG-JS-002')).toMatchObject({ line: 8 })
    expect(scan.findings.find((finding) => finding.rule === 'VG-JS-003')).toMatchObject({ line: 1 })
    expect(dependencyLabel(scan.dependencies[0])).toBe('Lookup completed with zero matching advisories')
    expect(createReportPayload(scan).scanId).toBe(scan.scanId)
    expect(createReportPayload(scan).findings).toEqual(scan.findings)
    expect(createHtmlReport(scan)).toContain('shop/api/server.js:3')
    expect(createHtmlReport(scan)).toContain('resolved 4.18.2')
  })

  it('clears previous evidence immediately even when the next attempt fails', async () => {
    const old = completeUrl('old-scan')
    let active = old
    const file = new File(['not a ZIP'], 'broken.zip')
    const result = await executeScan({ type: 'Source upload', target: 'broken', file, authorized: true }, (scan) => { active = scan })
    expect(active).toBe(result.scan)
    expect(active.scanId).not.toBe(old.scanId)
    expect(active.scanStatus).toBe('Failed')
    expect(active.errorCode).toBe('INVALID_ARCHIVE')
    expect(active.findings).toEqual([])
    expect(active.dependencies).toEqual([])
    expect(active.verificationHistory).toEqual([])
    expect(createHtmlReport(active)).toContain('No completed findings are available')
    expect(dependencyOutcome(active)).toContain('not completed')
  })

  it('does not execute either scanner without explicit authorization', async () => {
    const zip = vi.fn(scanZip), url = vi.fn(runUrlScan)
    const result = await executeScan({ type: 'Website URL', target: 'https://site.example', authorized: false }, () => {}, { zip, url })
    expect(result.scan).toMatchObject({ scanStatus: 'Failed', errorCode: 'AUTHORIZATION_REQUIRED' })
    expect(zip).not.toHaveBeenCalled()
    expect(url).not.toHaveBeenCalled()
  })

  it.each(['not a URL', 'http://site.example', 'https://user:pass@site.example', 'https://site.example:80'])('identifies invalid URL input without an authorization error: %s', async (target) => {
    const url = vi.fn(runUrlScan)
    const { scan } = await executeScan({ type: 'Website URL', target, authorized: true }, () => {}, { zip: scanZip, url })
    expect(scan.errorCode).toBe('INVALID_INPUT')
    expect(url).not.toHaveBeenCalled()
  })

  it('retains actual URL results and a failed-save notice without claiming saved history', async () => {
    const url = vi.fn(async (_target: string, authorized: boolean, scanId: string) => {
      expect(authorized).toBe(true)
      return { scan: completeUrl(scanId), saved: false, persistenceError: 'Storage unavailable' }
    })
    const outcome = await executeScan({ type: 'Website URL', target: 'https://site.example', authorized: true }, () => {}, { zip: scanZip, url })
    expect(outcome).toMatchObject({ saved: false, persistenceError: 'Storage unavailable', scan: { scanStatus: 'Completed with limitations', dependencies: [] } })
    expect(dependencyOutcome(outcome.scan)).toBe('Dependency advisory check unavailable: exact dependency versions could not be established.')
    const html = createHtmlReport(outcome.scan)
    expect(html).toContain('Website URL')
    expect(html).not.toContain('Source upload scan')
    expect(html).not.toContain('No arbitrary remote application was contacted')
  })

  it.each(['UNSAFE_TARGET', 'EXTERNAL_UNAVAILABLE', 'EXECUTION_FAILED', 'SCANNING_DISABLED'])('keeps a server %s failure distinct from authorization', async (code) => {
    const url = vi.fn(async () => { throw new ApiRequestError('Specific failure', code) })
    const outcome = await executeScan({ type: 'Website URL', target: 'https://site.example', authorized: true }, () => {}, { zip: scanZip, url })
    expect(outcome.scan).toMatchObject({ scanStatus: 'Failed', errorCode: code, findings: [] })
  })

  it('rejects stale IDs and success without completed supported checks', async () => {
    for (const invalid of ['id', 'coverage']) {
      const url = async (_target: string, _authorized: boolean, scanId: string) => ({ scan: invalid === 'id' ? completeUrl('stale') : { ...completeUrl(scanId), coverage: [] }, saved: false })
      const { scan } = await executeScan({ type: 'Website URL', target: 'https://site.example', authorized: true }, () => {}, { zip: scanZip, url })
      expect(scan.scanStatus).toBe('Failed')
      expect(scan.findings).toEqual([])
    }
  })

  it('keeps demo rows out of actual dashboard records and updates a single matching scan', () => {
    const first = completeUrl('one'), second = completeUrl('two'), demo = { ...completeUrl('demo'), isDemo: true }
    const rows = actualRecords(upsertScan([first, second, demo], { ...first, scanStatus: 'Failed' }))
    expect(rows).toHaveLength(2)
    expect(scanRecord(rows[0])).toMatchObject({ id: 'one', type: 'Website URL', status: 'Failed' })
  })

  it('associates ZIP evidence only after consent and never copies its inventory into URL results', () => {
    const url = completeUrl('url')
    const source = { ...pendingScan('shop'), scanStatus: 'Completed' as const }
    expect(() => associateSource(url, source, false)).toThrow(/confirmation/)
    const linked = associateSource(url, source, true)
    expect(linked.sourceAssociation?.scanId).toBe(source.scanId)
    expect(linked.dependencies).toEqual([])
    expect(linked.coverage).toEqual(url.coverage)
    expect(createReportPayload(linked).sourceAssociation).toEqual(linked.sourceAssociation)
    expect(source.sourceAssociation).toBeUndefined()
  })
})

describe('API connection failures', () => {
  it('reports an unreachable API as unavailable, not unauthorized', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new TypeError('fetch failed')))
    await expect(runUrlScan('https://site.example', true, 'current')).rejects.toMatchObject({ code: 'EXTERNAL_UNAVAILABLE' })
  })
  it('sends the actual authorization value and correlation ID', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({ scan: completeUrl('current'), saved: false })))
    vi.stubGlobal('fetch', fetchMock)
    await runUrlScan('https://site.example', false, 'current')
    expect(JSON.parse(fetchMock.mock.calls[0][1].body)).toEqual({ target: 'https://site.example', authorized: false, scanId: 'current' })
  })
})

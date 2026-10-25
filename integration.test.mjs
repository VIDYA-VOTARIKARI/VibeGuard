import test from 'node:test'
import assert from 'node:assert/strict'
import https from 'node:https'
import { promises as fs } from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import JSZip from 'jszip'
import { createServer } from 'vite'
import { __testing as apiTesting } from './server.mjs'
import { __testing as securityTesting, isForbiddenIp } from './server-security.mjs'
import { key, cert } from './server-test-tls-fixture.mjs'

// Full-stack tests use the real frontend workflow modules, Vite API proxy,
// Node API, bounded HTTPS transport and temporary persistent storage.
// They are not browser-click tests. Only DNS/dialing and OSV responses are
// controlled fixtures, never enabled by HTTP inputs or production settings.
test('ZIP and authorized URL results survive the complete proxy/API/report/history workflow', { timeout: 30_000 }, async (t) => {
  const dataDir = await fs.mkdtemp(path.join(os.tmpdir(), 'vibeguard-integration-'))
  const servers = []
  let vite
  const nativeFetch = globalThis.fetch
  t.after(async () => {
    globalThis.fetch = nativeFetch
    await vite?.close()
    for (const server of servers.reverse()) { server.closeAllConnections(); await new Promise((resolve) => server.close(resolve)) }
    await fs.rm(dataDir, { recursive: true, force: true })
  })
  async function listen(server) {
    servers.push(server)
    await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve) })
    return server.address().port
  }
  let networkRequests = 0
  const targetPort = await listen(https.createServer({ key, cert }, (request, response) => {
    networkRequests++
    assert.equal(request.method, 'GET')
    if (request.url === '/start') { response.writeHead(302, { location: '/final' }); response.end(); return }
    response.writeHead(200, { 'content-type': 'text/html', 'x-content-type-options': 'nosniff', 'server': 'Controlled test technology', 'set-cookie': 'session=private-test-cookie-value; Path=/' })
    response.end('<html><body>Controlled authorized fixture</body></html>')
  }))
  const scanner = securityTesting.createScanner({
    lookup: async () => [{ address: '8.8.8.8', family: 4 }],
    request(options, callback) {
      assert.equal(options.rejectUnauthorized, true)
      return https.request({ ...options, hostname: 'test-dial.invalid', port: targetPort, ca: cert,
        lookup(_hostname, settings, done) {
          options.lookup(options.hostname, settings, (error, address, family) => {
            assert.ifError(error)
            const pinned = Array.isArray(address) ? address[0].address : address
            assert.equal(isForbiddenIp(pinned), false)
            done(null, '127.0.0.1', 4)
          })
        },
      }, callback)
    },
  })
  const apiPort = await listen(apiTesting.createApiServer({ dataDir, scanner: scanner.safeFetch }))
  vite = await createServer({ configFile: false, logLevel: 'error', server: { host: '127.0.0.1', port: 0, proxy: { '/api': `http://127.0.0.1:${apiPort}` } } })
  await vite.listen()
  const base = `http://127.0.0.1:${vite.httpServer.address().port}`
  assert.equal((await nativeFetch(base)).status, 200)
  assert.equal((await nativeFetch(`${base}/api/health`)).status, 200)
  const workflow = await vite.ssrLoadModule('/src/workflow.ts')
  const api = await vite.ssrLoadModule('/src/api.ts')
  const reports = await vite.ssrLoadModule('/src/report.ts')
  const sourceScanner = await vite.ssrLoadModule('/src/scanner.ts')
  let cookie = ''
  globalThis.fetch = async (input, init) => {
    const url = typeof input === 'string' && input.startsWith('/api/') ? `${base}${input}` : String(input)
    // No unintended external service is contacted by this integration test.
    assert.ok(url.startsWith(`${base}/api/`), `Unexpected test request: ${url}`)
    const response = await nativeFetch(url, { ...init, headers: { ...init?.headers, ...(cookie ? { cookie } : {}) } })
    const session = response.headers.get('set-cookie')
    if (session) cookie = session.split(';')[0]
    return response
  }
  const zip = new JSZip()
  zip.file('shop/api/server.js', [
    'app.use(cors({ origin: true }))',
    'app.get("/orders/:id", (req, res) => {',
    ' const order = orders.find(o => o.id === req.params.id)',
    ' return res.json(order)',
    '})',
    'app.post("/checkout", (req, res) => {',
    ' const { quantity, unitPrice } = req.body',
    ' return res.json({ total: Number(quantity) * Number(unitPrice) })',
    '})',
  ].join('\n'))
  zip.file('shop/package.json', JSON.stringify({ dependencies: { 'fixture-package': '1.2.3' } }))
  const file = new File([await zip.generateAsync({ type: 'arraybuffer', compression: 'DEFLATE' })], 'shop.zip')
  const zipService = (file, target, checks, _lookup, options) => sourceScanner.scanZip(file, target, checks,
    async () => ({ advisories: new Map([['npm:fixture-package:1.2.3', []]]), responseCount: 1, source: 'Controlled OSV response', checkedAt: new Date().toISOString() }), options)
  const events = []
  const source = await workflow.executeScan({ type: 'Source upload', target: 'shop', file, authorized: true }, (scan) => events.push(scan.scanStatus), { zip: zipService, url: api.runUrlScan })
  assert.equal(source.saved, false)
  assert.equal(source.scan.findings.filter((finding) => finding.rule.startsWith('VG-JS-')).length, 3)
  assert.deepEqual([...new Set(events)], ['Pending', 'Running', 'Completed with limitations'])
  assert.equal(source.scan.dependencies[0].lookupStatus, 'no-match')
  assert.equal(reports.createReportPayload(source.scan).findings.length, source.scan.findings.length)
  assert.match(reports.createHtmlReport(source.scan), /shop\/api\/server.js:3/)

  await api.signUp('owner@example.test', 'correct horse battery fixture')
  // Explicit test consent/import step: creating an account saved nothing.
  assert.equal((await api.listSavedScans()).scans.length, 0)
  await api.saveScan(source.scan)
  const rejected = await workflow.executeScan({ type: 'Website URL', target: 'https://scan.fixture.test/start', authorized: false }, () => {})
  assert.equal(rejected.scan.errorCode, 'AUTHORIZATION_REQUIRED')
  assert.equal(networkRequests, 0)
  const website = await workflow.executeScan({ type: 'Website URL', target: 'https://scan.fixture.test/start', authorized: true }, () => {})
  assert.equal(website.scan.scanStatus, 'Completed with limitations')
  assert.equal(website.saved, true)
  assert.equal(networkRequests, 2)
  assert.notEqual(website.scan.scanId, source.scan.scanId)
  assert.equal(website.scan.dependencies.length, 0)
  assert.equal(website.scan.findings.some((finding) => finding.rule.startsWith('VG-JS-')), false)
  assert.ok(website.scan.findings.every((finding) => finding.scanId === website.scan.scanId))
  const associated = workflow.associateSource(website.scan, source.scan, true)
  await api.saveScan(associated)
  const history = (await api.listSavedScans()).scans
  assert.equal(history.length, 2)
  assert.equal(history.find((scan) => scan.scanId === website.scan.scanId).sourceAssociation.scanId, source.scan.scanId)
  const html = reports.createHtmlReport(associated)
  assert.match(html, /Website URL/)
  assert.match(html, /certificate chain/)
  assert.match(html, /exact dependency versions could not be established/)
  assert.equal(html.includes('private-test-cookie-value'), false)
  await api.signOut()
  await api.signUp('other@example.test', 'another correct fixture password')
  assert.equal((await api.listSavedScans()).scans.length, 0)
  const denied = await globalThis.fetch(`/api/scans/${source.scan.scanId}`)
  assert.equal(denied.status, 404)
  await api.signOut()
  await api.signIn('owner@example.test', 'correct horse battery fixture')
  assert.equal((await api.listSavedScans()).scans.length, 2)
})

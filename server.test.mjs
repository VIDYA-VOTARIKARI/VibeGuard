import test from 'node:test'
import assert from 'node:assert/strict'
import http from 'node:http'
import https from 'node:https'
import net from 'node:net'
import dgram from 'node:dgram'
import { Resolver } from 'node:dns/promises'
import { promises as fs } from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { setTimeout as delay } from 'node:timers/promises'
import { performance } from 'node:perf_hooks'
import { buildUrlScan, validateTarget, isForbiddenIp, __testing as apiTesting } from './server.mjs'
import { __testing as securityTesting, ApiError } from './server-security.mjs'
import { createStore, safeScanPayload } from './server-store.mjs'
import { key, cert } from './server-test-tls-fixture.mjs'

const { createScanner, publicDns } = securityTesting
const { createApiServer, DEPENDENCY_LIMITATION } = apiTesting
const origin = 'https://scan.fixture.test'
const publicAnswers = [{ address: '8.8.8.8', family: 4 }, { address: '2606:4700:4700::1111', family: 6 }]
const password = 'correct horse battery staple'
const fetched = { redirects: [], response: { status: 200, headers: {}, body: '' } }

async function listen(t, server) {
  const sockets = new Set()
  server.on('connection', (socket) => { sockets.add(socket); socket.on('close', () => sockets.delete(socket)) })
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve) })
  t.after(async () => {
    for (const socket of sockets) socket.destroy()
    if (server.listening) await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()))
  })
  return server.address().port
}

async function temporary(t) {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'vibeguard-server-test-'))
  t.after(() => fs.rm(directory, { recursive: true, force: true }))
  return directory
}

async function startApi(t, options = {}) {
  const dataDir = options.dataDir ?? await temporary(t)
  const server = createApiServer({ dataDir, ...options })
  const port = await listen(t, server)
  return {
    server, dataDir,
    async api(pathname, { body, headers = {}, method = body === undefined ? 'GET' : 'POST' } = {}) {
      const response = await fetch(`http://127.0.0.1:${port}${pathname}`, {
        method, headers: { 'content-type': 'application/json', ...headers },
        body: body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(body),
        signal: AbortSignal.timeout(5000),
      })
      return { response, body: await response.json() }
    },
  }
}

async function signup(api, email = 'first@example.com') {
  const result = await api('/api/auth/signup', { body: { email, password } })
  assert.equal(result.response.status, 201, JSON.stringify(result.body))
  return { cookie: result.response.headers.get('set-cookie').split(';', 1)[0], user: result.body.user, response: result.response }
}

function scanRecord(scanId = 'VG-OWNER-1', overrides = {}) {
  return { scanId, target: 'owned-project', findings: [], scans: [], verificationHistory: [], coverage: [], dependencies: [], runtimes: [], scanTypes: ['source'], fileCount: 1, checkedAt: '2026-10-25T10:00:00.000Z', isDemo: false, scanStatus: 'Completed', scanType: 'Source upload', ...overrides }
}

async function transportFixture(t, handler = (_req, res) => res.end('fixture')) {
  const received = []
  const server = https.createServer({ key, cert }, (req, res) => {
    received.push({ method: req.method, path: req.url, headers: req.headers, servername: req.socket.servername })
    handler(req, res)
  })
  const port = await listen(t, server)
  function transport({ trusted = true, onOptions = () => {}, destinationPort = port } = {}) {
    return (options, callback) => {
      onOptions(options)
      assert.equal(options.protocol, 'https:')
      assert.equal(options.port, 443)
      assert.equal(options.agent, false)
      assert.equal(options.rejectUnauthorized, true)
      assert.equal(options.autoSelectFamily, false)
      assert.ok(Array.isArray(options.ca) && !options.ca.includes(cert))
      return https.request({
        ...options, hostname: 'fixture-dial.invalid', port: destinationPort, family: 4,
        ...(trusted ? { ca: cert } : {}),
        // This in-process seam alone maps a previously validated public address
        // to a local test server. It never alters policy or disables TLS checks.
        lookup: (_host, settings, callback) => options.lookup(options.hostname, settings, (error, address, family) => {
          assert.ifError(error)
          const pinned = Array.isArray(address) ? address[0] : { address, family }
          assert.equal(isForbiddenIp(pinned.address), false)
          callback(null, '127.0.0.1', 4)
        }),
      }, callback)
    }
  }
  function scanner(options = {}) {
    return createScanner({ lookup: async () => publicAnswers, request: transport(), ...options })
  }
  return { server, port, received, scanner, transport }
}

test('conservative IPv4 classification covers special-purpose range boundaries', () => {
  const blocked = ['0.0.0.0', '0.255.255.255', '10.0.0.0', '10.255.255.255', '100.64.0.0', '100.127.255.255', '127.255.255.255', '169.254.0.0', '169.254.255.255', '172.16.0.0', '172.31.255.255', '192.0.0.9', '192.0.0.170', '192.0.2.255', '192.31.196.1', '192.52.193.1', '192.88.99.2', '192.168.255.255', '192.175.48.1', '198.18.0.0', '198.19.255.255', '198.51.100.1', '203.0.113.255', '224.0.0.0', '239.255.255.255', '240.0.0.0', '255.255.255.255']
  for (const address of blocked) assert.equal(isForbiddenIp(address), true, address)
  for (const address of ['1.1.1.1', '8.8.8.8', '100.63.255.255', '100.128.0.0', '172.15.255.255', '172.32.0.0', '192.0.1.1', '198.20.0.0', '198.51.101.1', '203.0.114.1', '223.255.255.254']) assert.equal(isForbiddenIp(address), false, address)
})

test('HTTP error pages remain limited observations, with explicit TLS and non-success coverage', () => {
  const scan = buildUrlScan(origin, { url: `${origin}/blocked?token=must-not-appear`, redirects: [], response: { status: 403, headers: {}, body: '' } })
  assert.equal(scan.scanStatus, 'Completed with limitations')
  assert.equal(scan.coverage.find((check) => check.id === 'url-availability').status, 'failed')
  assert.equal(scan.coverage.find((check) => check.id === 'tls').status, 'passed')
  assert.match(scan.limitations.join(' '), /non-success/)
  assert.equal(JSON.stringify(scan).includes('must-not-appear'), false)
})

test('IPv6 classification covers expanded, mixed, mapped, translation and reserved encodings', () => {
  const blocked = ['::', '0:0:0:0:0:0:0:0', '::1', '0000:0000:0000:0000:0000:0000:0000:0001', '[::1]', '::127.0.0.1', '::ffff:127.0.0.1', '0:0:0:0:0:ffff:7f00:1', '::ffff:8.8.8.8', '::ffff:0:127.0.0.1', '64:ff9b::7f00:1', '64:ff9b:1::a00:1', '100::1', '100:0:0:1::1', '2001::1', '2001:1::1', '2001:2::1', '2001:10::1', '2001:20::1', '2001:30::1', '2001:1ff::1', '2001:db8::1', '2002:7f00:1::1', '2620:4f:8000::1', '3fff::1', '3ffe::1', '4000::1', '5f00::1', 'fc00::1', 'FDFF::1', 'fe80::1', 'fe90::1', 'febf::1', 'fec0::1', 'ff02::1', 'fe80::1%eth0', '2001:4860::5efe:127.0.0.1', '2001:4860::200:5efe:7f00:1']
  for (const address of blocked) assert.equal(isForbiddenIp(address), true, address)
  for (const address of ['2001:4860:4860::8888', '2606:4700:4700::1111', '2001:04860::1'.replace('04860', '4860'), '2404:6800:4001::1', '2a00:1450:4001::1', '2c00::1', '[2001:4860::8888]']) assert.equal(isForbiddenIp(address), false, address)
  for (const address of ['', 'garbage', '1.2.3', '999.1.1.1', '1.2.3.4/path', '2001::1::2', '2001:4860::1%eth0', null, 123]) assert.equal(isForbiddenIp(address), true, String(address))
})

test('WHATWG URL normalization cannot hide restricted IP encodings', () => {
  for (const host of ['127.1', '2130706433', '0x7f000001', '0177.0.0.1', '0x7f.0.0.1', '%31%32%37.0.0.1', '127.0.0.1.', '[::ffff:7f00:1]', '[0:0:0:0:0:0:0:1]', '[::ffff:192.168.1.1]']) {
    assert.throws(() => validateTarget(`https://${host}/`), { code: 'UNSAFE_TARGET' }, host)
  }
})

test('URL validation rejects invalid types, credentials, schemes, ports and ambiguous authorities', () => {
  for (const raw of [undefined, null, {}, 8, '', 'not a url', '/relative', '//example.com', 'http://example.com', 'ftp://example.com', 'file:///etc/passwd', 'https:example.com', 'https:///example.com', 'https://user:pass@example.com', 'https://@example.com', 'https://example.com:80', 'https://example.com:8443', 'https://example.com:0', 'https://example.com:65536', 'https://example.com:', 'https://example.com\n', 'https://example.com\\@evil.test', 'https://example..com', 'https://-bad.example', 'https://example.com/' + 'a'.repeat(4096)]) {
    assert.throws(() => validateTarget(raw), { code: 'INVALID_INPUT' }, String(raw))
  }
  for (const host of ['localhost', 'api.localhost', 'api.local', 'service.internal', 'router.home.arpa', 'host.intranet', 'host.corp', 'hidden.onion']) assert.throws(() => validateTarget(`https://${host}`), { code: 'UNSAFE_TARGET' }, host)
  assert.equal(validateTarget('HTTPS://EXAMPLE.COM.:443/a?b=c#fragment').href, 'https://example.com/a?b=c')
  assert.equal(validateTarget('https://[2001:4860:4860::8888]:443').hostname, '[2001:4860:4860::8888]')
})

test('DNS validation rejects any unsafe/malformed answer before a request', async () => {
  for (const answers of [[], [{ address: '127.0.0.1', family: 4 }], [...publicAnswers, { address: '::1', family: 6 }], [{ address: '8.8.8.8', family: 6 }], [{ address: 'garbage', family: 4 }], [{ address: '2001:db8::1', family: 6 }], [null]]) {
    const scanner = createScanner({ lookup: async () => answers, request: () => assert.fail('unsafe transport executed') })
    await assert.rejects(scanner.safeFetch(origin), { code: answers.length ? 'UNSAFE_TARGET' : 'EXTERNAL_UNAVAILABLE' })
  }
})

test('DNS errors are sanitized and a stalled resolver is cancelled on its deadline', async () => {
  const failing = createScanner({ lookup: async () => { throw new Error('private DNS details C:\\secrets') } })
  await assert.rejects(failing.safeFetch(origin), (error) => error.code === 'EXTERNAL_UNAVAILABLE' && !error.message.includes('secrets'))
  let signal
  const stalled = createScanner({ lookup: async (_host, incoming) => { signal = incoming; return new Promise(() => {}) }, limits: { dnsMs: 40, totalMs: 1000 } })
  const started = performance.now()
  await assert.rejects(stalled.safeFetch(origin), { code: 'EXTERNAL_UNAVAILABLE', status: 504 })
  assert.ok(signal.aborted)
  assert.ok(performance.now() - started < 900)
})

test('native resolver queries both families with absolute names and fails on a partial DNS error', async () => {
  const names = []
  let cancelled = 0
  const resolver = {
    async resolve4(host) { names.push(host); return ['8.8.8.8'] },
    async resolve6(host) { names.push(host); throw Object.assign(new Error('SERVFAIL'), { code: 'ESERVFAIL' }) },
    cancel() { cancelled += 1 },
  }
  const scanner = createScanner({ lookup: (host, signal) => publicDns(host, signal, resolver) })
  await assert.rejects(scanner.safeFetch(origin), { code: 'EXTERNAL_UNAVAILABLE' })
  assert.deepEqual(names, ['scan.fixture.test.', 'scan.fixture.test.'])
  assert.equal(cancelled, 1)
  resolver.resolve6 = async () => { throw Object.assign(new Error(), { code: 'ENODATA' }) }
  assert.deepEqual(await scanner.resolveSafe('scan.fixture.test'), [{ address: '8.8.8.8', family: 4 }])
  resolver.resolve4 = async () => { throw Object.assign(new Error(), { code: 'ENOTFOUND' }) }
  await assert.rejects(scanner.resolveSafe('scan.fixture.test'), { code: 'EXTERNAL_UNAVAILABLE' })
})

test('actual c-ares DNS requests against a controlled silent UDP server are cancelled', async (t) => {
  const udp = dgram.createSocket('udp4')
  let queries = 0
  udp.on('message', () => { queries += 1 })
  await new Promise((resolve) => udp.bind(0, '127.0.0.1', resolve))
  t.after(() => new Promise((resolve) => udp.close(resolve)))
  const resolver = new Resolver({ timeout: 2000, tries: 1 })
  resolver.setServers([`127.0.0.1:${udp.address().port}`])
  const scanner = createScanner({ lookup: (host, signal) => publicDns(host, signal, resolver), limits: { dnsMs: 80, totalMs: 1000 } })
  await assert.rejects(scanner.safeFetch(origin), { code: 'EXTERNAL_UNAVAILABLE', status: 504 })
  assert.equal(queries, 2)
})

test('actual TLS request pins a validated address and preserves hostname, SNI, method and path', async (t) => {
  const fixture = await transportFixture(t)
  let dnsCalls = 0
  let optionsSeen
  const scanner = fixture.scanner({
    lookup: async () => { dnsCalls += 1; return dnsCalls === 1 ? publicAnswers : [{ address: '127.0.0.1', family: 4 }] },
    request: fixture.transport({ onOptions(options) { optionsSeen = options } }),
  })
  const result = await scanner.safeFetch(`${origin}/a?b=c#fragment`)
  assert.equal(result.response.body, 'fixture')
  assert.equal(dnsCalls, 1)
  assert.deepEqual(fixture.received.map(({ method, path, headers, servername }) => [method, path, headers.host, servername]), [['GET', '/a?b=c', 'scan.fixture.test', 'scan.fixture.test']])
  optionsSeen.lookup('anything.invalid', { all: true }, (error, addresses) => { assert.ifError(error); assert.deepEqual(addresses, [publicAnswers[0]]) })
  assert.equal(fixture.received[0].headers['accept-encoding'], 'identity')
  for (const name of ['cookie', 'authorization', 'proxy-authorization', 'referer', 'x-forwarded-for']) assert.equal(fixture.received[0].headers[name], undefined)
})

test('IPv6 DNS addresses are validated and pinned without a second name resolution', async (t) => {
  const fixture = await transportFixture(t)
  let seen
  const scanner = fixture.scanner({ lookup: async () => [publicAnswers[1]], request: fixture.transport({ onOptions(options) { seen = options } }) })
  assert.equal((await scanner.safeFetch(origin)).response.status, 200)
  assert.equal(seen.family, 6)
  seen.lookup('ignored', {}, (error, address, family) => { assert.ifError(error); assert.equal(address, publicAnswers[1].address); assert.equal(family, 6) })
})

test('TLS rejects untrusted and wrong-host certificates; only the explicit test trust succeeds', async (t) => {
  const fixture = await transportFixture(t)
  await assert.rejects(fixture.scanner({ request: fixture.transport({ trusted: false }) }).safeFetch(origin), { code: 'EXECUTION_FAILED' })
  assert.equal(fixture.received.length, 0)
  await assert.rejects(fixture.scanner().safeFetch('https://wrong.fixture.test'), { code: 'EXECUTION_FAILED' })
  assert.equal(fixture.received.length, 0)
  assert.equal((await fixture.scanner().safeFetch(origin)).response.status, 200)
  assert.equal(fixture.received.length, 1)
})

test('TLS handshake cannot be downgraded to a local plaintext HTTP server', async (t) => {
  let requests = 0
  const port = await listen(t, http.createServer((_req, res) => { requests += 1; res.end('plaintext') }))
  const fixture = await transportFixture(t)
  await assert.rejects(fixture.scanner({ request: fixture.transport({ destinationPort: port }) }).safeFetch(origin), { code: 'EXECUTION_FAILED' })
  assert.equal(requests, 0)
})

test('HTTPS redirects re-resolve every hop, preserve relative paths and never send cookies', async (t) => {
  const fixture = await transportFixture(t, (req, res) => {
    if (req.url === '/start') { res.writeHead(302, { location: '/second', 'set-cookie': 'session=SECRET; Secure' }); res.end('one') }
    else if (req.url === '/second') { res.writeHead(307, { location: 'https://other.fixture.test/final?q=1' }); res.end('two') }
    else res.end('done')
  })
  const hosts = []
  const scanner = fixture.scanner({ lookup: async (host) => { hosts.push(host); return publicAnswers } })
  const result = await scanner.safeFetch(`${origin}/start`)
  assert.deepEqual(hosts, ['scan.fixture.test', 'scan.fixture.test', 'other.fixture.test'])
  assert.deepEqual(result.redirects, [`${origin}/second`, 'https://other.fixture.test/final?q=1'])
  assert.equal(result.response.body, 'done')
  assert.deepEqual(fixture.received.map((req) => req.headers.host), ['scan.fixture.test', 'scan.fixture.test', 'other.fixture.test'])
  assert.ok(fixture.received.every((req) => !req.headers.cookie && !req.headers.authorization && !req.headers.referer))
})

test('unsafe redirects are rejected before any second transport request', async (t) => {
  const destinations = ['http://scan.fixture.test/plain', 'https://127.1/', 'https://[::ffff:7f00:1]/', 'https://metadata.internal/', 'https://user:pass@scan.fixture.test/', 'https://scan.fixture.test:80/', 'file:///secret', 'https://[malformed', 'https://mixed.fixture.test/']
  for (const location of destinations) {
    await t.test(location, async (t) => {
      const fixture = await transportFixture(t, (_req, res) => { res.writeHead(302, { location }); res.end() })
      const scanner = fixture.scanner({ lookup: async (host) => host === 'mixed.fixture.test' ? [...publicAnswers, { address: '10.0.0.1', family: 4 }] : publicAnswers })
      await assert.rejects(scanner.safeFetch(origin), { code: 'UNSAFE_TARGET' })
      assert.equal(fixture.received.length, 1)
    })
  }
})

test('same-host redirect rebinding is rejected and redirect loops are bounded', async (t) => {
  const fixture = await transportFixture(t, (_req, res) => { res.writeHead(301, { location: '/again' }); res.end() })
  let calls = 0
  const rebound = fixture.scanner({ lookup: async () => ++calls === 1 ? publicAnswers : [{ address: '169.254.169.254', family: 4 }] })
  await assert.rejects(rebound.safeFetch(origin), { code: 'UNSAFE_TARGET' })
  assert.equal(fixture.received.length, 1)
  await assert.rejects(fixture.scanner().safeFetch(origin), (error) => error.code === 'EXECUTION_FAILED' && /redirect limit/.test(error.message))
  assert.equal(fixture.received.length, 6) // Initial request plus four allowed redirects.
})

test('response limits cover declared length, streaming bytes, headers, compression and incomplete bodies', async (t) => {
  const handlers = {
    declared: (_req, res) => { res.writeHead(200, { 'content-length': 300_000 }); res.flushHeaders() },
    streaming: (_req, res) => { res.writeHead(200); res.write(Buffer.alloc(150_000)); res.end(Buffer.alloc(150_000)) },
    headers: (_req, res) => { res.setHeader('x-overflow', 'a'.repeat(20_000)); res.end() },
    compression: (_req, res) => { res.setHeader('content-encoding', 'gzip'); res.end('compressed') },
    incomplete: (_req, res) => { res.writeHead(200, { 'content-length': 100 }); res.write('short'); setTimeout(() => res.destroy(), 20) },
  }
  for (const [name, handler] of Object.entries(handlers)) await t.test(name, async (t) => {
    const fixture = await transportFixture(t, handler)
    await assert.rejects(fixture.scanner().safeFetch(origin), { code: 'EXECUTION_FAILED' })
  })
})

test('response byte budget is cumulative across redirect hops and accepts exact boundary', async (t) => {
  const fixture = await transportFixture(t, (req, res) => {
    if (req.url === '/boundary') { res.end(Buffer.alloc(256 * 1024)); return }
    if (req.url === '/') res.writeHead(302, { location: '/end' })
    res.end(Buffer.alloc(150_000))
  })
  const scanner = fixture.scanner()
  assert.equal((await scanner.safeFetch(`${origin}/boundary`)).response.body.length, 256 * 1024)
  await assert.rejects(scanner.safeFetch(origin), { code: 'EXECUTION_FAILED' })
})

test('absolute total deadline bounds stalled headers and a trickle body, then releases capacity', async (t) => {
  for (const mode of ['headers', 'trickle']) await t.test(mode, async (t) => {
    const fixture = await transportFixture(t, (req, res) => {
      if (req.url === '/ok') { res.end('ok'); return }
      if (mode === 'trickle') {
        res.write('start')
        const timer = setInterval(() => res.write('.'), 10)
        res.on('close', () => clearInterval(timer))
      }
    })
    const scanner = fixture.scanner({ limits: { totalMs: 160, concurrency: 1 } })
    const started = performance.now()
    await assert.rejects(scanner.safeFetch(origin), { code: 'EXECUTION_FAILED', status: 504 })
    assert.ok(performance.now() - started < 1000)
    assert.equal((await scanner.safeFetch(`${origin}/ok`)).response.body, 'ok')
  })
})

test('absolute total deadline includes TLS handshake, DNS and the whole redirect chain', async (t) => {
  const silentPort = await listen(t, net.createServer(() => {}))
  const fixture = await transportFixture(t, (_req, res) => {
    const timer = setTimeout(() => { res.writeHead(302, { location: '/again' }); res.end() }, 75)
    res.on('close', () => clearTimeout(timer))
  })
  await assert.rejects(fixture.scanner({ request: fixture.transport({ destinationPort: silentPort }), limits: { totalMs: 100 } }).safeFetch(origin), { status: 504 })
  let cancelled
  const scanner = fixture.scanner({ lookup: async (_host, signal) => { cancelled = signal; return new Promise(() => {}) }, limits: { dnsMs: 2000, totalMs: 80 } })
  await assert.rejects(scanner.safeFetch(origin), { code: 'EXECUTION_FAILED', status: 504 })
  assert.ok(cancelled.aborted)
  const started = performance.now()
  await assert.rejects(fixture.scanner({ limits: { totalMs: 180 } }).safeFetch(origin), { code: 'EXECUTION_FAILED', status: 504 })
  assert.ok(performance.now() - started < 1000)
  assert.ok(fixture.received.length >= 2 && fixture.received.length <= 3)
})

test('concurrency is bounded before DNS or transport and recovers after requests finish', async (t) => {
  const pending = []
  const fixture = await transportFixture(t, (req, res) => req.url === '/ok' ? res.end('ok') : pending.push(res))
  let dnsCalls = 0
  const scanner = fixture.scanner({ lookup: async () => { dnsCalls += 1; return publicAnswers }, limits: { concurrency: 2 } })
  const first = scanner.safeFetch(origin)
  const second = scanner.safeFetch(origin)
  await assert.rejects(scanner.safeFetch(origin), { code: 'EXTERNAL_UNAVAILABLE', status: 503 })
  for (let attempt = 0; pending.length < 2 && attempt < 100; attempt += 1) await delay(10)
  assert.equal(pending.length, 2)
  assert.equal(dnsCalls, 2)
  pending.forEach((res) => res.end('done'))
  await Promise.all([first, second])
  assert.equal((await scanner.safeFetch(`${origin}/ok`)).response.body, 'ok')
})

test('URL reports use crypto UUIDs, unique associated findings, redaction and honest unavailable inventory', () => {
  const observation = { redirects: [], response: { status: 200, body: 'SECRET_BODY', headers: { server: 'example-edge/unknown', 'x-powered-by': 'framework-signal', 'x-content-type-options': 'SECRET_HEADER', 'set-cookie': ['SECRET_NAME=SECRET_VALUE', 'SECRET_NAME=SECOND_VALUE', 'secure=value; Secure; HttpOnly; SameSite=Lax'] } } }
  const scan = buildUrlScan(origin, observation)
  assert.match(scan.scanId, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/)
  assert.notEqual(scan.scanId, buildUrlScan(origin, observation).scanId)
  assert.equal(scan.scanStatus, 'Completed with limitations')
  assert.equal(scan.scanType, 'Website URL')
  assert.equal(new Set(scan.findings.map((finding) => finding.id)).size, scan.findings.length)
  assert.ok(scan.findings.every((finding) => finding.scanId === scan.scanId))
  assert.equal(scan.findings.filter((finding) => finding.rule.startsWith('URL-COOKIE')).length, 6)
  assert.doesNotMatch(JSON.stringify(scan), /SECRET_|SECOND_VALUE/)
  assert.ok(scan.runtimes.every((runtime) => runtime.evidence === 'observed' && runtime.version === undefined))
  assert.match(scan.runtimes[0].details, /example-edge\/unknown/)
  assert.deepEqual(scan.dependencies, [])
  assert.deepEqual(scan.coverage.find((item) => item.id === 'dependencies'), { id: 'dependencies', label: 'Dependency advisory matching', status: 'unavailable', details: DEPENDENCY_LIMITATION, source: 'Website response', requestedCount: 0, matchedCount: 0 })
  assert.ok(scan.limitations.includes('Dependency advisory check unavailable: exact dependency versions could not be established.'))
})

test('HTTP URL API separates explicit authorization, invalid input and unsafe destinations', async (t) => {
  let invoked = 0
  const { api } = await startApi(t, { scanner: async () => { invoked += 1; return fetched } })
  const cases = [
    [{ target: origin }, 403, 'AUTHORIZATION_REQUIRED'],
    [{ target: origin, authorized: 'true' }, 403, 'AUTHORIZATION_REQUIRED'],
    [{ target: null, authorized: true }, 400, 'INVALID_INPUT'],
    [{ target: 'https://127.0.0.1', authorized: true }, 400, 'UNSAFE_TARGET'],
    [{ target: origin, authorized: true, scanId: '../private' }, 400, 'INVALID_INPUT'],
  ]
  for (const [body, status, code] of cases) {
    const result = await api('/api/url-scan', { body })
    assert.equal(result.response.status, status)
    assert.equal(result.body.code, code)
    assert.equal(result.body.scan, undefined)
  }
  assert.equal(invoked, 0)
})

test('HTTP URL API executes real TLS, honors correlation, redacts secrets and reports unsaved anonymous results', async (t) => {
  const fixture = await transportFixture(t, (_req, res) => { res.setHeader('set-cookie', ['id=SECRET', 'id=OTHER_SECRET']); res.end('SECRET_BODY') })
  const { api } = await startApi(t, { scanner: fixture.scanner().safeFetch })
  const result = await api('/api/url-scan', { body: { target: origin, authorized: true, scanId: 'correlation-123' }, headers: { cookie: 'api_secret=SECRET', authorization: 'Bearer SECRET', 'x-forwarded-for': '10.0.0.1' } })
  assert.equal(result.response.status, 200)
  assert.equal(result.body.scan.scanId, 'correlation-123')
  assert.equal(result.body.saved, false)
  assert.ok(result.body.scan.findings.every((finding) => finding.scanId === 'correlation-123'))
  assert.doesNotMatch(JSON.stringify(result.body), /SECRET/)
  assert.equal(fixture.received[0].headers.cookie, undefined)
  assert.equal(fixture.received[0].headers.authorization, undefined)
  const generated = await api('/api/url-scan', { body: { target: origin, authorized: true } })
  assert.match(generated.body.scan.scanId, /^[0-9a-f-]{36}$/)
})

test('HTTP errors distinguish DNS unavailable, execution failure, deadlines and disabled configuration', async (t) => {
  const fixture = await transportFixture(t)
  const cases = [
    [createScanner({ lookup: async () => { throw new Error('DNS private paths') } }).safeFetch, 503, 'EXTERNAL_UNAVAILABLE'],
    [fixture.scanner({ request: fixture.transport({ trusted: false }) }).safeFetch, 502, 'EXECUTION_FAILED'],
    [createScanner({ lookup: () => new Promise(() => {}), limits: { totalMs: 50, dnsMs: 1000 } }).safeFetch, 504, 'EXECUTION_FAILED'],
    [createScanner({ enabled: false }).safeFetch, 503, 'SCANNING_DISABLED'],
    [async () => { throw new Error('C:\\private\\secrets.json') }, 500, 'EXECUTION_FAILED'],
  ]
  for (const [scanner, status, code] of cases) {
    const { api } = await startApi(t, { scanner })
    const result = await api('/api/url-scan', { body: { target: origin, authorized: true } })
    assert.equal(result.response.status, status)
    assert.equal(result.body.code, code)
    assert.doesNotMatch(JSON.stringify(result.body), /private|secrets|\.json/)
  }
})

test('HTTP clients and environment cannot enable HTTP or supply destination/TLS bypasses', async (t) => {
  const previous = process.env.VIBEGUARD_ALLOW_HTTP_URL_SCAN
  process.env.VIBEGUARD_ALLOW_HTTP_URL_SCAN = 'true'
  t.after(() => previous === undefined ? delete process.env.VIBEGUARD_ALLOW_HTTP_URL_SCAN : process.env.VIBEGUARD_ALLOW_HTTP_URL_SCAN = previous)
  const { api } = await startApi(t)
  const malicious = { authorized: true, allowHttp: true, allowPrivate: true, rejectUnauthorized: false, lookup: '127.0.0.1', request: {}, scanner: {}, testMode: true }
  for (const [target, code] of [['http://example.com', 'INVALID_INPUT'], ['https://127.0.0.1', 'UNSAFE_TARGET']]) {
    const result = await api('/api/url-scan', { body: { ...malicious, target } })
    assert.equal(result.response.status, 400)
    assert.equal(result.body.code, code)
  }
  assert.throws(() => validateTarget('http://example.com'), { code: 'INVALID_INPUT' })
})

test('malformed JSON/cookies and hostile Host headers do not leak internal errors', async (t) => {
  const { api } = await startApi(t)
  for (const body of ['{', 'null', '[]', 'true', JSON.stringify({ target: 'x'.repeat(33_000) })]) {
    const result = await api('/api/url-scan', { body })
    assert.equal(result.response.status, 400)
    assert.equal(result.body.code, 'INVALID_INPUT')
  }
  const me = await api('/api/auth/me', { headers: { cookie: 'vg_session=%ZZ', host: 'invalid:bad:host' } })
  assert.deepEqual(me.body, { user: null })
  const health = await api('/api/health')
  assert.deepEqual(health.body, { ok: true })
})

test('spoofed forwarded inputs cannot evade URL rate limits', async (t) => {
  const { api } = await startApi(t, { scanner: async () => fetched })
  for (let index = 0; index < 6; index += 1) {
    const result = await api('/api/url-scan', { body: { target: origin, authorized: true }, headers: { 'x-forwarded-for': `8.8.8.${index}`, forwarded: `for=1.1.1.${index}` } })
    assert.equal(result.response.status, index < 5 ? 200 : 429)
    if (index === 5) assert.equal(result.response.headers.get('retry-after'), '60')
  }
})

test('history sorts multiple checkedAt records, isolates owners and preserves source associations', async (t) => {
  const { api } = await startApi(t)
  const first = await signup(api)
  const second = await signup(api, 'second@example.com')
  for (const [id, timestamp] of [['old', '2026-01-01T00:00:00.000Z'], ['new', '2026-10-25T00:00:00.000Z'], ['middle', '2026-05-01T00:00:00.000Z']]) {
    const scan = scanRecord(id, { checkedAt: timestamp, sourceAssociation: { scanId: 'source-123', target: 'source.zip', confirmedAt: timestamp }, limitations: ['external inventory incomplete'] })
    const saved = await api('/api/scans', { body: { scan }, headers: { cookie: first.cookie } })
    assert.equal(saved.response.status, 201)
    assert.equal(saved.body.saved, true)
  }
  const list = await api('/api/scans', { headers: { cookie: first.cookie } })
  assert.deepEqual(list.body.scans.map((scan) => scan.scanId), ['new', 'middle', 'old'])
  assert.equal(list.body.scans[0].sourceAssociation.scanId, 'source-123')
  assert.deepEqual((await api('/api/scans', { headers: { cookie: second.cookie } })).body.scans, [])
  assert.equal((await api('/api/scans/new', { headers: { cookie: second.cookie } })).response.status, 404)
  await api('/api/scans', { headers: { cookie: second.cookie }, body: { scan: scanRecord('new', { target: 'second-owner', ownerId: first.user.id }) } })
  assert.equal((await api('/api/scans/new', { headers: { cookie: first.cookie } })).body.scan.target, 'owned-project')
  assert.equal((await api('/api/scans/new', { headers: { cookie: second.cookie } })).body.scan.target, 'second-owner')
  assert.equal((await api('/api/scans')).response.status, 401)
})

test('saved report shapes validate lifecycle statuses, nested data, association dates and finding identity', () => {
  for (const scanStatus of ['Pending', 'Running', 'Completed', 'Completed with limitations', 'Failed']) assert.equal(safeScanPayload(scanRecord('valid', { scanStatus }), 'owner').scanStatus, scanStatus)
  const invalid = [
    { scanStatus: 'Success' }, { scanType: 'remote' }, { checkedAt: 'yesterday' }, { fileCount: -1 }, { isDemo: 'false' }, { limitations: [3] },
    { sourceAssociation: { scanId: 'x', target: 'source', confirmedAt: 'invalid' } },
    { coverage: [{}] }, { runtimes: [{}] }, { dependencies: [{}] }, { verificationHistory: [{}] }, { scans: [{}] }, { findings: [{}] },
    { scanId: '../../escape' }, { errorCode: {} }, { sourceFiles: [null] },
  ]
  for (const overrides of invalid) assert.throws(() => safeScanPayload(scanRecord('bad', overrides), 'owner'), { code: 'INVALID_INPUT' })
  const scan = buildUrlScan(origin, fetched, 'valid')
  const associated = safeScanPayload(scan, 'owner')
  assert.ok(associated.findings.every((finding) => finding.scanId === 'valid'))
  assert.throws(() => safeScanPayload({ ...scan, findings: [...scan.findings, scan.findings[0]] }, 'owner'), { code: 'INVALID_INPUT' })
  assert.throws(() => safeScanPayload({ ...scan, findings: [{ ...scan.findings[0], scanId: 'other' }] }, 'owner'), { code: 'INVALID_INPUT' })
  assert.throws(() => safeScanPayload(scanRecord('huge', { limitations: Array(400).fill('é'.repeat(90_000)) }), 'owner'), { code: 'INVALID_INPUT' })
})

test('accepts scan records between the former 2 MB and new 32 MB storage limit', () => {
  const large = safeScanPayload(scanRecord('large', { limitations: Array(100).fill('x'.repeat(90_000)) }), 'owner')
  assert.equal(large.scanId, 'large')
  assert.ok(Buffer.byteLength(JSON.stringify(large)) > 2 * 1024 * 1024)
})

test('history rejects malformed report shapes through HTTP and accepts current result contracts', async (t) => {
  const { api } = await startApi(t)
  const { cookie } = await signup(api)
  for (const scan of [null, {}, scanRecord('bad', { sourceAssociation: { scanId: 'source' } })]) {
    const result = await api('/api/scans', { body: { scan }, headers: { cookie } })
    assert.equal(result.response.status, 400)
    assert.equal(result.body.code, 'INVALID_INPUT')
  }
  const scan = buildUrlScan(origin, fetched)
  scan.sourceAssociation = { scanId: 'source-123', target: 'source.zip', confirmedAt: new Date().toISOString() }
  const saved = await api('/api/scans', { body: { scan }, headers: { cookie } })
  assert.equal(saved.response.status, 201)
  assert.deepEqual(saved.body.scan.sourceAssociation, scan.sourceAssociation)
})

test('concurrent history writes are atomic, isolated and durable after an API restart', async (t) => {
  const first = await startApi(t)
  const { cookie } = await signup(first.api)
  const saves = await Promise.all(Array.from({ length: 16 }, (_, index) => first.api('/api/scans', { body: { scan: scanRecord(`parallel-${index}`) }, headers: { cookie } })))
  assert.ok(saves.every((result) => result.response.status === 201))
  const updates = await Promise.all(Array.from({ length: 5 }, (_, index) => first.api('/api/scans', { body: { scan: scanRecord('same-id', { target: `update-${index}` }) }, headers: { cookie } })))
  assert.ok(updates.every((result) => result.response.status === 201))
  assert.equal((await first.api('/api/scans', { headers: { cookie } })).body.scans.length, 17)
  assert.deepEqual((await fs.readdir(first.dataDir)).sort(), ['store.json'])
  await new Promise((resolve) => first.server.close(resolve))
  const restarted = await startApi(t, { dataDir: first.dataDir })
  const login = await restarted.api('/api/auth/login', { body: { email: 'first@example.com', password } })
  assert.equal(login.response.status, 200)
  const newCookie = login.response.headers.get('set-cookie').split(';', 1)[0]
  const history = await restarted.api('/api/scans', { headers: { cookie: newCookie } })
  assert.equal(history.body.scans.length, 17)
  assert.equal(new Set(history.body.scans.map((scan) => scan.scanId)).size, 17)
})

test('storage read snapshots cannot mutate records and corrupt/error stores are never silently reset', async (t) => {
  for (const content of ['{', '{}', '{"users":[],"scans":[{}]}']) {
    const directory = await temporary(t)
    await fs.writeFile(path.join(directory, 'store.json'), content)
    const store = createStore(directory)
    await assert.rejects(store.read(), { code: 'EXTERNAL_UNAVAILABLE' })
    await assert.rejects(store.update((next) => next.users.push({})), { code: 'EXTERNAL_UNAVAILABLE' })
    assert.equal(await fs.readFile(path.join(directory, 'store.json'), 'utf8'), content)
  }
  const directory = await temporary(t)
  const denied = createStore(directory, { ...fs, async readFile() { throw Object.assign(new Error('EACCES C:\\private'), { code: 'EACCES' }) } })
  await assert.rejects(denied.read(), (error) => error.code === 'EXTERNAL_UNAVAILABLE' && !error.message.includes('private'))
  const fresh = createStore(directory)
  const snapshot = await fresh.read()
  snapshot.users.push('external mutation')
  assert.deepEqual(await fresh.read(), { users: [], scans: [] })
})

test('corrupt stores propagate sanitized HTTP failures without overwriting data', async (t) => {
  const directory = await temporary(t)
  await fs.writeFile(path.join(directory, 'store.json'), '{broken')
  const { api } = await startApi(t, { dataDir: directory })
  const result = await api('/api/auth/signup', { body: { email: 'first@example.com', password } })
  assert.equal(result.response.status, 503)
  assert.equal(result.body.code, 'EXTERNAL_UNAVAILABLE')
  assert.doesNotMatch(JSON.stringify(result.body), /store\.json|broken|vibeguard-server-test/)
  assert.equal(await fs.readFile(path.join(directory, 'store.json'), 'utf8'), '{broken')
})

test('successful URL scans survive failed atomic saves, roll back memory and persist on retry/restart', async (t) => {
  const directory = await temporary(t)
  let failWrites = false
  const io = { ...fs, async rename(...args) { if (failWrites) throw new Error('C:\\private\\disk error'); return fs.rename(...args) } }
  const storage = createStore(directory, io)
  const fixture = await transportFixture(t)
  const first = await startApi(t, { dataDir: directory, storage, scanner: fixture.scanner().safeFetch })
  const { cookie } = await signup(first.api)
  failWrites = true
  const result = await first.api('/api/url-scan', { body: { target: origin, authorized: true, scanId: 'save-failure' }, headers: { cookie } })
  assert.equal(result.response.status, 200)
  assert.equal(result.body.saved, false)
  assert.equal(result.body.scan.scanStatus, 'Completed with limitations')
  assert.ok(result.body.scan.findings.length)
  assert.match(result.body.persistenceError, /could not be saved/)
  assert.doesNotMatch(JSON.stringify(result.body), /disk error|private/)
  assert.equal((await storage.read()).scans.length, 0)
  assert.equal((await createStore(directory).read()).scans.length, 0)
  assert.deepEqual(await fs.readdir(directory), ['store.json'])
  const failedSave = await first.api('/api/scans', { body: { scan: result.body.scan }, headers: { cookie } })
  assert.equal(failedSave.response.status, 503)
  failWrites = false
  const retry = await first.api('/api/scans', { body: { scan: result.body.scan }, headers: { cookie } })
  assert.equal(retry.response.status, 201)
  assert.equal(retry.body.saved, true)
  assert.equal((await createStore(directory).read()).scans[0].scanId, 'save-failure')
  const next = await first.api('/api/url-scan', { body: { target: origin, authorized: true, scanId: 'saved-directly' }, headers: { cookie } })
  assert.equal(next.body.saved, true)
  assert.equal((await createStore(directory).read()).scans.length, 2)
})

test('auth endpoints retain signup/login/me/logout, secure production cookies and concurrent uniqueness', async (t) => {
  const { api } = await startApi(t, { production: true })
  const signups = await Promise.all([1, 2].map(() => api('/api/auth/signup', { body: { email: 'same@example.com', password } })))
  assert.deepEqual(signups.map((result) => result.response.status).sort(), [201, 409])
  const success = signups.find((result) => result.response.status === 201)
  assert.match(success.response.headers.get('set-cookie'), /; Secure/)
  assert.match(success.response.headers.get('set-cookie'), /HttpOnly; SameSite=Lax/)
  const cookie = success.response.headers.get('set-cookie').split(';', 1)[0]
  assert.equal((await api('/api/auth/me', { headers: { cookie } })).body.user.email, 'same@example.com')
  const badLogin = await api('/api/auth/login', { body: { email: 'same@example.com', password: 'wrong password here' } })
  assert.equal(badLogin.response.status, 401)
  const goodLogin = await api('/api/auth/login', { body: { email: 'SAME@example.com', password } })
  assert.equal(goodLogin.response.status, 200)
  const logout = await api('/api/auth/logout', { method: 'POST', headers: { cookie } })
  assert.match(logout.response.headers.get('set-cookie'), /Max-Age=0; Secure/)
  assert.equal((await api('/api/auth/me', { headers: { cookie } })).body.user, null)
  assert.equal((await api('/api/scans', { headers: { cookie } })).response.status, 401)
})

test('DNS deadline remains absolute when event-loop work delays the timer callback', async () => {
  const scanner = createScanner({
    lookup: () => {
      const until = performance.now() + 40
      while (performance.now() < until) { /* Model a delayed event-loop callback. */ }
      return publicAnswers
    },
    limits: { dnsMs: 15, totalMs: 1000 },
  })
  await assert.rejects(scanner.resolveSafe('scan.fixture.test'), { code: 'EXTERNAL_UNAVAILABLE', status: 504 })
})

test('environment TLS/proxy settings cannot weaken explicit transport security', async (t) => {
  let proxyRequests = 0
  const proxyPort = await listen(t, http.createServer((_req, res) => { proxyRequests += 1; res.end('proxy') }))
  const settings = { NODE_TLS_REJECT_UNAUTHORIZED: '0', NODE_USE_ENV_PROXY: '1', HTTPS_PROXY: `http://127.0.0.1:${proxyPort}`, HTTP_PROXY: `http://127.0.0.1:${proxyPort}`, ALL_PROXY: `http://127.0.0.1:${proxyPort}` }
  const previous = Object.fromEntries(Object.keys(settings).map((name) => [name, process.env[name]]))
  Object.assign(process.env, settings)
  t.after(() => {
    for (const [name, value] of Object.entries(previous)) value === undefined ? delete process.env[name] : process.env[name] = value
  })
  const fixture = await transportFixture(t)
  await assert.rejects(fixture.scanner({ request: fixture.transport({ trusted: false }) }).safeFetch(origin), { code: 'EXECUTION_FAILED' })
  assert.equal(fixture.received.length, 0)
  assert.equal((await fixture.scanner().safeFetch(origin)).response.status, 200)
  assert.equal(proxyRequests, 0)
})

test('production disable configuration returns SCANNING_DISABLED through its actual HTTP server', async (t) => {
  const dataDir = await temporary(t)
  const settings = { VIBEGUARD_DISABLE_URL_SCAN: 'true', VIBEGUARD_DATA_DIR: dataDir }
  const previous = Object.fromEntries(Object.keys(settings).map((name) => [name, process.env[name]]))
  Object.assign(process.env, settings)
  t.after(() => {
    for (const [name, value] of Object.entries(previous)) value === undefined ? delete process.env[name] : process.env[name] = value
  })
  const { server } = await import('./server.mjs?disabled-test')
  const port = await listen(t, server)
  const response = await fetch(`http://127.0.0.1:${port}/api/url-scan`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ target: origin, authorized: true, enabled: true }) })
  assert.equal(response.status, 503)
  const body = await response.json()
  assert.equal(body.code, 'SCANNING_DISABLED')
  assert.match(body.error, /configuration/)
  assert.deepEqual(await fs.readdir(dataDir), [])
})

test('protocol upgrades and redirects without a Location fail safely', async (t) => {
  for (const status of [101, 302]) await t.test(String(status), async (t) => {
    const fixture = await transportFixture(t, (_req, res) => {
      res.writeHead(status, status === 101 ? { connection: 'Upgrade', upgrade: 'test' } : {})
      res.end()
    })
    await assert.rejects(fixture.scanner().safeFetch(origin), { code: 'EXECUTION_FAILED' })
  })
})

test('literal public IPs skip DNS and still require a certificate for that IP', async (t) => {
  const fixture = await transportFixture(t)
  let seen
  const scanner = fixture.scanner({ lookup: () => assert.fail('literal IP invoked DNS'), request: fixture.transport({ onOptions(options) { seen = options } }) })
  await assert.rejects(scanner.safeFetch('https://8.8.8.8'), { code: 'EXECUTION_FAILED' })
  assert.equal(seen.servername, '')
  assert.equal(seen.headers.host, '8.8.8.8')
  assert.equal(fixture.received.length, 0)
})

test('failed partial file writes leave committed history intact and do not poison the write queue', async (t) => {
  const dataDir = await temporary(t)
  let failWrites = false
  const storage = createStore(dataDir, {
    ...fs,
    async open(...args) {
      const handle = await fs.open(...args)
      return {
        async writeFile(contents, encoding) {
          if (!failWrites) return handle.writeFile(contents, encoding)
          await handle.writeFile(contents.slice(0, 25), encoding)
          throw new Error('disk full at C:\\private\\store.json')
        },
        sync: () => handle.sync(), close: () => handle.close(),
      }
    },
  })
  const { api } = await startApi(t, { dataDir, storage })
  const { cookie } = await signup(api)
  const before = await fs.readFile(path.join(dataDir, 'store.json'), 'utf8')
  failWrites = true
  const result = await api('/api/scans', { headers: { cookie }, body: { scan: scanRecord('lost-write') } })
  assert.equal(result.response.status, 503)
  assert.equal(await fs.readFile(path.join(dataDir, 'store.json'), 'utf8'), before)
  assert.deepEqual(await fs.readdir(dataDir), ['store.json'])
  assert.equal((await storage.read()).scans.length, 0)
  failWrites = false
  assert.equal((await api('/api/scans', { headers: { cookie }, body: { scan: scanRecord('good-write') } })).response.status, 201)
  assert.deepEqual((await createStore(dataDir).read()).scans.map((scan) => scan.scanId), ['good-write'])
})

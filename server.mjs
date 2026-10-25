import http from 'node:http'
import path from 'node:path'
import crypto from 'node:crypto'
import { fileURLToPath } from 'node:url'
import { ApiError, isForbiddenIp, resolveSafe, safeFetch, validateTarget } from './server-security.mjs'
import { createStore, safeScanPayload, validScanId } from './server-store.mjs'

const ROOT = path.dirname(fileURLToPath(import.meta.url))
const SESSION_TTL_MS = 24 * 60 * 60 * 1000
const DEPENDENCY_LIMITATION = 'Dependency advisory check unavailable: exact dependency versions could not be established.'
const PERSISTENCE_ERROR = 'The scan completed, but its results could not be saved. Please try saving again.'

function json(res, status, payload, headers = {}) {
  if (res.destroyed || res.writableEnded) return
  const body = JSON.stringify(payload)
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', ...headers })
  res.end(body)
}

function parseCookies(request) {
  const cookies = Object.create(null)
  for (const part of (request.headers.cookie ?? '').split(';')) {
    const equals = part.indexOf('=')
    if (equals < 0) continue
    try { cookies[decodeURIComponent(part.slice(0, equals).trim())] = decodeURIComponent(part.slice(equals + 1)) } catch { /* Ignore malformed cookies. */ }
  }
  return cookies
}

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  return new Promise((resolve, reject) => crypto.scrypt(password, salt, 64, (error, derived) => error ? reject(error) : resolve({ salt, hash: derived.toString('hex') })))
}

function safeEqual(left, right) {
  const a = Buffer.from(left, 'hex')
  const b = Buffer.from(right, 'hex')
  return a.length === b.length && crypto.timingSafeEqual(a, b)
}

async function readJson(request, maxBytes = 3 * 1024 * 1024) {
  const invalid = () => new ApiError('INVALID_INPUT', 'The request must contain a valid JSON object within the size limit.')
  if (Number(request.headers['content-length'] ?? 0) > maxBytes) throw invalid()
  const chunks = []
  let total = 0
  try {
    for await (const chunk of request) {
      total += chunk.length
      if (total > maxBytes) throw invalid()
      chunks.push(chunk)
    }
    const body = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}')
    if (!body || typeof body !== 'object' || Array.isArray(body)) throw invalid()
    return body
  } catch { throw invalid() }
}

function headerFinding(scanId, url, title, rule, severity, evidence, remediation) {
  return {
    id: `${rule}-${crypto.randomUUID()}`, scanId, title, rule,
    category: 'Website headers', severity, confidence: 'Informational', status: 'Unresolved',
    file: 'HTTP response headers', evidence,
    whyItMatters: 'This is an externally observable signal only. It does not prove that the application is exploitable or secure.',
    remediation,
    prompt: `Review the observable website signal for ${url}. Validate the intended security policy in the deployment configuration, then retest the authorized URL.`,
    verificationMethod: 'Repeat the same read-only HTTPS response check after the deployment change.',
  }
}

export function buildUrlScan(target, fetched, scanId = crypto.randomUUID()) {
  const headers = fetched.response.headers
  const findings = []
  const add = (...args) => findings.push(headerFinding(scanId, target, ...args))
  if (!headers['strict-transport-security']) add('HSTS header was not observed', 'URL-HEADER-001', 'Low', 'strict-transport-security: not present', 'Configure HSTS only after confirming that every intended subdomain is HTTPS-capable.')
  if (headers['x-content-type-options']?.toLowerCase() !== 'nosniff') add('X-Content-Type-Options was not set to nosniff', 'URL-HEADER-002', 'Low', 'x-content-type-options: nosniff not observed', 'Set X-Content-Type-Options: nosniff where compatible with the application.')
  if (!headers['content-security-policy']) add('Content-Security-Policy was not observed', 'URL-HEADER-003', 'Informational', 'content-security-policy: not present', 'Review whether a restrictive Content-Security-Policy can be deployed without breaking the application.')
  const cookies = Array.isArray(headers['set-cookie']) ? headers['set-cookie'] : headers['set-cookie'] ? [headers['set-cookie']] : []
  cookies.forEach((cookie, index) => {
    // Even cookie names can contain sensitive identifiers. Never return names,
    // values, raw headers or response bodies from the observer.
    const name = `Cookie ${index + 1}`
    const attributes = cookie.split(';').slice(1).map((part) => part.trim().toLowerCase())
    if (!attributes.includes('secure')) add(`${name} lacks Secure`, 'URL-COOKIE-001', 'Medium', `${name}=<redacted>; Secure: not observed`, 'Set Secure on cookies that should only travel over HTTPS.')
    if (!attributes.includes('httponly')) add(`${name} lacks HttpOnly`, 'URL-COOKIE-002', 'Medium', `${name}=<redacted>; HttpOnly: not observed`, 'Set HttpOnly for cookies that do not need client-side JavaScript access.')
    if (!attributes.some((part) => /^samesite=(strict|lax|none)$/.test(part))) add(`${name} lacks a valid SameSite policy`, 'URL-COOKIE-003', 'Low', `${name}=<redacted>; SameSite: not observed`, 'Set an intentional SameSite policy for the cookie.')
  })
  const runtimes = []
  for (const [header, component] of [['server', 'Server header'], ['x-powered-by', 'X-Powered-By header']]) {
    if (headers[header]) runtimes.push({ component, ecosystem: 'HTTP', sourceFile: 'HTTP response headers', evidence: 'observed', details: `Observed ${header}: ${String(headers[header]).replace(/[\x00-\x1f\x7f]/g, '').slice(0, 256)}. This header may be altered by a proxy and does not establish an exact dependency version.` })
  }
  const successfulHttp = fetched.response.status >= 200 && fetched.response.status < 300
  const finalOrigin = new URL(fetched.url ?? target).origin
  return {
    findings, scans: [], target, scanId, fileCount: 0, checkedAt: new Date().toISOString(),
    scanTypes: ['HTTPS availability', 'TLS certificate validation', 'Redirect behavior', 'Security response headers', 'Observable cookie attributes', 'Observed technology signals'],
    scanType: 'Website URL', isDemo: false,
    coverage: [
      { id: 'url-availability', label: 'HTTPS response status', status: successfulHttp ? 'passed' : 'failed', details: `HTTP ${fetched.response.status} received over validated HTTPS. ${successfulHttp ? 'Successful HTTP response.' : 'Non-success response; observations may describe an error, login, or block page.'}`, source: 'Read-only HTTPS request' },
      { id: 'tls', label: 'TLS certificate validation', status: 'passed', details: 'The TLS connection validated the certificate chain and destination hostname against the configured public trust roots. Revocation status and a full TLS configuration audit were not tested.', source: 'Node TLS handshake' },
      { id: 'redirects', label: 'Redirect behavior', status: 'passed', details: `${fetched.redirects.length} redirect(s) followed and revalidated. Final origin: ${finalOrigin}. Redirect paths and queries are omitted to avoid retaining tokens.`, source: 'Read-only HTTPS request' },
      { id: 'headers', label: 'Security response headers', status: 'passed', details: 'Observable response headers were inspected; missing headers are informational findings, not proof of exploitability.', source: 'Read-only HTTPS request' },
      { id: 'cookies', label: 'Cookie security attributes', status: 'passed', details: `${cookies.length} Set-Cookie header(s) observed. Names and values are redacted.`, source: 'Read-only HTTPS request' },
      { id: 'dependencies', label: 'Dependency advisory matching', status: 'unavailable', details: DEPENDENCY_LIMITATION, source: 'Website response', requestedCount: 0, matchedCount: 0 },
    ],
    runtimes, dependencies: [], verificationHistory: [], scanStatus: 'Completed with limitations',
    limitations: [DEPENDENCY_LIMITATION, 'Read-only website observations do not inspect source code, authenticated behavior, or prove the absence of vulnerabilities.', ...(!successfulHttp ? [`HTTP ${fetched.response.status}: observations are limited to the non-success response, not the complete application.`] : [])],
  }
}

function createApiServer({ dataDir, storage = createStore(dataDir), scanner = safeFetch, production = false } = {}) {
  const sessions = new Map()
  const rateBuckets = new Map()
  function sessionCookie(token, maxAge = SESSION_TTL_MS / 1000) {
    return `vg_session=${encodeURIComponent(token)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${maxAge}${production ? '; Secure' : ''}`
  }
  function rateLimit(request, bucket, limit, windowMs) {
    // Forwarded headers are attacker input unless a proxy is explicitly trusted.
    const key = `${bucket}:${request.socket.remoteAddress ?? 'unknown'}`
    const now = Date.now()
    for (const [entry, value] of rateBuckets) if (value.resetAt <= now) rateBuckets.delete(entry)
    const current = rateBuckets.get(key)
    if (!current) {
      if (rateBuckets.size >= 10_000) return false
      rateBuckets.set(key, { count: 1, resetAt: now + windowMs })
      return true
    }
    if (current.count >= limit) return false
    current.count += 1
    return true
  }
  function getSession(request) {
    const token = parseCookies(request).vg_session
    const now = Date.now()
    for (const [key, session] of sessions) if (session.expiresAt <= now) sessions.delete(key)
    return sessions.get(token)
  }
  function startSession(userId) {
    const token = crypto.randomBytes(32).toString('base64url')
    sessions.set(token, { userId, expiresAt: Date.now() + SESSION_TTL_MS })
    return token
  }
  async function authenticatedUser(request) {
    const session = getSession(request)
    if (!session) return undefined
    const user = (await storage.read()).users.find((entry) => entry.id === session.userId)
    return user ? { id: user.id, email: user.email, createdAt: user.createdAt } : undefined
  }
  function requireUser(user, message) {
    if (!user) throw new ApiError('AUTHORIZATION_REQUIRED', message, 401)
  }
  async function saveScan(scan, ownerId) {
    const safe = safeScanPayload(scan, ownerId)
    await storage.update((store) => {
      const index = store.scans.findIndex((item) => item.scanId === safe.scanId && item.ownerId === ownerId)
      if (index >= 0) store.scans[index] = safe
      else store.scans.push(safe)
    })
    return safe
  }

  async function handle(request, response) {
    if (!rateLimit(request, 'all', 120, 60_000)) return json(response, 429, { error: 'Too many requests. Try again shortly.', code: 'EXTERNAL_UNAVAILABLE' }, { 'retry-after': '60' })
    let url
    try { url = new URL(request.url, 'http://localhost') } catch { throw new ApiError('INVALID_INPUT', 'Invalid request URL.') }
    if (request.method === 'GET' && url.pathname === '/api/health') return json(response, 200, { ok: true })

    if (request.method === 'POST' && url.pathname === '/api/url-scan') {
      const session = getSession(request)
      if (!rateLimit(request, 'url-scan', session ? 20 : 5, 60_000)) return json(response, 429, { error: 'URL scan rate limit reached. Try again later.', code: 'EXTERNAL_UNAVAILABLE' }, { 'retry-after': '60' })
      const body = await readJson(request, 32 * 1024)
      if (body.authorized !== true) throw new ApiError('AUTHORIZATION_REQUIRED', 'Explicit authorization is required before a website scan.', 403)
      if (body.scanId !== undefined && !validScanId(body.scanId)) throw new ApiError('INVALID_INPUT', 'Invalid scan correlation identifier.')
      const scanId = body.scanId ?? crypto.randomUUID()
      const target = validateTarget(body.target).href
      const fetched = await scanner(target)
      const scan = buildUrlScan(target, fetched, scanId)
      if (!session) return json(response, 200, { scan, saved: false })
      try {
        const user = await authenticatedUser(request)
        if (!user) return json(response, 200, { scan, saved: false, persistenceError: PERSISTENCE_ERROR })
        await saveScan(scan, user.id)
        return json(response, 200, { scan, saved: true })
      } catch {
        return json(response, 200, { scan, saved: false, persistenceError: PERSISTENCE_ERROR })
      }
    }

    if (request.method === 'POST' && url.pathname === '/api/auth/logout') {
      sessions.delete(parseCookies(request).vg_session)
      return json(response, 200, { ok: true }, { 'set-cookie': sessionCookie('', 0) })
    }
    if (request.method === 'GET' && url.pathname === '/api/auth/me') return json(response, 200, { user: await authenticatedUser(request) ?? null })
    if (request.method === 'POST' && ['/api/auth/signup', '/api/auth/login'].includes(url.pathname)) {
      if (!rateLimit(request, 'auth', 12, 60_000)) return json(response, 429, { error: 'Too many authentication attempts.', code: 'EXTERNAL_UNAVAILABLE' })
      const body = await readJson(request, 32 * 1024)
      const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : ''
      const password = typeof body.password === 'string' ? body.password : ''
      if (email.length > 254 || !/^\S+@\S+\.\S+$/.test(email) || password.length < 10 || password.length > 1024) throw new ApiError('INVALID_INPUT', 'Use a valid email and a password with 10 to 1024 characters.')
      const store = await storage.read()
      if (url.pathname.endsWith('signup')) {
        if (store.users.some((item) => item.email === email)) throw new ApiError('INVALID_INPUT', 'An account with that email already exists.', 409)
        const credentials = await hashPassword(password)
        const user = { id: crypto.randomUUID(), email, passwordHash: credentials.hash, passwordSalt: credentials.salt, createdAt: new Date().toISOString() }
        await storage.update((next) => {
          // Recheck inside the transaction: concurrent signups can race scrypt.
          if (next.users.some((item) => item.email === email)) throw new ApiError('INVALID_INPUT', 'An account with that email already exists.', 409)
          next.users.push(user)
        })
        return json(response, 201, { user: { id: user.id, email, createdAt: user.createdAt } }, { 'set-cookie': sessionCookie(startSession(user.id)) })
      }
      const existing = store.users.find((item) => item.email === email)
      if (!existing || !safeEqual((await hashPassword(password, existing.passwordSalt)).hash, existing.passwordHash)) throw new ApiError('AUTHORIZATION_REQUIRED', 'Invalid email or password.', 401)
      return json(response, 200, { user: { id: existing.id, email, createdAt: existing.createdAt } }, { 'set-cookie': sessionCookie(startSession(existing.id)) })
    }
    const user = await authenticatedUser(request)
    if (request.method === 'GET' && url.pathname === '/api/scans') {
      requireUser(user, 'Sign in to view saved scan history.')
      const store = await storage.read()
      const scans = store.scans.filter((scan) => scan.ownerId === user.id)
        .sort((a, b) => Date.parse(b.checkedAt) - Date.parse(a.checkedAt) || a.scanId.localeCompare(b.scanId))
      return json(response, 200, { scans })
    }
    if (request.method === 'GET' && url.pathname.startsWith('/api/scans/')) {
      requireUser(user, 'Sign in to view saved scans.')
      let id
      try { id = decodeURIComponent(url.pathname.slice('/api/scans/'.length)) } catch { throw new ApiError('INVALID_INPUT', 'Invalid scan identifier.') }
      if (!validScanId(id)) throw new ApiError('INVALID_INPUT', 'Invalid scan identifier.')
      const scan = (await storage.read()).scans.find((item) => item.scanId === id && item.ownerId === user.id)
      return scan ? json(response, 200, { scan }) : json(response, 404, { error: 'Scan not found.', code: 'INVALID_INPUT' })
    }
    if (request.method === 'POST' && url.pathname === '/api/scans') {
      requireUser(user, 'Sign in to save scan history.')
      const body = await readJson(request)
      const scan = await saveScan(body.scan, user.id)
      return json(response, 201, { scan, saved: true })
    }
    return json(response, 404, { error: 'Not found.', code: 'INVALID_INPUT' })
  }

  return http.createServer({ requestTimeout: 15_000, headersTimeout: 10_000, maxHeaderSize: 16 * 1024 }, (request, response) => {
    handle(request, response).catch((error) => {
      const known = error instanceof ApiError
      json(response, known ? error.status : 500, { error: known ? error.message : 'The request could not be completed.', code: known ? error.code : 'EXECUTION_FAILED' })
    })
  })
}

const server = createApiServer({
  dataDir: process.env.VIBEGUARD_DATA_DIR ?? path.join(ROOT, '.vibeguard-data'),
  production: process.env.NODE_ENV === 'production',
  scanner: process.env.VIBEGUARD_DISABLE_URL_SCAN === 'true'
    ? async () => { throw new ApiError('SCANNING_DISABLED', 'Remote URL scanning is disabled by server configuration.', 503) }
    : safeFetch,
})

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const port = Number(process.env.PORT ?? 8787)
  server.listen(port, '127.0.0.1', () => console.log(`VibeGuard API listening on http://127.0.0.1:${port}`))
}

export { isForbiddenIp, resolveSafe, safeFetch, validateTarget, server }
// Internal dependency injection for controlled local tests only; handle() never
// accepts scanner, resolver, transport, storage or TLS configuration from clients.
export const __testing = Object.freeze({ createApiServer, parseCookies, DEPENDENCY_LIMITATION })

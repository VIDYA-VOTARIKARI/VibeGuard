import https from 'node:https'
import { Resolver } from 'node:dns/promises'
import { isIP } from 'node:net'
import { checkServerIdentity, rootCertificates } from 'node:tls'
import { performance } from 'node:perf_hooks'

export class ApiError extends Error {
  constructor(code, message, status = 400) {
    super(message)
    this.code = code
    this.status = status
  }
}

const unsafe = () => new ApiError('UNSAFE_TARGET', 'The target contains a private, reserved, or otherwise restricted destination.')
const execution = (message) => new ApiError('EXECUTION_FAILED', message, 502)
const unavailable = () => new ApiError('EXTERNAL_UNAVAILABLE', 'The target DNS service is unavailable or returned no usable addresses.', 503)
const totalTimeout = () => new ApiError('EXECUTION_FAILED', 'The website scan exceeded its total deadline.', 504)
const defaults = Object.freeze({ totalMs: 15_000, dnsMs: 2_000, maxBytes: 256 * 1024, maxHeaders: 16 * 1024, redirects: 4, concurrency: 4 })

function ipv4Number(address) {
  return address.split('.').reduce((value, part) => (value << 8n) | BigInt(part), 0n)
}

function ipv6Number(address) {
  let value = address.toLowerCase()
  if (value.includes('.')) {
    const colon = value.lastIndexOf(':')
    const v4 = ipv4Number(value.slice(colon + 1))
    value = `${value.slice(0, colon)}:${(v4 >> 16n).toString(16)}:${(v4 & 65535n).toString(16)}`
  }
  const [left, right] = value.split('::')
  const a = left ? left.split(':') : []
  const b = right ? right.split(':') : []
  const words = right === undefined ? a : [...a, ...Array(8 - a.length - b.length).fill('0'), ...b]
  return words.reduce((result, word) => (result << 16n) | BigInt(`0x${word}`), 0n)
}

function ranges(cidrs, bits, parse) {
  return cidrs.map((cidr) => {
    const [address, prefix] = cidr.split('/')
    const shift = BigInt(bits - Number(prefix))
    return { prefix: parse(address) >> shift, shift }
  })
}
const inRanges = (value, entries) => entries.some(({ prefix, shift }) => value >> shift === prefix)

// Conservative snapshot of IANA special-purpose registries and IPv6 RIR
// allocations, reviewed 2026-10-25. Special-purpose exceptions are NOT allowed.
// Sources: iana.org/assignments/iana-ipv4-special-registry/
// iana.org/assignments/iana-ipv6-special-registry/
// iana.org/assignments/ipv6-unicast-address-assignments/
const restrictedV4 = ranges([
  '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8',
  '169.254.0.0/16', '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24',
  '192.31.196.0/24', '192.52.193.0/24', '192.88.99.0/24', '192.168.0.0/16',
  '192.175.48.0/24', '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24',
  '224.0.0.0/3',
], 32, ipv4Number)
const allocatedV6 = ranges([
  '2001:200::/23', '2001:400::/23', '2001:600::/23', '2001:800::/22',
  '2001:c00::/23', '2001:e00::/23', '2001:1200::/23', '2001:1400::/22',
  '2001:1800::/23', '2001:1a00::/23', '2001:1c00::/22', '2001:2000::/19',
  '2001:4000::/23', '2001:4200::/23', '2001:4400::/23', '2001:4600::/23',
  '2001:4800::/23', '2001:4a00::/23', '2001:4c00::/23', '2001:5000::/20',
  '2001:8000::/19', '2001:a000::/20', '2001:b000::/20', '2003::/18',
  '2400::/12', '2410::/12', '2600::/12', '2610::/23', '2620::/23',
  '2630::/12', '2800::/12', '2a00::/12', '2a10::/12', '2c00::/12',
], 128, ipv6Number)
const restrictedV6 = ranges(['2001:db8::/32', '2620:4f:8000::/48'], 128, ipv6Number)

export function isForbiddenIp(address) {
  if (typeof address !== 'string') return true
  const normalized = address.replace(/^\[([^\]]+)\]$/, '$1')
  if (normalized.includes('%')) return true
  const family = isIP(normalized)
  if (family === 4) return inRanges(ipv4Number(normalized), restrictedV4)
  if (family !== 6) return true // Invalid/ambiguous DNS answers fail closed.
  const value = ipv6Number(normalized)
  // Reject ISATAP (RFC 5214), including universal/local interface IDs.
  const interfacePrefix = (value >> 32n) & 0xffffffffn
  return !inRanges(value, allocatedV6) || inRanges(value, restrictedV6)
    || (interfacePrefix & 0xfcffffffn) === 0x00005efen
}

function validateHostname(raw) {
  const hostname = raw.toLowerCase().replace(/^\[([^\]]+)\]$/, '$1').replace(/\.$/, '')
  if (isIP(hostname)) {
    if (isForbiddenIp(hostname)) throw unsafe()
    return hostname
  }
  if (/(?:^|\.)(localhost|local|internal|intranet|lan|home|corp|onion)$/.test(hostname)
    || hostname.endsWith('.arpa')) throw unsafe()
  if (!hostname.includes('.') || hostname.length > 253
    || hostname.split('.').some((label) => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))) {
    throw new ApiError('INVALID_INPUT', 'Enter a valid public website hostname.')
  }
  return hostname
}

export function validateTarget(raw) {
  if (typeof raw !== 'string' || !raw || raw.length > 4096 || /[\s\\\x00-\x1f\x7f]/.test(raw)) {
    throw new ApiError('INVALID_INPUT', 'Enter a valid website URL.')
  }
  let url
  try { url = new URL(raw) } catch { throw new ApiError('INVALID_INPUT', 'Enter a valid website URL.') }
  if (url.protocol !== 'https:' || !/^https:\/\//i.test(raw)) throw new ApiError('INVALID_INPUT', 'Website scans require HTTPS.')
  const authority = raw.slice(raw.indexOf('//') + 2).split(/[/?#]/, 1)[0]
  if (!authority || authority.endsWith(':')) throw new ApiError('INVALID_INPUT', 'Enter a valid website URL and port.')
  if (url.username || url.password || authority.includes('@')) {
    throw new ApiError('INVALID_INPUT', 'Credentials are not allowed in website scan URLs.')
  }
  if (url.port) throw new ApiError('INVALID_INPUT', 'Unexpected ports are not allowed; website scans require port 443.')
  const hostname = validateHostname(url.hostname)
  url.hostname = isIP(hostname) === 6 ? `[${hostname}]` : hostname
  url.hash = ''
  return url
}

// A per-operation resolver can actually cancel DNS work, unlike dns.lookup's
// getaddrinfo worker. Query both families; a failed family is not ignored.
async function publicDns(hostname, signal, resolver = new Resolver({ timeout: defaults.dnsMs, tries: 1 })) {
  const cancel = () => resolver.cancel()
  signal.throwIfAborted()
  signal.addEventListener('abort', cancel, { once: true })
  try {
    const query = async (family) => {
      try {
        const addresses = await resolver[family === 4 ? 'resolve4' : 'resolve6'](`${hostname}.`)
        return addresses.map((address) => ({ address, family }))
      } catch (error) {
        if (['ENODATA', 'ENOTFOUND'].includes(error.code)) return []
        throw error
      }
    }
    return (await Promise.all([query(4), query(6)])).flat()
  } finally {
    resolver.cancel()
    signal.removeEventListener('abort', cancel)
  }
}

function abortable(promise, signal) {
  return new Promise((resolve, reject) => {
    const abort = () => reject(signal.reason)
    if (signal.aborted) { reject(signal.reason); return }
    signal.addEventListener('abort', abort, { once: true })
    Promise.resolve(promise).then(resolve, reject).finally(() => signal.removeEventListener('abort', abort))
  })
}

function createScanner({ lookup = publicDns, request = https.request, limits: overrides = {}, enabled = true } = {}) {
  const limits = { ...defaults, ...overrides }
  let active = 0

  async function resolveSafe(rawHostname, parentSignal) {
    const hostname = validateHostname(rawHostname)
    if (isIP(hostname)) return [{ address: hostname, family: isIP(hostname) }]
    const controller = new AbortController()
    const cancel = () => controller.abort(parentSignal.reason)
    if (parentSignal?.aborted) throw parentSignal.reason
    parentSignal?.addEventListener('abort', cancel, { once: true })
    const deadline = performance.now() + limits.dnsMs
    const expire = () => controller.abort(new ApiError('EXTERNAL_UNAVAILABLE', 'The target DNS lookup timed out.', 504))
    const timer = setTimeout(expire, limits.dnsMs)
    try {
      const answers = await abortable(Promise.resolve().then(() => lookup(hostname, controller.signal)), controller.signal)
      if (performance.now() >= deadline && !controller.signal.aborted) expire()
      controller.signal.throwIfAborted()
      if (!Array.isArray(answers) || !answers.length) throw unavailable()
      if (answers.some((item) => !item || ![4, 6].includes(item.family) || isIP(item.address) !== item.family || isForbiddenIp(item.address))) throw unsafe()
      return answers.map(({ address, family }) => ({ address, family }))
    } catch (error) {
      throw controller.signal.aborted ? controller.signal.reason : error instanceof ApiError ? error : unavailable()
    } finally {
      clearTimeout(timer)
      parentSignal?.removeEventListener('abort', cancel)
    }
  }

  async function requestOnce(url, context) {
    const addresses = await resolveSafe(url.hostname, context.signal)
    context.check()
    const pinned = addresses[0]
    const hostname = url.hostname.replace(/^\[([^\]]+)\]$/, '$1')
    return new Promise((resolve, reject) => {
      let req
      let settled = false
      const finish = (error, result) => {
        if (settled) return
        settled = true
        context.signal.removeEventListener('abort', abort)
        error ? reject(error) : resolve(result)
      }
      const fail = (error) => {
        finish(error)
        req?.destroy()
      }
      const abort = () => fail(context.signal.reason)
      context.signal.addEventListener('abort', abort, { once: true })
      try {
        context.check()
        req = request({
          protocol: 'https:', hostname, port: 443, method: 'GET',
          path: `${url.pathname || '/'}${url.search}`,
          headers: { host: url.host, 'user-agent': 'VibeGuard-safe-observer/2.0', accept: 'text/html,application/xhtml+xml,text/plain;q=0.8', 'accept-encoding': 'identity' },
          // Never use global agents, proxy env settings, env-added CAs, or an
          // env-controlled rejectUnauthorized default. One validated IP/hop.
          agent: false, autoSelectFamily: false, family: pinned.family,
          rejectUnauthorized: true, ca: rootCertificates, minVersion: 'TLSv1.2',
          servername: isIP(hostname) ? '' : hostname,
          checkServerIdentity: (_name, certificate) => checkServerIdentity(hostname, certificate),
          maxHeaderSize: limits.maxHeaders,
          lookup: (_host, options, callback) => options?.all
            ? callback(null, [{ ...pinned }]) : callback(null, pinned.address, pinned.family),
        }, (response) => {
          response.on('error', () => fail(execution('The website response was interrupted.')))
          response.on('aborted', () => fail(execution('The website response was interrupted.')))
          response.on('close', () => { if (!response.complete) fail(execution('The website response was incomplete.')) })
          const length = response.headers['content-length']
          if (length !== undefined && (!/^\d+$/.test(length) || Number(length) > context.remaining)) {
            fail(execution('The website response exceeded the response size limit.'))
            return
          }
          if (response.headers['content-encoding'] && response.headers['content-encoding'].toLowerCase() !== 'identity') {
            fail(execution('Compressed website responses are not supported by this bounded observer.'))
            return
          }
          const chunks = []
          response.on('data', (chunk) => {
            try { context.check() } catch (error) { fail(error); return }
            context.remaining -= chunk.length
            if (context.remaining < 0) { fail(execution('The website response exceeded the response size limit.')); return }
            chunks.push(chunk)
          })
          response.on('end', () => {
            try { context.check() } catch (error) { fail(error); return }
            if (!response.complete) { fail(execution('The website response was incomplete.')); return }
            finish(null, { status: response.statusCode ?? 0, headers: response.headers, body: Buffer.concat(chunks).toString('utf8') })
          })
        })
        req.on('error', () => fail(execution('The website HTTPS request failed; a secure response could not be established.')))
        req.on('upgrade', (_response, socket) => { socket.destroy(); fail(execution('Protocol upgrades are not supported.')) })
        req.end()
      } catch (error) {
        fail(error instanceof ApiError ? error : execution('The website HTTPS request could not be started.'))
      }
    })
  }

  async function safeFetch(raw) {
    let url = validateTarget(raw)
    if (!enabled) throw new ApiError('SCANNING_DISABLED', 'Remote URL scanning is disabled by server configuration.', 503)
    if (active >= limits.concurrency) throw new ApiError('EXTERNAL_UNAVAILABLE', 'The website scanner is busy. Try again shortly.', 503)
    active += 1
    const controller = new AbortController()
    const deadline = performance.now() + limits.totalMs
    const timer = setTimeout(() => controller.abort(totalTimeout()), limits.totalMs)
    const context = {
      signal: controller.signal, remaining: limits.maxBytes,
      check() {
        if (performance.now() >= deadline && !controller.signal.aborted) controller.abort(totalTimeout())
        controller.signal.throwIfAborted()
      },
    }
    const redirects = []
    try {
      for (let count = 0; count <= limits.redirects; count += 1) {
        context.check()
        const response = await requestOnce(url, context)
        if ([301, 302, 303, 307, 308].includes(response.status)) {
          if (!response.headers.location) throw execution('The website returned a redirect without a destination.')
          if (count === limits.redirects) throw execution('The target exceeded the redirect limit.')
          try {
            const location = response.headers.location
            if (/[\s\\\x00-\x1f\x7f]/.test(location)) throw unsafe()
            url = validateTarget(new URL(location, url).href)
          } catch { throw new ApiError('UNSAFE_TARGET', 'The website redirected to an unsafe or invalid destination.') }
          redirects.push(url.href)
          continue
        }
        return { url: url.href, response, redirects }
      }
      throw execution('The website scan could not be completed.')
    } finally {
      clearTimeout(timer)
      active -= 1
    }
  }
  return Object.freeze({ safeFetch, resolveSafe })
}

const scanner = createScanner()
export const safeFetch = scanner.safeFetch
export const resolveSafe = scanner.resolveSafe
// Private, in-process test seam. Neither HTTP inputs nor environment variables
// are ever passed here. Production exports above capture immutable dependencies.
export const __testing = Object.freeze({ createScanner, publicDns, defaults })

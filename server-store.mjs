import { promises as fs } from 'node:fs'
import path from 'node:path'
import crypto from 'node:crypto'
import { ApiError } from './server-security.mjs'

const MAX_SCAN_BYTES = 32 * 1024 * 1024
const record = (value) => value !== null && typeof value === 'object' && !Array.isArray(value)
const text = (value) => typeof value === 'string' && value.length <= 100_000
const nonempty = (value) => text(value) && value.trim().length > 0
const integer = (value) => Number.isSafeInteger(value) && value >= 0
const boolean = (value) => typeof value === 'boolean'
const date = (value) => typeof value === 'string' && /^\d{4}-\d\d-\d\dT/.test(value) && Number.isFinite(Date.parse(value))
const choices = (...values) => (value) => values.includes(value)
const list = (validate) => (value) => Array.isArray(value) && value.length <= 10_000 && value.every(validate)
const optional = (validate) => (value) => value === undefined || validate(value)
export const validScanId = (value) => typeof value === 'string' && /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(value)
const status = choices('Pending', 'Running', 'Completed', 'Completed with limitations', 'Failed')
const type = choices('Website URL', 'Source upload', 'Demo')
const severity = choices('Critical', 'High', 'Medium', 'Low', 'Informational')
const shape = (schema) => (value) => record(value) && Object.entries(schema).every(([key, validate]) => validate(value[key]))
const fields = (names, validator = text) => Object.fromEntries(names.split(' ').map((name) => [name, validator]))

const findingShape = shape({
  ...fields('id title rule category file evidence whyItMatters remediation prompt'),
  severity, confidence: choices('Confirmed', 'Likely', 'Informational'),
  status: choices('Unresolved', 'Fixed', 'Awaiting verification', 'Inconclusive'),
  line: optional(integer), scanId: optional(validScanId), isDemo: optional(boolean),
  ...fields('advisoryId affectedRange fixedVersion sourceUrl verificationMethod', optional(text)),
})
const coverageShape = shape({
  ...fields('id label details'), status: choices('passed', 'failed', 'unavailable', 'not-run'),
  ...fields('source error', optional(text)), checkedAt: optional(date),
  ...fields('requestedCount responseCount matchedCount skippedCount', optional(integer)), skippedDetails: optional(list(text)),
})
const runtimeShape = shape({
  ...fields('component ecosystem sourceFile'), ...fields('version details', optional(text)),
  evidence: choices('declared', 'resolved', 'observed', 'inferred', 'unknown'),
})
const advisoryShape = shape({
  ...fields('id packageName ecosystem version summary affectedRange sourceUrl source'),
  severity, checkedAt: date, fixedVersion: optional(text),
})
const dependencyShape = shape({
  ...fields('packageName ecosystem version manifest'), advisories: list(advisoryShape),
  versionSource: choices('declared', 'resolved', 'unknown'),
  lookupStatus: optional(choices('matched', 'no-match', 'unknown-version', 'unsupported', 'unavailable')),
  ...fields('lookupError declaredVersion resolvedVersion declarationFile resolutionFile', optional(text)),
})
const verificationShape = shape({
  ...fields('id testType summary'), findingId: optional(text), executedAt: date, passed: boolean,
  checks: list(shape({ ...fields('id label actor target expected actual'), passed: boolean })),
})
const summaryShape = shape({
  scanId: validScanId, target: nonempty, checkedAt: date, scanStatus: status, scanType: optional(type),
  findings: list(findingShape), coverage: list(coverageShape), runtimes: list(runtimeShape),
  dependencies: list(dependencyShape), verificationHistory: list(verificationShape),
  scanTypes: list(text), fileCount: integer, isDemo: boolean,
  scans: optional(list(shape({ ...fields('id name'), createdAt: date, type, status,
    ...fields('findingCount confirmedCount likelyCount files', integer), isDemo: optional(boolean) }))),
  limitations: optional(list(text)), sourceFiles: optional(list(text)), ...fields('errorCode error', optional(text)),
  sourceAssociation: optional(shape({ scanId: validScanId, target: nonempty, confirmedAt: date })),
})
const scanFields = 'scanId target checkedAt scanStatus scanType findings scans coverage runtimes dependencies verificationHistory scanTypes fileCount isDemo limitations sourceFiles errorCode error sourceAssociation'.split(' ')

export function safeScanPayload(input, ownerId) {
  if (!summaryShape(input) || Buffer.byteLength(JSON.stringify(input)) > MAX_SCAN_BYTES) {
    throw new ApiError('INVALID_INPUT', 'Invalid scan record or scan record exceeds the storage limit.')
  }
  const ids = new Set()
  for (const finding of input.findings) {
    if (!nonempty(finding.id) || ids.has(finding.id) || (finding.scanId !== undefined && finding.scanId !== input.scanId)) {
      throw new ApiError('INVALID_INPUT', 'Finding identifiers must be unique and associated with this scan.')
    }
    ids.add(finding.id)
  }
  const scan = structuredClone(Object.fromEntries(scanFields.filter((key) => input[key] !== undefined).map((key) => [key, input[key]])))
  scan.scans ??= []
  scan.findings = scan.findings.map((finding) => ({ ...finding, scanId: scan.scanId, evidence: finding.evidence.slice(0, 2000) }))
  return { ...scan, ownerId, storedAt: new Date().toISOString() }
}

const storeError = () => new ApiError('EXTERNAL_UNAVAILABLE', 'Saved scan storage is unavailable. Please try again later.', 503)
const userShape = shape({ id: validScanId, email: nonempty, passwordSalt: (value) => /^[a-f0-9]{32}$/.test(value), passwordHash: (value) => /^[a-f0-9]{128}$/.test(value), createdAt: date })

function validateStore(value) {
  if (!record(value) || !Array.isArray(value.users) || !Array.isArray(value.scans) || !value.users.every(userShape)) throw storeError()
  const userIds = new Set(value.users.map((user) => user.id))
  if (userIds.size !== value.users.length || new Set(value.users.map((user) => user.email)).size !== value.users.length) throw storeError()
  const keys = new Set()
  for (const scan of value.scans) {
    if (!record(scan) || !userIds.has(scan.ownerId) || (scan.storedAt !== undefined && !date(scan.storedAt))) throw storeError()
    try { safeScanPayload(scan, scan.ownerId) } catch { throw storeError() }
    const key = `${scan.ownerId}:${scan.scanId}`
    if (keys.has(key)) throw storeError()
    keys.add(key)
  }
  return value
}

export function createStore(dataDir, io = fs) {
  const dataFile = path.join(dataDir, 'store.json')
  let current
  let loading
  let queue = Promise.resolve()
  async function load() {
    if (current) return current
    loading ??= (async () => {
      let raw
      try { raw = await io.readFile(dataFile, 'utf8') } catch (error) {
        if (error.code === 'ENOENT') return { users: [], scans: [] }
        throw storeError()
      }
      try { return validateStore(JSON.parse(raw)) } catch { throw storeError() }
    })()
    current = await loading
    return current
  }
  async function write(next) {
    const temporary = `${dataFile}.${crypto.randomUUID()}.tmp`
    let handle
    try {
      await io.mkdir(dataDir, { recursive: true, mode: 0o700 })
      handle = await io.open(temporary, 'wx', 0o600)
      await handle.writeFile(JSON.stringify(next), 'utf8')
      await handle.sync()
      await handle.close()
      handle = undefined
      await io.rename(temporary, dataFile)
    } catch {
      throw storeError()
    } finally {
      if (handle) await handle.close().catch(() => {})
      await io.unlink(temporary).catch(() => {})
    }
  }
  return Object.freeze({
    async read() {
      await queue
      return structuredClone(await load())
    },
    update(mutator) {
      const operation = queue.then(async () => {
        const next = structuredClone(await load())
        await mutator(next)
        validateStore(next)
        await write(next)
        current = next // A failed write never commits an in-memory mutation.
        return structuredClone(next)
      })
      queue = operation.then(() => undefined, () => undefined)
      return operation
    },
  })
}

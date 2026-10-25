import { ApiRequestError, runUrlScan } from './api'
import { scanZip, type ScanChecks } from './scanner'
import type { DependencyRecord, ScanRecord, ScanSummary, ScanType } from './types'

export const isCompleted = (scan: ScanSummary) => scan.scanStatus === 'Completed' || scan.scanStatus === 'Completed with limitations'
export const scanKind = (scan: ScanSummary): ScanType => scan.scanType ?? (scan.isDemo ? 'Demo' : scan.coverage.some((check) => check.id === 'url-availability') ? 'Website URL' : 'Source upload')

export function pendingScan(target = 'No scan started', scanType: ScanType = 'Source upload'): ScanSummary {
  return {
    scanId: crypto.randomUUID(), target, scanType, scanStatus: 'Pending', checkedAt: new Date().toISOString(),
    findings: [], scans: [], coverage: [], dependencies: [], runtimes: [], verificationHistory: [],
    scanTypes: [], fileCount: 0, isDemo: scanType === 'Demo',
  }
}

export type ScanAttempt = { target: string; authorized: boolean } & (
  { type: 'Source upload'; file?: File | null; checks?: ScanChecks }
  | { type: 'Website URL' }
)
export type ScanOutcome = { scan: ScanSummary; saved: boolean; persistenceError?: string }

// Every attempt starts from an empty record; previous evidence is never an input.
// Transport failures and incomplete coverage cannot inherit a successful scan.
export async function executeScan(
  attempt: ScanAttempt,
  update: (scan: ScanSummary, phase: string) => void,
  services = { zip: scanZip, url: runUrlScan },
): Promise<ScanOutcome> {
  let scan = pendingScan(attempt.target.trim() || (attempt.type === 'Source upload' ? attempt.file?.name : undefined) || 'New scan', attempt.type)
  update(scan, 'Pending · validating input and authorization')
  let executing = false
  try {
    if (!attempt.authorized) throw new ApiRequestError('Confirm that you own or are authorized to test this application.', 'AUTHORIZATION_REQUIRED')
    if (attempt.type === 'Source upload' && !attempt.file) throw new ApiRequestError('Choose a source-code ZIP archive first.', 'INVALID_INPUT')
    if (attempt.type === 'Website URL') {
      let url: URL
      try { url = new URL(attempt.target) } catch { throw new ApiRequestError('Enter a valid HTTPS website URL.', 'INVALID_INPUT') }
      if (url.protocol !== 'https:' || url.username || url.password || url.port) throw new ApiRequestError('Use an HTTPS URL without credentials, on port 443.', 'INVALID_INPUT')
    }
    scan = { ...scan, scanStatus: 'Running' }
    update(scan, attempt.type === 'Website URL' ? 'Running · waiting for DNS, TLS, redirects, and response checks' : 'Running · validating archive')
    executing = true
    const result: ScanOutcome = attempt.type === 'Source upload'
      ? { scan: await services.zip(attempt.file!, scan.target, attempt.checks, undefined, { scanId: scan.scanId, onProgress: (phase) => update(scan, phase) }), saved: false }
      : await services.url(attempt.target, attempt.authorized, scan.scanId)
    if (result.scan.scanId !== scan.scanId || scanKind(result.scan) !== attempt.type || result.scan.findings.some((finding) => finding.scanId !== scan.scanId)) {
      throw new ApiRequestError('The scanner returned results for a different scan. No result was accepted.', 'INVALID_RESULT')
    }
    if (!isCompleted(result.scan) && result.scan.scanStatus !== 'Failed') throw new ApiRequestError('The scanner did not return a terminal result.', 'INVALID_RESULT')
    if (isCompleted(result.scan) && !result.scan.coverage.some((check) => (check.status === 'passed' && check.id !== 'source' && check.id !== 'runtime') || (check.id === 'dependencies' && (check.responseCount ?? 0) > 0))) {
      throw new ApiRequestError('No supported checks completed.', 'NO_SUPPORTED_CHECKS')
    }
    update(result.scan, result.scan.scanStatus)
    return result
  } catch (error) {
    scan = {
      ...pendingScan(scan.target, attempt.type), scanId: scan.scanId, scanStatus: 'Failed',
      errorCode: error instanceof ApiRequestError ? error.code : attempt.type === 'Source upload' ? 'INVALID_ARCHIVE' : 'EXECUTION_FAILED',
      error: error instanceof Error ? error.message : 'Scan execution failed.',
      coverage: [{ id: 'execution', label: executing ? 'Scan execution' : 'Input and authorization validation', status: 'failed', details: error instanceof Error ? error.message : 'No completed checks.' }],
      limitations: ['No completed scan result is available for this attempt.'],
    }
    update(scan, 'Failed')
    return { scan, saved: false }
  }
}

export const upsertScan = (records: ScanSummary[], scan: ScanSummary) => [scan, ...records.filter((record) => record.scanId !== scan.scanId)]
export const actualRecords = (records: ScanSummary[]) => [...new Map(records.filter((scan) => !scan.isDemo).map((scan) => [scan.scanId, scan])).values()]
export function scanRecord(scan: ScanSummary): ScanRecord {
  return { id: scan.scanId, name: scan.target, createdAt: scan.checkedAt, type: scanKind(scan), status: scan.scanStatus,
    findingCount: scan.findings.length, confirmedCount: scan.findings.filter((finding) => finding.confidence === 'Confirmed' && finding.status !== 'Fixed').length,
    likelyCount: scan.findings.filter((finding) => finding.confidence === 'Likely' && finding.status !== 'Fixed').length, files: scan.fileCount, isDemo: scan.isDemo }
}

export function associateSource(urlScan: ScanSummary, source: ScanSummary, confirmed: boolean): ScanSummary {
  if (!confirmed) throw new Error('Explicit confirmation is required to associate source evidence.')
  if (scanKind(urlScan) !== 'Website URL' || scanKind(source) !== 'Source upload' || !isCompleted(urlScan) || !isCompleted(source) || source.isDemo) throw new Error('Choose a completed website scan and a separate completed source ZIP scan.')
  return { ...urlScan, sourceAssociation: { scanId: source.scanId, target: source.target, confirmedAt: new Date().toISOString() } }
}

export function dependencyLabel(dependency: DependencyRecord) {
  switch (dependency.lookupStatus) {
    case 'matched': return 'Matching advisory found'
    case 'no-match': return 'Lookup completed with zero matching advisories'
    case 'unknown-version': return 'Dependency version unknown'
    case 'unsupported': return 'Unsupported dependency entry'
    default: return 'Lookup incomplete or unavailable'
  }
}

export function dependencyOutcome(scan: ScanSummary) {
  const check = scan.coverage.find((item) => item.id === 'dependencies')
  if (scanKind(scan) === 'Website URL') return 'Dependency advisory check unavailable: exact dependency versions could not be established.'
  if (!isCompleted(scan)) return `Dependency checks not completed · ${scan.scanStatus}`
  if (!check || check.status === 'not-run') return 'Dependency advisory check not run'
  if (check.status !== 'passed') return 'Dependency advisory lookup incomplete or unavailable'
  if ((check.skippedCount ?? 0) > 0 || scan.dependencies.some((entry) => entry.lookupStatus === 'unknown-version' || entry.lookupStatus === 'unsupported')) return 'Partial inventory · review unqueried entries'
  return check.matchedCount ? `${check.matchedCount} matching advisory records` : 'Lookup completed with zero matching advisories'
}

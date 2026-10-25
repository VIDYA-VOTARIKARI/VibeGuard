export type View = 'home' | 'dashboard' | 'scan' | 'findings' | 'demo' | 'patches' | 'history' | 'report'

export type Severity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational'
export type Confidence = 'Confirmed' | 'Likely' | 'Informational'
export type FindingStatus = 'Unresolved' | 'Fixed' | 'Awaiting verification' | 'Inconclusive'

export type CheckStatus = 'passed' | 'failed' | 'unavailable' | 'not-run'
export type ScanStatus = 'Pending' | 'Running' | 'Completed' | 'Completed with limitations' | 'Failed'
export type ScanType = 'Demo' | 'Source upload' | 'Website URL'
export type DependencyLookupStatus = 'matched' | 'no-match' | 'unknown-version' | 'unsupported' | 'unavailable'

export interface CheckCoverage {
  id: string
  label: string
  status: CheckStatus
  details: string
  source?: string
  checkedAt?: string
  requestedCount?: number
  responseCount?: number
  matchedCount?: number
  error?: string
  skippedCount?: number
  skippedDetails?: string[]
}

export interface RuntimeEvidence {
  component: string
  ecosystem: string
  version?: string
  sourceFile: string
  evidence: 'declared' | 'resolved' | 'observed' | 'inferred' | 'unknown'
  details?: string
}

export interface DependencyAdvisory {
  id: string
  packageName: string
  ecosystem: string
  version: string
  severity: Severity
  summary: string
  affectedRange: string
  fixedVersion?: string
  sourceUrl: string
  source: string
  checkedAt: string
}

export interface DependencyRecord {
  packageName: string
  ecosystem: string
  version: string
  manifest: string
  advisories: DependencyAdvisory[]
  versionSource: 'declared' | 'resolved' | 'unknown'
  lookupStatus?: DependencyLookupStatus
  lookupError?: string
  declaredVersion?: string
  resolvedVersion?: string
  declarationFile?: string
  resolutionFile?: string
}

export interface Finding {
  id: string
  title: string
  rule: string
  category: string
  severity: Severity
  confidence: Confidence
  status: FindingStatus
  file: string
  line?: number
  evidence: string
  whyItMatters: string
  remediation: string
  prompt: string
  isDemo?: boolean
  advisoryId?: string
  affectedRange?: string
  fixedVersion?: string
  sourceUrl?: string
  verificationMethod?: string
  scanId?: string
}

export interface ScanRecord {
  id: string
  name: string
  createdAt: string
  type: ScanType
  status: ScanStatus
  findingCount: number
  confirmedCount: number
  likelyCount: number
  files: number
  isDemo?: boolean
}

export interface ScanSummary {
  findings: Finding[]
  scans: ScanRecord[]
  target: string
  scanId: string
  fileCount: number
  checkedAt: string
  scanTypes: string[]
  isDemo: boolean
  coverage: CheckCoverage[]
  runtimes: RuntimeEvidence[]
  dependencies: DependencyRecord[]
  verificationHistory: VerificationRun[]
  scanStatus: ScanStatus
  scanType?: ScanType
  limitations?: string[]
  sourceFiles?: string[]
  errorCode?: string
  sourceAssociation?: { scanId: string; target: string; confirmedAt: string }
  error?: string
}

export interface AuthCheckResult {
  id: string
  label: string
  actor: string
  target: string
  expected: string
  actual: string
  passed: boolean
}

export interface VerificationRun {
  id: string
  findingId?: string
  executedAt: string
  testType: string
  passed: boolean
  summary: string
  checks: AuthCheckResult[]
}

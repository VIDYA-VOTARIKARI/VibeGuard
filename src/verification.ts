import type { Finding, ScanSummary } from './types'
import { isCompleted, scanKind } from './workflow'

function findingCheckId(finding: Finding) {
  if (finding.category === 'Secrets' || finding.category === 'Credentials') return 'secrets'
  if (finding.category === 'Configuration' || finding.category === 'Database') return 'configuration'
  if (finding.category === 'Authorization') return 'authorization'
  if (finding.category === 'Dependencies') return 'dependencies'
  return 'codeSafety'
}

export function mergeVerifiedRescan(previous: ScanSummary, current: ScanSummary): ScanSummary {
  if (previous.isDemo || current.isDemo || previous.target !== current.target || scanKind(previous) !== 'Source upload' || scanKind(current) !== 'Source upload' || !isCompleted(current)) return current
  const currentKeys = new Set(current.findings.map((finding) => `${finding.rule}:${finding.file}`))
  const passedChecks = new Set(current.coverage.filter((check) => check.status === 'passed').map((check) => check.id))
  const history = [...previous.verificationHistory, ...current.verificationHistory]
  const carried = previous.findings.filter((finding) => !currentKeys.has(`${finding.rule}:${finding.file}`)).map((finding): Finding => {
    const id = crypto.randomUUID()
    const present = current.sourceFiles?.includes(finding.file) === true
    // Static disappearance is not a runtime authorization/business-logic test.
    // Dependency removal is not proof of a fixed installed version either.
    const verifiable = !['Authorization', 'Business logic', 'Dependencies'].includes(finding.category)
    const passed = present && verifiable && passedChecks.has(findingCheckId(finding))
    const summary = passed ? `Follow-up scan ${current.scanId} no longer matched ${finding.rule} in the inspected file ${finding.file}. This verifies only removal of the static pattern.` : `Follow-up scan ${current.scanId} could not verify ${finding.rule} from ${previous.scanId}; the file/check or required runtime evidence was unavailable.`
    history.push({ id: crypto.randomUUID(), findingId: id, executedAt: current.checkedAt, testType: 'Source pattern follow-up', passed, summary, checks: [{ id: finding.rule, label: finding.title, actor: 'Static scanner', target: finding.file, expected: 'Same file inspected with supported verification evidence', actual: summary, passed }] })
    return { ...finding, id, scanId: current.scanId, status: passed ? 'Fixed' : 'Inconclusive', evidence: `${summary} Prior evidence: ${finding.evidence}` }
  })
  return { ...current, findings: [...current.findings, ...carried], verificationHistory: history }
}

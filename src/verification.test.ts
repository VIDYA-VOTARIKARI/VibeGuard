import { describe, expect, it } from 'vitest'
import { buildDemoFinding, createAuthorizationVerification, recordAuthorizationVerification, runAuthorizationCheck } from './demo'
import { scanTextFiles } from './scanner'
import { mergeVerifiedRescan } from './verification'

describe('authorization verification persistence', () => {
  it('records a failed vulnerable run and only resolves after a passing corrected retest', () => {
    const scan = scanTextFiles([{ path: 'demo/api/orders.ts', content: 'fixture' }], 'auth demo')
    const vulnerable = recordAuthorizationVerification(scan, runAuthorizationCheck(false), 'VERIFY-FAIL', '2026-10-25T10:00:00.000Z')
    expect(vulnerable.verificationHistory).toHaveLength(1)
    expect(vulnerable.verificationHistory[0]).toMatchObject({ id: 'VERIFY-FAIL', findingId: 'AUTHZ-DEMO-001', passed: false, executedAt: '2026-10-25T10:00:00.000Z' })
    expect(vulnerable.findings.find((finding) => finding.id === 'AUTHZ-DEMO-001')?.status).toBe('Unresolved')

    const corrected = recordAuthorizationVerification(vulnerable, runAuthorizationCheck(true), 'VERIFY-PASS', '2026-10-25T10:01:00.000Z')
    expect(corrected.verificationHistory).toHaveLength(2)
    expect(corrected.verificationHistory[1]).toMatchObject({ id: 'VERIFY-PASS', findingId: 'AUTHZ-DEMO-001', passed: true })
    expect(corrected.findings.find((finding) => finding.id === 'AUTHZ-DEMO-001')?.status).toBe('Fixed')
  })

  it('never marks a staged correction fixed without a passing verification event', () => {
    expect(buildDemoFinding(true).status).toBe('Unresolved')
    const failed = recordAuthorizationVerification(scanTextFiles([{ path: 'demo/api/orders.ts', content: 'fixture' }], 'auth demo'), runAuthorizationCheck(false), 'VERIFY-FAIL', '2026-10-25T10:00:00.000Z')
    expect(failed.findings.find((finding) => finding.id === 'AUTHZ-DEMO-001')?.status).not.toBe('Fixed')
  })

  it('rejects empty, missing, duplicate or contradictory check results as passing evidence', () => {
    const complete = runAuthorizationCheck(true)
    for (const checks of [[], complete.slice(1), [complete[0], complete[0], complete[2], complete[3]], complete.map((check) => ({ ...check, actual: 'not executed' }))]) {
      const verification = createAuthorizationVerification(checks)
      expect(verification.passed).toBe(false)
      expect(buildDemoFinding(true, { ...verification, passed: true }).status).not.toBe('Fixed')
    }
  })

  it('never attaches synthetic results to a source or URL scan', () => {
    const source = { ...scanTextFiles([{ path: 'app.js', content: '' }], 'source'), isDemo: false }
    expect(() => recordAuthorizationVerification(source, runAuthorizationCheck(true))).toThrow(/Synthetic/)
  })
})

describe('source rescan verification', () => {
  it('keeps a resolved finding in the new scan when the relevant check passes', () => {
    const previous = scanTextFiles([{ path: 'src/config.ts', content: 'const apiKey = "sk_live_1234567890abcdef"' }], 'same project')
    const current = scanTextFiles([{ path: 'src/config.ts', content: 'const apiKey = process.env.API_KEY' }], 'same project')
    previous.isDemo = false
    current.isDemo = false
    previous.scanType = current.scanType = 'Source upload'
    const result = mergeVerifiedRescan(previous, current)
    expect(result.findings.length).toBeGreaterThan(0)
    expect(result.findings.every((finding) => finding.status === 'Fixed')).toBe(true)
    expect(result.findings[0].evidence).toContain('Follow-up scan')
    expect(result.findings.every((finding) => finding.scanId === current.scanId)).toBe(true)
    expect(result.verificationHistory.every((run) => run.passed && run.checks.length > 0)).toBe(true)
  })

  it('does not resolve findings when the relevant check was unavailable', () => {
    const previous = scanTextFiles([{ path: 'src/config.ts', content: 'const apiKey = "sk_live_1234567890abcdef"' }], 'same project')
    const current = scanTextFiles([{ path: 'src/config.ts', content: 'const apiKey = process.env.API_KEY' }], 'same project')
    previous.isDemo = false
    current.isDemo = false
    previous.scanType = current.scanType = 'Source upload'
    current.coverage = current.coverage.map((check) => check.id === 'secrets' ? { ...check, status: 'unavailable' as const } : check)
    const result = mergeVerifiedRescan(previous, current)
    expect(result.findings).toHaveLength(previous.findings.length)
    expect(result.findings.every((finding) => finding.status === 'Inconclusive')).toBe(true)
    expect(result.verificationHistory.every((run) => !run.passed)).toBe(true)
  })

  it('does not merge distinct projects or resolve a deleted file', () => {
    const previous = { ...scanTextFiles([{ path: 'config.js', content: 'const secret = "sk_live_1234567890abcdef"' }], 'project A'), isDemo: false, scanType: 'Source upload' as const }
    const current = { ...scanTextFiles([{ path: 'different.js', content: 'console.log("hello")' }], 'project B'), isDemo: false, scanType: 'Source upload' as const }
    expect(mergeVerifiedRescan(previous, current)).toBe(current)
    const same = mergeVerifiedRescan(previous, { ...current, target: previous.target })
    expect(same.findings.every((finding) => finding.status === 'Inconclusive')).toBe(true)
  })

  it('does not call a missing authorization pattern runtime-verified', () => {
    const previous = { ...scanTextFiles([{ path: 'app.js', content: 'db.orders.find({ id: req.params.id })' }], 'project'), isDemo: false, scanType: 'Source upload' as const }
    const current = { ...scanTextFiles([{ path: 'app.js', content: 'db.orders.find({ id: req.params.id, owner_id: req.user.id })' }], 'project'), isDemo: false, scanType: 'Source upload' as const }
    expect(previous.findings.length).toBeGreaterThan(0)
    expect(mergeVerifiedRescan(previous, current).findings.every((finding) => finding.status !== 'Fixed')).toBe(true)
  })
})

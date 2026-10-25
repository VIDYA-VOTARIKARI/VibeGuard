import { describe, expect, it } from 'vitest'
import { recordAuthorizationVerification, runAuthorizationCheck } from './demo'
import { createHtmlReport, createReportPayload } from './report'
import { scanTextFiles } from './scanner'

describe('redacted report generation', () => {
  it('includes coverage and verification history in JSON without adding raw secret values', () => {
    const rawSecret = 'sk_live_1234567890abcdef'
    const scan = scanTextFiles([{ path: 'src/config.ts', content: `const apiKey = "${rawSecret}"` }], 'report fixture')
    scan.verificationHistory = [{
      id: 'VERIFY-1',
      executedAt: new Date().toISOString(),
      testType: 'Fixture test',
      passed: true,
      summary: 'The corrected fixture passed.',
      checks: [],
    }]
    const payload = createReportPayload(scan)
    const serialized = JSON.stringify(payload)
    expect(serialized).toContain('coverage')
    expect(serialized).toContain('verificationHistory')
    expect(serialized).not.toContain(rawSecret)
  })

  it('escapes finding content in the downloadable HTML report', () => {
    const scan = scanTextFiles([{ path: 'src/config.ts', content: 'const apiKey = "sk_live_1234567890abcdef"' }], '<report target>')
    const html = createHtmlReport(scan)
    expect(html).toContain('&lt;report target&gt;')
    expect(html).not.toContain('sk_live_1234567890abcdef')
  })

  it('does not expose short or punctuation-bearing credentials in matched source evidence', () => {
    const scan = scanTextFiles([{ path: 'config.ts', content: 'const password = "S3!x"; const database = "postgres://someone:short!@db.internal/app"' }], 'redaction')
    expect(scan.findings.length).toBeGreaterThan(0)
    expect(JSON.stringify(createReportPayload(scan))).not.toContain('S3!x')
    expect(createHtmlReport(scan)).not.toContain('short!')
  })

  it('reports the same persisted verification history and resolved status used by the scan', () => {
    const scan = scanTextFiles([{ path: 'demo/api/orders.ts', content: 'fixture' }], 'demo report')
    const verified = recordAuthorizationVerification(scan, runAuthorizationCheck(true), 'VERIFY-REPORT', '2026-10-25T10:02:00.000Z')
    const payload = createReportPayload(verified)
    expect(payload.verificationHistory).toHaveLength(1)
    expect(payload.verificationHistory[0]).toMatchObject({ id: 'VERIFY-REPORT', passed: true })
    expect(payload.findings.find((finding) => finding.id === 'AUTHZ-DEMO-001')?.status).toBe('Fixed')
  })
})

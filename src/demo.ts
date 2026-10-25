import type { AuthCheckResult, Finding, ScanSummary, VerificationRun } from './types'

export const vulnerableFixture = `
export async function getOrder(req, res) {
  const order = await db.orders.find({ id: req.params.id })
  return res.json(order)
}
`

export const fixedFixture = `
export async function getOrder(req, res) {
  const order = await db.orders.find({ id: req.params.id, owner_id: req.user.id })
  if (!order) return res.status(403).json({ error: 'Forbidden' })
  return res.json(order)
}
`

export function runAuthorizationCheck(isFixed: boolean): AuthCheckResult[] {
  const orderA = { id: 'ord_vg_001', owner: 'User A', total: '₹4,280' }
  const orderB = { id: 'ord_vg_002', owner: 'User B', total: '₹1,940' }
  const read = (actor: string | null, order: typeof orderA) => {
    if (!actor) return null
    if (isFixed && actor !== order.owner) return null
    return order
  }
  const bReadsA = read('User B', orderA)
  const aReadsA = read('User A', orderA)
  const bReadsB = read('User B', orderB)
  const anonymousReadsA = read(null, orderA)
  return [
    { id: 'cross-user', label: 'User B → User A order', actor: 'User B', target: 'ord_vg_001', expected: 'Access denied (403)', actual: bReadsA ? `Order returned · ${bReadsA.total}` : 'Access denied (403)', passed: !bReadsA },
    { id: 'owner-access', label: 'User A → User A order', actor: 'User A', target: 'ord_vg_001', expected: 'Order returned', actual: aReadsA ? `Order returned · ${aReadsA.total}` : 'Access denied (403)', passed: Boolean(aReadsA) },
    { id: 'peer-access', label: 'User B → User B order', actor: 'User B', target: 'ord_vg_002', expected: 'Order returned', actual: bReadsB ? `Order returned · ${bReadsB.total}` : 'Access denied (403)', passed: Boolean(bReadsB) },
    { id: 'anonymous-access', label: 'Unauthenticated → User A order', actor: 'Unauthenticated', target: 'ord_vg_001', expected: 'Access denied (401/403)', actual: anonymousReadsA ? `Order returned · ${anonymousReadsA.total}` : 'Access denied (401/403)', passed: !anonymousReadsA },
  ]
}

export function createAuthorizationVerification(results: AuthCheckResult[], id = `VERIFY-${crypto.randomUUID()}`, executedAt = new Date().toISOString()): VerificationRun {
  const expected = runAuthorizationCheck(true)
  const complete = results.length === expected.length && new Set(results.map((result) => result.id)).size === expected.length && expected.every((check) => results.some((result) => result.id === check.id && result.actor === check.actor && result.target === check.target && result.expected === check.expected))
  const passed = complete && expected.every((check) => results.some((result) => result.id === check.id && result.passed === true && result.actual === check.actual))
  return {
    id,
    findingId: 'AUTHZ-DEMO-001',
    executedAt,
    testType: 'Synthetic two-user authorization regression',
    passed,
    summary: passed ? 'All ownership and unauthenticated access checks passed.' : !complete ? 'The required authorization checks were incomplete; no passing verification is recorded.' : 'Authorization checks did not all pass; the finding remains unresolved.',
    checks: results,
  }
}

export function buildDemoFinding(isFixed: boolean, verification?: VerificationRun): Finding {
  const verified = Boolean(verification?.passed && verification.findingId === 'AUTHZ-DEMO-001' && createAuthorizationVerification(verification.checks).passed)
  const crossUser = verification?.checks.find((check) => check.id === 'cross-user')
  const evidence = verification
    ? `Executed ${verification.testType} at ${verification.executedAt}. Expected: ${crossUser?.expected ?? 'ownership enforcement'}. Actual: ${crossUser?.actual ?? verification.summary}.`
    : isFixed
      ? 'Correction is staged but no corrected authorization test has run yet; the finding is not verified.'
      : 'No authorization test has run for this fixture yet.'
  return {
    id: 'AUTHZ-DEMO-001',
    title: 'Cross-user order access is not blocked',
    rule: 'AUTHZ-DEMO-001',
    category: 'Authorization',
    severity: 'Critical',
    confidence: verification ? 'Confirmed' : 'Likely',
    status: verified ? 'Fixed' : 'Unresolved',
    file: 'demo/api/orders.ts',
    line: 3,
    evidence,
    whyItMatters: 'The endpoint authenticated User B but did not authorize access to User A’s order. This is a real broken-object-level-authorization pattern, not a model prediction.',
    remediation: 'Scope the database lookup to the authenticated user and return 403 when ownership does not match. Keep the ownership check on the server.',
    prompt: 'In demo/api/orders.ts, update getOrder to query by both id and owner_id = req.user.id. Return 403 when no owned order is found. Add tests for cross-user denial and legitimate self-access. Do not trust a user_id from the browser.',
    verificationMethod: 'Run the synthetic two-user authorization regression and require every check to pass before marking the finding fixed.',
    isDemo: true,
  }
}

export function recordAuthorizationVerification(scan: ScanSummary, results: AuthCheckResult[], id?: string, executedAt?: string): ScanSummary {
  if (!scan.isDemo) throw new Error('Synthetic authorization tests cannot verify real source or website scans.')
  const verification = createAuthorizationVerification(results, id, executedAt)
  const updated = buildDemoFinding(false, verification)
  return {
    ...scan,
    findings: [{ ...updated, scanId: scan.scanId }, ...scan.findings.filter((item) => item.id !== updated.id)],
    scanType: 'Demo',
    scanStatus: 'Completed',
    checkedAt: verification.executedAt,
    verificationHistory: [...scan.verificationHistory, verification],
    coverage: scan.coverage.map((item) => item.id === 'authorization' ? { ...item, status: verification.passed ? 'passed' as const : 'failed' as const, details: verification.summary } : item.id === 'source' ? { ...item, status: 'passed' as const, details: 'Controlled synthetic authorization fixture executed in memory; no uploaded or remote code ran.' } : item),
  }
}

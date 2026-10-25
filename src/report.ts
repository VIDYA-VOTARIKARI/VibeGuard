import type { ScanSummary } from './types'
import { dependencyLabel, isCompleted, scanKind } from './workflow'

function escapeHtml(value: string) {
  return value.replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;').replaceAll("'", '&#39;')
}

function safeUrl(value: string) {
  try {
    const url = new URL(value)
    return url.protocol === 'https:' || url.protocol === 'http:' ? url.toString() : ''
  } catch {
    return ''
  }
}

export function downloadReport(scan: ScanSummary) {
  const payload = createReportPayload(scan)
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' })
  const href = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = href
  link.download = `vibeguard-${scan.scanId.toLowerCase()}.json`
  link.click()
  URL.revokeObjectURL(href)
}

export function createReportPayload(scan: ScanSummary) {
  return {
    product: 'VibeGuard',
    tagline: 'Evidence from supported checks, with explicit limitations.',
    scanId: scan.scanId,
    generatedAt: new Date().toISOString(),
    target: scan.target,
    demoData: scan.isDemo,
    scanStatus: scan.scanStatus,
    scanType: scanKind(scan),
    checkedAt: scan.checkedAt,
    errorCode: scan.errorCode,
    sourceAssociation: scan.sourceAssociation,
    error: scan.error,
    scanTypes: scan.scanTypes,
    fileCount: scan.fileCount,
    coverage: scan.coverage,
    runtimes: scan.runtimes,
    dependencies: scan.dependencies,
    verificationHistory: scan.verificationHistory,
    findings: scan.findings,
    limitations: [
      ...(scanKind(scan) === 'Website URL' ? [
        'Website observations cover only the authorized URL response and validated redirects, not private source, hidden environment variables, internal database permissions, or the full dependency tree.',
        'Dependency advisory check unavailable: exact dependency versions could not be established.',
        'A user-confirmed source association does not prove which code is deployed; ZIP and URL evidence remain distinct.',
      ] : scan.isDemo ? ['This record contains controlled synthetic fixture evidence only; it does not verify an uploaded or remote application.'] : [
        'Static checks cover supported text files and deterministic patterns only; uploaded code is never executed.',
        'OSV requests disclose package name, ecosystem and exact version, not source contents. No deployed application was tested by this source scan.',
        'Manifest evidence does not prove a deployed runtime version.',
      ]),
      ...(scan.limitations ?? []),
      'If dependency advisory matching is unavailable, this report does not claim that dependencies are clean.',
      'A clean result is not a security certification.',
    ],
  }
}

export function downloadHtmlReport(scan: ScanSummary) {
  const html = createHtmlReport(scan)
  const blob = new Blob([html], { type: 'text/html' })
  const href = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = href
  link.download = `vibeguard-${scan.scanId.toLowerCase()}.html`
  link.click()
  URL.revokeObjectURL(href)
}

export function createHtmlReport(scan: ScanSummary) {
  const findings = scan.findings.map((item) => { const sourceUrl = safeUrl(item.sourceUrl ?? ''); return `<article><h2>${escapeHtml(item.title)}</h2><p><b>${escapeHtml(item.severity)}</b> · ${escapeHtml(item.confidence)} · ${escapeHtml(item.status)}</p><p><b>Location:</b> ${escapeHtml(item.file)}${item.line ? `:${item.line}` : ''}</p><p><b>Evidence:</b> ${escapeHtml(item.evidence)}</p><p><b>Why it matters:</b> ${escapeHtml(item.whyItMatters)}</p><p><b>Recommended fix:</b> ${escapeHtml(item.remediation)}</p>${item.advisoryId ? `<p><b>Advisory:</b> ${escapeHtml(item.advisoryId)} · ${sourceUrl ? `<a href="${escapeHtml(sourceUrl)}">${escapeHtml(sourceUrl)}</a>` : 'Source unavailable'}<br><b>Affected:</b> ${escapeHtml(item.affectedRange ?? 'Not provided')} · <b>Fixed:</b> ${escapeHtml(item.fixedVersion ?? 'Not confirmed')}</p>` : ''}</article>` }).join('')
  const coverage = scan.coverage.map((item) => `<li><b>${escapeHtml(item.label)}</b>: ${escapeHtml(item.status)} — ${escapeHtml(item.details)}${item.source ? ` · Source: ${escapeHtml(item.source)}` : ''}${item.checkedAt ? ` · Checked: ${escapeHtml(new Date(item.checkedAt).toLocaleString())}` : ''}${item.skippedCount ? ` · Skipped: ${item.skippedCount}` : ''}</li>`).join('')
  const verification = scan.verificationHistory.map((run) => `<article><h3>${escapeHtml(run.testType)}</h3><p>${run.passed ? 'Passed' : 'Failed'} · ${escapeHtml(new Date(run.executedAt).toLocaleString())} · ${escapeHtml(run.id)}</p><p>${escapeHtml(run.summary)}</p>${run.checks.map((check) => `<li>${escapeHtml(check.label)}: ${check.passed ? 'passed' : 'failed'} — expected ${escapeHtml(check.expected)}; actual ${escapeHtml(check.actual)}</li>`).join('')}</article>`).join('')
  const payload = createReportPayload(scan)
  const dependencies = scan.dependencies.map((entry) => `<li><b>${escapeHtml(entry.packageName)}</b> (${escapeHtml(entry.ecosystem)}) · declared ${escapeHtml(entry.declaredVersion ?? 'Unknown')} · resolved ${escapeHtml(entry.resolvedVersion ?? 'Not established')} · ${escapeHtml(entry.manifest)} · ${escapeHtml(dependencyLabel(entry))}${entry.lookupError ? ` — ${escapeHtml(entry.lookupError)}` : ''}</li>`).join('')
  const runtimes = scan.runtimes.map((entry) => `<li>${escapeHtml(entry.component)} · ${escapeHtml(entry.version ?? 'No exact version')} · ${escapeHtml(entry.evidence)} · ${escapeHtml(entry.sourceFile)} — ${escapeHtml(entry.details ?? '')}</li>`).join('')
  const association = scan.sourceAssociation ? `<h2>Source association (user confirmed)</h2><p>${escapeHtml(scan.sourceAssociation.target)} · ${escapeHtml(scan.sourceAssociation.scanId)} · ${escapeHtml(scan.sourceAssociation.confirmedAt)}. Results remain separate; deployment identity is not verified.</p>` : ''
  const html = `<!doctype html><html><head><meta charset="utf-8"><title>VibeGuard report ${escapeHtml(scan.scanId)}</title><style>body{font-family:Arial,sans-serif;max-width:900px;margin:48px auto;padding:0 24px;color:#152020}h1{color:#0a8c73}article{border:1px solid #dbe4df;border-radius:12px;padding:20px;margin:16px 0}small{color:#63736e}li{margin:7px 0}a{color:#087f64;word-break:break-word}</style></head><body>
  <h1>VibeGuard security report</h1><p>${escapeHtml(scan.target)} · ${escapeHtml(scan.scanId)}</p>
  <small>${escapeHtml(scanKind(scan))} · ${escapeHtml(scan.scanStatus)} · ${escapeHtml(scan.checkedAt)}</small>
  ${scan.error ? `<p>${escapeHtml(scan.errorCode ?? 'Error')}: ${escapeHtml(scan.error)}</p>` : ''}
  <h2>Coverage</h2><ul>${coverage || '<li>No checks executed.</li>'}</ul>
  <h2>Findings</h2>${findings || `<p>${isCompleted(scan) ? 'No findings were reported by executed checks. This is not proof of security.' : 'No completed findings are available.'}</p>`}
  <h2>Dependency inventory</h2><ul>${dependencies || '<li>No reliable dependency inventory available for this scan.</li>'}</ul>
  <h2>Runtime and technology evidence</h2><ul>${runtimes || '<li>No runtime evidence established.</li>'}</ul>
  ${association}<h2>Verification history</h2>${verification || '<p>No verification run recorded.</p>'}
  <hr><h2>Limitations</h2><ul>${[...new Set(payload.limitations)].map((limit) => `<li>${escapeHtml(limit)}</li>`).join('')}</ul></body></html>`
  return html
}

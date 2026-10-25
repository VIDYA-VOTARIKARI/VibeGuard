import { useState } from 'react'
import { ArrowRight, Download, FileArchive, FileText, Info, ScanLine } from 'lucide-react'
import { createReportPayload, downloadHtmlReport, downloadReport } from './report'
import { dependencyOutcome, isCompleted, scanKind } from './workflow'
import type { ScanSummary } from './types'

export function SavedHistory({ scans, loading, onOpen, onSignIn, email }: { scans: ScanSummary[]; loading: boolean; onOpen: (scan: ScanSummary) => void; onSignIn: () => void; email?: string }) {
  return <div className="workspace-view">
    <div className="page-header"><div><div className="eyebrow">Saved history</div><h1>Your scan history.</h1><p>{email ? `Server-confirmed saved records for ${email}. Local-only results are in Overview.` : 'Accounts are optional. Current results and report downloads remain available without login.'}</p></div>{!email && <button className="button primary" onClick={onSignIn}>Sign in</button>}</div>
    {!email ? <div className="panel history-empty"><h3>Anonymous scans remain local.</h3><p>Download your report before leaving. Anonymous scans are never silently attached to an account.</p></div>
      : loading ? <p role="status">Loading saved records…</p>
      : scans.length ? <div className="history-list">{[...scans].sort((a, b) => b.checkedAt.localeCompare(a.checkedAt)).map((scan) => <button className="history-card" key={scan.scanId} onClick={() => onOpen(scan)}><div className="history-card-icon"><FileArchive size={17} /></div><div><strong>{scan.target}</strong><span>{scan.scanId} · {new Date(scan.checkedAt).toLocaleString()}</span><small>{scanKind(scan)} · {scan.scanStatus}</small><small>{dependencyOutcome(scan)}</small></div><div className="history-card-metrics"><b>{scan.findings.length}</b><span>findings</span><small>{scan.verificationHistory.length} verification runs</small></div><ArrowRight size={16} /></button>)}</div>
      : <div className="panel history-empty"><h3>No saved scans</h3><p>Only records acknowledged by persistent storage appear here.</p></div>}
  </div>
}

export function ScanDashboard({ scans, onOpen, onNew }: { scans: ScanSummary[]; onOpen: (scan: ScanSummary) => void; onNew: () => void }) {
  const actual = scans.filter((scan) => !scan.isDemo)
  const findings = actual.flatMap((scan) => scan.findings)
  const metrics = [
    ['Total scans', actual.length, 'Actual records only; demo excluded'],
    ['Completed', actual.filter(isCompleted).length, 'Including completed with limitations'],
    ['Open findings', findings.filter((finding) => finding.status !== 'Fixed').length, 'Across scan records, not unique issues'],
    ['Failed attempts', actual.filter((scan) => scan.scanStatus === 'Failed').length, 'Not counted as successful scans'],
  ]
  return <div className="workspace-view">
    <div className="page-header"><div><div className="eyebrow">Workspace overview</div><h1>Your actual scan records.</h1><p>No seeded results contribute to these counts. Local results last for this browser session.</p></div><button className="button primary" onClick={onNew}><ScanLine size={16} /> New scan</button></div>
    <div className="stats-grid">{metrics.map(([label, value, help]) => <div className="stat-card" key={label}><div className="stat-icon green"><FileArchive size={18} /></div><div><div className="stat-label">{label}</div><div className="stat-value">{value}</div><div className="stat-helper">{help}</div></div></div>)}</div>
    <section className="panel recent-panel"><div className="panel-heading"><div><div className="eyebrow">Activity</div><h3>Recent scans</h3></div></div>
      {actual.length ? <div className="scan-table"><div className="table-row table-head"><span>Target</span><span>Status</span><span>Findings</span><span>Run date</span><span /></div>{[...actual].sort((a, b) => b.checkedAt.localeCompare(a.checkedAt)).map((scan) => <button className="table-row" key={scan.scanId} onClick={() => onOpen(scan)}><span className="target-cell"><span className="target-icon"><FileArchive size={16} /></span><span><strong>{scan.target}</strong><small>{scanKind(scan)} · {scan.scanId}</small></span></span><span className={`pill ${scan.scanStatus === 'Completed' ? 'safe-pill' : 'warning-pill'}`}>{scan.scanStatus}</span><span>{scan.findings.length}</span><span>{new Date(scan.checkedAt).toLocaleString()}</span><ArrowRight size={15} /></button>)}</div> : <div className="empty-state"><h3>No scans yet</h3><p>Run an authorized ZIP or website scan. A failed attempt is recorded without borrowing earlier findings.</p><button className="button secondary" onClick={onNew}>Start a scan</button></div>}
    </section>
  </div>
}

export function SourceAssociation({ scan, sources, onAssociate, onOpen }: { scan: ScanSummary; sources: ScanSummary[]; onAssociate: (source: ScanSummary) => void; onOpen: (source: ScanSummary) => void }) {
  const [selected, setSelected] = useState('')
  if (scanKind(scan) !== 'Website URL' || !isCompleted(scan)) return null
  const linked = sources.find((source) => source.scanId === scan.sourceAssociation?.scanId)
  return <section className="panel scan-card source-association">
    <h3>Separate source evidence</h3><p>A confirmed association is your assertion, not proof that the ZIP is deployed. This website scan retains its own findings and unavailable dependency check.</p>
    {scan.sourceAssociation && <p>Associated: {scan.sourceAssociation.target} · {scan.sourceAssociation.scanId} {linked && <button className="text-button" onClick={() => onOpen(linked)}>Open ZIP results <ArrowRight size={14} /></button>}</p>}
    {sources.length ? <div className="hero-actions"><select aria-label="Source scan to associate" value={selected} onChange={(event) => setSelected(event.target.value)}><option value="">Choose a separately scanned ZIP</option>{sources.map((source) => <option key={source.scanId} value={source.scanId}>{source.target} · {source.scanId}</option>)}</select><button className="button secondary" disabled={!sources.some((source) => source.scanId === selected)} onClick={() => { const source = sources.find((entry) => entry.scanId === selected); if (source) onAssociate(source) }}>Confirm source association</button></div> : <p>Upload and scan a source ZIP first, then reopen this website record from Overview or saved history.</p>}
  </section>
}

export function ReportPreview({ scan }: { scan: ScanSummary }) {
  const payload = createReportPayload(scan)
  return <div className="workspace-view">
    <div className="page-header"><div><div className="eyebrow">Audit trail</div><h1>Take the evidence with you.</h1><p>Downloads use this exact scan record, including failures, limitations, and verification history.</p></div><div className="header-actions"><button className="button secondary" onClick={() => downloadHtmlReport(scan)}><FileText size={15} /> HTML</button><button className="button primary" onClick={() => downloadReport(scan)}><Download size={15} /> Download JSON</button></div></div>
    <div className="report-layout"><div className="report-preview panel">
      <div className="report-top"><h2>VibeGuard</h2><span className="pill warning-pill">{scanKind(scan)} · {scan.scanStatus}</span></div>
      <div className="report-title"><h2>{scan.target}</h2><p className="mono">{scan.scanId} · {new Date(scan.checkedAt).toLocaleString()}</p></div>
      {scan.error && <p role="alert">{scan.errorCode}: {scan.error}</p>}
      <div className="report-metrics"><div><strong>{scan.findings.length}</strong><span>findings</span></div><div><strong>{scan.findings.filter((finding) => finding.confidence === 'Confirmed').length}</strong><span>confirmed evidence</span></div><div><strong>{scan.findings.filter((finding) => finding.status === 'Fixed').length}</strong><span>verified patterns</span></div><div><strong>{scan.fileCount}</strong><span>files checked</span></div></div>
      <section className="report-section"><h3>Coverage ledger</h3>{scan.coverage.length ? scan.coverage.map((check) => <div className="coverage-row" key={check.id}><span className={`coverage-status ${check.status}`} /><div><strong>{check.label} · {check.status}</strong><span>{check.details}</span></div></div>) : <p>No checks executed.</p>}</section>
      <section className="report-section"><h3>Findings</h3>{scan.findings.length ? scan.findings.map((finding) => <div className="report-finding" key={finding.id}><div><strong>{finding.title}</strong><span>{finding.file}{finding.line ? `:${finding.line}` : ''} · {finding.severity} · {finding.confidence} · {finding.status}</span></div></div>) : <p>{isCompleted(scan) ? 'No findings were reported by the executed checks. This is not proof of security.' : 'No completed findings are available.'}</p>}</section>
      <section className="report-section"><h3>Patch Intelligence</h3><p>{dependencyOutcome(scan)}</p><p>{scan.dependencies.length} inventory entries · {scan.runtimes.length} runtime/technology signals</p></section>
      <section className="report-section"><h3>Verification history</h3>{scan.verificationHistory.length ? scan.verificationHistory.map((run) => <div key={run.id}><strong>{run.testType} · {run.passed ? 'Passed' : 'Not passed'}</strong><p>{run.executedAt} · {run.summary}</p></div>) : <p>No verification run recorded.</p>}</section>
      {scan.sourceAssociation && <section className="report-section"><h3>Source association (user confirmed)</h3><p>{scan.sourceAssociation.target} · {scan.sourceAssociation.scanId}</p><p>Results remain separate; deployment identity is not verified.</p></section>}
      <div className="report-limits"><Info size={15} /><div><strong>Limitations are part of the report.</strong>{payload.limitations.map((limit) => <p key={limit}>{limit}</p>)}</div></div>
    </div></div>
  </div>
}

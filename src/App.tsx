import { useEffect, useMemo, useRef, useState } from 'react'
import {
  AlertTriangle,
  ArrowRight,
  BadgeCheck,
  BarChart3,
  BookOpen,
  Bot,
  Check,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  ClipboardCheck,
  CloudUpload,
  Code2,
  Copy,
  Download,
  FileArchive,
  FileCode2,
  FileText,
  Globe2,
  HelpCircle,
  ExternalLink,
  Info,
  LayoutDashboard,
  LockKeyhole,
  Menu,
  Play,
  RefreshCw,
  ScanLine,
  Search,
  Server,
  Shield,
  ShieldCheck,
  Sparkles,
  Terminal,
  UploadCloud,
  UserRound,
  X,
  XCircle,
  Zap,
} from 'lucide-react'
import type { ReactNode } from 'react'
import { buildDemoFinding, fixedFixture, recordAuthorizationVerification, runAuthorizationCheck, vulnerableFixture } from './demo'
import { downloadHtmlReport, downloadReport } from './report'
import type { AuthCheckResult, Finding, ScanRecord, ScanSummary, View } from './types'
import { mergeVerifiedRescan } from './verification'
import { getCurrentUser, listSavedScans, saveScan, signIn, signOut, signUp, type PublicUser } from './api'
import { actualRecords, associateSource, dependencyLabel, dependencyOutcome as describeDependencies, executeScan, isCompleted, pendingScan, scanKind, scanRecord, upsertScan, type ScanAttempt } from './workflow'
import { ScanInput } from './ScanInput'
import { ReportPreview, SavedHistory, ScanDashboard, SourceAssociation } from './ScanViews'

const demoDate = new Date('2026-10-24T12:30:00.000Z').toISOString()

const demoExtraFindings: Finding[] = [
  {
    id: 'DEMO-SECRET-001',
    title: 'Supabase service key is bundled in frontend config',
    rule: 'SECRET-004',
    category: 'Secrets',
    severity: 'Critical',
    confidence: 'Confirmed',
    status: 'Unresolved',
    file: 'src/lib/supabase.ts',
    line: 8,
    evidence: 'const serviceKey = "eyJ••••9kQ"',
    whyItMatters: 'A privileged service credential in browser-shipped code can let an attacker act with the application’s backend permissions.',
    remediation: 'Rotate the key, remove it from the client bundle, and use the public anon key only with strict row-level security policies.',
    prompt: 'Move the privileged Supabase service key out of src/lib/supabase.ts. Rotate it, keep only the anon key in browser code, and enforce row-level security for every user-owned table.',
    isDemo: true,
  },
  {
    id: 'DEMO-CONFIG-001',
    title: 'Database policy is permissive by default',
    rule: 'DB-001',
    category: 'Database',
    severity: 'High',
    confidence: 'Likely',
    status: 'Unresolved',
    file: 'supabase/migrations/001_orders.sql',
    line: 21,
    evidence: 'alter table orders disable row level security;',
    whyItMatters: 'Without a row-level policy, a login check alone does not prove that the current user owns the row being returned.',
    remediation: 'Enable row-level security and add explicit select, insert, update, and delete policies tied to auth.uid().',
    prompt: 'Harden supabase/migrations/001_orders.sql: enable row level security on orders and add policies that require auth.uid() = owner_id. Include a test for cross-user denial.',
    isDemo: true,
  },
]

const initialDemoFindings = [buildDemoFinding(false), ...demoExtraFindings]

const initialDemoScan: ScanSummary = {
  findings: initialDemoFindings,
  scans: [],
  target: 'Acme Orders · controlled demo fixture',
  scanId: 'VG-DEMO-001',
  fileCount: 14,
  checkedAt: demoDate,
  scanTypes: ['Secrets & credentials', 'Configuration patterns', 'Authorization test'],
  isDemo: true,
  coverage: [
    { id: 'source', label: 'Controlled authorization fixture', status: 'not-run', details: 'Synthetic User A/User B orders have not executed yet.' },
    { id: 'secrets', label: 'Secrets & credentials', status: 'not-run', details: 'Not part of the controlled authorization demo.' },
    { id: 'configuration', label: 'Configuration patterns', status: 'not-run', details: 'Not part of the controlled authorization demo.' },
    { id: 'authorization', label: 'Authorization regression test', status: 'not-run', details: 'No authorization test has run for this demo record yet.' },
    { id: 'dependencies', label: 'Dependency advisory matching', status: 'not-run', details: 'Not part of the controlled authorization demo.' },
    { id: 'runtime', label: 'Runtime and framework detection', status: 'not-run', details: 'Not part of the controlled authorization demo.' },
  ],
  runtimes: [],
  dependencies: [],
  verificationHistory: [],
  scanStatus: 'Completed',
}

function formatDate(value: string) {
  return new Intl.DateTimeFormat('en-IN', { day: '2-digit', month: 'short', year: 'numeric' }).format(new Date(value))
}

function formatDateTime(value: string) {
  return new Intl.DateTimeFormat('en-IN', { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value))
}

function severityClass(value: Finding['severity']) {
  return value.toLowerCase().replace(' ', '-')
}

function confidenceClass(value: Finding['confidence']) {
  return value.toLowerCase()
}

function StatCard({ label, value, helper, icon, tone = 'green' }: { label: string; value: string | number; helper: string; icon: ReactNode; tone?: string }) {
  return (
    <div className="stat-card">
      <div className={`stat-icon ${tone}`}>{icon}</div>
      <div>
        <div className="stat-label">{label}</div>
        <div className="stat-value">{value}</div>
        <div className="stat-helper">{helper}</div>
      </div>
    </div>
  )
}

function Logo({ compact = false }: { compact?: boolean }) {
  return (
    <div className={`brand ${compact ? 'compact' : ''}`}>
      <div className="brand-mark"><ShieldCheck size={20} strokeWidth={2.5} /></div>
      {!compact && <div><div className="brand-name">Vibe<span>Guard</span></div><div className="brand-kicker">AI app security</div></div>}
    </div>
  )
}

function Pill({ children, className = '' }: { children: ReactNode; className?: string }) {
  return <span className={`pill ${className}`}>{children}</span>
}

function FindingBadge({ finding }: { finding: Finding }) {
  return <div className="badge-row"><Pill className={`severity ${severityClass(finding.severity)}`}>{finding.severity}</Pill><Pill className={`confidence ${confidenceClass(finding.confidence)}`}>{finding.confidence}</Pill></div>
}

function EmptyState({ title, description, action }: { title: string; description: string; action?: ReactNode }) {
  return <div className="empty-state"><div className="empty-icon"><Search size={24} /></div><h3>{title}</h3><p>{description}</p>{action}</div>
}

function App() {
  const [view, setView] = useState<View>('home')
  const [mobileNavOpen, setMobileNavOpen] = useState(false)
  const [activeScan, setActiveScan] = useState<ScanSummary>(() => pendingScan())
  const [localScans, setLocalScans] = useState<ScanSummary[]>([])
  const [demoScan, setDemoScan] = useState<ScanSummary>(() => ({ ...initialDemoScan, scanId: crypto.randomUUID(), findings: [], scanStatus: 'Pending', scanType: 'Demo', fileCount: 0 }))
  const [selectedFindingId, setSelectedFindingId] = useState('')
  const [filter, setFilter] = useState('All')
  const [targetUrl, setTargetUrl] = useState('')
  const [websiteUrl, setWebsiteUrl] = useState('')
  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  const [scanTypes, setScanTypes] = useState(['secrets', 'authorization', 'configuration', 'codeSafety', 'dependencies'])
  const [authorized, setAuthorized] = useState(false)
  const [scanError, setScanError] = useState('')
  const [isScanning, setIsScanning] = useState(false)
  const [scanPhase, setScanPhase] = useState('')
  const [demoFixed, setDemoFixed] = useState(false)
  const [demoResults, setDemoResults] = useState<AuthCheckResult[] | null>(null)
  const [demoRunning, setDemoRunning] = useState(false)
  const [copied, setCopied] = useState(false)
  const [currentUser, setCurrentUser] = useState<PublicUser | null>(null)
  const [authOpen, setAuthOpen] = useState(false)
  const [authMode, setAuthMode] = useState<'login' | 'signup'>('login')
  const [authError, setAuthError] = useState('')
  const [savedScans, setSavedScans] = useState<ScanSummary[]>([])
  const [historyLoading, setHistoryLoading] = useState(false)
  const [persistenceNotice, setPersistenceNotice] = useState('')
  const scanBusy = useRef(false)
  const accountEpoch = useRef(0)
  const records = actualRecords([...savedScans, ...localScans])

  useEffect(() => {
    const epoch = accountEpoch.current
    getCurrentUser().then(({ user }) => { if (epoch === accountEpoch.current) setCurrentUser(user) }).catch(() => undefined)
  }, [])

  useEffect(() => {
    if (!currentUser) {
      setSavedScans([])
      return
    }
    let cancelled = false
    setHistoryLoading(true)
    listSavedScans().then(({ scans }) => { if (!cancelled) setSavedScans((current) => [...new Map([...scans, ...current].map((scan) => [scan.scanId, scan])).values()]) }).catch((error) => { if (!cancelled) setPersistenceNotice(error instanceof Error ? error.message : 'Saved history is unavailable.') }).finally(() => { if (!cancelled) setHistoryLoading(false) })
    return () => { cancelled = true }
  }, [currentUser])

  const allFindings = activeScan.findings
  const selectedFinding = allFindings.find((item) => item.id === selectedFindingId) ?? allFindings[0]
  const filteredFindings = useMemo(() => {
    if (filter === 'All') return allFindings
    if (filter === 'Confirmed') return allFindings.filter((item) => item.confidence === 'Confirmed')
    if (filter === 'Likely') return allFindings.filter((item) => item.confidence === 'Likely')
    if (filter === 'Resolved') return allFindings.filter((item) => item.status === 'Fixed')
    return allFindings.filter((item) => item.category === filter)
  }, [allFindings, filter])

  const summary = useMemo(() => ({
    confirmed: allFindings.filter((item) => item.confidence === 'Confirmed' && item.status !== 'Fixed').length,
    likely: allFindings.filter((item) => item.confidence === 'Likely' && item.status !== 'Fixed').length,
    resolved: allFindings.filter((item) => item.status === 'Fixed').length,
    critical: allFindings.filter((item) => item.severity === 'Critical' && item.status !== 'Fixed').length,
  }), [allFindings])

  const navigate = (next: View) => {
    setView(next)
    setMobileNavOpen(false)
    window.scrollTo({ top: 0, behavior: 'smooth' })
  }

  const setFinding = (finding: Finding) => {
    if (!finding) return
    setSelectedFindingId(finding.id)
    if (view !== 'findings') navigate('findings')
  }

  const runDemo = (fixed = demoFixed) => {
    setDemoRunning(true)
    setDemoResults(null)
    window.setTimeout(() => {
      const results = runAuthorizationCheck(fixed)
      setDemoResults(results)
      setDemoRunning(false)
      const nextScan = recordAuthorizationVerification(demoScan, results)
      setDemoScan(nextScan)
    }, 700)
  }

  const applyCorrection = () => {
    setDemoFixed(true)
    setDemoResults(null)
    setSelectedFindingId('AUTHZ-DEMO-001')
  }

  const handleFile = (file: File | undefined) => {
    setScanError('')
    setAuthorized(false)
    if (!file) { setSelectedFile(null); return }
    if (!file.name.toLowerCase().endsWith('.zip')) {
      setSelectedFile(null)
      setScanError('Only .zip archives are accepted. VibeGuard never executes uploaded application code.')
      return
    }
    if (file.size > 10 * 1024 * 1024) {
      setSelectedFile(null)
      setScanError('This archive is larger than the 10 MB MVP limit. Split the project or upload a focused source bundle.')
      return
    }
    setSelectedFile(file)
  }

  const runScan = async (attempt: ScanAttempt) => {
    if (scanBusy.current) return
    scanBusy.current = true
    const epoch = accountEpoch.current
    const previous = activeScan
    const compare = attempt.type === 'Source upload' && scanKind(previous) === 'Source upload' && isCompleted(previous) && previous.target === attempt.target && window.confirm('Treat this ZIP as a follow-up for the same project? Only supported checks on files still present can verify changed static patterns. This does not verify runtime authorization.')
    setIsScanning(true)
    setScanError('')
    setPersistenceNotice('')
    setFilter('All')
    setSelectedFindingId('')
    try {
      const outcome = await executeScan(attempt, (scan, phase) => {
        if (accountEpoch.current === epoch) { setActiveScan(scan); setScanPhase(phase) }
      })
      if (accountEpoch.current !== epoch) return
      const result = compare ? mergeVerifiedRescan(previous, outcome.scan) : outcome.scan
      setActiveScan(result)
      setLocalScans((history) => upsertScan(history, result))
      if (outcome.saved && currentUser) setSavedScans((history) => upsertScan(history, result))
      if (outcome.persistenceError) setPersistenceNotice(outcome.persistenceError)
      else if (currentUser && attempt.type === 'Website URL' && isCompleted(result) && !outcome.saved) setPersistenceNotice('This URL result is local only. The API did not confirm saving it; your session may have expired.')
      // The URL endpoint saves its own result. Never infer persistence from login.
      if (currentUser && (attempt.type === 'Source upload' || result.scanStatus === 'Failed')) {
        try {
          const saved = await saveScan(result)
          if (accountEpoch.current === epoch) setSavedScans((history) => upsertScan(history, saved.scan))
        } catch {
          if (accountEpoch.current === epoch) setPersistenceNotice('Results remain available locally, but this scan was not saved to account history.')
        }
      }
      if (accountEpoch.current !== epoch) return
      setSelectedFindingId(result.findings[0]?.id ?? '')
      if (result.scanStatus === 'Failed') setScanError(result.error ?? 'No supported checks completed.')
      else navigate('findings')
    } finally {
      scanBusy.current = false
      setIsScanning(false)
    }
  }

  const startScan = () => runScan({ type: 'Source upload', target: targetUrl || selectedFile?.name || 'New source scan', file: selectedFile, authorized,
    checks: { secrets: scanTypes.includes('secrets'), configuration: scanTypes.includes('configuration'), authorization: scanTypes.includes('authorization'), dependencies: scanTypes.includes('dependencies'), codeSafety: scanTypes.includes('codeSafety') } })
  const startUrlScan = (target: string, confirmed: boolean) => runScan({ type: 'Website URL', target, authorized: confirmed })

  const openScan = (scan: ScanSummary) => { setActiveScan(scan); setFilter('All'); setSelectedFindingId(scan.findings[0]?.id ?? ''); navigate('findings') }
  const attachSource = async (source: ScanSummary) => {
    const confirmed = window.confirm(`Associate ZIP scan ${source.scanId} (${source.target}) with URL scan ${activeScan.scanId}? This records your assertion that they belong together; it does not prove that this source is deployed. Results and dependency inventories stay separate.`)
    if (!confirmed) return
    const associated = associateSource(activeScan, source, confirmed)
    const epoch = accountEpoch.current
    setActiveScan(associated)
    setLocalScans((history) => upsertScan(history, associated))
    if (currentUser && savedScans.some((scan) => scan.scanId === associated.scanId)) {
      try {
        const saved = await saveScan(associated)
        if (epoch === accountEpoch.current) setSavedScans((history) => upsertScan(history, saved.scan))
      } catch { setPersistenceNotice('The source association is local only; account history could not be updated.') }
    }
  }

  const copyPrompt = async () => {
    if (!selectedFinding) return
    await navigator.clipboard?.writeText(selectedFinding.prompt)
    setCopied(true)
    window.setTimeout(() => setCopied(false), 1600)
  }

  const toggleScanType = (type: string) => setScanTypes((current) => current.includes(type) ? current.filter((item) => item !== type) : [...current, type])

  const handleAuth = async (email: string, password: string) => {
    setAuthError('')
    try {
      const result = authMode === 'login' ? await signIn(email, password) : await signUp(email, password)
      accountEpoch.current += 1
      setSavedScans([])
      setCurrentUser(result.user)
      setAuthOpen(false)
      if (authMode === 'signup' && !activeScan.isDemo && isCompleted(activeScan)) {
        const consent = window.confirm('Save the current anonymous scan to this new account? This will not include any other anonymous history.')
        const epoch = accountEpoch.current
        if (consent) saveScan(activeScan).then(({ scan }) => { if (epoch === accountEpoch.current) setSavedScans((history) => upsertScan(history, scan)) }).catch(() => { if (epoch === accountEpoch.current) setPersistenceNotice('Your account was created, but the current scan could not be saved.') })
      }
    } catch (error) {
      setAuthError(error instanceof Error ? error.message : 'Authentication failed.')
    }
  }

  const handleLogout = async () => {
    try { await signOut() } catch { setPersistenceNotice('Logout could not be confirmed. Retry when the API is available.'); return }
    accountEpoch.current += 1
    setCurrentUser(null)
    setSavedScans([])
    setLocalScans([])
    setActiveScan(pendingScan())
    setSelectedFindingId('')
    setPersistenceNotice('')
    setScanError('')
    setView('home')
  }

  const renderView = () => {
    switch (view) {
      case 'dashboard': return <ScanDashboard scans={records} onOpen={openScan} onNew={() => navigate('scan')} />
      case 'scan': return <ScanInput targetUrl={targetUrl} setTargetUrl={setTargetUrl} selectedFile={selectedFile} onFile={handleFile} scanTypes={scanTypes} toggleScanType={toggleScanType} authorized={authorized} setAuthorized={setAuthorized} error={scanError} isScanning={isScanning} phase={scanPhase} scan={activeScan} onStartZip={startScan} onStartUrl={startUrlScan} onDemo={() => navigate('demo')} onReset={() => setScanError('')} websiteUrl={websiteUrl} setWebsiteUrl={setWebsiteUrl} />
      case 'history': return <SavedHistory scans={savedScans} loading={historyLoading} onOpen={openScan} onSignIn={() => { setAuthMode('login'); setAuthOpen(true) }} email={currentUser?.email} />
      case 'findings': return <FindingsView scan={activeScan} findings={filteredFindings} allFindings={allFindings} selected={selectedFinding} filter={filter} setFilter={setFilter} onSelect={setFinding} onCopy={copyPrompt} copied={copied} onDemoVerify={() => navigate('demo')} />
      case 'demo': return <DemoView fixed={demoFixed} setFixed={(fixed) => { setDemoFixed(fixed); setDemoResults(null) }} results={demoResults} running={demoRunning} onRun={() => runDemo()} onApply={applyCorrection} onFindings={() => openScan(demoScan)} />
      case 'patches': return <><SourceAssociation scan={activeScan} sources={records.filter((scan) => scanKind(scan) === 'Source upload' && isCompleted(scan))} onAssociate={attachSource} onOpen={openScan} /><PatchIntelligenceView scan={activeScan} /></>
      case 'report': return <ReportPreview scan={activeScan} />
      default: return <LandingView onScan={() => navigate('scan')} onDemo={() => navigate('demo')} onDashboard={() => navigate('dashboard')} onSignIn={() => { setAuthMode('login'); setAuthOpen(true) }} onHistory={() => navigate('history')} currentUser={currentUser} />
    }
  }

  return (
    <div className="app-shell">
      <header className="topbar">
        <button className="mobile-menu" onClick={() => setMobileNavOpen((open) => !open)} aria-label="Toggle navigation"><Menu size={20} /></button>
        <button className="topbar-logo" onClick={() => navigate('home')} aria-label="Go to VibeGuard home"><Logo /></button>
        <div className="topbar-actions"><div className="authorization-chip"><LockKeyhole size={14} /> Authorized testing only</div>{currentUser ? <><button className="account-link" onClick={() => navigate('history')}>{currentUser.email}</button><button className="button ghost compact-button" onClick={handleLogout}>Log out</button></> : <button className="button ghost compact-button" onClick={() => { setAuthMode('login'); setAuthOpen(true) }}>Sign in</button>}</div>
      </header>
      <aside className={`sidebar ${mobileNavOpen ? 'open' : ''}`}>
        <div className="sidebar-workspace"><div className="workspace-avatar">A</div><div><div className="workspace-name">Acme workspace</div><div className="workspace-plan">MVP workspace <ChevronDown size={13} /></div></div></div>
        <nav className="sidebar-nav">
          <div className="nav-label">Workspace</div>
          <NavItem icon={<LayoutDashboard size={17} />} label="Overview" active={view === 'dashboard'} onClick={() => navigate('dashboard')} />
          <NavItem icon={<ScanLine size={17} />} label="Start a scan" active={view === 'scan'} onClick={() => navigate('scan')} accent />
           <NavItem icon={<AlertTriangle size={17} />} label="Findings" active={view === 'findings'} badge={allFindings.filter((item) => item.status !== 'Fixed').length} onClick={() => navigate('findings')} />
           <NavItem icon={<ShieldCheck size={17} />} label="AuthZ demo" active={view === 'demo'} onClick={() => navigate('demo')} />
           <NavItem icon={<Bot size={17} />} label="Patch intelligence" active={view === 'patches'} onClick={() => navigate('patches')} />
           <NavItem icon={<FileText size={17} />} label="Reports" active={view === 'report'} onClick={() => navigate('report')} />
           <NavItem icon={<FileArchive size={17} />} label="Scan history" active={view === 'history'} onClick={() => navigate('history')} />
          <div className="nav-label nav-label-spaced">Resources</div>
          <NavItem icon={<BookOpen size={17} />} label="How it works" active={false} onClick={() => navigate('home')} />
           <NavItem icon={<HelpCircle size={17} />} label="Security coverage" active={view === 'patches'} onClick={() => navigate('patches')} />
        </nav>
        <div className="sidebar-bottom"><div className="sidebar-tip"><Sparkles size={16} /><div><strong>Build with confidence</strong><span>Run the demo before your pitch.</span></div></div><div className="sidebar-footer"><span>v0.1 MVP</span><span className="status-dot"><i /> Local scanner ready</span></div></div>
      </aside>
      <main className="main-content">
        <div className="main-inner">{persistenceNotice && <div className="persistence-notice"><Info size={15} /> {persistenceNotice}<button onClick={() => setPersistenceNotice('')} aria-label="Dismiss notice"><X size={14} /></button></div>}{renderView()}</div>
      </main>
      {authOpen && <AuthModal mode={authMode} error={authError} onClose={() => setAuthOpen(false)} onModeChange={(mode) => { setAuthMode(mode); setAuthError('') }} onSubmit={handleAuth} />}
    </div>
  )
}

function NavItem({ icon, label, active, onClick, badge, accent }: { icon: ReactNode; label: string; active: boolean; onClick: () => void; badge?: number; accent?: boolean }) {
  return <button className={`nav-item ${active ? 'active' : ''} ${accent ? 'accent' : ''}`} onClick={onClick}>{icon}<span>{label}</span>{badge !== undefined && badge > 0 && <span className="nav-badge">{badge}</span>}</button>
}

function AuthModal({ mode, error, onClose, onModeChange, onSubmit }: { mode: 'login' | 'signup'; error: string; onClose: () => void; onModeChange: (mode: 'login' | 'signup') => void; onSubmit: (email: string, password: string) => void }) {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  return <div className="modal-backdrop" role="presentation" onMouseDown={(event) => { if (event.currentTarget === event.target) onClose() }}><div className="modal-card" role="dialog" aria-modal="true" aria-labelledby="auth-title"><button className="modal-close" onClick={onClose} aria-label="Close"><X size={17} /></button><div className="eyebrow">Optional account</div><h2 id="auth-title">{mode === 'login' ? 'Sign in to save scan history.' : 'Create a VibeGuard account.'}</h2><p>{mode === 'login' ? 'Anonymous scanning still works without an account. Sign in only when you want persistent history.' : 'Accounts use server-side password hashing and protect scan history per user.'}</p><form onSubmit={(event) => { event.preventDefault(); onSubmit(email, password) }}><label>Email<input type="email" autoComplete="email" value={email} onChange={(event) => setEmail(event.target.value)} required /></label><label>Password<input type="password" autoComplete={mode === 'login' ? 'current-password' : 'new-password'} minLength={10} value={password} onChange={(event) => setPassword(event.target.value)} required /><small>At least 10 characters.</small></label>{error && <div className="form-error"><AlertTriangle size={14} /> {error}</div>}<button className="button primary full" type="submit">{mode === 'login' ? 'Sign in' : 'Create account'}</button></form><button className="modal-switch" onClick={() => onModeChange(mode === 'login' ? 'signup' : 'login')}>{mode === 'login' ? 'Need an account? Sign up' : 'Already have an account? Sign in'}</button></div></div>
}

function HistoryView({ scans, loading, onOpen, onSignIn, currentUser }: { scans: ScanSummary[]; loading: boolean; onOpen: (scan: ScanSummary) => void; onSignIn: () => void; currentUser: PublicUser | null }) {
  if (!currentUser) return <div className="workspace-view"><PageHeader eyebrow="Saved history" title="Your scans, when you need them." description="Sign in to save scan records across browser sessions. Anonymous scans remain temporary; download the report before leaving." action={<button className="button primary" onClick={onSignIn}>Sign in</button>} /><div className="panel history-empty"><FileArchive size={28} /><h3>History is optional.</h3><p>Core source scanning, Patch Intelligence, the controlled authorization demo, and report downloads do not require registration.</p></div></div>
  return <div className="workspace-view"><PageHeader eyebrow="Saved history" title="Your scan history." description={`Persistent records for ${currentUser.email}. Anonymous scans are never silently attached to this account.`} action={<Pill className="safe-pill"><LockKeyhole size={13} /> Private to you</Pill>} /><div className="history-retention"><Info size={15} /> Stored scans are associated with your account. Delete or rotate the deployment data store according to your retention policy.</div>{loading ? <div className="panel history-empty"><RefreshCw className="spin-icon" size={24} /><h3>Loading saved scans…</h3></div> : scans.length ? <div className="history-list">{scans.map((scan) => <button className="history-card" key={scan.scanId} onClick={() => onOpen(scan)}><div className="history-card-icon">{scan.target.startsWith('http') ? <Globe2 size={17} /> : scan.isDemo ? <Sparkles size={17} /> : <FileArchive size={17} />}</div><div><strong>{scan.target}</strong><span>{scan.scanId} · {formatDateTime(scan.checkedAt)}</span><small>{scan.scanTypes.join(' · ')}</small></div><div className="history-card-metrics"><b>{scan.findings.length}</b><span>findings</span><small>{scan.findings.filter((finding) => finding.status === 'Fixed').length} fixed · {scan.findings.filter((finding) => finding.confidence === 'Likely').length} likely</small></div><ChevronRight size={17} /></button>)}</div> : <div className="panel history-empty"><FileArchive size={28} /><h3>No saved scans yet.</h3><p>Run a source ZIP or authorized URL scan, then it will appear here.</p></div>}</div>
}

function ProductionScanView({ targetUrl, setTargetUrl, selectedFile, onFile, scanTypes, toggleScanType, authorized, setAuthorized, error, isScanning, progress, onStartZip, onStartUrl, onDemo, onReset, websiteUrl, setWebsiteUrl }: { targetUrl: string; setTargetUrl: (value: string) => void; selectedFile: File | null; onFile: (file: File | undefined) => void; scanTypes: string[]; toggleScanType: (type: string) => void; authorized: boolean; setAuthorized: (value: boolean) => void; error: string; isScanning: boolean; progress: number; onStartZip: () => void; onStartUrl: (target: string) => void; onDemo: () => void; onReset: () => void; websiteUrl: string; setWebsiteUrl: (value: string) => void }) {
  const [mode, setMode] = useState<'zip' | 'url'>('zip')
  const [showUrlModal, setShowUrlModal] = useState(false)
  if (error || isScanning) return <div className="workspace-view"><PageHeader eyebrow="New security scan" title={isScanning ? 'Scanning safely.' : 'The scan did not complete.'} description={isScanning ? 'VibeGuard is running only the selected read-only checks. Uploaded code is not executed.' : 'No successful scan result was saved for this attempt.'} action={<Pill className={isScanning ? 'safe-pill' : 'warning-pill'}>{isScanning ? 'SCAN IN PROGRESS' : 'SCAN FAILED'}</Pill>} /><div className="panel scan-status-panel"><div className={`scan-status-icon ${isScanning ? 'running' : 'failed'}`}>{isScanning ? <RefreshCw size={23} /> : <XCircle size={23} />}</div><h3>{isScanning ? `Running supported checks · ${progress}%` : 'No successful result was reported.'}</h3><p>{isScanning ? 'The URL observer validates destinations and redirects, while source scans stay in memory.' : error}</p>{isScanning && <div className="scan-progress-track"><i style={{ width: `${progress}%` }} /></div>}<div className="hero-actions"><button className="button ghost" onClick={onReset}>Choose another scan</button><button className="button secondary" onClick={onDemo}>Open controlled demo <ArrowRight size={15} /></button></div></div></div>
  return <div className="workspace-view"><PageHeader eyebrow="New security scan" title="Check your next launch." description="Choose a source scan for detailed evidence or an authorized website scan for limited externally observable signals." action={<Pill className="safe-pill"><LockKeyhole size={13} /> Read-only by default</Pill>} /><div className="scan-mode-tabs"><button className={mode === 'zip' ? 'selected' : ''} onClick={() => setMode('zip')}><UploadCloud size={17} /><span><strong>Scan Source ZIP</strong><small>Recommended for detailed findings</small></span></button><button className={mode === 'url' ? 'selected' : ''} onClick={() => setMode('url')}><Globe2 size={17} /><span><strong>Scan Website URL</strong><small>Safe observable checks only</small></span></button></div>{mode === 'zip' ? <div className="scan-layout"><div className="scan-main"><div className="panel scan-card"><div className="scan-card-header"><div className="step-chip">01</div><div><h3>Upload source code</h3><p>Detailed source, configuration, runtime, and dependency evidence.</p></div></div><div className="field-group"><label htmlFor="target">Project identifier <span>optional</span></label><div className="input-wrap"><FileArchive size={17} /><input id="target" value={targetUrl} onChange={(event) => setTargetUrl(event.target.value)} placeholder="e.g. campus-events-web" /></div></div><div className="dropzone" onClick={() => document.getElementById('source-upload-production')?.click()} role="button" tabIndex={0}><input id="source-upload-production" type="file" accept=".zip,application/zip" onChange={(event) => onFile(event.target.files?.[0])} hidden /><div className="upload-icon"><UploadCloud size={23} /></div>{selectedFile ? <><strong>{selectedFile.name}</strong><span>{(selectedFile.size / 1024).toFixed(1)} KB · ready to scan</span><button className="dropzone-link" onClick={(event) => { event.stopPropagation(); onFile(undefined) }}>Choose a different ZIP</button></> : <><strong>Drop your source ZIP here</strong><span>or click to browse · max 10 MB</span><span className="dropzone-link">Read-only source inspection; no npm install and no uploaded code execution.</span></>}</div></div><div className="panel scan-card scan-options"><div className="scan-card-header"><div className="step-chip">02</div><div><h3>Select checks</h3><p>Turn off a check only when you have a reason.</p></div></div><div className="check-grid"><CheckOption checked={scanTypes.includes('secrets')} onClick={() => toggleScanType('secrets')} icon={<LockKeyhole size={16} />} title="Secrets & credentials" body="API keys, tokens, hardcoded passwords" /><CheckOption checked={scanTypes.includes('authorization')} onClick={() => toggleScanType('authorization')} icon={<ShieldCheck size={16} />} title="Authorization patterns" body="Ownership checks and risky data lookups" /><CheckOption checked={scanTypes.includes('configuration')} onClick={() => toggleScanType('configuration')} icon={<Server size={16} />} title="Configuration" body="Environment, framework, and policy signals" /><CheckOption checked={scanTypes.includes('dependencies')} onClick={() => toggleScanType('dependencies')} icon={<Bot size={16} />} title="Patch intelligence" body="Exact lockfile versions and OSV matching" /></div><label className="authorization-check"><input type="checkbox" checked={authorized} onChange={(event) => setAuthorized(event.target.checked)} /><span>I own this project or have explicit authorization to scan it.</span></label><button className="button primary full" onClick={onStartZip}><ScanLine size={16} /> Run source scan</button></div></div><div className="scan-aside"><div className="panel aside-card"><div className="eyebrow">Anonymous access</div><h3>No account required.</h3><p>Anonymous scans are temporary. Download the report before leaving if you want a copy.</p></div><div className="panel aside-card"><div className="eyebrow">Optional history</div><h3>Save across sessions.</h3><p>Sign in only when you want persistent scan history. A scan is never attached silently.</p></div></div></div> : <div className="url-scan-layout"><div className="panel scan-card"><div className="scan-card-header"><div className="step-chip">01</div><div><h3>Enter an authorized website</h3><p>HTTPS only by default. No crawling, credential attacks, or destructive requests.</p></div></div><div className="field-group"><label htmlFor="website-url">Website URL</label><div className="input-wrap"><Globe2 size={17} /><input id="website-url" value={websiteUrl} onChange={(event) => setWebsiteUrl(event.target.value)} placeholder="https://your-app.example" inputMode="url" /></div><small>VibeGuard will inspect availability, redirects, security headers, cookies, and limited technology signals. Exact dependency versions require source or an SBOM.</small></div><div className="url-limitations"><Info size={16} /><div><strong>URL scans are not source scans.</strong><span>They cannot inspect private code, hidden environment variables, internal policies, or every authorization flaw.</span></div></div><button className="button primary" onClick={() => setShowUrlModal(true)}><Globe2 size={16} /> Continue with URL scan</button><button className="button ghost" onClick={() => setMode('zip')}>Upload Source ZIP instead</button></div><div className="panel aside-card"><div className="eyebrow">Safe remote checks</div><h3>Conservative by design.</h3><p>VibeGuard blocks private and restricted destinations, revalidates redirects, limits response size and time, and does not expand scan scope automatically.</p><div className="coverage-list compact-list"><div><span className="coverage-icon confirmed"><Check size={15} /></span><div><strong>Read-only</strong><span>No writes or exploit attempts.</span></div></div><div><span className="coverage-icon likely"><Search size={15} /></span><div><strong>Observable</strong><span>Signals are labeled as inferred or observed.</span></div></div></div></div></div>}{showUrlModal && <div className="modal-backdrop" role="presentation"><div className="modal-card url-confirm-modal" role="dialog" aria-modal="true" aria-labelledby="url-scan-title"><button className="modal-close" onClick={() => setShowUrlModal(false)} aria-label="Close"><X size={17} /></button><div className="eyebrow">Authorized URL scan</div><h2 id="url-scan-title">Want a more detailed security scan?</h2><p>Website URL scanning can inspect only externally observable signals. It cannot reliably inspect private source code, hidden environment variables, internal database permissions, or every authorization flaw.</p><p>For more detailed findings, upload your source-code ZIP. VibeGuard can inspect supported source files, configuration, and dependency manifests.</p><div className="modal-actions"><button className="button primary" onClick={() => { setShowUrlModal(false); onStartUrl(websiteUrl) }}>Continue with URL Scan</button><button className="button secondary" onClick={() => { setShowUrlModal(false); setMode('zip') }}>Upload Source ZIP</button><button className="button ghost" onClick={() => setShowUrlModal(false)}>Cancel</button></div><small className="modal-safety-note"><LockKeyhole size={13} /> By continuing, you confirm that you own this website or have explicit permission to test it.</small></div></div>}</div>
}

function PageHeader({ eyebrow, title, description, action }: { eyebrow?: string; title: string; description?: string; action?: ReactNode }) {
  return <div className="page-header"><div><div className="eyebrow">{eyebrow}</div><h1>{title}</h1>{description && <p>{description}</p>}</div>{action}</div>
}

function LandingView({ onScan, onDemo, onDashboard, onSignIn, onHistory, currentUser }: { onScan: () => void; onDemo: () => void; onDashboard: () => void; onSignIn: () => void; onHistory: () => void; currentUser: PublicUser | null }) {
  return <div className="landing">
     <div className="landing-top"><div className="landing-brand"><Logo /></div><div className="landing-nav"><button onClick={() => document.getElementById('how-it-works')?.scrollIntoView({ behavior: 'smooth' })}>How it works</button><button onClick={() => document.getElementById('coverage')?.scrollIntoView({ behavior: 'smooth' })}>Coverage</button><button onClick={currentUser ? onHistory : onSignIn}>{currentUser ? 'Scan history' : 'Sign in'} <ArrowRight size={14} /></button><button onClick={onDashboard}>Open workspace <ArrowRight size={14} /></button></div></div>
     <section className="hero-section"><div className="hero-copy"><div className="hero-overline"><span className="live-dot" /> Public source and authorized website security checks</div><h1>Build with AI.<br /><em>Launch with confidence.</em></h1><p className="hero-description">Scan source code, investigate known dependency vulnerabilities, and check authorized websites for observable security issues. <strong>No login is required to try the core scanner.</strong></p><div className="hero-actions"><button className="button primary large" onClick={onScan}><ScanLine size={18} /> Scan my app <ArrowRight size={17} /></button><button className="button ghost large" onClick={onDemo}><Play size={16} /> Explore demo</button></div><div className="hero-note"><LockKeyhole size={14} /> Upload Source ZIP is recommended for detailed findings. URL scans are read-only and limited.</div></div><HeroVisual onDemo={onDemo} /></section>
    <section className="trust-strip"><span>Designed for builders using</span><strong><Sparkles size={14} /> Lovable</strong><strong><Zap size={14} /> Bolt</strong><strong><Code2 size={14} /> Cursor</strong><strong><Terminal size={14} /> Replit</strong><span className="trust-end">No paid API key required for the MVP <CheckCircle2 size={15} /></span></section>
    <section className="landing-section" id="how-it-works"><div className="section-heading"><div><div className="eyebrow">From “probably fine” to proven</div><h2>A security check that shows its work.</h2></div><p>VibeGuard does not turn model guesses into scary red alerts. Each result is backed by source evidence or a controlled test you can repeat.</p></div><div className="feature-grid"><FeatureCard number="01" icon={<FileCode2 size={21} />} title="Scan the code you actually ship" body="Upload a source ZIP and run deterministic checks for secrets, credentials, risky configuration, and authorization patterns." /><FeatureCard number="02" icon={<ClipboardCheck size={21} />} title="See evidence in plain English" body="Every finding includes a redacted code location, confidence status, why it matters, and a fix prompt for your AI assistant." /><FeatureCard number="03" icon={<BadgeCheck size={21} />} title="Verify the correction" body="Run the same two-user authorization test again. The issue only turns fixed when unauthorized access is actually blocked." /></div></section>
    <section className="landing-section coverage-section" id="coverage"><div className="coverage-panel"><div className="coverage-copy"><div className="eyebrow">The VibeGuard difference</div><h2>Not just a vulnerability list.</h2><p>Beginners need to know what happened, not just what a scanner predicts. VibeGuard keeps <strong>confirmed</strong>, <strong>likely</strong>, and <strong>informational</strong> results separate.</p><div className="coverage-list"><div><span className="coverage-icon confirmed"><Check size={15} /></span><div><strong>Confirmed</strong><span>Reproduced by a safe, authorized test.</span></div></div><div><span className="coverage-icon likely"><Search size={15} /></span><div><strong>Likely</strong><span>Supported by source evidence; needs review or retest.</span></div></div><div><span className="coverage-icon info"><Info size={15} /></span><div><strong>Informational</strong><span>A security recommendation, never a fabricated incident.</span></div></div></div><button className="button secondary" onClick={onDemo}>Try the two-user demo <ArrowRight size={15} /></button></div><div className="mini-finding-card"><div className="mini-card-top"><span className="mini-status"><span /> Confirmed by test</span><span className="mono">AUTHZ-DEMO-001</span></div><h3>User B can read User A’s order</h3><p className="mono">demo/api/orders.ts:3</p><div className="evidence-snippet"><span className="line-number">03</span><span>db.orders.find({'{'} id: req.params.id {'}'})</span></div><div className="mini-card-result"><XCircle size={16} /><span>Test returned <strong>ord_vg_001</strong> to User B</span></div><div className="mini-card-footer"><span>Critical</span><span>Run verification →</span></div></div></div></section>
    <section className="landing-cta"><div><div className="eyebrow">Ready when you are</div><h2>Ship the idea. Don’t ship the leak.</h2><p>Start with a controlled demo or scan a source archive in under a minute.</p></div><div className="hero-actions"><button className="button primary" onClick={onScan}>Start a scan <ArrowRight size={16} /></button><button className="button ghost" onClick={onDemo}>See the proof first</button></div></section>
    <footer className="landing-footer"><Logo /><span>© 2026 VibeGuard · Built for responsible AI-assisted development</span><span className="footer-limitation"><Info size={14} /> A clean scan is not a security certification.</span></footer>
  </div>
}

function HeroVisual({ onDemo }: { onDemo: () => void }) {
  return <div className="hero-visual"><div className="visual-glow" /><div className="scan-window"><div className="window-top"><div className="window-dots"><i /><i /><i /></div><span className="mono">vibeguard / acme-orders</span><span className="window-lock"><LockKeyhole size={13} /> authorized</span></div><div className="visual-body"><div className="visual-sidebar"><div className="visual-sidebar-logo"><Shield size={16} /></div><span className="active-line" /><span /><span /><span /><span /></div><div className="visual-main"><div className="visual-title"><div><span className="mono">SCAN / VG-DEMO-001</span><h3>Security posture</h3></div><span className="demo-pill">DEMO DATA</span></div><div className="visual-score"><div className="ring"><div><strong>3</strong><span>findings</span></div></div><div><span className="score-label">Attention needed</span><p>2 confirmed · 1 likely</p><div className="score-bar"><i /></div></div></div><div className="visual-findings"><div className="visual-finding critical"><span className="finding-dot" /><div><strong>Cross-user order access</strong><span>Confirmed by test · AUTHZ</span></div><span>Critical</span></div><div className="visual-finding high"><span className="finding-dot" /><div><strong>Service key in frontend</strong><span>Confirmed · SECRETS</span></div><span>Critical</span></div><div className="visual-finding likely"><span className="finding-dot" /><div><strong>Permissive DB policy</strong><span>Evidence found · DATABASE</span></div><span>High</span></div></div><button className="visual-action" onClick={onDemo}>Open controlled demo <ArrowRight size={13} /></button></div></div></div><div className="floating-proof"><div className="proof-icon"><CheckCircle2 size={18} /></div><div><strong>Evidence attached</strong><span>3 checks completed just now</span></div><Sparkles size={16} /></div></div>
}

function FeatureCard({ number, icon, title, body }: { number: string; icon: ReactNode; title: string; body: string }) {
  return <div className="feature-card"><div className="feature-top"><span className="feature-number">{number}</span><span className="feature-icon">{icon}</span></div><h3>{title}</h3><p>{body}</p><ArrowRight className="feature-arrow" size={17} /></div>
}

function DashboardView({ scan, history, summary, onNavigate, onSelectFinding }: { scan: ScanSummary; history: ScanRecord[]; summary: { confirmed: number; likely: number; resolved: number; critical: number }; onNavigate: (view: View) => void; onSelectFinding: (finding: Finding) => void }) {
  const status = summary.critical > 0 ? 'Needs attention' : summary.confirmed + summary.likely > 0 ? 'Review recommended' : 'No open findings'
  return <div className="workspace-view"><PageHeader eyebrow="Workspace overview" title="Good morning, builder." description="A clear read on the security of your AI-built applications." action={<button className="button primary" onClick={() => onNavigate('scan')}><ScanLine size={16} /> New scan</button>} />
     {scan.isDemo ? <div className="demo-banner"><div className="demo-banner-icon"><Sparkles size={18} /></div><div><strong>You’re viewing seeded demonstration data</strong><span>Use the AuthZ demo or upload your own ZIP to replace it with a real scan.</span></div><button onClick={() => onNavigate('demo')}>Run demo <ArrowRight size={15} /></button></div> : <div className="demo-banner real-scan-banner"><div className="demo-banner-icon"><CheckCircle2 size={18} /></div><div><strong>Latest scan: {scan.target}</strong><span>{scan.scanId} · This workspace view is based on your actual scan record.</span></div><button onClick={() => onNavigate('history')}>View history <ArrowRight size={15} /></button></div>}
    <div className="status-hero"><div className="status-copy"><div className="status-kicker"><span className="live-dot" /> Current security status</div><h2>{status}</h2><p>{summary.critical > 0 ? 'Start with the confirmed authorization and secret findings below.' : 'VibeGuard has no confirmed open findings in this workspace.'}</p><button className="text-button" onClick={() => onNavigate('findings')}>Review findings <ArrowRight size={15} /></button></div><div className="status-orbit"><div className="orbit-ring"><div className="orbit-core"><ShieldCheck size={30} /><span>{summary.resolved > 0 ? 'verified' : 'open'}</span></div></div><div className="orbit-label label-top"><strong>{summary.confirmed}</strong><span>confirmed</span></div><div className="orbit-label label-right"><strong>{summary.likely}</strong><span>likely</span></div><div className="orbit-label label-bottom"><strong>{summary.resolved}</strong><span>resolved</span></div></div></div>
    <div className="stats-grid"><StatCard label="Total scans" value={history.length} helper="Across this workspace" icon={<BarChart3 size={18} />} /><StatCard label="Confirmed findings" value={summary.confirmed} helper="Reproduced or strongly evidenced" icon={<AlertTriangle size={18} />} tone="red" /><StatCard label="Likely findings" value={summary.likely} helper="Need review or retest" icon={<Search size={18} />} tone="amber" /><StatCard label="Issues resolved" value={summary.resolved} helper="Verified by a follow-up check" icon={<BadgeCheck size={18} />} tone="blue" /></div>
    <div className="dashboard-grid"><div className="panel recent-panel"><div className="panel-heading"><div><div className="eyebrow">Activity</div><h3>Recent scans</h3></div><button className="text-button" onClick={() => onNavigate('scan')}>New scan <ArrowRight size={14} /></button></div><div className="scan-table"><div className="table-row table-head"><span>Target</span><span>Status</span><span>Findings</span><span>Run date</span><span /></div>{history.slice(0, 4).map((item) => <button className="table-row" key={item.id} onClick={() => onNavigate(item.isDemo ? 'demo' : 'findings')}><span className="target-cell"><span className={`target-icon ${item.type === 'Demo' ? 'demo' : ''}`}>{item.type === 'Demo' ? <Sparkles size={15} /> : <FileArchive size={15} />}</span><span><strong>{item.name}</strong><small className="mono">{item.id}</small></span></span><span><Pill className="status-complete"><CheckCircle2 size={12} /> {item.status}</Pill></span><span className="finding-count"><strong>{item.findingCount}</strong><small>{item.confirmedCount} confirmed</small></span><span className="muted">{formatDate(item.createdAt)}</span><ChevronRight size={16} className="row-arrow" /></button>)}</div></div><div className="panel quick-panel"><div className="panel-heading"><div><div className="eyebrow">Next best step</div><h3>Review what matters</h3></div></div><div className="quick-finding" onClick={() => onSelectFinding(scan.findings[0])}><div className="quick-finding-top"><Pill className="severity critical">Critical</Pill><span className="mono">{scan.findings[0]?.rule}</span></div><h4>{scan.findings[0]?.title}</h4><p>{scan.findings[0]?.evidence}</p><span className="text-button">Open evidence <ArrowRight size={14} /></span></div><div className="quick-links"><button onClick={() => onNavigate('demo')}><ShieldCheck size={16} /> Test authorization <ArrowRight size={14} /></button><button onClick={() => onNavigate('report')}><Download size={16} /> Download report <ArrowRight size={14} /></button></div></div></div>
  </div>
}

function ScanView({ targetUrl, setTargetUrl, selectedFile, onFile, scanTypes, toggleScanType, authorized, setAuthorized, error, isScanning, progress, onStart, onDemo, onReset }: { targetUrl: string; setTargetUrl: (value: string) => void; selectedFile: File | null; onFile: (file: File | undefined) => void; scanTypes: string[]; toggleScanType: (type: string) => void; authorized: boolean; setAuthorized: (value: boolean) => void; error: string; isScanning: boolean; progress: number; onStart: () => void; onDemo: () => void; onReset: () => void }) {
  if (error || isScanning) return <div className="workspace-view"><PageHeader eyebrow="New security scan" title={isScanning ? 'Scanning the source safely.' : 'The scan did not complete.'} description={isScanning ? 'VibeGuard is inspecting supported source text in memory. Uploaded application code is not executed.' : 'No successful source result was saved for this attempt. Review the error, then choose another archive or use the controlled demo.'} action={<Pill className={isScanning ? 'safe-pill' : 'warning-pill'}>{isScanning ? 'SCAN IN PROGRESS' : 'SCAN FAILED'}</Pill>} /><div className="panel scan-status-panel"><div className={`scan-status-icon ${isScanning ? 'running' : 'failed'}`}>{isScanning ? <RefreshCw size={23} /> : <XCircle size={23} />}</div><h3>{isScanning ? `Checking source files · ${progress}%` : 'No findings were reported as successful.'}</h3><p>{isScanning ? 'Archive validation, JavaScript rules, configuration checks, and dependency coverage are being evaluated.' : error}</p>{isScanning && <div className="scan-progress-track"><i style={{ width: `${progress}%` }} /></div>}<div className="hero-actions"><button className="button ghost" onClick={onReset}>Choose another ZIP</button><button className="button secondary" onClick={onDemo}>Open controlled demo <ArrowRight size={15} /></button></div></div></div>
  return <div className="workspace-view"><PageHeader eyebrow="New security scan" title="Check your next launch." description="Start with a source archive. Remote application testing is intentionally gated in this MVP." action={<Pill className="safe-pill"><LockKeyhole size={13} /> Read-only by default</Pill>} />
    <div className="scan-layout"><div className="scan-main"><div className="panel scan-card"><div className="scan-card-header"><div className="step-chip">01</div><div><h3>Choose what to scan</h3><p>Upload a ZIP of the source you intend to ship.</p></div></div><div className="field-group"><label htmlFor="target">Target name <span>optional</span></label><div className="input-wrap"><Globe2 size={17} /><input id="target" value={targetUrl} onChange={(event) => setTargetUrl(event.target.value)} placeholder="e.g. campus-events-web" /></div><small>For a live URL, we only record the identifier. No remote request is made in this MVP.</small></div><div className="dropzone" onClick={() => document.getElementById('source-upload')?.click()} role="button" tabIndex={0} onKeyDown={(event) => { if (event.key === 'Enter') document.getElementById('source-upload')?.click() }}><input id="source-upload" type="file" accept=".zip,application/zip" onChange={(event) => onFile(event.target.files?.[0])} hidden /><div className="upload-icon"><UploadCloud size={23} /></div>{selectedFile ? <><strong>{selectedFile.name}</strong><span>{(selectedFile.size / 1024).toFixed(1)} KB · ready to scan</span><button className="dropzone-link" onClick={(event) => { event.stopPropagation(); onFile(undefined) }}>Choose a different ZIP</button></> : <><strong>Drop your source ZIP here</strong><span>or click to browse · max 10 MB</span><span className="dropzone-link">We reject path traversal and never execute uploaded code.</span></>}</div></div><div className="panel scan-card scan-options"><div className="scan-card-header"><div className="step-chip">02</div><div><h3>Select checks</h3><p>Turn off a check only when you have a reason.</p></div></div><div className="check-grid"><CheckOption checked={scanTypes.includes('secrets')} onClick={() => toggleScanType('secrets')} icon={<LockKeyhole size={16} />} title="Secrets & credentials" body="API keys, tokens, hardcoded passwords" /><CheckOption checked={scanTypes.includes('authorization')} onClick={() => toggleScanType('authorization')} icon={<UserRound size={16} />} title="Authorization patterns" body="Ownership filters and access checks" /><CheckOption checked={scanTypes.includes('configuration')} onClick={() => toggleScanType('configuration')} icon={<Terminal size={16} />} title="Configuration safety" body=".env handling and risky database settings" /></div></div><div className="panel scan-card"><div className="scan-card-header"><div className="step-chip">03</div><div><h3>Confirm authorization</h3><p>You must own the target or have explicit permission to test it.</p></div></div><label className={`authorization-check ${authorized ? 'checked' : ''}`}><input type="checkbox" checked={authorized} onChange={(event) => setAuthorized(event.target.checked)} /><span className="custom-check">{authorized && <Check size={14} />}</span><span>I confirm I own this application or have explicit authorization to test it. I understand the scanner is read-only and does not certify complete security.</span></label>{error && <div className="error-box"><AlertTriangle size={16} /><span>{error}</span></div>}<div className="scan-actions"><button className="button primary large" onClick={onStart} disabled={isScanning}>{isScanning ? <><RefreshCw size={17} className="spin" /> Scanning {progress}%</> : <><ScanLine size={17} /> Run secure scan</>}</button><button className="button ghost" onClick={onDemo}><Sparkles size={16} /> Use controlled demo</button></div>{isScanning && <div className="progress-track"><div style={{ width: `${progress}%` }} /></div>}</div></div><aside className="scan-aside"><div className="aside-card demo-aside"><div className="aside-icon"><Sparkles size={18} /></div><div className="eyebrow">No source handy?</div><h3>Run the two-user proof.</h3><p>See User B attempt to read User A’s order, then apply a correction and rerun the test.</p><button className="text-button" onClick={onDemo}>Open controlled demo <ArrowRight size={15} /></button></div><div className="aside-card"><div className="aside-heading"><ShieldCheck size={18} /><strong>What happens to uploads?</strong></div><ul className="plain-list"><li><CheckCircle2 size={14} /> ZIP and file size are validated</li><li><CheckCircle2 size={14} /> Archive traversal is rejected</li><li><CheckCircle2 size={14} /> Supported text files are scanned locally</li><li><CheckCircle2 size={14} /> Secrets are redacted in evidence</li></ul><div className="limitation-note"><Info size={15} /> Unsupported areas are disclosed in the report.</div></div></aside></div>
  </div>
}

function CheckOption({ checked, onClick, icon, title, body }: { checked: boolean; onClick: () => void; icon: ReactNode; title: string; body: string }) {
  return <button className={`check-option ${checked ? 'selected' : ''}`} onClick={onClick}><span className="option-check">{checked && <Check size={14} />}</span><span className="option-icon">{icon}</span><span><strong>{title}</strong><small>{body}</small></span></button>
}

function FindingsView({ scan, findings, allFindings, selected, filter, setFilter, onSelect, onCopy, copied, onDemoVerify }: { scan: ScanSummary; findings: Finding[]; allFindings: Finding[]; selected?: Finding; filter: string; setFilter: (value: string) => void; onSelect: (finding: Finding) => void; onCopy: () => void; copied: boolean; onDemoVerify: () => void }) {
  const scanLabel = `${scanKind(scan)} · ${scan.scanStatus}`
  const emptyDescription = isCompleted(scan) ? 'No findings match this view. Only executed checks contribute results; review coverage and limitations in Patch Intelligence. No matches are not proof of security.' : scan.error ?? 'No completed result is available. Start a scan and review its coverage.'
  return <div className="workspace-view findings-view"><PageHeader eyebrow="Evidence center" title="Findings, not guesses." description={`${allFindings.length} finding${allFindings.length === 1 ? '' : 's'} from the current scan. Start with confirmed evidence, then review likely patterns.`} action={<div className="header-actions"><Pill className={scan.isDemo ? 'demo-pill' : scan.scanStatus === 'Completed' ? 'safe-pill' : 'warning-pill'}>{scanLabel}</Pill><button className="button secondary" onClick={() => window.print()}><FileText size={15} /> Print view</button></div>} />
    <div className="finding-summary-strip"><div><span className="summary-dot red" /><strong>{allFindings.filter((item) => item.confidence === 'Confirmed').length}</strong><span>confirmed</span></div><div><span className="summary-dot amber" /><strong>{allFindings.filter((item) => item.confidence === 'Likely').length}</strong><span>likely</span></div><div><span className="summary-dot green" /><strong>{allFindings.filter((item) => item.status === 'Fixed').length}</strong><span>fixed</span></div><div className="strip-note"><Info size={15} /> A finding is only “confirmed” when evidence or an authorized test supports it.</div></div>
     <div className="findings-layout"><div className="findings-list-panel"><div className="filter-row">{['All', 'Confirmed', 'Likely', 'Resolved', 'Authorization', 'Secrets', 'Database', 'Business logic', 'Configuration'].map((item) => <button key={item} className={filter === item ? 'selected' : ''} onClick={() => setFilter(item)}>{item}{item !== 'All' && <span>{item === 'Confirmed' ? allFindings.filter((f) => f.confidence === 'Confirmed').length : item === 'Likely' ? allFindings.filter((f) => f.confidence === 'Likely').length : item === 'Resolved' ? allFindings.filter((f) => f.status === 'Fixed').length : allFindings.filter((f) => f.category === item).length}</span>}</button>)}</div><div className="findings-list">{findings.length ? findings.map((finding) => <button className={`finding-list-item ${selected?.id === finding.id ? 'selected' : ''}`} key={finding.id} onClick={() => onSelect(finding)}><div className="finding-list-top"><span className={`severity-dot ${severityClass(finding.severity)}`} /><span className="finding-category">{finding.category}</span><span className="finding-status">{finding.status === 'Fixed' ? <CheckCircle2 size={13} /> : finding.status}</span></div><h3>{finding.title}</h3><div className="finding-list-meta"><span className={`mini-severity ${severityClass(finding.severity)}`}>{finding.severity}</span><span>{finding.file}:{finding.line ?? 'n/a'}</span></div><ChevronRight size={16} className="finding-chevron" /></button>) : <EmptyState title="No findings in this view" description={emptyDescription} />}</div></div><FindingDetail finding={selected} onCopy={onCopy} copied={copied} onDemoVerify={onDemoVerify} /></div>
  </div>
}

function FindingDetail({ finding, onCopy, copied, onDemoVerify }: { finding?: Finding; onCopy: () => void; copied: boolean; onDemoVerify: () => void }) {
  if (!finding) return <div className="finding-detail-panel"><EmptyState title="Select a finding" description="Choose a finding on the left to inspect its evidence and remediation." /></div>
  return <div className="finding-detail-panel"><div className="detail-heading"><div><div className="detail-rule mono">{finding.rule} · {finding.category}</div><h2>{finding.title}</h2><FindingBadge finding={finding} /></div><div className={`detail-status ${finding.status === 'Fixed' ? 'fixed' : ''}`}>{finding.status === 'Fixed' ? <CheckCircle2 size={15} /> : <AlertTriangle size={15} />}{finding.status}</div></div><div className="detail-location"><FileCode2 size={15} /><span className="mono">{finding.file}</span>{finding.line && <span className="line-pill">line {finding.line}</span>}</div><section className="detail-section"><div className="detail-section-title"><span className="section-number">01</span><div><h3>Evidence</h3><p>What VibeGuard observed</p></div></div><div className="evidence-block"><div className="evidence-block-top"><span className="evidence-label"><span /> Redacted evidence</span><span className="mono">{finding.confidence === 'Confirmed' ? 'test-backed' : 'static signal'}</span></div><code>{finding.evidence}</code></div></section><section className="detail-section"><div className="detail-section-title"><span className="section-number">02</span><div><h3>Why it matters</h3><p>In plain English</p></div></div><p className="detail-copy">{finding.whyItMatters}</p></section><section className="detail-section"><div className="detail-section-title"><span className="section-number">03</span><div><h3>Recommended fix</h3><p>Review before applying</p></div></div><p className="detail-copy">{finding.remediation}</p></section><section className="detail-section prompt-section"><div className="detail-section-title"><span className="section-number">04</span><div><h3>Prompt for your AI assistant</h3><p>Contextual, but never a substitute for verification</p></div></div><div className="prompt-box"><code>{finding.prompt}</code><button className="copy-button" onClick={onCopy}>{copied ? <><Check size={15} /> Copied</> : <><Copy size={15} /> Copy prompt</>}</button></div></section>{finding.isDemo && <div className="verify-callout"><div className="callout-icon"><ShieldCheck size={18} /></div><div><strong>Verification is available for this demo finding</strong><p>Run the same two-user test after applying the ownership check. VibeGuard will only mark it fixed when the unauthorized request is denied.</p></div><button className="button secondary" onClick={onDemoVerify}>Open test <ArrowRight size={14} /></button></div>}</div>
}

function DemoView({ fixed, setFixed, results, running, onRun, onApply, onFindings }: { fixed: boolean; setFixed: (value: boolean) => void; results: AuthCheckResult[] | null; running: boolean; onRun: () => void; onApply: () => void; onFindings: () => void }) {
  const passed = results?.every((item) => item.passed)
  return <div className="workspace-view"><PageHeader eyebrow="Controlled security lab" title="Prove the authorization check." description="A safe, synthetic two-user workflow that demonstrates a real broken-object-level-authorization flaw." action={<Pill className="safe-pill"><LockKeyhole size={13} /> No external target</Pill>} />
    <div className="demo-lab-banner"><div className="demo-banner-icon"><Sparkles size={18} /></div><div><strong>Demonstration data only</strong><span>User A, User B, and order totals are synthetic fixtures. No live application is contacted.</span></div><div className="lab-state"><span className={fixed ? 'fixed-state' : 'open-state'} />{fixed ? 'Correction staged' : 'Vulnerable fixture'}</div></div>
    <div className="lab-layout"><div className="lab-main"><div className="panel lab-panel"><div className="lab-panel-header"><div><div className="eyebrow">The scenario</div><h3>Can User B read User A’s order?</h3><p>Authentication succeeds for both users. The question is whether the API checks ownership before returning the row.</p></div><div className="test-illustration"><div className="user-bubble"><UserRound size={17} /><span>User A</span></div><div className="connection-line"><span>{fixed ? 'blocked' : 'leaked'}</span></div><div className="user-bubble user-b"><UserRound size={17} /><span>User B</span></div></div></div><div className="actor-grid"><div className="actor-card"><div className="actor-card-top"><div className="actor-avatar user-a">A</div><span>Owner</span></div><h4>User A</h4><p>Owns <strong>ord_vg_001</strong></p><span className="order-chip"><FileText size={13} /> ₹4,280 order</span></div><div className={`access-card ${fixed ? 'blocked' : 'leaked'}`}><div className="access-icon">{fixed ? <LockKeyhole size={20} /> : <AlertTriangle size={20} />}</div><div><strong>{fixed ? 'Ownership enforced' : 'Ownership missing'}</strong><span>{fixed ? 'Server returns 403' : 'Request returned order'}</span></div></div><div className="actor-card"><div className="actor-card-top"><div className="actor-avatar user-b">B</div><span>Attacker simulation</span></div><h4>User B</h4><p>Requests <strong>ord_vg_001</strong></p><span className="order-chip"><Globe2 size={13} /> GET /orders/:id</span></div></div></div><div className="panel code-compare"><div className="compare-header"><div><div className="eyebrow">The code path</div><h3>One filter changes the result.</h3></div><div className="toggle-wrap"><span>{fixed ? 'Corrected' : 'Vulnerable'}</span><button className={`toggle ${fixed ? 'on' : ''}`} onClick={() => setFixed(!fixed)} aria-label="Toggle corrected fixture"><i /></button></div></div><div className="code-columns"><div><div className="code-label vulnerable-label"><span /> Vulnerable fixture</div><pre><code>{vulnerableFixture.trim()}</code></pre></div><div><div className="code-label fixed-label"><span /> Corrected fixture</div><pre><code>{fixedFixture.trim()}</code></pre></div></div><div className="code-note"><Info size={15} /> This demo compares isolated in-memory fixtures. It does not execute arbitrary uploaded code.</div></div><div className="panel test-results"><div className="test-results-header"><div><div className="eyebrow">Actual test run</div><h3>{results ? (passed ? 'All authorization checks passed' : 'The flaw reproduced') : 'Ready to run the proof'}</h3><p>{results ? `${results.filter((item) => item.passed).length} of ${results.length} checks passed.` : 'Run the test to make the evidence concrete.'}</p></div><button className="button primary" onClick={onRun} disabled={running}>{running ? <><RefreshCw size={16} className="spin" /> Running…</> : <><Play size={16} /> {results ? 'Run again' : 'Run authorization test'}</>}</button></div>{results ? <div className="result-list">{results.map((result) => <div className={`result-row ${result.passed ? 'passed' : 'failed'}`} key={result.id}><span className="result-icon">{result.passed ? <CheckCircle2 size={17} /> : <XCircle size={17} />}</span><div><strong>{result.label}</strong><span>{result.actor} → {result.target}</span></div><div className="result-expect"><span>Expected: {result.expected}</span><strong>{result.actual}</strong></div><span className="result-status">{result.passed ? 'PASS' : 'FAIL'}</span></div>)}</div> : <div className="test-placeholder"><div className="test-placeholder-icon"><ClipboardCheck size={22} /></div><span>VibeGuard will execute three safe requests: cross-user denial, owner self-access, and legitimate peer access.</span></div>}</div></div><aside className="lab-aside"><div className="aside-card correction-card"><div className="eyebrow">Fix → verify</div><h3>Try the complete loop.</h3><ol className="lab-steps"><li className={!fixed ? 'current' : 'done'}><span>{fixed ? <Check size={13} /> : '1'}</span><div><strong>Reproduce</strong><small>See User B receive User A’s order.</small></div></li><li className={fixed ? 'current' : ''}><span>{fixed ? '2' : '2'}</span><div><strong>Apply correction</strong><small>Scope the query to the session owner.</small></div></li><li><span>3</span><div><strong>Verify</strong><small>Block the cross-user request, keep self-access.</small></div></li></ol>{!fixed ? <button className="button secondary full" onClick={onApply}><Code2 size={15} /> Apply correction in demo</button> : <button className="button primary full" onClick={onRun} disabled={running}><ClipboardCheck size={15} /> Verify correction</button>}{results && passed && <div className="verified-callout"><BadgeCheck size={16} /><span><strong>Verified in this fixture</strong>User B was denied and both legitimate checks passed.</span></div>}</div><div className="aside-card"><div className="aside-heading"><ShieldCheck size={18} /><strong>Why this matters</strong></div><p className="aside-copy">A login proves identity. It does not prove ownership. Every user-owned read and write needs an authorization decision on the server.</p><button className="text-button" onClick={onFindings}>See finding details <ArrowRight size={14} /></button></div></aside></div>
  </div>
}

const hostingGuidance: Record<string, { owner: string; action: string; provider: string; validate: string; docs: string }> = {
  'Not sure': {
    owner: 'Start in source control and your deployment settings. Do not upload production credentials to VibeGuard.',
    action: 'Remove secrets from source, rotate exposed values, and confirm which platform injects environment variables at deploy time.',
    provider: 'The hosting provider may manage the operating system and runtime patch level; your team still owns application code, dependencies, and access policy.',
    validate: 'Rescan the corrected source, redeploy through your normal pipeline, and verify the relevant application or authorization test.',
    docs: 'https://owasp.org/www-project-cheat-sheets/cheatsheets/Secrets_Management_Cheat_Sheet.html',
  },
  Vercel: {
    owner: 'Source code and project environment variables are controlled by your team.',
    action: 'Rotate exposed values, remove them from client-side code, and store server-only values in Vercel Environment Variables.',
    provider: 'Vercel manages the deployment platform. It does not automatically fix application authorization or an unsafe dependency.',
    validate: 'Create a preview deployment, exercise the protected route, and run the source scan again before promoting to production.',
    docs: 'https://vercel.com/docs/environment-variables',
  },
  Netlify: {
    owner: 'Source code and site environment variables are controlled by your team.',
    action: 'Use Netlify environment variables for server/build configuration and ensure privileged values are never exposed in browser bundles.',
    provider: 'Netlify manages build and hosting infrastructure. Application-level ownership checks remain your responsibility.',
    validate: 'Run a deploy preview, test the corrected route with two users, and rescan the source bundle.',
    docs: 'https://docs.netlify.com/build/environment-variables/',
  },
  Replit: {
    owner: 'Source code, Replit Secrets, and application access rules are controlled by your team.',
    action: 'Move credentials into Replit Secrets, rotate any value committed to source, and keep authorization checks on the server.',
    provider: 'Replit manages the workspace and runtime surface; it does not prove that a route enforces record ownership.',
    validate: 'Run the controlled regression test or an equivalent integration test after restarting the deployment.',
    docs: 'https://docs.replit.com/replit-workspace/workspace-features/secrets',
  },
  Hostinger: {
    owner: 'Your team controls application code and the hosting panel settings available on the selected plan.',
    action: 'Use the provider’s environment-variable or application configuration mechanism, and confirm the plan supports the runtime version you need.',
    provider: 'OS and runtime patching depends on the product plan. Do not assume shared hosting gives you server-administration access.',
    validate: 'Confirm the deployed runtime separately from manifest evidence, then rerun the source and authorization checks.',
    docs: 'https://support.hostinger.com/en/',
  },
  Docker: {
    owner: 'Your team controls the image, Dockerfile, runtime configuration, and secret injection.',
    action: 'Do not bake secrets into image layers. Rebuild from a corrected lockfile and inject runtime secrets through the orchestrator or secret store.',
    provider: 'Docker is packaging, not a vulnerability database or authorization control. The registry and host still need separate access controls.',
    validate: 'Rebuild without cached secret layers, inspect the image configuration, and run the application regression test in an isolated environment.',
    docs: 'https://docs.docker.com/engine/swarm/secrets/',
  },
  'Self-managed VPS / cloud': {
    owner: 'Your team owns source, dependencies, deployment settings, runtime patching, network policy, and server access.',
    action: 'Patch the runtime and OS through your normal change process, rotate exposed credentials, and restrict service identities and network exposure.',
    provider: 'The cloud provider supplies infrastructure; application and host hardening remain your responsibility unless a managed service says otherwise.',
    validate: 'Record the observed runtime separately, run post-deploy smoke and authorization tests, and rescan the corrected source.',
    docs: 'https://owasp.org/www-project-cheat-sheets/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html',
  },
}

function PatchIntelligenceView({ scan }: { scan: ScanSummary }) {
  const [hosting, setHosting] = useState('Not sure')
  const advisories = scan.dependencies.flatMap((dependency) => dependency.advisories)
  const dependencyCoverage = scan.coverage.find((item) => item.id === 'dependencies')
  const guidance = hostingGuidance[hosting]
  const dependencyOutcome = describeDependencies(scan)
  return <div className="workspace-view"><PageHeader eyebrow="Patch intelligence" title="Turn evidence into the next safe change." description="Advisories and version evidence stay separate from static guesses. A missing advisory lookup is reported as incomplete, never clean." action={<Pill className={dependencyCoverage?.status === 'unavailable' ? 'warning-pill' : dependencyCoverage?.matchedCount ? 'warning-pill' : 'safe-pill'}><Server size={13} /> {dependencyOutcome}</Pill>} />
    <div className="patch-hero panel"><div><div className="eyebrow">{scanKind(scan)} · {scan.scanStatus} · {scan.scanId}</div><h2>{advisories.length ? `${advisories.length} advisory records need review` : dependencyOutcome}</h2><p>{dependencyCoverage?.details ?? 'No dependency check was executed.'}</p><p>Zero matching advisories do not prove that the project is secure.</p>{dependencyCoverage?.source && <small className="patch-source">Source: {dependencyCoverage.source}{dependencyCoverage.checkedAt ? ` · last checked ${formatDateTime(dependencyCoverage.checkedAt)}` : ''}</small>}</div><div className="patch-hero-stat"><strong>{scan.dependencies.length}</strong><span>inventoried entries</span></div></div>
    <div className="patch-grid"><section className="panel patch-panel"><div className="panel-heading"><div><div className="eyebrow">Dependency inventory</div><h3>{scanKind(scan) === 'Website URL' ? 'No reliable package inventory observed' : 'What the source contained'}</h3></div></div>
      {scan.dependencies.length ? <div className="dependency-inventory">{scan.dependencies.map((dependency, index) => <div className="dependency-row" key={`${dependency.manifest}-${dependency.packageName}-${index}`}>
        <div><strong>{dependency.packageName}</strong><span>{dependency.ecosystem} · {dependency.versionSource}</span><small>Declared: {dependency.declaredVersion ?? 'Unknown'}</small><small>Resolved: {dependency.resolvedVersion ?? 'Not established'}</small></div>
        <div><span className="mono">{dependency.manifest}</span>{dependency.declarationFile && <small>Declaration: {dependency.declarationFile}</small>}{dependency.resolutionFile && <small>Resolution: {dependency.resolutionFile}</small>}<small>{dependencyLabel(dependency)}</small>{dependency.lookupError && <small>{dependency.lookupError}</small>}</div>
      </div>)}</div> : <EmptyState title="No dependency inventory" description={dependencyOutcome} />}
      {dependencyCoverage?.skippedDetails?.length ? <details className="skipped-dependencies"><summary>{dependencyCoverage.skippedDetails.length} inventory limitations</summary>{dependencyCoverage.skippedDetails.map((detail) => <span key={detail}>{detail}</span>)}</details> : null}
    </section>
      <section className="panel patch-panel"><div className="panel-heading"><div><div className="eyebrow">Matched advisories</div><h3>Advisory evidence</h3></div><span className="mono">{advisories.length} records</span></div>
        {advisories.length ? advisories.map((advisory, index) => <article className="advisory-card" key={`${advisory.id}-${index}`}><div className="advisory-card-top"><span>{advisory.severity} · {advisory.id}</span><a href={/^https:\/\//.test(advisory.sourceUrl) ? advisory.sourceUrl : undefined} target="_blank" rel="noreferrer">Source</a></div><h4>{advisory.packageName} @ {advisory.version}</h4><p>{advisory.summary}</p><p>Affected: {advisory.affectedRange}</p><p>Fixed version: {advisory.fixedVersion ?? 'Not established for a single upgrade branch; consult advisory'}</p><small>Checked {formatDateTime(advisory.checkedAt)} via {advisory.source}. Validate the upgrade branch and rerun tests.</small></article>) : <EmptyState title="No advisory records available" description={dependencyOutcome} />}
      </section>
      <section className="panel patch-panel"><div className="panel-heading"><div><div className="eyebrow">Version evidence</div><h3>Runtime & framework signals</h3></div></div>{scan.runtimes.length ? scan.runtimes.map((runtime) => <div className="runtime-row" key={`${runtime.component}-${runtime.sourceFile}-${runtime.evidence}`}><div className="runtime-icon"><Code2 size={15} /></div><div><strong>{runtime.component}</strong><span>{runtime.version ?? (runtime.evidence === 'unknown' ? 'Not declared' : 'Unknown')} · {runtime.evidence} in {runtime.sourceFile}</span><small>{runtime.details ?? (runtime.evidence === 'resolved' ? 'Resolved dependency evidence; not an observed deployed runtime.' : 'Declared project evidence; not an observed deployed runtime.')}</small></div></div>) : <EmptyState title="Runtime unknown" description="No supported manifest version was detected. A project file does not prove the deployed server runtime." />}</section></div>
    <section className="panel hosting-panel"><div className="panel-heading"><div><div className="eyebrow">Hosting-aware guidance</div><h3>Where should the fix happen?</h3></div><select value={hosting} onChange={(event) => setHosting(event.target.value)} aria-label="Hosting provider"><option>Not sure</option><option>Vercel</option><option>Netlify</option><option>Replit</option><option>Hostinger</option><option>Docker</option><option>Self-managed VPS / cloud</option></select></div><div className="hosting-grid"><div><span className="hosting-label">Your team changes</span><p>{guidance.owner}</p><p>{guidance.action}</p></div><div><span className="hosting-label">Provider boundary</span><p>{guidance.provider}</p><p><strong>Validate:</strong> {guidance.validate}</p><a href={guidance.docs} target="_blank" rel="noreferrer"><ExternalLink size={14} /> Consult official guidance</a></div></div></section>
    <section className="coverage-panel workspace-coverage"><div className="coverage-copy"><div className="eyebrow">Coverage ledger</div><h2>Know what actually ran.</h2><p>Coverage states are part of the result. “Unavailable” means the service failed or was not supported; it is never treated as a clean check.</p>{scan.coverage.map((check) => <div className="coverage-row" key={check.id}><span className={`coverage-status ${check.status}`} /> <div><strong>{check.label}</strong><span>{check.status} · {check.details}</span></div></div>)}</div></section>
  </div>
}

function EvidenceReportView({ scan, onDownloadJson, onDownloadHtml }: { scan: ScanSummary; onDownloadJson: () => void; onDownloadHtml: () => void }) {
  const unresolved = scan.findings.filter((item) => item.status !== 'Fixed').length
  return <div className="workspace-view"><PageHeader eyebrow="Audit trail" title="Take the evidence with you." description="A redacted report based on the current scan record, including incomplete checks and verification history." action={<div className="header-actions"><button className="button secondary" onClick={onDownloadHtml}><FileText size={15} /> HTML</button><button className="button primary" onClick={onDownloadJson}><Download size={15} /> Download JSON</button></div>} />
    <div className="report-layout"><div className="report-preview panel"><div className="report-top"><div className="report-brand"><Logo /></div><Pill className={scan.isDemo ? 'demo-pill' : 'safe-pill'}>{scan.isDemo ? 'DEMO DATA' : 'SOURCE SCAN'}</Pill></div><div className="report-title"><div className="eyebrow">Security report</div><h2>{scan.target}</h2><p className="mono">{scan.scanId} · {new Date(scan.checkedAt).toLocaleString('en-IN')}</p></div><div className="report-metrics"><div><strong>{scan.findings.length}</strong><span>findings</span></div><div><strong>{scan.findings.filter((item) => item.confidence === 'Confirmed').length}</strong><span>confirmed</span></div><div><strong>{scan.findings.filter((item) => item.status === 'Fixed').length}</strong><span>verified fixed</span></div><div><strong>{scan.fileCount}</strong><span>files checked</span></div></div><div className="report-section"><div className="report-section-heading"><h3>Coverage ledger</h3><span>{scan.coverage.filter((item) => item.status === 'passed').length} passed · {scan.coverage.filter((item) => item.status === 'unavailable').length} unavailable</span></div>{scan.coverage.map((item) => <div className="report-check" key={item.id}><span className={`coverage-status ${item.status}`} />{item.label}<span>{item.status}</span></div>)}</div><div className="report-section"><div className="report-section-heading"><h3>Findings included</h3><span>{unresolved} open</span></div>{scan.findings.length ? scan.findings.map((item) => <div className="report-finding" key={item.id}><span className={`severity-dot ${severityClass(item.severity)}`} /><div><strong>{item.title}</strong><span>{item.file}:{item.line ?? 'n/a'} · {item.confidence} · {item.status}</span></div><span className={`report-finding-status ${item.status === 'Fixed' ? 'fixed' : ''}`}>{item.status === 'Fixed' ? 'Verified' : item.severity}</span></div>) : <EmptyState title="No findings" description="No supported finding matched the current scan checks." />}</div><div className="report-section"><div className="report-section-heading"><h3>Verification history</h3><span>{scan.verificationHistory.length} run{scan.verificationHistory.length === 1 ? '' : 's'}</span></div>{scan.verificationHistory.length ? scan.verificationHistory.map((run) => <div className="verification-summary" key={run.id}><div><strong>{run.passed ? 'Passed' : 'Failed'} · {run.testType}</strong><span>{new Date(run.executedAt).toLocaleString('en-IN')}</span></div><p>{run.summary}</p></div>) : <p className="muted-copy">No verification run recorded for this scan.</p>}</div><div className="report-limits"><Info size={15} /><div><strong>Limitations are part of the report.</strong><p>VibeGuard checks supported text patterns and controlled fixtures. It does not certify the complete security of an application, infer a deployed runtime from a manifest, or replace a professional review.</p></div></div></div><div className="report-aside"><div className="panel aside-card"><div className="eyebrow">Share safely</div><h3>Redaction is on.</h3><p>Reports include limited evidence only. Full secret values and credentials are never included.</p><Pill className="safe-pill"><LockKeyhole size={13} /> No raw secrets</Pill></div><div className="panel aside-card"><div className="eyebrow">Next step</div><h3>{unresolved ? 'Fix, then rerun.' : 'Keep the audit trail.'}</h3><p>{unresolved ? 'Use the finding prompt as a starting point, apply the change in your own environment, then upload the corrected source.' : 'A resolved finding means the relevant verification condition passed; it is not a complete security certification.'}</p><button className="button secondary full" onClick={() => window.print()}><FileText size={15} /> Print report</button></div></div></div>
  </div>
}

function ReportView({ scan, onDownloadJson, onDownloadHtml }: { scan: ScanSummary; onDownloadJson: () => void; onDownloadHtml: () => void }) {
  const unresolved = scan.findings.filter((item) => item.status !== 'Fixed').length
  return <div className="workspace-view"><PageHeader eyebrow="Audit trail" title="Take the evidence with you." description="A redacted report for sharing with your team or attaching to a hackathon submission." action={<div className="header-actions"><button className="button secondary" onClick={onDownloadHtml}><FileText size={15} /> HTML</button><button className="button primary" onClick={onDownloadJson}><Download size={15} /> Download JSON</button></div>} />
    <div className="report-layout"><div className="report-preview panel"><div className="report-top"><div className="report-brand"><Logo /></div><Pill className={scan.isDemo ? 'demo-pill' : 'safe-pill'}>{scan.isDemo ? 'DEMO DATA' : 'SOURCE SCAN'}</Pill></div><div className="report-title"><div className="eyebrow">Security report</div><h2>{scan.target}</h2><p className="mono">{scan.scanId} · {new Date(scan.checkedAt).toLocaleString('en-IN')}</p></div><div className="report-metrics"><div><strong>{scan.findings.length}</strong><span>findings</span></div><div><strong>{scan.findings.filter((item) => item.confidence === 'Confirmed').length}</strong><span>confirmed</span></div><div><strong>{scan.findings.filter((item) => item.status === 'Fixed').length}</strong><span>verified fixed</span></div><div><strong>{scan.fileCount}</strong><span>files checked</span></div></div><div className="report-section"><div className="report-section-heading"><h3>Checks performed</h3><span>{scan.scanTypes.length} checks</span></div>{scan.scanTypes.map((item) => <div className="report-check" key={item}><CheckCircle2 size={15} />{item}<span>completed</span></div>)}</div><div className="report-section"><div className="report-section-heading"><h3>Findings included</h3><span>{unresolved} open</span></div>{scan.findings.map((item) => <button className="report-finding" key={item.id}><span className={`severity-dot ${severityClass(item.severity)}`} /><div><strong>{item.title}</strong><span>{item.file}:{item.line} · {item.confidence}</span></div><span className={`report-finding-status ${item.status === 'Fixed' ? 'fixed' : ''}`}>{item.status === 'Fixed' ? 'Verified' : item.severity}</span></button>)}</div><div className="report-limits"><Info size={15} /><div><strong>Limitations are part of the report.</strong><p>VibeGuard checks supported text patterns and controlled fixtures. It does not certify the complete security of an application, scan arbitrary third-party targets, or replace a professional review.</p></div></div></div><aside className="report-aside"><div className="aside-card"><div className="aside-icon"><Download size={18} /></div><div className="eyebrow">Export options</div><h3>Share what was actually checked.</h3><p>JSON is machine-readable for CI or issue tracking. HTML is easier to attach to a review or judge submission.</p><button className="button primary full" onClick={onDownloadJson}><Download size={15} /> Download JSON report</button><button className="button ghost full" onClick={onDownloadHtml}><FileText size={15} /> Download HTML report</button></div><div className="aside-card report-trust"><div className="aside-heading"><BadgeCheck size={18} /><strong>Verification language</strong></div><p>VibeGuard never adds a “Verified by VibeGuard” badge unless the defined test passes. A clean static scan is not a security certification.</p></div></aside></div>
  </div>
}

export default App

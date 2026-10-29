import { useRef, useState } from 'react'
import { AlertTriangle, ArrowRight, Check, FileArchive, Globe2, LockKeyhole, RefreshCw, UploadCloud, X } from 'lucide-react'
import type { ScanSummary } from './types'
import { MAX_ARCHIVE_BYTES, formatFileSize, formatMegabytes } from './limits'

interface Props {
  targetUrl: string; setTargetUrl: (value: string) => void
  websiteUrl: string; setWebsiteUrl: (value: string) => void
  selectedFile: File | null; onFile: (file: File | undefined) => void
  scanTypes: string[]; toggleScanType: (type: string) => void
  authorized: boolean; setAuthorized: (value: boolean) => void
  error: string; isScanning: boolean; phase: string; progress?: number; scan: ScanSummary
  onStartZip: () => void; onStartUrl: (target: string, confirmed: boolean) => void
  onDemo: () => void; onReset: () => void
}

export function ScanInput(props: Props) {
  const [mode, setMode] = useState<'zip' | 'url'>('zip')
  const [modal, setModal] = useState(false)
  const [urlAuthorized, setUrlAuthorized] = useState(false)
  const picker = useRef<HTMLInputElement>(null)
  const chooseZip = () => { setMode('zip'); setModal(false); setUrlAuthorized(false); picker.current?.click() }
  const checks = [
    ['secrets', 'Secrets & credentials', 'Redacted deterministic source patterns'],
    ['authorization', 'Authorization heuristics', 'Ownership signals; not a live exploit test'],
    ['configuration', 'Configuration patterns', 'Environment, CORS, and policy signals'],
    ['codeSafety', 'Code safety & pricing', 'Client-controlled totals and risky rendering'],
    ['dependencies', 'Dependency advisories', 'Exact package name/version sent to OSV; no source contents'],
  ]
  return <div className="workspace-view">
    <div className="page-header"><div><div className="eyebrow">New security scan</div><h1>Check your next launch.</h1><p>Source evidence and authorized website observations stay separate.</p></div><span className="pill safe-pill"><LockKeyhole size={13} /> Read-only checks</span></div>
    <input ref={picker} id="source-upload-production" type="file" accept=".zip,application/zip" hidden onChange={(event) => { props.onFile(event.target.files?.[0]); event.target.value = '' }} />
    {props.isScanning ? <div className="panel scan-status-panel" role="status" aria-live="polite">
      <div className="scan-status-icon running"><RefreshCw className="spin-icon" size={23} /></div><h3>{props.scan.scanStatus}</h3><p>{props.phase}</p>
      {props.progress !== undefined && <div className="scan-progress-track" role="progressbar" aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.round(props.progress)}><i style={{ width: `${Math.max(0, Math.min(100, props.progress))}%` }} /></div>}
      {props.progress !== undefined && <small>{Math.round(props.progress)}%</small>}
      <small>{props.scan.scanId}</small>
      <p>Progress only reflects completed local processing. No success is reported until checks finish.</p>
    </div> : <>
      {props.error && <div className="form-error" role="alert"><AlertTriangle size={17} /><div><strong>{props.scan.errorCode === 'AUTHORIZATION_REQUIRED' ? 'Authorization not confirmed' : props.scan.errorCode === 'EXTERNAL_UNAVAILABLE' ? 'Service unavailable' : props.scan.scanStatus === 'Failed' ? 'Scan failed' : 'Input needs attention'}</strong><p>{props.error}</p></div><button className="button ghost" onClick={props.onReset}>Dismiss</button></div>}
      <div className="scan-mode-tabs">
        <button className={mode === 'zip' ? 'selected' : ''} onClick={() => setMode('zip')}><UploadCloud size={17} /><span><strong>Scan Source ZIP</strong><small>Recommended for detailed findings</small></span></button>
        <button className={mode === 'url' ? 'selected' : ''} onClick={() => setMode('url')}><Globe2 size={17} /><span><strong>Scan Website URL</strong><small>Limited externally observable checks</small></span></button>
      </div>
      <div className="scan-layout"><div className="scan-main">
        <section className="panel scan-card">
          <div className="scan-card-header"><div className="step-chip">01</div><div><h3>{mode === 'zip' ? 'Upload source code' : 'Authorized website URL'}</h3><p>{mode === 'zip' ? 'Nested source, configuration, and dependency evidence.' : 'HTTPS, redirects, response headers, and observable cookies only.'}</p></div></div>
          {mode === 'zip' ? <>
            <div className="field-group"><label htmlFor="project-name">Project identifier <span>optional</span></label><div className="input-wrap"><FileArchive size={17} /><input id="project-name" value={props.targetUrl} onChange={(event) => props.setTargetUrl(event.target.value)} placeholder="e.g. shop-backend" /></div></div>
            <div className="dropzone" role="button" tabIndex={0} aria-label="Choose source ZIP" onClick={chooseZip} onKeyDown={(event) => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); chooseZip() } }} onDragOver={(event) => event.preventDefault()} onDrop={(event) => { event.preventDefault(); props.onFile(event.dataTransfer.files[0]) }}>
              <div className="upload-icon"><UploadCloud size={23} /></div><strong>{props.selectedFile?.name ?? 'Drop your source ZIP here'}</strong><span>{props.selectedFile ? `${formatFileSize(props.selectedFile.size)} · click to replace` : `or click to browse · maximum ${formatMegabytes(MAX_ARCHIVE_BYTES)}`}</span>
            </div>
            {props.selectedFile && <button className="text-button" onClick={() => props.onFile(undefined)}>Clear selected ZIP</button>}
          </> : <div className="field-group"><label htmlFor="website-url">Website URL</label><div className="input-wrap"><Globe2 size={17} /><input id="website-url" type="url" value={props.websiteUrl} onChange={(event) => { props.setWebsiteUrl(event.target.value); setUrlAuthorized(false) }} placeholder="https://your-authorized-website.example" /></div><small>HTTPS on port 443. Private networks, credentials, and unsafe redirects are rejected.</small></div>}
        </section>
        {mode === 'zip' && <section className="panel scan-card scan-options"><h3>Select checks</h3><div className="check-grid">{checks.map(([id, title, details]) => <button key={id} className={`check-option ${props.scanTypes.includes(id) ? 'selected' : ''}`} onClick={() => props.toggleScanType(id)} aria-pressed={props.scanTypes.includes(id)}><span className="option-check">{props.scanTypes.includes(id) && <Check size={14} />}</span><span><strong>{title}</strong><small>{details}</small></span></button>)}</div></section>}
        <section className="panel scan-card">
          {mode === 'zip' && <label className="authorization-confirmation"><input type="checkbox" checked={props.authorized} onChange={(event) => props.setAuthorized(event.target.checked)} /> I own this code or have explicit permission to inspect it.</label>}
          <div className="hero-actions"><button className="button primary" onClick={mode === 'zip' ? props.onStartZip : () => { setUrlAuthorized(false); setModal(true) }}>{mode === 'zip' ? 'Run source scan' : 'Review URL scan authorization'} <ArrowRight size={16} /></button><button className="button ghost" onClick={props.onDemo}>Open controlled demo</button></div>
        </section>
      </div><aside className="panel scan-card"><h3>Know the limits.</h3><p>ZIP checks never execute code or install packages. Source heuristics need review; no matches do not prove security.</p><p>Website checks cannot inspect private source, environment variables, internal database permissions, or the complete dependency tree.</p><p>No login is required. Download anonymous results before leaving. Account history is saved only after the API confirms persistence.</p></aside></div>
    </>}
    {modal && <div className="modal-backdrop" onKeyDown={(event) => { if (event.key === 'Escape') setModal(false) }}><div className="modal-card" role="dialog" aria-modal="true" aria-labelledby="url-scan-title">
      <button className="modal-close" onClick={() => setModal(false)} aria-label="Cancel URL scan"><X size={17} /></button>
      <h2 id="url-scan-title">Want a more detailed security scan?</h2>
      <p>Website URL scanning can inspect only externally observable security signals. It cannot reliably inspect private source code, dependency lockfiles, or every authorization flaw.</p>
      <p>For deeper analysis, upload your source-code ZIP to inspect supported code, configuration, and dependency manifests.</p>
      <p className="mono">{props.websiteUrl || 'No website URL entered'}</p>
      <label className="authorization-confirmation"><input autoFocus type="checkbox" checked={urlAuthorized} onChange={(event) => setUrlAuthorized(event.target.checked)} /> I own this website or have explicit permission to run these read-only checks.</label>
      <div className="modal-actions"><button className="button primary" disabled={!urlAuthorized} onClick={() => { setModal(false); props.onStartUrl(props.websiteUrl, urlAuthorized) }}>Continue with URL Scan</button><button className="button secondary" onClick={chooseZip}>Upload Source ZIP</button><button className="button ghost" onClick={() => setModal(false)}>Cancel</button></div>
    </div></div>}
  </div>
}

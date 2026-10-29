import { createElement } from 'react'
import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it } from 'vitest'
import { ScanInput } from './ScanInput'
import { ReportPreview, SavedHistory, ScanDashboard, SourceAssociation } from './ScanViews'
import { pendingScan } from './workflow'

const noop = () => {}
describe('rendered workflow views', () => {
  it('renders source input, separate scan choices, and explicit source authorization', () => {
    const html = renderToStaticMarkup(createElement(ScanInput, {
      targetUrl: '', setTargetUrl: noop, websiteUrl: '', setWebsiteUrl: noop,
      selectedFile: null, onFile: noop, scanTypes: ['secrets'], toggleScanType: noop,
      authorized: false, setAuthorized: noop, error: '', isScanning: false, phase: '', scan: pendingScan(),
      onStartZip: noop, onStartUrl: noop, onDemo: noop, onReset: noop,
    }))
    expect(html).toContain('Scan Source ZIP')
    expect(html).toContain('Scan Website URL')
    expect(html).toContain('type="file"')
    expect(html).toContain('I own this code or have explicit permission')
    expect(html).toContain('Client-controlled totals')
  })

  it('renders actual execution phase without made-up percentages', () => {
    const html = renderToStaticMarkup(createElement(ScanInput, {
      targetUrl: '', setTargetUrl: noop, websiteUrl: '', setWebsiteUrl: noop,
      selectedFile: null, onFile: noop, scanTypes: [], toggleScanType: noop,
      authorized: true, setAuthorized: noop, error: '', isScanning: true, phase: 'Matching exact dependency versions against OSV', scan: { ...pendingScan(), scanStatus: 'Running' },
      onStartZip: noop, onStartUrl: noop, onDemo: noop, onReset: noop,
    }))
    expect(html).toContain('Matching exact dependency versions against OSV')
    expect(html).not.toMatch(/\d+%/)
    expect(html).not.toContain('Choose another scan')
  })

  it('renders reported progress without inventing it', () => {
    const html = renderToStaticMarkup(createElement(ScanInput, {
      targetUrl: '', setTargetUrl: noop, websiteUrl: '', setWebsiteUrl: noop,
      selectedFile: null, onFile: noop, scanTypes: [], toggleScanType: noop,
      authorized: true, setAuthorized: noop, error: '', isScanning: true, phase: 'Extracting supported text', progress: 42, scan: { ...pendingScan(), scanStatus: 'Running' },
      onStartZip: noop, onStartUrl: noop, onDemo: noop, onReset: noop,
    }))
    expect(html).toContain('42%')
    expect(html).toContain('role="progressbar"')
  })

  it('has no seeded dashboard rows or unsafe empty-finding actions', () => {
    const html = renderToStaticMarkup(createElement(ScanDashboard, { scans: [], onOpen: noop, onNew: noop }))
    expect(html).toContain('No scans yet')
    expect(html).not.toContain('Launchpad')
    expect(html).not.toContain('Campus events')
    expect(html).not.toContain('Critical')
  })

  it('reports failed URL scans without source-success labels or inventory claims', () => {
    const scan = { ...pendingScan('https://site.example', 'Website URL'), scanStatus: 'Failed' as const, errorCode: 'EXTERNAL_UNAVAILABLE', error: 'DNS unavailable' }
    const html = renderToStaticMarkup(createElement(ReportPreview, { scan }))
    expect(html).toContain('Website URL')
    expect(html).toContain('Failed')
    expect(html).toContain('DNS unavailable')
    expect(html).toContain('No completed findings')
    expect(html).toContain('Download JSON')
    expect(html).not.toContain('SOURCE SCAN')
  })

  it('history shows lifecycle and reports only supplied saved rows', () => {
    const scan = { ...pendingScan('owned'), scanStatus: 'Completed with limitations' as const }
    const html = renderToStaticMarkup(createElement(SavedHistory, { scans: [scan], email: 'owner@example.com', loading: false, onOpen: noop, onSignIn: noop }))
    expect(html).toContain(scan.scanId)
    expect(html).toContain('Completed with limitations')
    expect(html).toContain('Server-confirmed saved records')
  })

  it('renders source association as a separate explicit action', () => {
    const scan = { ...pendingScan('https://site.example', 'Website URL'), scanStatus: 'Completed with limitations' as const }
    const source = { ...pendingScan('shop.zip'), scanStatus: 'Completed' as const }
    const html = renderToStaticMarkup(createElement(SourceAssociation, { scan, sources: [source], onAssociate: noop, onOpen: noop }))
    expect(html).toContain('Confirm source association')
    expect(html).toContain('not proof that the ZIP is deployed')
    expect(html).toContain(source.scanId)
  })
})

import type { CheckCoverage, DependencyAdvisory, DependencyRecord, Severity } from './types'
import type { SourceFile } from './scanner'

export type DependencyInput = Omit<DependencyRecord, 'advisories' | 'versionSource'> & { versionSource?: DependencyRecord['versionSource'] }
export interface DependencySkip { packageName?: string; ecosystem: string; version?: string; manifest: string; reason: string }
export interface DependencyInventory { dependencies: Array<DependencyInput & { versionSource: DependencyRecord['versionSource'] }>; skipped: DependencySkip[] }
export interface AdvisoryLookupResult {
  advisories: Map<string, DependencyAdvisory[]>
  source: string
  checkedAt: string
  /** Number of unique exact-version queries whose pagination completed. */
  responseCount: number
  errors?: Map<string, string>
}
export type OsvLookup = (dependencies: DependencyInput[]) => Promise<AdvisoryLookupResult>

const SUPPORTED = new Set(['npm', 'PyPI', 'Packagist'])
const semver = /^v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/
const directory = (path: string) => path.slice(0, Math.max(0, path.lastIndexOf('/')))
const join = (root: string, path: string) => root ? `${root}/${path}` : path
const normalizeName = (name: string, ecosystem: string) => ecosystem === 'PyPI' ? name.toLowerCase().replace(/[-_.]+/g, '-') : name
export const dependencyKey = (name: string, ecosystem: string, version: string) => `${ecosystem}:${normalizeName(name, ecosystem)}:${version}`
const keyFor = (dependency: DependencyInput) => dependencyKey(dependency.packageName, dependency.ecosystem, dependency.version)
const object = (value: unknown): value is Record<string, unknown> => Boolean(value) && typeof value === 'object' && !Array.isArray(value)
const string = (value: unknown) => typeof value === 'string' ? value : undefined

function exactVersion(version: string, ecosystem: string) {
  // Recognize an exact version's syntax only. OSV, never this client, evaluates
  // affected ecosystem ranges. In particular, >=1.2.3 is NOT version 1.2.3.
  if (ecosystem === 'npm') return semver.test(version)
  if (ecosystem === 'PyPI') return /^\d+(?:!\d+)?(?:\.\d+)*(?:(?:a|b|rc)\d+)?(?:\.post\d+)?(?:\.dev\d+)?(?:\+[A-Za-z0-9.-]+)?$/i.test(version)
  if (ecosystem === 'Packagist') return /^v?\d+(?:\.\d+){1,3}(?:[-+][A-Za-z0-9.-]+)?$/.test(version)
  return false
}

type Candidate = DependencyInventory['dependencies'][number] & { project: string; direct?: boolean; selector?: string }
export function discoverDependencyInventory(files: SourceFile[]): DependencyInventory {
  const entries: Candidate[] = []
  const issues: DependencySkip[] = []
  const issue = (file: SourceFile, ecosystem: string, reason: string) => issues.push({ ecosystem, manifest: file.path, reason })
  const add = (file: SourceFile, ecosystem: string, name: string, raw: unknown, resolved = false, extra: Partial<Candidate> = {}) => {
    const version = string(raw)?.trim() || 'unknown'
    const supported = SUPPORTED.has(ecosystem)
    const exact = supported && exactVersion(version, ecosystem)
    const unsupportedSpec = /^(?:file:|link:|workspace:|npm:|git(?:\+|:)|https?:|github:)/.test(version)
    entries.push({
      packageName: normalizeName(name, ecosystem), ecosystem, version, manifest: file.path,
      project: directory(file.path), versionSource: raw === undefined || raw === null ? 'unknown' : resolved ? 'resolved' : 'declared',
      ...(resolved ? { resolvedVersion: string(raw), resolutionFile: file.path } : { declaredVersion: string(raw), declarationFile: file.path }),
      ...(!supported || unsupportedSpec ? { lookupStatus: 'unsupported' as const, lookupError: 'Unsupported ecosystem or non-registry dependency specification.' }
        : !exact ? { lookupStatus: 'unknown-version' as const, lookupError: 'An exact registry version is unavailable; ranges are not exact versions.' } : {}),
      ...extra,
    })
  }
  const unparsed = (file: SourceFile, ecosystem: string, reason: string) => {
    issue(file, ecosystem, reason)
    add(file, ecosystem, `[unparsed ${file.path.split('/').pop()}]`, undefined, false, { lookupStatus: 'unsupported', lookupError: reason })
  }
  const fields = (file: SourceFile, parsed: Record<string, unknown>, ecosystem: string, names: string[]) => {
    for (const field of names) {
      if (parsed[field] === undefined) continue
      if (!object(parsed[field])) { unparsed(file, ecosystem, `Invalid ${field} dependency section.`); continue }
      for (const [name, version] of Object.entries(parsed[field])) {
        // Preserve operators and malformed/unknown entries rather than dropping them.
        add(file, ecosystem, name, version)
      }
    }
  }
  for (const file of files) {
    const name = file.path.split('/').pop()?.toLowerCase() ?? ''
    try {
      if (['package.json', 'package-lock.json', 'npm-shrinkwrap.json', 'composer.json', 'composer.lock', 'pipfile.lock'].includes(name)) {
        const parsed: unknown = JSON.parse(file.content)
        if (!object(parsed)) throw new Error('Expected a JSON object.')
        if (name === 'package.json') fields(file, parsed, 'npm', ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'])
        else if (name === 'composer.json') {
          for (const field of ['require', 'require-dev']) {
            if (parsed[field] === undefined) continue
            if (!object(parsed[field])) throw new Error(`Invalid ${field} section.`)
            for (const [pkg, version] of Object.entries(parsed[field])) add(file, pkg.includes('/') ? 'Packagist' : 'PHP platform', pkg, version)
          }
        } else if (name === 'composer.lock') {
          for (const field of ['packages', 'packages-dev']) {
            if (parsed[field] === undefined) continue
            if (!Array.isArray(parsed[field])) throw new Error(`Invalid ${field} section.`)
            for (const pkg of parsed[field]) {
              if (!object(pkg) || typeof pkg.name !== 'string') { unparsed(file, 'Packagist', 'Invalid lockfile package entry.'); continue }
              add(file, 'Packagist', pkg.name, pkg.version, true, { direct: true })
            }
          }
        } else if (name === 'pipfile.lock') {
          for (const field of ['default', 'develop']) {
            if (parsed[field] === undefined) continue
            if (!object(parsed[field])) throw new Error(`Invalid ${field} section.`)
            for (const [pkg, info] of Object.entries(parsed[field])) {
              const spec = object(info) ? string(info.version) : undefined
              add(file, 'PyPI', pkg, spec?.startsWith('==') ? spec.slice(2) : spec, true, { direct: true })
            }
          }
        } else if (parsed.packages !== undefined) {
          if (!object(parsed.packages)) throw new Error('Invalid lockfile packages section.')
          const root = object(parsed.packages['']) ? parsed.packages[''] : {}
          const declarations = Object.assign({}, ...['dependencies', 'devDependencies', 'optionalDependencies'].map((key) => object(root[key]) ? root[key] : {})) as Record<string, unknown>
          for (const [location, info] of Object.entries(parsed.packages)) {
            if (!location || !location.includes('node_modules/')) continue
            const pkg = location.slice(location.lastIndexOf('node_modules/') + 13)
            if (!object(info)) { add(file, 'npm', pkg, undefined, true); continue }
            const prefix = location.slice(0, location.indexOf('node_modules/')).replace(/\/$/, '')
            const direct = location === join(prefix, `node_modules/${pkg}`)
            add(file, 'npm', string(info.name) ?? pkg, info.version, true, {
              direct, project: prefix ? join(directory(file.path), prefix) : directory(file.path), selector: direct ? string(declarations[pkg]) : undefined,
              ...(info.link ? { lookupStatus: 'unsupported', lookupError: 'Linked/workspace lock entry has no registry resolution.' } : {}),
            })
          }
        } else if (object(parsed.dependencies)) {
          // Iterative traversal prevents deep v1 lockfiles exhausting the call stack.
          const queue = [{ dependencies: parsed.dependencies, direct: true }]
          for (let index = 0; index < queue.length; index++) {
            const { dependencies, direct } = queue[index]
            for (const [pkg, info] of Object.entries(dependencies)) {
              add(file, 'npm', pkg, object(info) ? info.version : undefined, true, { direct })
              if (object(info) && object(info.dependencies)) queue.push({ dependencies: info.dependencies, direct: false })
            }
          }
        } else if (parsed.lockfileVersion !== 1) throw new Error('Unrecognized or incomplete npm lockfile structure.')
      } else if (/^requirements(?:[-.][\w.-]+)?\.txt$/.test(name)) {
        for (const raw of file.content.replace(/\\\r?\n/g, ' ').split(/\r?\n/)) {
          const line = raw.replace(/\s+#.*$/, '').trim()
          if (!line || line.startsWith('#')) continue
          const match = /^([A-Za-z0-9][A-Za-z0-9_.-]*)(?:\[[^\]]+\])?\s*(.*)$/.exec(line)
          if (!match || line.startsWith('-')) { unparsed(file, 'PyPI', 'Requirement include, option, or editable entry requires manual inspection.'); continue }
          const spec = match[2].split(';')[0].replace(/\s+--hash=.*$/, '').trim()
          const pin = /^==([^=,\s*]+)$/.exec(spec)
          add(file, 'PyPI', match[1], pin ? pin[1] : spec || undefined, false, { declaredVersion: spec || undefined })
          if (match[2].includes(';')) issue(file, 'PyPI', `Environment marker for ${match[1]} was not evaluated; its pin is inventoried conservatively.`)
        }
      } else if (name === 'yarn.lock') {
        let header = '', version: string | undefined
        const flush = () => {
          if (!header || header === '__metadata') return
          for (const descriptor of header.split(/,\s*/)) {
            const match = /^((?:@[^/\s]+\/)?[^@\s]+)@(.+)$/.exec(descriptor.replace(/^["']|["']$/g, ''))
            if (match) {
              const selector = match[2].replace(/^npm:/, '')
              const unsupported = /^(?:patch:|workspace:|portal:|file:|link:|git(?:\+|:)|https?:)/.test(match[2]) || (match[2].startsWith('npm:') && selector.includes('@'))
              add(file, 'npm', match[1], version, true, { direct: true, selector, ...(unsupported ? { lookupStatus: 'unsupported', lookupError: 'Yarn alias or non-registry resolution requires manual inspection.' } : {}) })
            }
            else unparsed(file, 'npm', 'Unrecognized Yarn descriptor.')
          }
        }
        for (const line of file.content.split(/\r?\n/)) {
          if (!line.trim() || line.trimStart().startsWith('#')) continue
          if (/^\S.*:\s*$/.test(line)) {
            flush(); header = line.trim().replace(/:\s*$/, '').replace(/^["']|["']$/g, ''); version = undefined
          } else {
            const match = /^\s+version\s*:?\s*["']?([^"'\s]+)["']?\s*$/.exec(line)
            if (match) version = match[1]
          }
        }
        flush()
        issue(file, 'npm', 'Yarn inventory supports conventional block descriptors only; arbitrary YAML aliases and inline layouts are not fully evaluated.')
        if (!header) unparsed(file, 'npm', 'Unrecognized or empty Yarn lockfile.')
      } else if (name === 'pnpm-lock.yaml') {
        let section = '', importer = '.', dependency = '', specifier: string | undefined
        let recognized = false
        const scalars = (value: string) => value.trim().replace(/^["']|["']$/g, '')
        for (const line of file.content.split(/\r?\n/)) {
          if (/^\S/.test(line)) { section = line.split(':')[0]; continue }
          if (section === 'packages') {
            const key = /^ {2}(\S.*):\s*$/.exec(line)
            if (!key) continue
            const descriptor = scalars(key[1]).replace(/^\//, '')
            const match = /^((?:@[^/\s]+\/)?[^@/\s]+)(?:@|\/)([^\s(]+)(?:\(.*\))?$/.exec(descriptor)
            if (match) { add(file, 'npm', match[1], match[2], true); recognized = true }
            else unparsed(file, 'npm', 'Unsupported pnpm package key.')
          } else if (section === 'importers') {
            const project = /^ {2}(\S.*):\s*$/.exec(line)
            const pkg = /^ {6}(\S.*):\s*$/.exec(line)
            const spec = /^ {8}specifier:\s*(.+)$/.exec(line)
            const resolution = /^ {8}version:\s*(.+)$/.exec(line)
            if (project) { importer = scalars(project[1]); dependency = ''; specifier = undefined }
            if (pkg) { dependency = scalars(pkg[1]); specifier = undefined }
            if (spec) specifier = scalars(spec[1])
            if (resolution && dependency) {
              const projectPath = importer === '.' ? directory(file.path) : join(directory(file.path), importer)
              if (importer.split('/').includes('..') || importer.startsWith('/')) { unparsed(file, 'npm', 'Unsafe pnpm importer path.'); continue }
              add(file, 'npm', dependency, scalars(resolution[1]).replace(/\(.*$/, ''), true, { direct: true, selector: specifier, project: projectPath })
              recognized = true
            }
          }
        }
        // This bounded text parser does not claim to implement arbitrary YAML.
        issue(file, 'npm', 'pnpm inventory supports conventional packages/importers blocks only; YAML aliases, inline mappings and other layouts are not fully evaluated.')
        if (!recognized) unparsed(file, 'npm', 'No supported pnpm lockfile entries were parsed.')
      } else if (/^(?:pyproject\.toml|poetry\.lock|uv\.lock|pipfile|gemfile(?:\.lock)?|cargo\.(?:toml|lock)|go\.(?:mod|sum)|pom\.xml|build\.gradle(?:\.kts)?|bun\.lockb?|deno\.(?:jsonc?|lock))$/.test(name)) {
        unparsed(file, 'Unsupported manifest', 'This manifest/lockfile format is inventoried but not parsed for advisory matching.')
      }
    } catch {
      // JSON parser diagnostics can include raw source fragments or credentials.
      unparsed(file, name.startsWith('composer') ? 'Packagist' : name.startsWith('pip') ? 'PyPI' : 'npm', 'Malformed manifest/lockfile: invalid data or unsupported structure; source contents omitted.')
    }
  }

  const resolved = entries.filter((entry) => entry.resolutionFile !== undefined)
  const resolutionIndex = new Map<string, Candidate[]>()
  const projectKey = (entry: Candidate) => `${entry.project}|${entry.ecosystem}|${entry.packageName}`
  for (const resolution of resolved) {
    const key = projectKey(resolution)
    const candidates = resolutionIndex.get(key) ?? []
    candidates.push(resolution)
    resolutionIndex.set(key, candidates)
  }
  const merged: Candidate[] = []
  const consumed = new Set<Candidate>()
  for (const declaration of entries.filter((entry) => entry.resolutionFile === undefined)) {
    const candidates = (resolutionIndex.get(projectKey(declaration)) ?? []).filter((resolution) => resolution.direct && !resolution.lookupStatus
      && (resolution.selector === undefined || resolution.selector === declaration.declaredVersion)
      && (!exactVersion(declaration.version, declaration.ecosystem) || declaration.version.replace(/^v/, '') === resolution.version.replace(/^v/, '')))
    const versions = new Set(candidates.map((candidate) => candidate.version))
    if (versions.size === 1) {
      for (const resolution of candidates) {
        merged.push({ ...resolution, declaredVersion: declaration.declaredVersion, declarationFile: declaration.manifest })
        consumed.add(resolution)
      }
    } else merged.push(declaration)
  }
  merged.push(...resolved.filter((entry) => !consumed.has(entry)))
  // Project AND resolution file participate in identity; independent projects
  // retain their own evidence even when OSV queries can safely be deduplicated.
  const unique = new Map<string, Candidate>()
  for (const entry of merged) {
    const key = `${entry.project}|${entry.manifest}|${keyFor(entry)}|${entry.declarationFile ?? ''}|${entry.declaredVersion ?? ''}`
    const existing = unique.get(key)
    if (!existing || (!existing.declarationFile && entry.declarationFile)) unique.set(key, entry)
  }
  const dependencies = [...unique.values()].map(({ project: _project, direct: _direct, selector: _selector, ...entry }) => entry)
  const skipped = [...issues, ...dependencies.filter((entry) => entry.lookupStatus).map((entry) => ({ packageName: entry.packageName, ecosystem: entry.ecosystem, version: entry.version, manifest: entry.manifest, reason: entry.lookupError ?? 'Lookup not supported.' }))]
  return { dependencies, skipped }
}

export const discoverDependencies = (files: SourceFile[]) => discoverDependencyInventory(files).dependencies

function severityFromOsv(vulnerability: Record<string, unknown>): Severity {
  const specific = object(vulnerability.database_specific) ? vulnerability.database_specific : {}
  const named = string(specific.severity)?.toLowerCase()
  if (named === 'critical') return 'Critical'
  if (named === 'high') return 'High'
  if (named === 'medium' || named === 'moderate') return 'Medium'
  if (named === 'low') return 'Low'
  // CVSS vectors are not numeric scores. Do not misparse "CVSS:3.1/...".
  return 'Informational'
}

function parseAdvisory(dependency: DependencyInput, raw: unknown, checkedAt: string): DependencyAdvisory | undefined {
  if (!object(raw) || typeof raw.id !== 'string' || !raw.id || !Array.isArray(raw.affected)) throw new Error('OSV returned an incomplete advisory (full affected records are required).')
  if (raw.withdrawn !== undefined && typeof raw.withdrawn !== 'string') throw new Error('OSV returned an invalid withdrawn timestamp.')
  if (raw.withdrawn) return undefined
  const affected = raw.affected.filter((item): item is Record<string, unknown> => object(item) && object(item.package) && item.package.ecosystem === dependency.ecosystem && typeof item.package.name === 'string' && normalizeName(item.package.name, dependency.ecosystem) === normalizeName(dependency.packageName, dependency.ecosystem))
  if (!affected.length) throw new Error(`OSV returned an advisory for a different package: ${raw.id}.`)
  // /query already evaluated this exact package/version. Do not reimplement
  // ecosystem range logic (SEMVER, ECOSYSTEM, GIT) in the browser.
  const ranges = affected.flatMap((item) => Array.isArray(item.ranges) ? item.ranges.filter(object) : [])
  const events = ranges.flatMap((range) => Array.isArray(range.events) ? range.events.filter(object) : [])
  if (!events.length && !affected.some((item) => Array.isArray(item.versions) && item.versions.some((version) => typeof version === 'string'))) throw new Error('OSV returned an incomplete affected-version record.')
  const fixed = [...new Set(events.flatMap((event) => typeof event.fixed === 'string' ? [event.fixed] : []))]
  const affectedRange = events.flatMap((event) => Object.entries(event).filter(([key, value]) => ['introduced', 'fixed', 'last_affected', 'limit'].includes(key) && typeof value === 'string').map(([key, value]) => `${key.replace('_', ' ')}: ${value}`)).join(', ') || 'Exact package/version matched by OSV; see the advisory for affected versions.'
  return {
    id: raw.id, packageName: dependency.packageName, ecosystem: dependency.ecosystem, version: dependency.version,
    severity: severityFromOsv(raw), summary: string(raw.summary) ?? 'OSV returned an advisory for this exact dependency version.',
    affectedRange,
    // Multiple affected branches do not establish a single safe upgrade target.
    fixedVersion: fixed.length === 1 ? fixed[0] : undefined,
    sourceUrl: `https://osv.dev/vulnerability/${encodeURIComponent(raw.id)}`, source: 'OSV.dev', checkedAt,
  }
}

async function responseJson(response: Response): Promise<unknown> {
  const max = 4 * 1024 * 1024
  if (Number(response.headers.get('content-length')) > max) throw new Error('OSV response exceeds the 4 MB safety limit.')
  if (!response.body) throw new Error('OSV returned an empty HTTP body.')
  const reader = response.body.getReader(), decoder = new TextDecoder()
  let size = 0, text = ''
  try {
    while (true) {
      const { value, done } = await reader.read()
      if (done) break
      size += value.byteLength
      if (size > max) throw new Error('OSV response exceeds the 4 MB safety limit.')
      text += decoder.decode(value, { stream: true })
    }
    return JSON.parse(text + decoder.decode()) as unknown
  } catch (error) { await reader.cancel().catch(() => undefined); throw error }
  finally { reader.releaseLock() }
}

// Official contract: https://google.github.io/osv.dev/post-v1-query/
// querybatch returns only IDs/modified timestamps, not full advisory records.
// https://google.github.io/osv.dev/post-v1-querybatch/
export const lookupOsvAdvisories: OsvLookup = async (dependencies) => {
  const checkedAt = new Date().toISOString(), advisories = new Map<string, DependencyAdvisory[]>(), errors = new Map<string, string>()
  const unique = [...new Map(dependencies.map((dependency) => [keyFor(dependency), dependency])).values()]
  let responseCount = 0, next = 0
  const deadline = Date.now() + 30_000
  await Promise.all(Array.from({ length: Math.min(4, unique.length) }, async () => {
    while (next < unique.length) {
      const index = next++, dependency = unique[index], key = keyFor(dependency)
      if (index >= 200 || Date.now() >= deadline) { errors.set(key, 'OSV lookup budget exceeded (200 unique versions / 30 seconds).'); continue }
      if (!SUPPORTED.has(dependency.ecosystem) || !exactVersion(dependency.version, dependency.ecosystem)) { errors.set(key, 'An exact supported registry version is required.'); continue }
      const found = new Map<string, DependencyAdvisory>()
      try {
        let token: string | undefined
        const tokens = new Set<string>()
        for (let page = 0; ; page++) {
          if (page >= 10 || Date.now() >= deadline) throw new Error('OSV pagination did not finish within the lookup safety budget.')
          const controller = new AbortController()
          const timeout = globalThis.setTimeout(() => controller.abort(), Math.min(5_000, Math.max(1, deadline - Date.now())))
          let payload: unknown
          try {
            const response = await fetch('https://api.osv.dev/v1/query', {
              method: 'POST', headers: { 'content-type': 'application/json' }, credentials: 'omit', referrerPolicy: 'no-referrer',
              body: JSON.stringify({ package: { name: normalizeName(dependency.packageName, dependency.ecosystem), ecosystem: dependency.ecosystem }, version: dependency.version, ...(token ? { page_token: token } : {}) }), signal: controller.signal,
            })
            if (!response.ok) throw new Error(`OSV returned HTTP ${response.status}.`)
            payload = await responseJson(response)
          } catch (error) {
            if (controller.signal.aborted) throw new Error('OSV advisory lookup timed out (5-second request / 30-second total budget).')
            throw error
          } finally { globalThis.clearTimeout(timeout) }
          // {} is OSV's valid zero-match response. ID-only batch results, null,
          // malformed vulns and error envelopes must never become "no-match".
          if (!object(payload) || Object.keys(payload).some((key) => !['vulns', 'next_page_token'].includes(key)) || (payload.vulns !== undefined && !Array.isArray(payload.vulns))) throw new Error('OSV returned an incomplete or invalid query response.')
          for (const raw of (payload.vulns as unknown[] | undefined) ?? []) {
            const advisory = parseAdvisory(dependency, raw, checkedAt)
            if (advisory) found.set(advisory.id, advisory)
          }
          if (payload.next_page_token !== undefined && typeof payload.next_page_token !== 'string') throw new Error('OSV returned an invalid pagination token.')
          token = string(payload.next_page_token) || undefined
          if (!token) break
          if (tokens.has(token)) throw new Error('OSV pagination repeated a token; results are incomplete.')
          tokens.add(token)
        }
        advisories.set(key, [...found.values()]); responseCount++
      } catch (error) {
        if (found.size) advisories.set(key, [...found.values()])
        errors.set(key, `OSV lookup unavailable: ${error instanceof Error ? error.message : 'network error'}`)
      }
    }
  }))
  return { advisories, errors, source: 'OSV.dev', checkedAt, responseCount }
}

export async function scanDependencies(files: SourceFile[], advisoryLookup: OsvLookup = lookupOsvAdvisories, enabled = true) {
  const inventory = discoverDependencyInventory(files)
  const skippedDetails = [...new Set(inventory.skipped.map((entry) => `${entry.packageName ?? 'Manifest'} (${entry.manifest}): ${entry.reason}`))]
  const requested = [...new Map(inventory.dependencies.filter((dependency) => !dependency.lookupStatus).map((dependency) => [keyFor(dependency), dependency])).values()]
  const coverage: Omit<CheckCoverage, 'id' | 'label'> = { status: 'not-run', details: '', source: 'OSV.dev', requestedCount: enabled ? requested.length : 0, responseCount: 0, matchedCount: 0, skippedCount: skippedDetails.length, skippedDetails }
  let lookup: AdvisoryLookupResult | undefined, failure: string | undefined
  if (enabled && requested.length) {
    try { lookup = await advisoryLookup(requested) }
    catch (error) { failure = error instanceof Error ? error.message : 'Advisory service unavailable.' }
  }
  const dependencies: DependencyRecord[] = inventory.dependencies.map((dependency) => {
    if (dependency.lookupStatus) return { ...dependency, advisories: [] }
    const key = keyFor(dependency), records = lookup?.advisories.get(key)
    const error = !enabled ? 'Dependency advisory matching was disabled.' : failure ?? lookup?.errors?.get(key) ?? (records === undefined ? 'OSV returned an incomplete result for this exact version.' : undefined)
    return { ...dependency, advisories: records ?? [], lookupStatus: error ? 'unavailable' : records?.length ? 'matched' : 'no-match', ...(error ? { lookupError: error } : {}) }
  })
  const unavailable = dependencies.filter((dependency) => dependency.lookupStatus === 'unavailable')
  const complete = requested.filter((dependency) => lookup?.advisories.has(keyFor(dependency)) && !lookup.errors?.has(keyFor(dependency))).length
  const matchedCount = dependencies.reduce((total, dependency) => total + dependency.advisories.length, 0)
  Object.assign(coverage, { checkedAt: lookup?.checkedAt ?? new Date().toISOString(), responseCount: complete, matchedCount })
  if (!enabled) coverage.details = 'Disabled by the scan options. Dependency inventory is retained; no OSV request was made.'
  else if (!requested.length) coverage.details = `No supported exact-version dependency entries were available; no OSV request was made. ${skippedDetails.length} inventory limitations.`
  else {
    coverage.status = unavailable.length ? 'unavailable' : 'passed'
    coverage.details = `Completed ${complete}/${requested.length} unique exact-version queries against ${lookup?.source ?? 'OSV.dev'}; ${matchedCount} matching advisory records returned. ${skippedDetails.length} inventory limitations. Only completed empty responses are no-match results.`
    if (unavailable.length) coverage.error = [...new Set(unavailable.map((dependency) => dependency.lookupError))].join(' ')
  }
  return { dependencies, coverage }
}

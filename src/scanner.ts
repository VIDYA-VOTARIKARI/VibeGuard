import { discoverDependencies, lookupOsvAdvisories, scanDependencies } from './intelligence'
import { readSourceZip } from './zip'
import type { CheckCoverage, Finding, RuntimeEvidence, ScanSummary, Severity } from './types'

const JAVASCRIPT = /\.(?:[cm]?js|jsx|[cm]?ts|tsx)$/i

export type SourceFile = { path: string; content: string }

export type ScanChecks = {
  secrets?: boolean
  configuration?: boolean
  authorization?: boolean
  dependencies?: boolean
  codeSafety?: boolean
}

const defaultChecks: Required<ScanChecks> = {
  secrets: true,
  configuration: true,
  authorization: true,
  dependencies: true,
  codeSafety: true,
}

const redact = (value: string) => {
  const trimmed = value.replace(/["'`\s,;]+$/g, '')
  if (trimmed.length < 8) return '[redacted]'
  return `${trimmed.slice(0, 4)}••••${trimmed.slice(-3)}`
}

const lineNumber = (content: string, index: number) => content.slice(0, index).split('\n').length

const evidenceLine = (content: string, index: number, matched: string) => {
  const line = content.split('\n')[lineNumber(content, index) - 1]?.trim() ?? matched.trim()
  return line.replace(/(["'`])(?:\\.|(?!\1)[^\\\r\n])*?\1/g, (literal) => `${literal[0]}[redacted literal]${literal[0]}`).replace(/(['"`=:\s])([A-Za-z0-9_\-./+=]{8,})/g, (_all, prefix: string, secret: string) => `${prefix}${redact(secret)}`)
}

const finding = (partial: Omit<Finding, 'id'>): Finding => ({ ...partial, id: crypto.randomUUID() })

const isPlaceholder = (value: string) => /example|placeholder|change[-_ ]?me|your[_ -]?(key|token|secret|password)|dummy|fake|not[-_ ]?a[-_ ]?real/i.test(value)

export async function readZip(file: File): Promise<SourceFile[]> {
  const { files } = await readSourceZip(file)
  if (!files.length) throw new Error('No supported text source files were found in this archive.')
  return files
}

function makeFinding(
  file: SourceFile,
  index: number,
  matched: string,
  details: Omit<Finding, 'id' | 'file' | 'line' | 'evidence'>,
): Finding {
  const line = lineNumber(file.content, index)
  const sensitive = /^(SECRET-|CRED-|CONFIG-00[12]$)/.test(details.rule)
  return finding({ ...details, file: file.path, line, evidence: sensitive ? `${details.rule} matched at source line ${line}; sensitive contents redacted (••••).` : evidenceLine(file.content, index, matched) })
}

function findingWithScan(findingValue: Finding, scanId: string, verificationMethod: string) {
  return { ...findingValue, scanId, verificationMethod }
}

function hasOwnershipGuard(handlerText: string) {
  const authenticatedUser = '(?:req|request)\\.user\\.id|auth\\.uid|current_user'
  const ownerField = '(?:owner[_A-Za-z]*|user[_A-Za-z]*)'
  return new RegExp(`(?:${ownerField}\\s*(?:===|!==|==|!=|:|=)\\s*(?:${authenticatedUser})|(?:${authenticatedUser})\\s*(?:===|!==|==|!=)\\w+\\.${ownerField})`, 'i').test(handlerText)
}

// Preserve offsets for line evidence while excluding comments/string examples.
// This is deliberately a heuristic, not a JavaScript parser or exploit proof.
function codeOnly(text: string, keepStrings = false) {
  return text.replace(/\/\*[\s\S]*?\*\/|\/\/[^\n]*|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`/g, (value) => keepStrings && !value.startsWith('/') ? value : value.replace(/[^\n]/g, ' '))
}

function handlerScope(text: string, index: number, original = text) {
  let start = 0, end = text.length
  const bodies = /(?:=>\s*|function\b[^{}]*\([^{}]*\)\s*)\{/g
  for (const match of text.matchAll(bodies)) {
    const open = match.index + match[0].length - 1
    if (open > index) break
    let depth = 1, close = open + 1
    for (; close < text.length && depth; close++) {
      if (text[close] === '{') depth++
      if (text[close] === '}') depth--
    }
    if (close > index && open >= start) { start = open; end = close }
  }
  // Also bound top-level heuristics to route registrations when no body matched.
  if (start === 0) {
    for (const match of text.matchAll(/\b(?:app|router)\.(?:get|post|put|patch|delete|use)\s*\(/g)) {
      if (match.index <= index) start = match.index
      else { end = Math.min(end, match.index); break }
    }
  }
  return original.slice(start, end)
}

function scanJavaScript(file: SourceFile, checks: Required<ScanChecks>): Finding[] {
  const findings: Finding[] = []
  const text = codeOnly(file.content)
  const orderLookup = /orders?\.find\s*\(\s*\(?\s*\w+\s*\)?\s*=>\s*\w+\.id\s*===?\s*(?:req|request)\.params\.id\s*\)?/gi
  for (const lookupMatch of checks.authorization ? text.matchAll(orderLookup) : []) {
    const handlerText = handlerScope(text, lookupMatch.index)
    if (!hasOwnershipGuard(handlerText)) {
      findings.push(makeFinding(file, lookupMatch.index, lookupMatch[0], {
        title: 'Order lookup does not enforce ownership',
        rule: 'VG-JS-001',
        category: 'Authorization',
        severity: 'High',
        confidence: 'Likely',
        status: 'Awaiting verification',
        whyItMatters: 'The Express handler retrieves an order by a request-controlled identifier, but the surrounding handler does not visibly constrain the result to the authenticated user. Static analysis cannot prove exploitability without an authorized request test.',
        remediation: 'Enforce ownership on the server before returning the requested resource. Query by both the order identifier and the authenticated user identity, or reject the request when the owner does not match.',
        prompt: `Fix ${file.path}:${lineNumber(text, lookupMatch.index)}. For GET /api/orders/:id, retrieve the order using req.params.id and req.user.id (or the framework equivalent), return 403/404 for another user’s order, and add an integration test for User A, User B, and unauthenticated access.`,
        verificationMethod: 'Run an authorized two-user integration test that requests User A’s order as User B and verifies denial.',
      }))
    }
  }

  const priceExpression = /Number\s*\(\s*(?:(?:req|request)\.body\.)?quantity\s*\)\s*\*\s*Number\s*\(\s*(?:(?:req|request)\.body\.)?unitPrice\s*\)/gi
  for (const priceMatch of checks.codeSafety ? text.matchAll(priceExpression) : []) {
    const handlerText = handlerScope(text, priceMatch.index)
    const clientPrice = /(?:req|request)\.body\.unitPrice|\{[^{}]*\bunitPrice\b[^{}]*\}\s*=\s*(?:req|request)\.body/.test(handlerText)
    if (clientPrice) {
      findings.push(makeFinding(file, priceMatch.index, priceMatch[0], {
        title: 'Checkout total uses client-controlled pricing',
        rule: 'VG-JS-002',
        category: 'Business logic',
        severity: 'High',
        confidence: 'Likely',
        status: 'Unresolved',
        whyItMatters: 'The order total is calculated from quantity and unitPrice supplied through the request body. A client can change the price unless the server retrieves the authoritative price from its product catalog.',
        remediation: 'Accept a product identifier and validated quantity, retrieve the authoritative price on the server, and calculate the total from trusted catalog data. Never trust a price supplied by the browser.',
        prompt: `Harden ${file.path}:${lineNumber(text, priceMatch.index)}. Accept a product ID and validated quantity only, fetch the product price from the trusted server-side catalog, calculate the total on the server, and add a test proving a modified client price is ignored.`,
        verificationMethod: 'Run a checkout integration test that tampers with unitPrice and verifies the stored total uses the catalog price.',
      }))
    }
  }

  for (const corsMatch of checks.configuration ? text.matchAll(/cors\s*\(\s*\{[^{}]*?\borigin\s*:\s*true\b[^{}]*\}\s*\)/gi) : []) {
    findings.push(makeFinding(file, corsMatch.index, corsMatch[0], {
      title: 'CORS reflects arbitrary request origins',
      rule: 'VG-JS-003',
      category: 'Configuration',
      severity: 'Medium',
      confidence: 'Likely',
      status: 'Unresolved',
      whyItMatters: 'origin: true reflects the caller’s Origin instead of enforcing an explicit trusted-origin allowlist. CORS is a browser policy, not a replacement for authentication or authorization.',
      remediation: 'Configure the intended trusted origins explicitly, restrict methods and credentials as needed, and enforce authentication and authorization independently on every protected route.',
      prompt: `Replace cors({ origin: true }) near ${file.path}:${lineNumber(text, corsMatch.index)} with an explicit trusted-origin allowlist from server-side configuration. Add tests for allowed and rejected origins, and keep route authentication/authorization separate.`,
      verificationMethod: 'Run an HTTP configuration test with an allowed origin and an untrusted origin, then verify protected routes still require authorization.',
    }))
  }
  return findings
}

function scanFile(file: SourceFile, checks: Required<ScanChecks>): Finding[] {
  const findings: Finding[] = []
  const text = file.content

  if (JAVASCRIPT.test(file.path)) findings.push(...scanJavaScript(file, checks))

  if (checks.secrets) {
    const secretPatterns: Array<{ regex: RegExp; title: string; rule: string; category: string; severity: Severity }> = [
      { regex: /(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{12,}/g, title: 'Stripe-like API key in source', rule: 'SECRET-001', category: 'Secrets', severity: 'Critical' },
      { regex: /AIza[0-9A-Za-z_-]{30,}/g, title: 'Google API key in source', rule: 'SECRET-002', category: 'Secrets', severity: 'High' },
      { regex: /gh[pousr]_[A-Za-z0-9_]{30,}/g, title: 'GitHub token in source', rule: 'SECRET-003', category: 'Secrets', severity: 'Critical' },
      { regex: /AKIA[0-9A-Z]{16}/g, title: 'AWS access key in source', rule: 'SECRET-005', category: 'Secrets', severity: 'Critical' },
      { regex: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g, title: 'Private key material in source', rule: 'SECRET-006', category: 'Secrets', severity: 'Critical' },
      { regex: /(?:api[_-]?key|access[_-]?token|secret)\s*[:=]\s*["'`]([A-Za-z0-9_\-./+=]{12,})["'`]/gi, title: 'Hardcoded secret-like value', rule: 'SECRET-004', category: 'Secrets', severity: 'High' },
      { regex: /(?:postgres|mysql|mongodb(?:\+srv)?)\:\/\/[^\s"'`/:]+:[^\s"'`@]+@/gi, title: 'Database connection string contains credentials', rule: 'SECRET-007', category: 'Secrets', severity: 'Critical' },
    ]
    for (const pattern of secretPatterns) {
      pattern.regex.lastIndex = 0
      const match = pattern.regex.exec(text)
      if (match?.index === undefined || isPlaceholder(match[0])) continue
      findings.push(makeFinding(file, match.index, match[0], {
        title: pattern.title,
        rule: pattern.rule,
        category: pattern.category,
        severity: pattern.severity,
        confidence: 'Confirmed',
        status: 'Unresolved',
        whyItMatters: 'Anyone who can read this file or a shipped bundle may be able to reuse the credential. A redacted match is shown so the raw value is not exposed in VibeGuard.',
        remediation: 'Rotate the credential, remove it from source and build output, and use a server-side secret store or environment variable with the smallest required permissions.',
        prompt: `Find the exposed secret in ${file.path} near line ${lineNumber(text, match.index)}. Remove the raw value, rotate it, and wire the application to a server-side environment variable. Do not print or expose the secret in client bundles.`,
      }))
    }

    const credentialPattern = /(?:password|passwd|pwd|client_secret)\s*[:=]\s*["'`](?!process\.env|import\.meta\.env)[^"'`\n]{4,}["'`]/gi
    const credentialMatch = credentialPattern.exec(text)
    if (credentialMatch?.index !== undefined && !isPlaceholder(credentialMatch[0])) {
      findings.push(makeFinding(file, credentialMatch.index, credentialMatch[0], {
        title: 'Hardcoded credential',
        rule: 'CRED-001',
        category: 'Credentials',
        severity: 'Critical',
        confidence: 'Likely',
        status: 'Unresolved',
        whyItMatters: 'A password committed to source is easy to copy and difficult to revoke safely. It can also leak through source control history and build logs.',
        remediation: 'Rotate the credential immediately. Store it outside source control, scope it to the smallest permission set, and add the file pattern to your secret-scanning policy.',
        prompt: `Replace the hardcoded credential near ${file.path}:${lineNumber(text, credentialMatch.index)} with a server-side environment variable. Add a safe startup error when it is missing and remove the old value from git history if it was committed.`,
      }))
    }
  }

  if (checks.configuration) {
    if (/(?:^|\/)\.env(?:\..+)?$/i.test(file.path) && /(?:=).{4,}/.test(text) && !/\.env\.(?:example|sample|template)/i.test(file.path)) {
      const match = /(?:^|\n)[A-Z][A-Z0-9_]*\s*=/.exec(text)
      findings.push(makeFinding(file, (match?.index ?? 0) + (match?.[0].startsWith('\n') ? 1 : 0), match?.[0] ?? text.slice(0, 20), {
        title: 'Environment file contains values',
        rule: 'CONFIG-001',
        category: 'Configuration',
        severity: 'High',
        confidence: 'Likely',
        status: 'Unresolved',
        whyItMatters: 'A real .env file can be uploaded, committed, or copied into a frontend build by mistake. Environment files should be local-only and treated as sensitive input.',
        remediation: 'Keep only placeholders in .env.example, add real .env files to .gitignore, and only read server-side variables in trusted backend code. Rotate values that were committed.',
        prompt: `Audit ${file.path}. Keep placeholders only in the example file, add real environment files to .gitignore, and ensure browser code never reads server-only secrets. Rotate any credential that was committed.`,
      }))
    }

    const laravelKey = /(?:^|\n)APP_KEY\s*=\s*(?!base64:\[?your|change[-_ ]?me|null)[^\n]{16,}/i.exec(text)
    if (laravelKey && !/\.env\.example/i.test(file.path)) {
      const keyIndex = laravelKey.index + Math.max(laravelKey[0].indexOf('APP_KEY'), 0)
      findings.push(makeFinding(file, keyIndex, laravelKey[0], {
        title: 'Laravel APP_KEY appears in a real environment file',
        rule: 'CONFIG-002',
        category: 'Configuration',
        severity: 'Critical',
        confidence: 'Confirmed',
        status: 'Unresolved',
        whyItMatters: 'Laravel uses APP_KEY for application encryption and signing. If it was exposed, rotate it using the framework’s supported procedure and review encrypted data impact.',
        remediation: 'Remove the value from source, rotate APP_KEY safely, invalidate exposed sessions where appropriate, and keep production environment files outside the repository.',
        prompt: `Secure ${file.path}: remove the Laravel APP_KEY from source control, rotate it through the deployment secret manager, review encrypted data and sessions, and add an .env.example placeholder only.`,
      }))
    }

    const permissivePattern = /(?:allowAnonymous|publicAccess|anon|enableRLS\s*\(\s*false\s*\)|rowLevelSecurity\s*:\s*false)/i
    const permissiveMatch = permissivePattern.exec(text)
    if (permissiveMatch) {
      findings.push(makeFinding(file, permissiveMatch.index, permissiveMatch[0], {
        title: 'Database access policy appears permissive',
        rule: 'DB-001',
        category: 'Database',
        severity: 'High',
        confidence: 'Likely',
        status: 'Unresolved',
        whyItMatters: 'A permissive database policy can expose rows to anonymous users or bypass row-level authorization. Static evidence needs a controlled request test before it can be called confirmed.',
        remediation: 'Enable row-level security or an equivalent policy, require authentication, and write an ownership rule for every user-owned table. Re-run the two-user verification test.',
        prompt: `Review the database policy near ${file.path}:${lineNumber(text, permissiveMatch.index)}. Require authentication and enforce owner_id = auth user for reads and writes. Add a test proving User B cannot read User A data.`,
      }))
    }
  }

  if (checks.authorization && /\.(?:[cm]?js|jsx|[cm]?ts|tsx|py|rb|go|java|php|sql)$/i.test(file.path)) {
    const javascript = JAVASCRIPT.test(file.path)
    const code = javascript ? codeOnly(text) : text
    const withoutComments = javascript ? codeOnly(text, true) : text
    const queryPattern = /(?:select\s+\*|\.\s*find\s*\(|\bfrom\s*\(['"`][^'"`]+['"`])/gi
    for (const match of withoutComments.matchAll(queryPattern)) {
      if (javascript && !code.slice(match.index, match.index + 4).trim()) continue
      // The dedicated order rule handles only this lookup, not every query in
      // a file containing one order handler.
      if (javascript && /\borders?$/.test(code.slice(0, match.index)) && /^\.find\s*\(\s*\(?\s*\w+\s*\)?\s*=>\s*\w+\.id\s*===?\s*(?:req|request)\.params\.id/i.test(code.slice(match.index))) continue
      const scope = javascript ? handlerScope(code, match.index, withoutComments) : withoutComments
      if (hasOwnershipGuard(scope) || /(?:owner_id|user_id|auth\.uid|current_user|authorization)/i.test(scope)) continue
      findings.push(makeFinding(file, match.index, match[0], {
        title: 'Data query has no visible ownership check',
        rule: 'AUTHZ-001',
        category: 'Authorization',
        severity: 'High',
        confidence: 'Likely',
        status: 'Awaiting verification',
        whyItMatters: 'Authentication answers “who are you?”. Authorization answers “what may you access?”. A query without an ownership constraint can become a cross-user data leak.',
        remediation: 'Add a server-side owner check using the authenticated user identity. Never trust a user_id supplied only by the client. Verify both unauthorized denial and legitimate self-access.',
        prompt: `Harden the data access near ${file.path}:${lineNumber(text, match.index)}. Use the authenticated session identity on the server, filter by owner_id, and return 403 for another user’s record. Add an integration test for User A and User B.`,
      }))
    }
  }

  if (checks.codeSafety) {
    const match = /eval\s*\(|dangerouslySetInnerHTML/i.exec(JAVASCRIPT.test(file.path) ? codeOnly(text) : text)
    if (match) {
      findings.push(makeFinding(file, match.index, match[0], {
        title: 'Risky code execution or rendering pattern',
        rule: 'CODE-001',
        category: 'Code safety',
        severity: 'Medium',
        confidence: 'Likely',
        status: 'Unresolved',
        whyItMatters: 'Dynamic execution and untrusted HTML rendering can turn user-controlled input into script execution or supply-chain risk.',
        remediation: 'Avoid dynamic code execution, sanitize untrusted markup with a vetted allowlist, and pin dependencies with lockfiles and review.',
        prompt: `Review the risky pattern near ${file.path}:${lineNumber(text, match.index)}. Remove dynamic execution or sanitize untrusted markup with a vetted allowlist. Explain the trust boundary in a short code comment.`,
      }))
    }
  }

  return findings
}

function detectRuntimes(files: SourceFile[]): RuntimeEvidence[] {
  const runtimes: RuntimeEvidence[] = []
  for (const file of files) {
    const name = file.path.split('/').pop() ?? ''
    if (name === 'package.json') {
      try {
        const parsed = JSON.parse(file.content) as { engines?: { node?: unknown } }
        const version = typeof parsed?.engines?.node === 'string' ? parsed.engines.node : undefined
        runtimes.push({ component: 'Node.js', ecosystem: 'node', version, sourceFile: file.path, evidence: version ? 'declared' : 'unknown', details: version ? 'Declared engines.node constraint; the deployed runtime was not observed.' : 'package.json has no engines.node declaration. The deployed runtime was not observed.' })
      } catch { /* Malformed manifests are retained in dependency coverage. */ }
    }
    const runtimeFiles: Record<string, [string, string]> = { '.nvmrc': ['Node.js', 'node'], '.node-version': ['Node.js', 'node'], '.python-version': ['Python', 'PyPI'], '.ruby-version': ['Ruby', 'RubyGems'] }
    if (runtimeFiles[name] && file.content.trim()) {
      const [component, ecosystem] = runtimeFiles[name]
      runtimes.push({ component, ecosystem, version: file.content.trim().split(/\s/)[0], sourceFile: file.path, evidence: 'declared', details: 'Runtime version file; not observed deployment evidence.' })
    }
    if (/^(?:Dockerfile(?:\..+)?|Containerfile)$/.test(name)) {
      for (const match of file.content.matchAll(/^\s*FROM\s+(?:--platform=\S+\s+)?(node|python|php|ruby)(?::([^\s@]+))?/gim)) {
        runtimes.push({ component: { node: 'Node.js', python: 'Python', php: 'PHP', ruby: 'Ruby' }[match[1].toLowerCase()]!, ecosystem: match[1].toLowerCase(), version: match[2], sourceFile: file.path, evidence: 'declared', details: 'Container image tag, not an exact or observed runtime version.' })
      }
    }
    if (name === '.tool-versions') {
      for (const match of file.content.matchAll(/^(nodejs|python|ruby|php)\s+([^\s#]+)/gm)) runtimes.push({ component: { nodejs: 'Node.js', python: 'Python', ruby: 'Ruby', php: 'PHP' }[match[1]]!, ecosystem: match[1], version: match[2], sourceFile: file.path, evidence: 'declared' })
    }
  }
  const components: Record<string, string> = { 'npm:express': 'Express', 'npm:next': 'Next.js', 'npm:react': 'React', 'npm:react-dom': 'React DOM', 'Packagist:laravel/framework': 'Laravel', 'PHP platform:php': 'PHP' }
  for (const dependency of discoverDependencies(files)) {
    const component = components[`${dependency.ecosystem}:${dependency.packageName}`]
    if (component) runtimes.push({ component, ecosystem: dependency.ecosystem, version: dependency.version === 'unknown' ? undefined : dependency.version, sourceFile: dependency.manifest, evidence: dependency.versionSource ?? 'unknown', details: 'Manifest or lockfile evidence; the deployed version was not observed.' })
  }
  return runtimes
}

function coverageFor(checks: Required<ScanChecks>, files: SourceFile[], dependencyStatus: Omit<CheckCoverage, 'id' | 'label'>, runtimes: RuntimeEvidence[], skipped: string[] = []): CheckCoverage[] {
  const code = files.some((file) => /\.(?:[cm]?js|jsx|[cm]?ts|tsx|py|rb|go|java|php|sql)$/i.test(file.path))
  const check = (id: keyof ScanChecks, label: string, applicable: boolean, details: string): CheckCoverage => ({ id, label, status: checks[id] && applicable ? 'passed' : 'not-run', details: !checks[id] ? 'Disabled by the scan options.' : !applicable ? 'No applicable supported source files were available.' : details })
  return [
    { id: 'source', label: 'Source archive validation', status: files.length ? 'passed' : 'failed', details: `${files.length} supported text files inspected without executing uploaded code.`, skippedCount: skipped.length, skippedDetails: skipped },
    check('secrets', 'Secrets & credentials', files.length > 0, 'Deterministic secret and credential patterns ran.'),
    check('configuration', 'Configuration patterns', files.length > 0, 'Environment, framework, CORS, and database policy patterns ran.'),
    check('authorization', 'Authorization heuristics', code, 'Static ownership heuristics ran; this does not prove exploitability.'),
    check('codeSafety', 'Code safety & checkout pricing', code || files.some((file) => /\.html$/i.test(file.path)), 'Dynamic execution/rendering and client-controlled pricing heuristics ran.'),
    { id: 'dependencies', label: 'Dependency advisory matching', ...dependencyStatus },
    { id: 'runtime', label: 'Runtime and framework detection', status: runtimes.length ? 'passed' : 'not-run', details: runtimes.length ? 'All supported nested runtime declarations were inspected; deployed versions were not observed.' : 'No supported runtime version evidence was found.', skippedDetails: runtimes.filter((runtime) => runtime.evidence === 'unknown').map((runtime) => `${runtime.component} (${runtime.sourceFile}): runtime version is unknown.`) },
  ]
}

function completion(coverage: CheckCoverage[]) {
  const limitations = [...new Set(coverage.flatMap((check) => [
    ...(check.status !== 'passed' ? [`${check.label}: ${check.details}${check.error ? ` ${check.error}` : ''}`] : []),
    ...(check.skippedDetails ?? []),
  ]))]
  const meaningful = coverage.some((check) => ['secrets', 'configuration', 'authorization', 'codeSafety', 'dependencies'].includes(check.id) && (check.status === 'passed' || (check.id === 'dependencies' && (check.responseCount ?? 0) > 0)))
  return { limitations, scanStatus: !meaningful ? 'Failed' as const : limitations.length ? 'Completed with limitations' as const : 'Completed' as const, ...(!meaningful ? { errorCode: 'NO_SUPPORTED_CHECKS', error: 'No meaningful supported checks completed.' } : {}) }
}

export type ZipScanOptions = { scanId?: string; onProgress?: (phase: string) => void }

export async function scanZip(
  file: File,
  target = 'Uploaded project',
  selectedChecks: ScanChecks = {},
  advisoryLookup = lookupOsvAdvisories,
  options: ZipScanOptions = {},
): Promise<ScanSummary> {
  const { files, skipped } = await readSourceZip(file, options.onProgress)
  const checks = { ...defaultChecks, ...selectedChecks }
  const scanId = options.scanId ?? crypto.randomUUID()
  options.onProgress?.('Running selected static source checks')
  const findings = files.flatMap((sourceFile) => scanFile(sourceFile, checks)).map((item) => findingWithScan(item, scanId, item.verificationMethod ?? 'Review the source evidence and rerun the relevant check after remediation.'))
  options.onProgress?.('Inventorying nested manifests and lockfiles')
  if (checks.dependencies) options.onProgress?.('Matching exact dependency versions against OSV')
  const dependencyResult = await scanDependencies(files, advisoryLookup, checks.dependencies)
  const dependencyFindings = dependencyResult.dependencies.flatMap((dependency) => dependency.advisories.map((advisory) => findingWithScan(finding({
    title: `${advisory.packageName} has a known advisory`,
    rule: `DEP-${advisory.id}`,
    category: 'Dependencies',
    severity: advisory.severity,
    confidence: 'Confirmed',
    status: 'Unresolved',
    file: dependency.manifest,
    evidence: `${advisory.packageName}@${advisory.version} matched ${advisory.id}; OSV receives package name, ecosystem and exact version, not source contents.`,
    whyItMatters: advisory.summary,
    remediation: advisory.fixedVersion ? `The advisory lists a fix at ${advisory.fixedVersion}. Confirm the appropriate fixed release for this dependency branch, update ${advisory.packageName}, and rerun advisory matching and regression tests.` : `Upgrade ${advisory.packageName} after confirming a fixed release in the advisory source, then run the project’s regression tests.`,
    prompt: `Update ${advisory.packageName} from ${advisory.version} to ${advisory.fixedVersion ?? 'a verified fixed release'}. Review the advisory ${advisory.id}, regenerate the lockfile, and run the application’s regression and security tests.`,
    advisoryId: advisory.id,
    affectedRange: advisory.affectedRange,
    fixedVersion: advisory.fixedVersion,
    sourceUrl: advisory.sourceUrl,
    verificationMethod: 'Regenerate the lockfile and rerun advisory matching against the resolved version.',
  }), scanId, 'Regenerate the lockfile and rerun advisory matching against the resolved version.')))
  const allFindings = [...findings, ...dependencyFindings]
  options.onProgress?.('Detecting runtime declarations and finalizing coverage')
  const runtimes = detectRuntimes(files)
  const now = new Date().toISOString()
  const coverage = coverageFor(checks, files, dependencyResult.coverage, runtimes, skipped)
  const scanTypes = coverage.filter((check) => check.id !== 'source' && check.status === 'passed').map((check) => check.label)
  return {
    findings: allFindings,
    scans: [],
    target,
    scanId,
    fileCount: files.length,
    checkedAt: now,
    scanTypes,
    isDemo: false,
    coverage,
    runtimes,
    dependencies: dependencyResult.dependencies,
    verificationHistory: [],
    scanType: 'Source upload',
    sourceFiles: files.map((file) => file.path),
    ...completion(coverage),
  }
}

export function scanTextFiles(files: SourceFile[], target: string, selectedChecks: ScanChecks = {}): ScanSummary {
  const checks = { ...defaultChecks, ...selectedChecks }
  const scanId = crypto.randomUUID()
  const findings = files.flatMap((file) => scanFile(file, checks)).map((item) => findingWithScan(item, scanId, item.verificationMethod ?? 'Review the source evidence and rerun the relevant check after remediation.'))
  const runtimes = detectRuntimes(files)
  const coverage = coverageFor(checks, files, { status: 'not-run', details: 'Dependency lookups are only run by the asynchronous ZIP scan.' }, runtimes)
  return {
    findings,
    scans: [],
    target,
    scanId,
    fileCount: files.length,
    checkedAt: new Date().toISOString(),
    scanTypes: coverage.filter((check) => check.id !== 'source' && check.status === 'passed').map((check) => check.label),
    isDemo: true,
    coverage,
    runtimes,
    dependencies: [],
    verificationHistory: [],
    scanType: 'Demo',
    sourceFiles: files.map((file) => file.path),
    ...completion(coverage),
  }
}

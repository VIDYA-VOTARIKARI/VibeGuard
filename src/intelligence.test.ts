import { afterEach, describe, expect, it, vi } from 'vitest'
import { dependencyKey, discoverDependencyInventory, lookupOsvAdvisories, scanDependencies, type DependencyInput } from './intelligence'

afterEach(() => { vi.unstubAllGlobals(); vi.useRealTimers() })
const dependency: DependencyInput = { packageName: 'lodash', ecosystem: 'npm', version: '4.17.20', manifest: 'shop/package-lock.json', versionSource: 'resolved' }
const key = 'npm:lodash:4.17.20'
const lock = (path = 'shop/package-lock.json', version = '4.17.20') => ({ path, content: JSON.stringify({ lockfileVersion: 3, packages: { 'node_modules/lodash': { version } } }) })
// Full /query fixture: /querybatch would return only id and modified.
const advisory = {
  schema_version: '1.6.0', id: 'GHSA-35jh-r3h4-6jhm', modified: '2024-01-01T00:00:00Z', published: '2021-01-01T00:00:00Z',
  summary: 'Command injection in lodash', database_specific: { severity: 'HIGH' },
  affected: [{ package: { ecosystem: 'npm', name: 'lodash' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.17.21' }] }] }],
}
const stubResponse = (payload: unknown, status = 200) => vi.stubGlobal('fetch', vi.fn(async () => Response.json(payload, { status })))

describe('project-aware dependency inventory', () => {
  it('merges ranges only with the same independent project resolution in either input order', () => {
    const files = [
      { path: 'apps/a/package.json', content: '{"dependencies":{"lodash":"^4.17.0","express":"^4.18.0"}}' },
      lock('apps/a/package-lock.json', '4.17.20'),
      { path: 'apps/b/package.json', content: '{"dependencies":{"lodash":"^4.17.21","express":"^5.0.0"}}' },
      lock('apps/b/package-lock.json', '4.17.21'),
      { path: 'apps/c/package.json', content: '{"dependencies":{"lodash":"^4.17.0"}}' },
    ]
    for (const input of [files, [...files].reverse()]) {
      const result = discoverDependencyInventory(input)
      expect(result.dependencies).toHaveLength(5)
      expect(result.dependencies).toEqual(expect.arrayContaining([
        expect.objectContaining({ packageName: 'lodash', declaredVersion: '^4.17.0', resolvedVersion: '4.17.20', declarationFile: 'apps/a/package.json', resolutionFile: 'apps/a/package-lock.json' }),
        expect.objectContaining({ packageName: 'lodash', declaredVersion: '^4.17.21', resolvedVersion: '4.17.21', declarationFile: 'apps/b/package.json' }),
        expect.objectContaining({ packageName: 'lodash', version: '^4.17.0', manifest: 'apps/c/package.json', lookupStatus: 'unknown-version' }),
      ]))
    }
  })

  it('keeps identical versions in independent projects while deduplicating exact OSV requests', async () => {
    const fetchMock = vi.fn(async () => Response.json({ vulns: [advisory] })); vi.stubGlobal('fetch', fetchMock)
    const result = await scanDependencies([lock('a/package-lock.json'), lock('b/package-lock.json')])
    expect(result.dependencies).toHaveLength(2)
    expect(result.dependencies.map((dep) => dep.manifest)).toEqual(['a/package-lock.json', 'b/package-lock.json'])
    expect(result.dependencies.every((dep) => dep.lookupStatus === 'matched')).toBe(true)
    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(result.coverage).toMatchObject({ requestedCount: 1, responseCount: 1, matchedCount: 2 })
  })

  it('keeps transitive versions separate and never resolves a declaration against a nested transitive copy', () => {
    const result = discoverDependencyInventory([
      { path: 'package.json', content: '{"dependencies":{"lodash":"^4.17.0"}}' },
      { path: 'package-lock.json', content: JSON.stringify({ packages: { 'node_modules/a': { version: '1.0.0' }, 'node_modules/a/node_modules/lodash': { version: '3.10.1' } } }) },
    ])
    expect(result.dependencies.find((dep) => dep.declarationFile === 'package.json')).toMatchObject({ version: '^4.17.0', lookupStatus: 'unknown-version' })
    expect(result.dependencies.find((dep) => dep.version === '3.10.1')?.declarationFile).toBeUndefined()
  })

  it('keeps stale or conflicting lock evidence distinct from exact declarations', () => {
    const result = discoverDependencyInventory([{ path: 'shop/package.json', content: '{"dependencies":{"lodash":"4.17.21"}}' }, lock()])
    expect(result.dependencies.map((dep) => dep.version).sort()).toEqual(['4.17.20', '4.17.21'])
  })

  it('supports v1 npm/shrinkwrap entries, optional/dev/peer declarations and missing lock versions', () => {
    const result = discoverDependencyInventory([
      { path: 'package.json', content: '{"dependencies":{"a":"^1.0.0"},"optionalDependencies":{"optional":"*"},"peerDependencies":{"peer":">=1"},"devDependencies":{"dev":"1.0.0"}}' },
      { path: 'npm-shrinkwrap.json', content: '{"lockfileVersion":1,"dependencies":{"a":{"version":"1.2.3","dependencies":{"nested":{"version":"0.1.2"}}},"missing":{}}}' },
    ])
    expect(result.dependencies).toEqual(expect.arrayContaining([
      expect.objectContaining({ packageName: 'a', version: '1.2.3', declaredVersion: '^1.0.0', versionSource: 'resolved' }),
      expect.objectContaining({ packageName: 'nested', version: '0.1.2' }),
      expect.objectContaining({ packageName: 'missing', versionSource: 'unknown', lookupStatus: 'unknown-version' }),
      expect.objectContaining({ packageName: 'optional', version: '*', lookupStatus: 'unknown-version' }),
      expect.objectContaining({ packageName: 'peer', version: '>=1', lookupStatus: 'unknown-version' }),
      expect.objectContaining({ packageName: 'dev', version: '1.0.0' }),
    ]))
  })

  it('retains npm aliases, workspace/file dependencies, unversioned and malformed entries', () => {
    const result = discoverDependencyInventory([{ path: 'package.json', content: '{"dependencies":{"alias":"npm:lodash@4.17.20","local":"file:../lib","workspace":"workspace:*","unknown":null,"invalid":{"x":1},"range":"^1.2.3"}}' }])
    expect(result.dependencies).toHaveLength(6)
    expect(result.dependencies.filter((dep) => dep.lookupStatus === 'unsupported')).toHaveLength(3)
    expect(result.dependencies.filter((dep) => dep.lookupStatus === 'unknown-version')).toHaveLength(3)
  })

  it('preserves Python operators, normalized names, short exact pins, markers and unsupported includes', async () => {
    const fetchMock = vi.fn(async () => Response.json({})); vi.stubGlobal('fetch', fetchMock)
    const result = await scanDependencies([{ path: 'python/requirements-prod.txt', content: [
      'Django>=1.2.3', 'flask~=2.0.1', 'urllib3==1.26.*', 'unversioned', 'Requests==2.31.0; python_version >= "3.8"',
      'my_pkg[extra]==1.2', 'special===1.2.3', 'thing @ https://example.invalid/thing.whl', '-r base.txt',
    ].join('\n') }])
    expect(result.dependencies.find((dep) => dep.packageName === 'django')).toMatchObject({ version: '>=1.2.3', declaredVersion: '>=1.2.3', lookupStatus: 'unknown-version' })
    expect(result.dependencies.find((dep) => dep.packageName === 'unversioned')).toMatchObject({ versionSource: 'unknown', lookupStatus: 'unknown-version' })
    expect(result.dependencies.find((dep) => dep.packageName === 'requests')).toMatchObject({ version: '2.31.0', lookupStatus: 'no-match' })
    expect(result.dependencies.find((dep) => dep.packageName === 'my-pkg')).toMatchObject({ version: '1.2', declaredVersion: '==1.2', lookupStatus: 'no-match' })
    const bodies = fetchMock.mock.calls.map((call) => JSON.parse((call as unknown as [string, RequestInit])[1].body as string))
    expect(bodies.map((body) => body.version).sort()).toEqual(['1.2', '2.31.0'])
    expect(result.coverage.skippedDetails?.join(' ')).toContain('Environment marker')
  })

  it('parses Composer and Pipfile locks and retains unsupported ecosystems and formats', () => {
    const result = discoverDependencyInventory([
      { path: 'php/composer.json', content: '{"require":{"php":"^8.2","laravel/framework":"^10.0"}}' },
      { path: 'php/composer.lock', content: '{"packages":[{"name":"laravel/framework","version":"v10.1.2"}],"packages-dev":[{"name":"vendor/test","version":"1.2.3"}]}' },
      { path: 'python/Pipfile.lock', content: '{"default":{"requests":{"version":"==2.31.0"}},"develop":{"pytest":{"version":"==8.0.0"}}}' },
      { path: 'rust/Cargo.lock', content: '[[package]]\nname="example"\nversion="1.2.3"' },
      { path: 'python/pyproject.toml', content: '[project]\ndependencies=["requests>=2"]' },
    ])
    expect(result.dependencies).toEqual(expect.arrayContaining([
      expect.objectContaining({ packageName: 'laravel/framework', declaredVersion: '^10.0', resolvedVersion: 'v10.1.2' }),
      expect.objectContaining({ packageName: 'php', lookupStatus: 'unsupported' }),
      expect.objectContaining({ packageName: 'requests', version: '2.31.0', versionSource: 'resolved' }),
      expect.objectContaining({ manifest: 'rust/Cargo.lock', lookupStatus: 'unsupported' }),
      expect.objectContaining({ manifest: 'python/pyproject.toml', lookupStatus: 'unsupported' }),
    ]))
  })

  it('handles Yarn classic/Berry selectors and pnpm scoped packages/importers without claiming full YAML coverage', () => {
    const result = discoverDependencyInventory([
      { path: 'classic/package.json', content: '{"dependencies":{"@scope/pkg":"^1.2.0"}}' },
      { path: 'classic/yarn.lock', content: '"@scope/pkg@^1.2.0", "@scope/pkg@~1.2.3":\n  version "1.2.3"\n  resolved "https://registry.npmjs.org/@scope/pkg"\n' },
      { path: 'berry/yarn.lock', content: '__metadata:\n  version: 8\n"lodash@npm:^4.17.0":\n  version: 4.17.20\n  resolution: "lodash@npm:4.17.20"\n' },
      { path: 'pnpm/apps/store/package.json', content: '{"dependencies":{"@scope/pkg":"^1.2.0"}}' },
      { path: 'pnpm/pnpm-lock.yaml', content: "lockfileVersion: '9.0'\nimporters:\n  apps/store:\n    dependencies:\n      '@scope/pkg':\n        specifier: ^1.2.0\n        version: 1.2.3(peer@2.0.0)\npackages:\n  '@scope/pkg@1.2.3':\n    resolution: {integrity: sha512-example}\n" },
    ])
    expect(result.dependencies).toEqual(expect.arrayContaining([
      expect.objectContaining({ packageName: '@scope/pkg', version: '1.2.3', declaredVersion: '^1.2.0', declarationFile: 'classic/package.json' }),
      expect.objectContaining({ packageName: 'lodash', version: '4.17.20', manifest: 'berry/yarn.lock' }),
      expect.objectContaining({ packageName: '@scope/pkg', version: '1.2.3', declaredVersion: '^1.2.0', declarationFile: 'pnpm/apps/store/package.json', resolutionFile: 'pnpm/pnpm-lock.yaml' }),
    ]))
    expect(result.skipped.some((skip) => skip.reason.includes('YAML'))).toBe(true)
  })

  it('retains malformed manifests as inventory and coverage limitations', async () => {
    const lookup = vi.fn()
    const result = await scanDependencies([{ path: 'package.json', content: '{bad' }, { path: 'package-lock.json', content: '{"packages":[]}' }], lookup)
    expect(result.dependencies).toHaveLength(2)
    expect(result.dependencies.every((dep) => dep.lookupStatus === 'unsupported')).toBe(true)
    expect(result.coverage.status).toBe('not-run')
    expect(result.coverage.skippedDetails?.join(' ')).toContain('Malformed manifest')
    expect(lookup).not.toHaveBeenCalled()
  })

  it('does not query Yarn aliases and workspace versions as real registry packages', async () => {
    const fetchMock = vi.fn(); vi.stubGlobal('fetch', fetchMock)
    const result = await scanDependencies([{ path: 'yarn.lock', content: '"alias@npm:lodash@^4.17.0":\n  version: 4.17.20\n"local@workspace:packages/local":\n  version: 0.0.0-use.local\n' }])
    expect(result.dependencies).toHaveLength(2)
    expect(result.dependencies.every((entry) => entry.lookupStatus === 'unsupported')).toBe(true)
    expect(fetchMock).not.toHaveBeenCalled()
  })
})

describe('realistic exact-version OSV query contract', () => {
  it('uses full /query responses with exact package identity and no source upload', async () => {
    stubResponse({ vulns: [advisory] })
    const result = await scanDependencies([lock()])
    expect(result.dependencies[0]).toMatchObject({ lookupStatus: 'matched', advisories: [expect.objectContaining({ id: advisory.id, severity: 'High', fixedVersion: '4.17.21' })] })
    expect(result.coverage).toMatchObject({ status: 'passed', responseCount: 1, matchedCount: 1 })
    const call = vi.mocked(fetch).mock.calls[0]
    expect(call[0]).toBe('https://api.osv.dev/v1/query')
    expect(JSON.parse(call[1]?.body as string)).toEqual({ package: { ecosystem: 'npm', name: 'lodash' }, version: '4.17.20' })
  })

  it.each([{}, { vulns: [] }])('reports only complete empty responses as no-match: %j', async (response) => {
    stubResponse(response)
    const result = await scanDependencies([lock()])
    expect(result.dependencies[0].lookupStatus).toBe('no-match')
    expect(result.coverage).toMatchObject({ status: 'passed', responseCount: 1, matchedCount: 0 })
  })

  it('uses OSV matching for ecosystem-specific/prerelease ranges instead of local semver logic', async () => {
    const dep = { ...dependency, packageName: 'example', ecosystem: 'PyPI', version: '1.2rc1' }
    stubResponse({ vulns: [{ ...advisory, database_specific: {}, affected: [{ package: { ecosystem: 'PyPI', name: 'Example' }, ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '1.2' }] }] }] }] })
    const result = await lookupOsvAdvisories([dep])
    expect(result.advisories.get('PyPI:example:1.2rc1')).toHaveLength(1)
    expect(result.errors?.size).toBe(0)
  })

  it('follows pages including empty/token-only pages and deduplicates advisory IDs', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(Response.json({ next_page_token: 'first' }))
      .mockResolvedValueOnce(Response.json({ vulns: [advisory], next_page_token: 'second' }))
      .mockResolvedValueOnce(Response.json({ vulns: [advisory, { ...advisory, id: 'GHSA-second' }] }))
    vi.stubGlobal('fetch', fetchMock)
    const result = await lookupOsvAdvisories([dependency])
    expect(result.responseCount).toBe(1)
    expect(result.advisories.get(key)).toHaveLength(2)
    expect(fetchMock.mock.calls.map((call) => JSON.parse(call[1].body).page_token)).toEqual([undefined, 'first', 'second'])
  })

  it.each([
    null, [], { results: [{ vulns: [{ id: 'GHSA-id-only', modified: '2024-01-01' }] }] },
    { vulns: [{ id: 'GHSA-id-only', modified: '2024-01-01' }] }, { vulns: null }, { error: 'unavailable' },
    { vulns: [null] }, { next_page_token: 7 }, { vulns: [{ ...advisory, affected: [] }] },
    { vulns: [{ ...advisory, affected: [{ package: { name: 'lodash', ecosystem: 'npm' } }] }] },
    { vulns: [{ ...advisory, withdrawn: true }] },
    { vulns: [{ ...advisory, affected: [{ package: { name: 'different', ecosystem: 'npm' } }] }] },
  ])('does not turn incomplete/wrong-package/ID-only payloads into clean results: %j', async (payload) => {
    stubResponse(payload)
    const result = await scanDependencies([lock()])
    expect(result.dependencies[0]).toMatchObject({ lookupStatus: 'unavailable', advisories: [] })
    expect(result.coverage.status).toBe('unavailable')
    expect(result.coverage.responseCount).toBe(0)
  })

  it('preserves known matches when later pagination fails and labels the lookup unavailable', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValueOnce(Response.json({ vulns: [advisory], next_page_token: 'more' })).mockRejectedValueOnce(new TypeError('Failed to fetch')))
    const result = await scanDependencies([lock()])
    expect(result.dependencies[0].advisories).toHaveLength(1)
    expect(result.dependencies[0].lookupStatus).toBe('unavailable')
    expect(result.coverage).toMatchObject({ status: 'unavailable', responseCount: 0, matchedCount: 1 })
  })

  it('rejects repeated pagination tokens rather than reporting clean or looping', async () => {
    stubResponse({ next_page_token: 'loop' })
    const result = await scanDependencies([lock()])
    expect(result.dependencies[0].lookupError).toContain('repeated a token')
    expect(vi.mocked(fetch)).toHaveBeenCalledTimes(2)
  })

  it('bounds endless distinct pagination tokens', async () => {
    let index = 0; vi.stubGlobal('fetch', vi.fn(async () => Response.json({ next_page_token: `page-${index++}` })))
    const result = await scanDependencies([lock()])
    expect(result.dependencies[0].lookupStatus).toBe('unavailable')
    expect(result.dependencies[0].lookupError).toContain('pagination')
    expect(vi.mocked(fetch)).toHaveBeenCalledTimes(10)
  })

  it.each([429, 500, 503])('retains HTTP %i failures as unavailable', async (status) => {
    stubResponse({}, status)
    const result = await scanDependencies([lock()])
    expect(result.dependencies[0].lookupError).toContain(String(status))
    expect(result.dependencies[0].lookupStatus).toBe('unavailable')
  })

  it('retains network, invalid JSON and oversized responses as unavailable', async () => {
    for (const mock of [
      vi.fn().mockRejectedValue(new TypeError('network offline')),
      vi.fn(async () => new Response('{invalid JSON')),
      vi.fn(async () => new Response('{}', { headers: { 'content-length': '999999999' } })),
    ]) {
      vi.stubGlobal('fetch', mock)
      expect((await scanDependencies([lock()])).dependencies[0].lookupStatus).toBe('unavailable')
    }
  })

  it('aborts timed-out requests and returns honest per-entry errors', async () => {
    vi.useFakeTimers()
    vi.stubGlobal('fetch', vi.fn((_url: string, init: RequestInit) => new Promise((_resolve, reject) => init.signal?.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError'))))))
    const pending = scanDependencies([lock()])
    await vi.advanceTimersByTimeAsync(5_001)
    const result = await pending
    expect(result.dependencies[0].lookupStatus).toBe('unavailable')
    expect(result.coverage.error).toContain('timed out')
  })

  it('does not mistake a missing injected lookup map entry for a zero match', async () => {
    const result = await scanDependencies([lock()], async () => ({ advisories: new Map(), responseCount: 1, source: 'OSV.dev', checkedAt: new Date().toISOString() }))
    expect(result.dependencies[0]).toMatchObject({ lookupStatus: 'unavailable', lookupError: expect.stringContaining('incomplete') })
    expect(result.coverage.responseCount).toBe(0)
  })

  it('keeps successful results when a separate package lookup fails', async () => {
    vi.stubGlobal('fetch', vi.fn(async (_url: string, init: RequestInit) => JSON.parse(init.body as string).version === '4.17.20' ? Response.json({ vulns: [advisory] }) : Response.json({}, { status: 503 })))
    const result = await scanDependencies([lock('a/package-lock.json'), lock('b/package-lock.json', '4.17.21')])
    expect(result.dependencies.map((dep) => dep.lookupStatus)).toEqual(['matched', 'unavailable'])
    expect(result.coverage).toMatchObject({ status: 'unavailable', requestedCount: 2, responseCount: 1 })
  })

  it('does not invent one fixed version from multiple release branches or parse CVSS vectors as numbers', async () => {
    stubResponse({ vulns: [{ ...advisory, database_specific: {}, severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }], affected: [{ package: { ecosystem: 'npm', name: 'lodash' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '3.10.2' }, { introduced: '4.0.0' }, { fixed: '4.17.21' }] }] }] }] })
    const result = await lookupOsvAdvisories([dependency])
    expect(result.advisories.get(key)?.[0]).toMatchObject({ fixedVersion: undefined, severity: 'Informational' })
  })

  it('does not query a range even if lookupOsvAdvisories is called directly', async () => {
    const fetchMock = vi.fn(); vi.stubGlobal('fetch', fetchMock)
    const result = await lookupOsvAdvisories([{ ...dependency, version: '>=4.17.20' }])
    expect(fetchMock).not.toHaveBeenCalled()
    expect(result.errors?.get(dependencyKey('lodash', 'npm', '>=4.17.20'))).toContain('exact supported')
  })

  it('bounds query volume and marks overflow unavailable rather than clean', async () => {
    stubResponse({})
    const dependencies = Array.from({ length: 201 }, (_, index) => ({ ...dependency, packageName: `package-${index}` }))
    const result = await lookupOsvAdvisories(dependencies)
    expect(vi.mocked(fetch)).toHaveBeenCalledTimes(200)
    expect(result.responseCount).toBe(200)
    expect(result.errors?.get('npm:package-200:4.17.20')).toContain('budget exceeded')
    expect(result.advisories.has('npm:package-200:4.17.20')).toBe(false)
  })
})

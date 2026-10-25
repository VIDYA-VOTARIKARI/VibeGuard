# VibeGuard 2.0

> Evidence from supported checks, with explicit limitations.

VibeGuard is a hackathon-ready, evidence-first security scanner for applications built with AI coding tools. This MVP keeps deterministic source checks, safe authorization testing, remediation guidance, and report generation in one responsive web application.

## What is implemented

- Responsive landing page with VibeGuard positioning, authorization notice, workflow, coverage, and demo CTA.
- Workspace dashboard derived only from actual scan records; illustrative landing-page demo content does not contribute to counts.
- Shared lifecycle: `Pending` → `Running` → `Completed`, `Completed with limitations`, or `Failed`. Every attempt has a UUID and starts with empty findings, inventory, and verification history. Authorization, invalid input, unsafe destinations, execution failures, and unavailable services remain distinct.
- Source ZIP upload with:
  - 10 MB archive-size limit.
  - ZIP-only validation.
  - raw central/local ZIP record validation before inflation, followed by streamed byte limits and CRC validation of inspected files.
  - file-count limit and supported-text-file allowlist.
  - 25 MB maximum extracted-size and 1 MB maximum supported-text-file limits.
  - unsafe compression-ratio rejection for decompression-bomb style archives.
  - archive path-traversal rejection (`/absolute/path` and `..` segments).
  - no execution of uploaded application code.
- Deterministic local checks for:
  - Stripe-like, Google, GitHub, AWS, private-key, database-credential, and secret-like API key patterns.
  - hardcoded credentials.
  - risky `.env` handling and Laravel `APP_KEY` exposure.
  - permissive database/RLS configuration indicators.
  - data queries without a visible ownership/authorization constraint.
  - selected risky rendering or dynamic-code patterns.
- Node.js/Express JavaScript rules for the vulnerable shop fixture:
  - `VG-JS-001` — order lookup without a visible server-side ownership guard (`Likely` until an authorized test reproduces access).
  - `VG-JS-002` — checkout totals calculated from client-controlled `quantity` and `unitPrice`.
  - `VG-JS-003` — permissive `cors({ origin: true })` configuration.
- Nested project directories are traversed in-memory; generated directories such as `node_modules`, `dist`, `build`, `.git`, and coverage output are ignored.
- Runtime and framework evidence from supported manifests, clearly labelled as declared, resolved, or unknown rather than observed deployment versions. Node.js projects without `engines.node` now show the runtime as unknown instead of implying a version.
- Dependency inventory supports npm manifests/locks (including shrinkwrap), conventional Yarn/pnpm blocks, pinned Python requirements/Pipfile locks, and Composer manifests/locks. Independent nested projects retain their own declarations and resolutions. Ranges, malformed entries, and unsupported formats are retained as explicit limitations instead of disappearing.
- Patch Intelligence queries OSV `/v1/query` with exact package name, ecosystem, and version. Unlike `/querybatch`, this endpoint returns full advisory records. Pagination, partial responses, timeouts, and errors are handled per version; affected-version matching is delegated to OSV rather than guessed locally. Limits: 4 concurrent requests, 5 seconds per request, 30 seconds total, 200 distinct versions, 10 pages per version, and 4 MB per response.
- Each dependency shows `matched`, `no-match`, `unknown-version`, `unsupported`, or `unavailable`. Only a completed empty lookup is `no-match`; this never proves that the project is secure. Existing matches remain visible if a later response is unavailable. Unknown severity is shown as Informational, not a guessed CVSS score; multiple fixed release branches do not become one invented upgrade target.
- Hosting-aware guidance for Vercel, Netlify, Replit, Hostinger, Docker, self-managed VPS/cloud, and unknown environments.
- A coverage ledger showing passed, failed, unavailable, and not-run checks.
- Secret redaction in visible evidence and reports.
- Findings view with severity, confidence (`Confirmed`, `Likely`, `Informational`), location, evidence, plain-English impact, remediation, and copyable AI coding prompts.
- Controlled two-user authorization lab using synthetic User A/User B order fixtures:
  - vulnerable fixture reproduces cross-user access;
  - corrected fixture denies User B and unauthenticated access while preserving User A and User B self-access;
  - verification history records each executed run with its ID, timestamp, expected outcomes, actual outcomes, and evidence summary;
  - “Fixed” is applied only after the executed verification checks pass; staging a correction alone does not resolve the finding.
- Downloadable JSON and HTML reports with scan metadata, coverage state, findings, advisory references, verification history, and limitations.
- Anonymous public workflow: source ZIP scanning, Patch Intelligence, controlled AuthZ demo, and report downloads do not require an account.
- Optional accounts backed by the local API: signup, login, logout, HttpOnly session cookies, password hashing with Node scrypt, and per-user scan history.
- Persistent history for authenticated users using the configured server data directory. Anonymous scans remain temporary unless the user explicitly consents to save the current completed scan during signup.
- Authorized website URL scanning requires the explicit permission checkbox in the recommendation popup. Continue starts the scan; Upload Source ZIP opens the existing picker; Cancel starts no request. The popup explains that website observations cannot replace source inspection.
- The server permits HTTPS only, port 443, without embedded credentials. All DNS answers are validated conservatively against restricted address ranges, each request pins a validated IP, and every redirect is revalidated. Limits: 2 seconds for DNS, 15 seconds total, 4 redirects, 4 concurrent scans, 256 KiB cumulative response bytes, and 16 KiB response headers. No crawling, cookie replay, package installation, or application execution.
- URL evidence includes validated TLS/hostname connection status, final response code, redirect count/final origin, missing security headers, cookie attributes with names/values redacted, and qualified observed technology headers. Error/block/login responses do not claim successful HTTP availability. Certificate revocation and a full TLS configuration audit are not implemented.
- URL scans explicitly separate observable headers/cookies/technology signals from source and dependency analysis. Exact package versions are not inferred from a website fingerprint.
- Website Patch Intelligence says: **Dependency advisory check unavailable: exact dependency versions could not be established.** A separately scanned ZIP can be associated only after confirmation; this stores a pointer, not copied findings or dependency evidence, and does not prove deployment identity.
- Saving failure does not discard completed results or pretend history was saved. API history uses server-side owner checks, `checkedAt` ordering, validated record shapes, and serialized atomic file replacement. Tests exercise concurrent writes, rollback after failures, owner isolation, and reading history after a server restart.
- No paid API key or server-side model is required for the basic workflow.

## Run locally

Requirements:

- Node.js 24 recommended (tested with `v24.18.0`; installed Vite requires `^20.19.0 || >=22.12.0`)
- npm 9+
- A browser/runtime supporting `File.arrayBuffer`, Web Streams, and `DecompressionStream('deflate-raw')`. Unsupported decompression fails explicitly rather than falling back to unbounded inflation.

```bash
npm install
npm run api
npm run dev
```

Run `npm run api` in one terminal and `npm run dev` in another. Open the local URL printed by Vite, usually `http://localhost:5173`.

For a production build:

```bash
npm run build
npm run preview
```

Keep `npm run api` running for preview too. Both Vite development and local preview proxy `/api` to port 8787. Vite preview is not a public production server. A public deployment needs its own same-origin HTTPS reverse proxy for `/api`, static hosting for `dist`, restricted egress, and durable storage outside the web root.

## Judge demonstration sequence

1. Open the landing page and click **Explore demo**.
2. In the controlled security lab, click **Run authorization test**.
3. Observe the failed `User B → User A order` check and the passing owner, peer, and unauthenticated checks.
4. Click **Apply correction in demo**.
5. Click **Verify correction** (or **Run again**).
6. Confirm all four actual fixture checks pass and the finding is marked fixed.
7. Open **See finding details** to inspect evidence and the tailored remediation prompt.
8. Open **Patch intelligence** to inspect dependency/runtime evidence and select a hosting provider for remediation guidance.
9. Open **Reports** and download both JSON and HTML reports.
10. To demonstrate real source scanning, open **Start a scan**, upload a ZIP containing supported source files, check the ownership confirmation, and run the scan.

## Environment variables

- `PORT` — API port, default `8787`.
- `VIBEGUARD_DATA_DIR` — persistent server data directory, default `.vibeguard-data`.
- `VIBEGUARD_DISABLE_URL_SCAN=true` — disables outbound website scanning with an explicit `SCANNING_DISABLED` response.
- `NODE_ENV=production` — adds Secure to the HttpOnly/SameSite session cookie; requires an HTTPS frontend/proxy.

The former `VIBEGUARD_ALLOW_HTTP_URL_SCAN` setting no longer enables HTTP. There is no environment or HTTP-input bypass for DNS/IP/TLS checks. Loopback dialing and a test CA exist only in controlled in-process test fixtures. `server-test-tls-fixture.mjs` contains a clearly labelled public, non-secret TEST ONLY certificate/key, never used by production scanning.

No paid AI API key is required. The application intentionally does not expose an AI provider key in frontend code. An optional server-side AI explanation service can be added later behind an API boundary; deterministic finding records must remain the source of truth.

## Scope and limitations

- The frontend still keeps the active workspace scan in memory. Authenticated history persists in the API data directory and is only as durable as the configured storage volume.
- The current persistence implementation is a local JSON store intended for a single-instance deployment or prototype. A production multi-instance deployment should replace it with a transactional database and shared session strategy before claiming enterprise production readiness.
- Sessions remain in memory; server restarts require signing in again. Custom local authentication has not been replaced by an established identity provider. Do not treat this repair as a public-production authentication/security certification. Recovery, account deletion/retention automation, shared sessions, and multi-process storage are not implemented.
- ZIP support is intentionally bounded: UTF-8 names, STORE/DEFLATE, at most 350 entries. ZIP64, encryption, multipart/self-extracting layouts, links/special files, ambiguous paths, and unsafe archives are rejected. Ignored/unsupported content is not inflated or CRC-checked and appears in the coverage limitations.
- Yarn/pnpm support is a bounded block-layout parser, not general YAML evaluation. Unsupported layouts remain limited/unavailable. An exact version declaration is not proof of the version actually deployed.
- Static checks cover supported text files and deterministic patterns; they do not prove the absence of vulnerabilities.
- Dependency matching depends on a reachable OSV.dev request. If the advisory service is unavailable, the scan explicitly says `unavailable` and does not claim a clean dependency result.
- Website URL scanning is limited to authorized, read-only observable checks. It does not inspect private source, hidden environment variables, internal database permissions, or every authorization flaw.
- The URL scanner rejects private, loopback, link-local, reserved, and restricted destinations and revalidates redirects. It does not crawl links or run intrusive tests.
- The authorization lab uses in-memory synthetic fixtures rather than executing uploaded code.
- Browser-click/end-to-end visual testing was unavailable: the computer tool reported `virtual_unavailable` on this Windows CLI. React markup tests and a real Vite-proxy/API/TLS/storage integration test passed, but they are not a substitute for a browser interaction test.
- IPv6 classification/pinning is tested; a native IPv6 socket integration test and expired/revoked-certificate fixtures were not run. Conservative address-allocation rules need maintenance; enforce outbound network restrictions in deployment too.
- A follow-up ZIP is compared only after explicit same-project confirmation. Missing files, unavailable checks, or missing runtime authorization evidence remain inconclusive, not fixed. Complete synthetic authorization tests cannot update a real source/URL finding; empty/incomplete/contradictory test sets never pass.
- A clean result is not a security certification and VibeGuard never grants a “Verified by VibeGuard” badge for a static scan alone.

## Verification in this workspace — October 25, 2026

- `npm test` — 134 tests passed across 7 files: ZIP/parser limits, source rules, advisory matching/failure/pagination, verification, reports, redaction, lifecycle/no-stale-results, API errors, and rendered views.
- `npm run test:server` — 60 tests passed: actual controlled HTTP/TLS transport, trusted/untrusted/wrong-host certificates, DNS cancellation, restricted destinations, rebinding, redirects, deadlines, response limits, concurrency, authorization, redaction, and persistent-history failures/isolation/restarts.
- `npm run test:integration` — 1 full-stack integration test passed: generated ZIP → real frontend pipeline → reports; signup/explicit import → authorized local TLS target through Vite proxy and Node API → URL results → confirmed source association → saved history/report → logout/login and cross-user denial. OSV responses and network dialing are controlled fixtures; this is not a live website vulnerability claim or browser-click test.
- `npm run build` — TypeScript and Vite production output passed.
- `npm audit --audit-level=high` — 0 reported dependency vulnerabilities (not proof of application security).
- Local API restarted with the repaired code; API health and development `/api/health` proxy returned HTTP 200. A temporary Vite production-preview server also returned HTTP 200 for `/` and `/api/health`, then shut down.

The actual user-uploaded e-commerce ZIP was not present in the workspace. Generated vulnerable archives exercise the same three code patterns; no seeded findings substitute for scanning. In `src/zip.test.ts`, all three rules are found in `shop/api/server.cjs`: ownership at line 7, client pricing at line 16, and permissive CORS at line 5. `integration.test.mjs` independently creates and scans its own fixture.

No public deployment was performed. Tests do not establish that an arbitrary website/project is secure. All test commands are designed to finish within five minutes and use temporary storage, never `.vibeguard-data`.

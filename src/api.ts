import type { ScanSummary } from './types'

export interface PublicUser {
  id: string
  email: string
  createdAt: string
}

export class ApiRequestError extends Error {
  constructor(message: string, public code: string, public status?: number) { super(message) }
}

async function request<T>(path: string, init: RequestInit = {}) {
  const controller = new AbortController()
  const timeout = setTimeout(() => controller.abort(), 25_000)
  try {
    let response: Response
    try { response = await fetch(path, { ...init, signal: controller.signal, credentials: 'include', headers: { 'content-type': 'application/json', ...(init.headers ?? {}) } }) }
    catch { throw new ApiRequestError('The VibeGuard API is unavailable or timed out. Start the API server and check its connection.', 'EXTERNAL_UNAVAILABLE') }
    const payload = await response.json().catch(() => null) as (T & { error?: string; code?: string }) | null
    if (!payload) throw new ApiRequestError('The API returned an invalid response. Check the API proxy configuration.', 'EXTERNAL_UNAVAILABLE', response.status)
    if (!response.ok) throw new ApiRequestError(payload.error ?? `Request failed with HTTP ${response.status}.`, payload.code ?? 'EXECUTION_FAILED', response.status)
    return payload
  } finally { clearTimeout(timeout) }
}

export function getCurrentUser() {
  return request<{ user: PublicUser | null }>('/api/auth/me')
}

export function signUp(email: string, password: string) {
  return request<{ user: PublicUser }>('/api/auth/signup', { method: 'POST', body: JSON.stringify({ email, password }) })
}

export function signIn(email: string, password: string) {
  return request<{ user: PublicUser }>('/api/auth/login', { method: 'POST', body: JSON.stringify({ email, password }) })
}

export function signOut() {
  return request<{ ok: true }>('/api/auth/logout', { method: 'POST', body: '{}' })
}

export function saveScan(scan: ScanSummary) {
  return request<{ scan: ScanSummary }>('/api/scans', { method: 'POST', body: JSON.stringify({ scan }) })
}

export function listSavedScans() {
  return request<{ scans: ScanSummary[] }>('/api/scans')
}

export function runUrlScan(target: string, authorized: boolean, scanId: string) {
  return request<{ scan: ScanSummary; saved: boolean; persistenceError?: string }>('/api/url-scan', { method: 'POST', body: JSON.stringify({ target, authorized, scanId }) })
}

/**
 * The single typed API client.
 *
 * Everything goes to a relative /api/... path: the SPA must work behind nginx
 * at http://127.0.0.1 and at the LAN address, so no host is ever hardcoded.
 * The CSRF token lives in memory only (it is fetched from /api/auth/me and
 * refreshed by the auth provider); every mutating request carries it.
 */

import type {
  AuditEntry,
  Control,
  ControlCreate,
  ControlUpdate,
  DashboardSummary,
  DashboardTrend,
  Engine,
  EvidenceDetail,
  EvidenceItem,
  Fact,
  FindingDetail,
  FindingSummary,
  FindingSummaryStats,
  FindingUpdate,
  Framework,
  FrameworkCreate,
  FrameworkRef,
  FrameworkRefCreate,
  FrameworkUpdate,
  Health,
  LogLine,
  MeResponse,
  PostureRow,
  RunDetail,
  RunSummary,
  Scope,
  ScopeCreate,
  ScopeEntry,
  ScopeEntryCreate,
  ScopeUpdate,
  Setting,
  Target,
  TargetCreate,
  TargetUpdate,
  TestVersion,
  TestVersionCreate,
  User,
  UserCreate,
  UserUpdate,
  ValidationTest,
  ValidationTestCreate,
  ValidationTestDetail,
} from './types'

export class ApiError extends Error {
  readonly status: number
  readonly detail: string
  readonly raw: unknown

  constructor(status: number, detail: string, raw: unknown) {
    super(detail)
    this.name = 'ApiError'
    this.status = status
    this.detail = detail
    this.raw = raw
  }
}

let csrfToken: string | null = null

export function setCsrfToken(token: string | null): void {
  csrfToken = token
}

type UnauthorizedHandler = () => void
let unauthorizedHandler: UnauthorizedHandler | null = null

/** The auth provider registers a handler so a 401 anywhere logs the UI out. */
export function setUnauthorizedHandler(handler: UnauthorizedHandler | null): void {
  unauthorizedHandler = handler
}

export type QueryValue = string | number | boolean | null | undefined

function formatValidationDetail(items: unknown[]): string {
  const parts = items.map((item) => {
    if (item !== null && typeof item === 'object') {
      const rec = item as Record<string, unknown>
      const loc = Array.isArray(rec.loc) ? rec.loc.map(String).join('.') : null
      const msg = typeof rec.msg === 'string' ? rec.msg : JSON.stringify(item)
      return loc ? `${loc}: ${msg}` : msg
    }
    return String(item)
  })
  return parts.join('; ')
}

async function readErrorDetail(res: Response): Promise<{ detail: string; raw: unknown }> {
  const text = await res.text().catch(() => '')
  let raw: unknown = null
  if (text) {
    try {
      raw = JSON.parse(text)
    } catch {
      raw = text
    }
  }
  let detail: string
  if (raw !== null && typeof raw === 'object' && 'detail' in raw) {
    const d = (raw as { detail: unknown }).detail
    if (typeof d === 'string') {
      detail = d
    } else if (Array.isArray(d)) {
      detail = formatValidationDetail(d)
    } else {
      detail = JSON.stringify(d)
    }
  } else if (typeof raw === 'string' && raw.trim() !== '') {
    detail = raw.trim().slice(0, 800)
  } else {
    detail = `${res.status} ${res.statusText || 'Request failed'}`
  }
  return { detail, raw }
}

interface RequestOptions {
  query?: Record<string, QueryValue>
  body?: unknown
  /** Mutating requests send the CSRF header unless explicitly opted out. */
  csrf?: boolean
  signal?: AbortSignal
  retriedAfterCsrfRefresh?: boolean
}

async function refreshCsrfToken(): Promise<boolean> {
  try {
    const res = await fetch('/api/auth/me', {
      method: 'GET',
      credentials: 'same-origin',
      headers: { Accept: 'application/json' },
    })
    if (!res.ok) return false
    const data = (await res.json()) as MeResponse
    if (typeof data.csrf_token === 'string') {
      csrfToken = data.csrf_token
      return true
    }
    return false
  } catch {
    return false
  }
}

async function request<T>(method: string, path: string, options: RequestOptions = {}): Promise<T> {
  const url = new URL(`/api${path}`, window.location.origin)
  if (options.query) {
    for (const [key, value] of Object.entries(options.query)) {
      if (value === undefined || value === null || value === '') continue
      url.searchParams.set(key, String(value))
    }
  }

  const headers: Record<string, string> = { Accept: 'application/json' }
  const init: RequestInit = {
    method,
    credentials: 'same-origin',
    headers,
    signal: options.signal ?? null,
  }
  if (options.body !== undefined) {
    headers['Content-Type'] = 'application/json'
    init.body = JSON.stringify(options.body)
  }

  const mutating = method !== 'GET' && method !== 'HEAD'
  if (mutating && options.csrf !== false) {
    if (csrfToken === null) {
      // A mutating call before the session is resolved: try once to learn the
      // token rather than failing with a confusing 403.
      const ok = await refreshCsrfToken()
      if (!ok) {
        throw new ApiError(
          0,
          'Your session could not be verified for this action. Sign in again.',
          null,
        )
      }
    }
    headers['X-CSRF-Token'] = csrfToken ?? ''
  }

  let res: Response
  try {
    res = await fetch(url.toString(), init)
  } catch (cause) {
    if (cause instanceof DOMException && cause.name === 'AbortError') throw cause
    throw new ApiError(0, 'The platform could not be reached. Check that the API is running.', null)
  }

  if (res.status === 401 && path !== '/auth/login' && path !== '/auth/me') {
    unauthorizedHandler?.()
  }

  if (!res.ok) {
    if (res.status === 403 && mutating && options.csrf !== false && !options.retriedAfterCsrfRefresh) {
      // The session may have rotated (re-login in another tab); refresh the
      // token once and retry before surfacing a 403.
      const refreshed = await refreshCsrfToken()
      if (refreshed) {
        return request<T>(method, path, { ...options, retriedAfterCsrfRefresh: true })
      }
    }
    const { detail, raw } = await readErrorDetail(res)
    throw new ApiError(res.status, detail, raw)
  }

  if (res.status === 204) return undefined as T
  const text = await res.text()
  if (!text) return undefined as T
  return JSON.parse(text) as T
}

const get = <T,>(path: string, query?: Record<string, QueryValue>) =>
  request<T>('GET', path, { query })
const post = <T,>(path: string, body?: unknown, csrf = true) =>
  request<T>('POST', path, { body, csrf })
const patch = <T,>(path: string, body: unknown) => request<T>('PATCH', path, { body })
const put = <T,>(path: string, body: unknown) => request<T>('PUT', path, { body })
const del = <T,>(path: string) => request<T>('DELETE', path)

/**
 * Some list endpoints could reasonably be an array or an {items, total}
 * envelope; normalise both so a backend choice does not break the UI.
 */
export function asArray<T>(data: unknown): T[] {
  if (Array.isArray(data)) return data as T[]
  if (data !== null && typeof data === 'object') {
    const items = (data as { items?: unknown }).items
    if (Array.isArray(items)) return items as T[]
  }
  return []
}

export function asPage<T>(data: unknown): { items: T[]; total: number } {
  if (Array.isArray(data)) return { items: data as T[], total: data.length }
  if (data !== null && typeof data === 'object') {
    const obj = data as { items?: unknown; total?: unknown }
    if (Array.isArray(obj.items)) {
      const items = obj.items as T[]
      return { items, total: typeof obj.total === 'number' ? obj.total : items.length }
    }
  }
  return { items: [], total: 0 }
}

// --------------------------------------------------------------- endpoints --

export interface RunFilters {
  status?: string
  test_id?: number
  target_id?: number
  engine_id?: string
  assertion_status?: string
  limit?: number
  offset?: number
}

export interface FindingFilters {
  status?: string
  severity?: string
  target_id?: number
  control_id?: number
  test_id?: number
  q?: string
  limit?: number
  offset?: number
}

export interface EvidenceFilters {
  run_id?: number
  kind?: string
  limit?: number
  offset?: number
}

export interface AuditFilters {
  actor_user_id?: number
  action?: string
  entity_type?: string
  limit?: number
  offset?: number
}

export const api = {
  // -- auth ---------------------------------------------------------------
  me: () => get<MeResponse>('/auth/me'),
  login: (username: string, password: string) =>
    post<MeResponse>('/auth/login', { username, password }, false),
  logout: () => post<{ status: string }>('/auth/logout', undefined),
  changePassword: (current_password: string, new_password: string) =>
    post<{ status: string; sessions_revoked?: boolean }>('/auth/change-password', {
      current_password,
      new_password,
    }),

  // -- system -------------------------------------------------------------
  health: () => get<Health>('/health'),
  settings: () => get<Setting[]>('/settings'),
  putSetting: (key: string, value: Record<string, unknown>) =>
    put<Setting>(`/settings/${key}`, { value }),

  // -- catalogue ----------------------------------------------------------
  engines: () => get<Engine[]>('/engines'),
  frameworks: () => get<Framework[]>('/frameworks'),
  createFramework: (payload: FrameworkCreate) => post<Framework>('/frameworks', payload),
  updateFramework: (id: number, payload: FrameworkUpdate) =>
    patch<Framework>(`/frameworks/${id}`, payload),
  deleteFramework: (id: number) => del<void>(`/frameworks/${id}`),

  // -- directory ----------------------------------------------------------
  users: () => get<User[]>('/users'),
  /** Includes deactivated accounts, so an administrator can reactivate them. */
  allUsers: () => get<User[]>('/users', { active_only: false }),
  createUser: (payload: UserCreate) => post<User>('/users', payload),
  updateUser: (id: number, payload: UserUpdate) => patch<User>(`/users/${id}`, payload),

  // -- registry -----------------------------------------------------------
  controls: (query?: { category?: string; q?: string; limit?: number; offset?: number }) =>
    get<Control[]>('/controls', query),
  control: (id: number) => get<Control>(`/controls/${id}`),
  createControl: (payload: ControlCreate) => post<Control>('/controls', payload),
  updateControl: (id: number, payload: ControlUpdate) =>
    patch<Control>(`/controls/${id}`, payload),
  deleteControl: (id: number) => del<void>(`/controls/${id}`),
  addControlRef: (controlId: number, payload: FrameworkRefCreate) =>
    post<FrameworkRef>(`/controls/${controlId}/refs`, payload),
  removeControlRef: (controlId: number, refId: number) =>
    del<void>(`/controls/${controlId}/refs/${refId}`),
  targets: (query?: { enabled?: boolean; tag?: string; limit?: number; offset?: number }) =>
    get<Target[]>('/targets', query),
  target: (id: number) => get<Target>(`/targets/${id}`),
  createTarget: (payload: TargetCreate) => post<Target>('/targets', payload),
  updateTarget: (id: number, payload: TargetUpdate) => patch<Target>(`/targets/${id}`, payload),
  deleteTarget: (id: number) => del<void>(`/targets/${id}`),
  targetScopes: (id: number) => get<Scope[]>(`/targets/${id}/scopes`),
  linkTargetScope: (targetId: number, scopeId: number) =>
    put<void>(`/targets/${targetId}/scopes/${scopeId}`, undefined),
  unlinkTargetScope: (targetId: number, scopeId: number) =>
    del<void>(`/targets/${targetId}/scopes/${scopeId}`),
  scopes: (query?: { active?: boolean }) => get<Scope[]>('/scopes', query),
  scope: (id: number) => get<Scope>(`/scopes/${id}`),
  createScope: (payload: ScopeCreate) => post<Scope>('/scopes', payload),
  updateScope: (id: number, payload: ScopeUpdate) => patch<Scope>(`/scopes/${id}`, payload),
  deleteScope: (id: number) => del<void>(`/scopes/${id}`),
  addScopeEntry: (scopeId: number, payload: ScopeEntryCreate) =>
    post<ScopeEntry>(`/scopes/${scopeId}/entries`, payload),
  removeScopeEntry: (scopeId: number, entryId: number) =>
    del<void>(`/scopes/${scopeId}/entries/${entryId}`),

  // -- tests --------------------------------------------------------------
  tests: (query?: {
    control_id?: number
    tag?: string
    enabled?: boolean
    q?: string
    limit?: number
    offset?: number
  }) => get<ValidationTest[]>('/tests', query),
  test: (id: number) => get<ValidationTestDetail>(`/tests/${id}`),
  createTest: (payload: ValidationTestCreate) => post<ValidationTestDetail>('/tests', payload),
  updateTest: (id: number, payload: Record<string, unknown>) =>
    patch<ValidationTestDetail>(`/tests/${id}`, payload),
  deleteTest: (id: number) => del<void>(`/tests/${id}`),
  createTestVersion: (id: number, payload: TestVersionCreate) =>
    post<TestVersion>(`/tests/${id}/versions`, payload),

  // -- runs ---------------------------------------------------------------
  runs: (query?: RunFilters) => get<unknown>('/runs', query as Record<string, QueryValue>),
  run: (id: number) => get<RunDetail>(`/runs/${id}`),
  startRun: (test_id: number, target_ids: number[]) =>
    post<{ runs: RunSummary[] }>('/runs', { test_id, target_ids }),
  cancelRun: (id: number) => post<unknown>(`/runs/${id}/cancel`, undefined),
  runLog: (id: number, after_id = 0, limit = 1000) =>
    get<LogLine[]>(`/runs/${id}/log`, { after_id, limit }),
  runFacts: (id: number, fact_type?: string) =>
    get<Fact[]>(`/runs/${id}/facts`, { fact_type }),
  runStreamUrl: (id: number) => `/api/runs/${id}/stream`,

  // -- findings -----------------------------------------------------------
  findings: (query?: FindingFilters) =>
    get<unknown>('/findings', query as Record<string, QueryValue>),
  finding: (id: number) => get<FindingDetail>(`/findings/${id}`),
  updateFinding: (id: number, payload: FindingUpdate) =>
    patch<FindingDetail>(`/findings/${id}`, payload),
  retestFinding: (id: number) => post<{ run_id: number }>(`/findings/${id}/retest`, undefined),
  findingSummary: () => get<FindingSummaryStats>('/findings/summary'),

  // -- evidence -----------------------------------------------------------
  evidence: (query?: EvidenceFilters) =>
    get<unknown>('/evidence', query as Record<string, QueryValue>),
  evidenceItem: (id: number) => get<EvidenceDetail>(`/evidence/${id}`),
  evidenceContentUrl: (id: number) => `/api/evidence/${id}/content`,

  // -- dashboard ----------------------------------------------------------
  dashboardSummary: () => get<DashboardSummary>('/dashboard/summary'),
  dashboardTrend: (days = 30) => get<DashboardTrend>('/dashboard/trend', { days }),
  postureByControl: (limit = 20) => get<PostureRow[]>('/dashboard/posture_by_control', { limit }),

  // -- audit --------------------------------------------------------------
  audit: (query?: AuditFilters) => get<unknown>('/audit', query as Record<string, QueryValue>),
}

export { asArray as asListT, asPage as asPageT }

/** Findings list helper that always returns {items,total}. */
export async function fetchFindings(
  query?: FindingFilters,
): Promise<{ items: FindingSummary[]; total: number }> {
  return asPage<FindingSummary>(await api.findings(query))
}

/** Runs list helper that tolerates an array or an {items,total} envelope. */
export async function fetchRuns(
  query?: RunFilters,
): Promise<{ items: RunSummary[]; total: number }> {
  return asPage<RunSummary>(await api.runs(query))
}

export async function fetchEvidence(
  query?: EvidenceFilters,
): Promise<{ items: EvidenceItem[]; total: number }> {
  return asPage<EvidenceItem>(await api.evidence(query))
}

export async function fetchAudit(
  query?: AuditFilters,
): Promise<{ items: AuditEntry[]; total: number }> {
  return asPage<AuditEntry>(await api.audit(query))
}

export interface EvidenceContentResult {
  /** True when the bytes fetched are exactly what was recorded at write time. */
  intact: boolean
  /** The digest the server computed while serving the bytes, if present. */
  servedSha256: string | null
  blob: Blob
}

/**
 * Fetch evidence bytes with the integrity header checked. The caller must not
 * present a non-intact file as if it were the original.
 */
export async function fetchEvidenceContent(id: number): Promise<EvidenceContentResult> {
  const res = await fetch(api.evidenceContentUrl(id), {
    method: 'GET',
    credentials: 'same-origin',
  })
  if (!res.ok) {
    const { detail, raw } = await readErrorDetail(res)
    throw new ApiError(res.status, detail, raw)
  }
  const header = res.headers.get('X-Evidence-Intact')
  const digest = res.headers.get('X-Content-SHA256')
  const blob = await res.blob()
  return { intact: header !== 'false', servedSha256: digest, blob }
}

/** TanStack Query keys, kept in one place so invalidation is predictable. */
export const qk = {
  me: ['auth', 'me'] as const,
  health: ['health'] as const,
  settings: ['settings'] as const,
  engines: ['engines'] as const,
  frameworks: ['frameworks'] as const,
  users: ['users'] as const,
  controls: (filters?: Record<string, QueryValue>) => ['controls', filters ?? {}] as const,
  control: (id: number) => ['control', id] as const,
  targets: (filters?: Record<string, QueryValue>) => ['targets', filters ?? {}] as const,
  target: (id: number) => ['target', id] as const,
  targetScopes: (id: number) => ['target-scopes', id] as const,
  scopes: (filters?: Record<string, QueryValue>) => ['scopes', filters ?? {}] as const,
  scope: (id: number) => ['scope', id] as const,
  tests: (filters?: Record<string, QueryValue>) => ['tests', filters ?? {}] as const,
  test: (id: number) => ['test', id] as const,
  runs: (filters?: Record<string, QueryValue>) => ['runs', filters ?? {}] as const,
  run: (id: number) => ['run', id] as const,
  runLog: (id: number) => ['run-log', id] as const,
  runFacts: (id: number, factType?: string) => ['run-facts', id, factType ?? ''] as const,
  findings: (filters?: Record<string, QueryValue>) => ['findings', filters ?? {}] as const,
  finding: (id: number) => ['finding', id] as const,
  findingSummary: ['findings', 'summary'] as const,
  evidence: (filters?: Record<string, QueryValue>) => ['evidence', filters ?? {}] as const,
  evidenceItem: (id: number) => ['evidence-item', id] as const,
  audit: (filters?: Record<string, QueryValue>) => ['audit', filters ?? {}] as const,
  dashboardSummary: ['dashboard', 'summary'] as const,
  dashboardTrend: (days: number) => ['dashboard', 'trend', days] as const,
  posture: (limit: number) => ['dashboard', 'posture', limit] as const,
}

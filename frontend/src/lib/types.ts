/**
 * TypeScript mirrors of the backend response models.
 *
 * Source of truth: backend/app/schemas/*.py and backend/app/models/enums.py.
 * If a type here disagrees with the backend, the backend is right.
 */

// --------------------------------------------------------------- enums ----

export type Role = 'admin' | 'analyst' | 'viewer'

export type TargetType = 'host' | 'webapp' | 'api' | 'tls' | 'ssh' | 'local'

export type ScopeEntryKind = 'cidr' | 'host'

export type RunStatus =
  | 'queued'
  | 'running'
  | 'passed'
  | 'failed'
  | 'inconclusive'
  | 'not_applicable'
  | 'error'
  | 'cancelled'
  | 'dead'

export type AssertionStatus = 'pass' | 'fail' | 'inconclusive' | 'not_applicable'

export type FindingStatus =
  | 'open'
  | 'triaged'
  | 'remediating'
  | 'accepted_risk'
  | 'false_positive'
  | 'resolved'

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical'

export type TriggerKind = 'manual' | 'retest' | 'scheduled'

export type EvidenceKind = 'stdout' | 'stderr' | 'artifact'

export type StreamKind = 'stdout' | 'stderr' | 'system'

// ----------------------------------------------------------------- auth ----

export interface User {
  id: number
  username: string
  email: string | null
  full_name: string | null
  role: Role
  is_active: boolean
  must_change_password: boolean
  last_login_at: string | null
  created_at: string | null
}

export interface MeResponse {
  user: User
  csrf_token: string
}

// ------------------------------------------------------------- registry ----

export interface Framework {
  id: number
  key: string
  name: string
  version: string | null
  description: string | null
  source: string | null
  enabled: boolean
  created_at: string
}

export interface FrameworkRef {
  id: number
  framework_id: number
  control_id: number
  ref_code: string
  title: string | null
}

export interface Control {
  id: number
  key: string
  title: string
  category: string | null
  description: string | null
  expected_state: string | null
  default_severity: Severity
  remediation: string | null
  enabled: boolean
  created_at: string
  refs: FrameworkRef[]
}

export interface Target {
  id: number
  name: string
  target_type: TargetType
  host: string
  port: number
  protocol: string
  path: string
  tags: string[]
  criticality: Severity
  owner: string | null
  notes: string | null
  enabled: boolean
  created_at: string
}

export interface ScopeEntry {
  id: number
  kind: ScopeEntryKind
  value: string
  ports: string
  protocol: string
  note: string | null
}

export interface Scope {
  id: number
  name: string
  description: string | null
  authorization_ref: string | null
  approved_by_user_id: number | null
  allow_broad: boolean
  is_lab: boolean
  active: boolean
  expires_at: string | null
  created_at: string
  entries: ScopeEntry[]
}

// -------------------------------------------------------------- engines ----

/** Minimal structural view of a JSON Schema, enough to render a form. */
export interface JsonSchemaNode {
  type?: string | string[]
  title?: string
  description?: string
  default?: unknown
  enum?: unknown[]
  anyOf?: JsonSchemaNode[]
  items?: JsonSchemaNode
  properties?: Record<string, JsonSchemaNode>
  required?: string[]
  minLength?: number
  maxLength?: number
  minimum?: number
  maximum?: number
  pattern?: string
  /** pydantic v2 emits $defs; components may be referenced inline. */
  $defs?: Record<string, JsonSchemaNode>
  $ref?: string
}

export interface Engine {
  id: string
  title: string
  description: string
  fact_types: string[]
  target_types: string[]
  default_timeout: number
  mutating: boolean
  internal: boolean
  notes: string
  params_schema: JsonSchemaNode
}

// ---------------------------------------------------------------- tests ----

export interface TargetSelector {
  target_ids: number[]
  tags: string[]
  target_types: TargetType[]
}

export interface TestVersion {
  id: number
  test_id: number
  version: number
  engine_id: string
  engine_params: Record<string, unknown>
  assertion: Record<string, unknown>
  control_id: number
  severity: Severity
  note: string | null
  created_by_user_id: number | null
  created_at: string
}

export interface ValidationTest {
  id: number
  key: string
  name: string
  description: string | null
  control_id: number
  tags: string[]
  target_selector: TargetSelector | Record<string, never>
  enabled: boolean
  current_version: number
  created_at: string
  updated_at: string | null
}

export interface ValidationTestDetail extends ValidationTest {
  versions: TestVersion[]
}

export interface TestVersionCreate {
  engine_id: string
  engine_params: Record<string, unknown>
  assertion: Record<string, unknown>
  severity?: Severity
  note?: string
}

export interface ValidationTestCreate {
  key: string
  name: string
  description?: string
  control_id: number
  tags?: string[]
  target_selector?: TargetSelector
  enabled?: boolean
  version: TestVersionCreate
}

// ----------------------------------------------------------------- runs ----

export interface RunSummary {
  id: number
  test_id: number
  test_key: string
  test_name: string
  target_id: number
  target_name: string
  target_host: string
  target_port: number
  engine_id: string
  status: RunStatus
  trigger: TriggerKind
  authorized_by_username: string | null
  attempt: number
  queued_at: string
  started_at: string | null
  finished_at: string | null
  duration_seconds: number | null
  exit_code: number | null
  assertion_status: AssertionStatus | null
  error_message: string | null
  findings_count: number
}

export interface RunFactSummary {
  fact_type: string
  count: number
}

export interface AssertionResult {
  id: number
  assertion_index: number
  assertion: Record<string, unknown>
  status: AssertionStatus
  severity: Severity
  reason: string | null
  fact_ids: number[]
  evaluated_at: string
}

export interface RunEvidence {
  id: number
  kind: EvidenceKind
  filename: string
  sha256: string
  size_bytes: number
  mime: string
  truncated: boolean
  created_at: string
}

export interface RunDetail extends RunSummary {
  argv: string[] | null
  tool_versions: Record<string, unknown> | null
  resolved_ips: string[] | null
  scope_snapshot: Record<string, unknown> | null
  timeout_seconds: number | null
  observed_summary: Record<string, unknown> | null
  cancel_requested: boolean
  retest_of_finding_id: number | null
  facts_summary: RunFactSummary[]
  assertion_results: AssertionResult[]
  evidence: RunEvidence[]
}

export interface LogLine {
  id: number
  ts: string
  stream: StreamKind
  level: string
  message: string
}

export interface Fact {
  id: number
  fact_type: string
  subject: string
  key: string
  value: unknown
  confidence: number
  detail: string | null
  evidence_id: number | null
}

// ------------------------------------------------------------- findings ----

export interface FindingSummary {
  id: number
  status: FindingStatus
  severity: Severity
  title: string
  control_id: number
  control_key: string
  control_title: string
  test_id: number
  test_key: string
  target_id: number
  target_name: string
  first_seen_at: string
  last_seen_at: string
  last_run_id: number | null
  occurrences: number
  last_status: AssertionStatus | null
  assigned_to: number | null
  retest_of_finding_id: number | null
  resolved_at: string | null
}

export interface FindingTimelineEntry {
  id: number
  kind: string
  note: string | null
  created_at: string
  actor: string | null
  from_status: FindingStatus | null
  to_status: FindingStatus | null
  due_at: string | null
}

export interface EvidenceItem {
  id: number
  run_id: number
  kind: EvidenceKind
  filename: string
  sha256: string
  size_bytes: number
  mime: string
  truncated: boolean
  created_at: string
  detail: Record<string, unknown> | null
}

export interface EvidenceVerification {
  exists: boolean
  sha256: string | null
  size_bytes: number | null
  digest_matches: boolean
  size_matches: boolean
  intact: boolean
}

export interface EvidenceDetail extends EvidenceItem {
  verification: EvidenceVerification
}

export interface FindingDetail extends FindingSummary {
  description: string | null
  expected: unknown
  observed: unknown
  reason: string | null
  facts: Fact[]
  evidence: EvidenceItem[]
  timeline: FindingTimelineEntry[]
  remediation_guidance: string | null
}

export interface FindingUpdate {
  status?: FindingStatus
  severity?: Severity
  assigned_to?: number | null
  note?: string | null
}

export interface FindingSummaryStats {
  by_severity: Record<string, number>
  by_status: Record<string, number>
  open_total: number
  overdue_total: number
}

// ------------------------------------------------------------- evidence ----

// ------------------------------------------------------------- dashboard --

export interface DashboardSummary {
  assertions: Record<AssertionStatus, number>
  findings: {
    by_severity: Record<string, number>
    by_status: Record<string, number>
  }
  targets: { total: number; scoped: number }
  runs: { last_24h: number; running: number; queued: number; failed: number }
  coverage: {
    controls_total: number
    controls_with_recent_results: number
    controls_stale: number
  }
  last_updated: string
}

export interface TrendDay {
  date: string
  pass: number
  fail: number
  inconclusive: number
  not_applicable: number
}

export interface DashboardTrend {
  days: TrendDay[]
}

export interface PostureRow {
  control_id: number
  control_key: string
  control_title: string
  category: string | null
  pass: number
  fail: number
  inconclusive: number
  not_applicable: number
  coverage_ratio: number
  last_evaluated_at: string | null
}

// ---------------------------------------------------------------- audit ----

export interface AuditEntry {
  id: number
  ts: string
  actor: string | null
  actor_user_id: number | null
  action: string
  entity_type: string | null
  entity_id: string | null
  summary: string | null
  detail: Record<string, unknown> | null
  ip_address: string | null
  user_agent: string | null
  request_id: string | null
}

// ------------------------------------------------------------- settings ----

export interface Setting {
  key: string
  value: Record<string, unknown>
  updated_at: string
  updated_by_user_id: number | null
  is_default: boolean
}

export interface Health {
  status: string
  version: string
  database: { ok: boolean; error: string | null }
  safe_mode: boolean
  kill_switch: boolean
}

// ------------------------------------------------------------- SSE types ---

export interface RunStreamLogEvent extends LogLine {
  type: 'log'
}

export interface RunStreamStatusEvent {
  type: 'status'
  status: RunStatus
  [key: string]: unknown
}

export interface RunStreamDoneEvent {
  type: 'done'
}

export type RunStreamEvent =
  | RunStreamLogEvent
  | RunStreamStatusEvent
  | RunStreamDoneEvent

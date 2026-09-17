/**
 * Status -> visual tone mapping. Colours are enforced consistently:
 * pass=green, fail=red, inconclusive=amber, not_applicable=slate,
 * open=red, resolved=green, accepted_risk=blue. INCONCLUSIVE is never green.
 */

import type {
  AssertionStatus,
  FindingStatus,
  RunStatus,
  Severity,
  TargetType,
} from './types'

export type Tone =
  | 'pass'
  | 'fail'
  | 'incon'
  | 'na'
  | 'accent'
  | 'mute'
  | 'crit'
  | 'high'
  | 'med'
  | 'low'
  | 'info'
  | 'blue'

export const assertionTone: Record<AssertionStatus, Tone> = {
  pass: 'pass',
  fail: 'fail',
  inconclusive: 'incon',
  not_applicable: 'na',
}

export const assertionLabel: Record<AssertionStatus, string> = {
  pass: 'PASS',
  fail: 'FAIL',
  inconclusive: 'INCONCLUSIVE',
  not_applicable: 'N/A',
}

export const assertionOrder: AssertionStatus[] = [
  'pass',
  'fail',
  'inconclusive',
  'not_applicable',
]

export const assertionColor: Record<AssertionStatus, string> = {
  pass: 'var(--color-pass)',
  fail: 'var(--color-fail)',
  inconclusive: 'var(--color-incon)',
  not_applicable: 'var(--color-na)',
}

export const runTone: Record<RunStatus, Tone> = {
  queued: 'mute',
  running: 'accent',
  passed: 'pass',
  failed: 'fail',
  inconclusive: 'incon',
  not_applicable: 'na',
  error: 'crit',
  cancelled: 'mute',
  dead: 'mute',
}

export const runLabel: Record<RunStatus, string> = {
  queued: 'QUEUED',
  running: 'RUNNING',
  passed: 'PASSED',
  failed: 'FAILED',
  inconclusive: 'INCONCLUSIVE',
  not_applicable: 'N/A',
  error: 'ERROR',
  cancelled: 'CANCELLED',
  dead: 'DEAD',
}

export const runStatuses: RunStatus[] = [
  'queued',
  'running',
  'passed',
  'failed',
  'inconclusive',
  'not_applicable',
  'error',
  'cancelled',
  'dead',
]

export const findingStatusTone: Record<FindingStatus, Tone> = {
  open: 'fail',
  triaged: 'incon',
  remediating: 'accent',
  accepted_risk: 'blue',
  false_positive: 'mute',
  resolved: 'pass',
}

export const findingStatuses: FindingStatus[] = [
  'open',
  'triaged',
  'remediating',
  'accepted_risk',
  'false_positive',
  'resolved',
]

export const severityTone: Record<Severity, Tone> = {
  info: 'info',
  low: 'low',
  medium: 'med',
  high: 'high',
  critical: 'crit',
}

export const severities: Severity[] = ['info', 'low', 'medium', 'high', 'critical']

export const severityColor: Record<Severity, string> = {
  info: 'var(--color-info)',
  low: 'var(--color-low)',
  medium: 'var(--color-med)',
  high: 'var(--color-high)',
  critical: 'var(--color-crit)',
}

export const targetTypes: TargetType[] = ['host', 'webapp', 'api', 'tls', 'ssh', 'local']

export const activeRunStatuses: RunStatus[] = ['queued', 'running']

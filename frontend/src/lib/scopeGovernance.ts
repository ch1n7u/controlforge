/** Governance checks for scopes: expiry and broad-scope risk. */

import { daysUntil } from './format'
import type { Scope } from './types'

export type ExpiryState = 'expired' | 'soon' | 'ok' | 'none'

export const EXPIRY_SOON_DAYS = 14

export function expiryState(scope: Scope): ExpiryState {
  const days = daysUntil(scope.expires_at)
  if (days === null) return 'none'
  if (days < 0) return 'expired'
  if (days <= EXPIRY_SOON_DAYS) return 'soon'
  return 'ok'
}

/** Why a scope would not authorize a run, for pickers that list scopes. */
export function authorizationSuffix(scope: Scope): string {
  if (!scope.active) return ' (inactive)'
  if (expiryState(scope) === 'expired') return ' (expired)'
  return ''
}

export function governanceProblems(scope: Scope): string[] {
  const problems: string[] = []
  if (!scope.active) problems.push('inactive')
  if (expiryState(scope) === 'expired') problems.push('expired')
  if (scope.allow_broad) problems.push('broad')
  if (!scope.authorization_ref) problems.push('missing authorization reference')
  return problems
}

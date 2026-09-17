/** Error rendering helpers shared by every page. */

import { ApiError } from './api'

export function errorText(error: unknown): string {
  if (error instanceof ApiError) return error.detail
  if (error instanceof Error) return error.message
  return String(error)
}

export function isUnauthorized(error: unknown): boolean {
  return error instanceof ApiError && error.status === 401
}

export function isForbidden(error: unknown): boolean {
  return error instanceof ApiError && error.status === 403
}

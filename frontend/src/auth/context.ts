import { createContext, useContext } from 'react'
import type { MeResponse, User } from '../lib/types'

export interface AuthValue {
  /** null once resolved and anonymous. */
  me: MeResponse | null
  user: User | null
  /** True until /api/auth/me has resolved for the first time. */
  isPending: boolean
  /** Non-null when /api/auth/me failed for a reason other than 401 (e.g. API down). */
  error: unknown
  isWriter: boolean
  isAdmin: boolean
  login: (username: string, password: string) => Promise<MeResponse>
  logout: () => Promise<void>
  changePassword: (currentPassword: string, newPassword: string) => Promise<void>
}

export const AuthContext = createContext<AuthValue | null>(null)

export function useAuth(): AuthValue {
  const value = useContext(AuthContext)
  if (value === null) {
    throw new Error('useAuth must be used inside <AuthProvider>')
  }
  return value
}

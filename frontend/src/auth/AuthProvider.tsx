import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect, useMemo, type ReactNode } from 'react'
import { Navigate, useLocation } from 'react-router-dom'
import { api, ApiError, qk, setCsrfToken, setUnauthorizedHandler } from '../lib/api'
import { ErrorNotice, Loading } from '../components/ui'
import type { MeResponse } from '../lib/types'
import { AuthContext, useAuth, type AuthValue } from './context'

export function AuthProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient()

  const meQuery = useQuery<MeResponse | null>({
    queryKey: qk.me,
    queryFn: async () => {
      try {
        const me = await api.me()
        setCsrfToken(me.csrf_token)
        return me
      } catch (error) {
        if (error instanceof ApiError && error.status === 401) {
          setCsrfToken(null)
          return null
        }
        throw error
      }
    },
    staleTime: 5 * 60_000,
    retry: false,
    refetchOnWindowFocus: true,
  })

  // A 401 from any request (expired session, revoked by a password change in
  // another tab) drops the UI back to anonymous state.
  useEffect(() => {
    setUnauthorizedHandler(() => {
      setCsrfToken(null)
      queryClient.setQueryData<MeResponse | null>(qk.me, null)
    })
    return () => setUnauthorizedHandler(null)
  }, [queryClient])

  const value = useMemo<AuthValue>(() => {
    const me = meQuery.data ?? null
    const role = me?.user.role ?? null
    return {
      me,
      user: me?.user ?? null,
      isPending: meQuery.isPending,
      error: meQuery.error,
      isWriter: role === 'admin' || role === 'analyst',
      isAdmin: role === 'admin',
      login: async (username, password) => {
        const result = await api.login(username, password)
        setCsrfToken(result.csrf_token)
        queryClient.setQueryData(qk.me, result)
        return result
      },
      logout: async () => {
        try {
          await api.logout()
        } finally {
          setCsrfToken(null)
          queryClient.setQueryData<MeResponse | null>(qk.me, null)
          queryClient.removeQueries({ predicate: (query) => query.queryKey[0] !== 'auth' })
        }
      },
      changePassword: async (currentPassword, newPassword) => {
        await api.changePassword(currentPassword, newPassword)
        // The backend revokes every session for the user on password change,
        // including this one; the UI must sign in again.
        setCsrfToken(null)
        queryClient.setQueryData<MeResponse | null>(qk.me, null)
      },
    }
  }, [meQuery.data, meQuery.isPending, meQuery.error, queryClient])

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function RequireAuth({ children }: { children: ReactNode }) {
  const { me, isPending, error } = useAuth()
  const location = useLocation()

  if (isPending) {
    return (
      <div className="flex min-h-svh items-center justify-center bg-bg">
        <Loading label="Checking session" />
      </div>
    )
  }
  if (error) {
    return (
      <div className="mx-auto max-w-xl p-8">
        <ErrorNotice
          title="Cannot reach Valtros"
          error={error}
          onRetry={() => window.location.reload()}
        />
        <p className="mt-3 text-[12px] text-dim">
          Your session could not be confirmed. Check that the Valtros server is running,
          then reload.
        </p>
      </div>
    )
  }
  if (!me) {
    return <Navigate to="/login" replace state={{ from: location }} />
  }
  return <>{children}</>
}

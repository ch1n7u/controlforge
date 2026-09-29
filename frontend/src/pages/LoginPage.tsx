import { useMutation } from '@tanstack/react-query'
import { useEffect, useState } from 'react'
import { Navigate, useLocation, useNavigate } from 'react-router-dom'
import { useAuth } from '../auth/context'
import { errorText } from '../lib/errors'
import { Button, Field, Input, Loading } from '../components/ui'

export function LoginPage() {
  const { me, isPending, error: sessionError, login } = useAuth()
  const navigate = useNavigate()
  const location = useLocation()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')

  useEffect(() => {
    document.title = 'Sign in · CONTROLFORGE'
  }, [])

  const state = location.state as
    | { from?: { pathname?: string; search?: string }; notice?: string }
    | null
  const from = state?.from?.pathname ? `${state.from.pathname}${state.from.search ?? ''}` : '/'

  const mutation = useMutation({
    mutationFn: () => login(username, password),
    onSuccess: (result) => {
      navigate(result.user.must_change_password ? '/' : from, { replace: true })
    },
  })

  if (isPending) {
    return (
      <div className="flex min-h-svh items-center justify-center bg-bg">
        <Loading label="Checking session" />
      </div>
    )
  }
  if (me) return <Navigate to={from} replace />

  return (
    <div className="flex min-h-svh items-center justify-center bg-bg p-4">
      <div className="w-full max-w-sm">
        <div className="mb-5 text-center">
          <div className="font-mono text-[18px] font-semibold tracking-wide text-ink">
            CONTROL<span className="text-accent">FORGE</span>
          </div>
          <div className="mt-1 text-[12px] text-dim">
            Continuous security control validation and effectiveness testing
          </div>
        </div>

        <form
          onSubmit={(event) => {
            event.preventDefault()
            mutation.mutate()
          }}
          className="border border-edge bg-panel p-5"
        >
          <h1 className="text-[15px] font-semibold text-ink">Sign in</h1>

          {state?.notice && (
            <div className="mt-3 border border-accent/40 bg-accent/10 p-2 text-[12px] text-ink">
              {state.notice}
            </div>
          )}
          {sessionError !== null && sessionError !== undefined && (
            <div className="mt-3 border border-fail/40 bg-fail/5 p-2 text-[12px] text-fail">
              {errorText(sessionError)}
            </div>
          )}

          <div className="mt-4 space-y-3">
            <Field label="Username" required>
              <Input
                autoFocus
                autoComplete="username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
              />
            </Field>
            <Field label="Password" required>
              <Input
                type="password"
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            </Field>
          </div>

          {mutation.isError && (
            <div className="mt-3 border border-fail/40 bg-fail/5 p-2 text-[12px] text-fail">
              {errorText(mutation.error)}
            </div>
          )}

          <Button
            type="submit"
            variant="primary"
            className="mt-4 w-full justify-center"
            disabled={mutation.isPending || username === '' || password === ''}
          >
            {mutation.isPending ? 'Signing in...' : 'Sign in'}
          </Button>
          <p className="mt-3 text-[11px] leading-4 text-dim">
            Accounts are provisioned by an administrator. If you are locked out, ask an
            administrator to reset your password.
          </p>
        </form>
      </div>
    </div>
  )
}

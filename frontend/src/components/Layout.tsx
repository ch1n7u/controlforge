import { useMutation, useQuery } from '@tanstack/react-query'
import { useEffect, useState } from 'react'
import { Link, NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom'
import { api, ApiError, qk } from '../lib/api'
import { errorText } from '../lib/errors'
import { fmtRelative } from '../lib/format'
import { useAuth } from '../auth/context'
import { Badge, Button, Field, Input } from './ui'

const NAV_GROUPS: Array<{ label?: string; items: Array<{ to: string; label: string; end?: boolean }> }> = [
  {
    // The overview is served at /overview; "/" only redirects there, so linking
    // to "/" would leave this item never appearing active.
    items: [{ to: '/overview', label: 'Overview' }],
  },
  {
    label: 'Validation',
    items: [
      { to: '/runs', label: 'Runs' },
      { to: '/findings', label: 'Findings' },
      { to: '/evidence', label: 'Evidence' },
    ],
  },
  {
    label: 'Configuration',
    items: [
      { to: '/controls', label: 'Controls' },
      { to: '/tests', label: 'Tests' },
      { to: '/targets', label: 'Targets' },
      { to: '/scopes', label: 'Scopes' },
    ],
  },
  {
    label: 'Administration',
    items: [
      { to: '/audit', label: 'Audit log' },
      { to: '/settings', label: 'Settings' },
    ],
  },
]

const NAV_ITEMS = NAV_GROUPS.flatMap((group) => group.items)

/** Detail routes are listed before the list routes they extend. */
const TITLE_ROUTES: Array<[RegExp, string]> = [
  [/^\/overview/, 'Overview'],
  [/^\/runs\/[^/]+/, 'Run'],
  [/^\/runs/, 'Runs'],
  [/^\/findings\/[^/]+/, 'Finding'],
  [/^\/findings/, 'Findings'],
  [/^\/evidence\/[^/]+/, 'Evidence item'],
  [/^\/evidence/, 'Evidence'],
  [/^\/controls\/[^/]+/, 'Control'],
  [/^\/controls/, 'Controls'],
  [/^\/tests\/new/, 'New test'],
  [/^\/tests\/[^/]+/, 'Test'],
  [/^\/tests/, 'Tests'],
  [/^\/targets\/[^/]+/, 'Target'],
  [/^\/targets/, 'Targets'],
  [/^\/scopes\/[^/]+/, 'Scope'],
  [/^\/scopes/, 'Scopes'],
  [/^\/audit/, 'Audit log'],
  [/^\/settings/, 'Settings'],
]

function navClass(isActive: boolean): string {
  return `block border-l-2 px-3 py-1.5 text-[13px] ${
    isActive
      ? 'border-accent bg-accent/10 text-ink'
      : 'border-transparent text-mute hover:border-edge2 hover:bg-raise hover:text-ink'
  }`
}

function EnvironmentStrip() {
  const health = useQuery({
    queryKey: qk.health,
    queryFn: api.health,
    staleTime: 15_000,
    refetchInterval: 30_000,
    retry: false,
  })
  const data = health.data
  const dbOk = data?.database.ok ?? false
  const status = health.isPending
    ? 'Checking status...'
    : health.isError
      ? 'Platform unreachable'
      : dbOk
        ? 'All systems operational'
        : 'Database unavailable'
  return (
    <div className="space-y-1.5 border-t border-edge px-3 py-2.5 text-[11px]">
      <div
        className="flex items-center gap-2"
        title={data ? `Valtros ${data.version}` : undefined}
      >
        <span
          aria-hidden
          className={`size-1.5 shrink-0 rounded-full ${
            health.isPending ? 'bg-dim' : dbOk ? 'bg-pass' : 'bg-fail'
          }`}
        />
        <span className="text-mute">{status}</span>
      </div>
      {data && (
        <div className="flex flex-wrap gap-1">
          {data.safe_mode ? (
            <Badge tone="incon" title="Engines are restricted to non-intrusive argument templates">
              Safe mode
            </Badge>
          ) : (
            <Badge tone="crit" title="Safe mode is off: engines may use intrusive argument templates">
              Safe mode off
            </Badge>
          )}
          {data.kill_switch && (
            <Badge tone="fail" title="The kill switch is on: no new runs are claimed">
              Kill switch
            </Badge>
          )}
        </div>
      )}
    </div>
  )
}

export function Layout() {
  const { user, logout, me } = useAuth()
  const navigate = useNavigate()
  const { pathname } = useLocation()
  const [menuOpen, setMenuOpen] = useState(false)
  const [passwordOpen, setPasswordOpen] = useState(false)

  // The browser tab is part of the product surface; leaving every page titled
  // "Valtros" would make a stack of open tabs indistinguishable.
  useEffect(() => {
    const match = TITLE_ROUTES.find(([pattern]) => pattern.test(pathname))
    document.title = match ? `${match[1]} · Valtros` : 'Valtros'
  }, [pathname])

  const doLogout = async () => {
    await logout()
    navigate('/login', { replace: true })
  }

  return (
    <div className="flex min-h-svh bg-bg">
      <aside className="hidden w-56 shrink-0 flex-col border-r border-edge bg-panel md:flex">
        <div className="border-b border-edge px-3 py-3">
          <Link to="/" className="block">
            <div className="font-mono text-[14px] font-semibold tracking-wide text-ink">
              CONTROL<span className="text-accent">FORGE</span>
            </div>
            <div className="mt-0.5 text-[11px] text-dim">
              Control validation &amp; effectiveness testing
            </div>
          </Link>
        </div>
        <nav className="flex-1 overflow-y-auto py-2">
          {NAV_GROUPS.map((group, index) => (
            <div key={group.label ?? 'primary'} className={index > 0 ? 'mt-3' : ''}>
              {group.label && (
                <div className="px-3 pb-1 text-[10px] font-semibold tracking-wider text-dim uppercase">
                  {group.label}
                </div>
              )}
              {group.items.map((item) => (
                <NavLink
                  key={item.to}
                  to={item.to}
                  end={item.end}
                  className={({ isActive }) => navClass(isActive)}
                >
                  {item.label}
                </NavLink>
              ))}
            </div>
          ))}
        </nav>
        <EnvironmentStrip />
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex items-center justify-between gap-3 border-b border-edge bg-panel px-4 py-2">
          <div className="flex items-center gap-3 md:hidden">
            <span className="font-mono text-[13px] font-semibold text-ink">
              CONTROL<span className="text-accent">FORGE</span>
            </span>
          </div>
          <div className="hidden text-[12px] text-dim md:block">
            {user?.must_change_password
              ? 'This account still has the bootstrap password - change it before operating.'
              : ''}
          </div>
          <div className="flex items-center gap-2">
            {user?.must_change_password && (
              <Button variant="danger" size="sm" onClick={() => setPasswordOpen(true)}>
                Change password
              </Button>
            )}
            <div className="relative">
              <button
                type="button"
                onClick={() => setMenuOpen((v) => !v)}
                className="flex items-center gap-2 border border-edge2 px-2 py-1 text-[12px] text-ink hover:bg-raise"
                aria-haspopup="menu"
                aria-expanded={menuOpen}
              >
                <span className="font-mono">{user?.username}</span>
                <span className="text-dim">{user?.role ?? ''}</span>
              </button>
              {menuOpen && (
                <div
                  role="menu"
                  className="absolute right-0 z-30 mt-1 w-56 border border-edge2 bg-raise py-1 shadow-lg"
                  onMouseLeave={() => setMenuOpen(false)}
                >
                  <div className="border-b border-edge px-3 py-1.5 text-[11px] text-dim">
                    Signed in as <span className="font-mono text-mute">{user?.username}</span>
                    {me?.user.last_login_at && (
                      <div className="mt-0.5">
                        Previous sign-in {fmtRelative(me.user.last_login_at)}
                      </div>
                    )}
                  </div>
                  <button
                    type="button"
                    role="menuitem"
                    className="block w-full px-3 py-1.5 text-left text-[13px] text-ink hover:bg-panel2"
                    onClick={() => {
                      setMenuOpen(false)
                      setPasswordOpen(true)
                    }}
                  >
                    Change password
                  </button>
                  <button
                    type="button"
                    role="menuitem"
                    className="block w-full px-3 py-1.5 text-left text-[13px] text-fail hover:bg-panel2"
                    onClick={() => {
                      setMenuOpen(false)
                      void doLogout()
                    }}
                  >
                    Sign out
                  </button>
                </div>
              )}
            </div>
          </div>
        </header>

        <nav className="flex gap-1 overflow-x-auto border-b border-edge bg-panel px-2 py-1 md:hidden">
          {NAV_ITEMS.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              className={({ isActive }) =>
                `whitespace-nowrap px-2 py-1 text-[12px] ${isActive ? 'bg-accent/15 text-ink' : 'text-mute'}`
              }
            >
              {item.label}
            </NavLink>
          ))}
        </nav>

        <main className="min-w-0 flex-1 p-4 md:p-5">
          <Outlet />
        </main>
      </div>

      {passwordOpen && <ChangePasswordDialog onClose={() => setPasswordOpen(false)} />}
    </div>
  )
}

function ChangePasswordDialog({ onClose }: { onClose: () => void }) {
  const { changePassword } = useAuth()
  const navigate = useNavigate()
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [confirm, setConfirm] = useState('')
  const [localError, setLocalError] = useState<string | null>(null)

  const mutation = useMutation({
    mutationFn: () => changePassword(current, next),
    onSuccess: () => {
      onClose()
      navigate('/login', {
        replace: true,
        state: { notice: 'Password changed. Every session was revoked - sign in with the new password.' },
      })
    },
  })

  const submit = (event: React.FormEvent) => {
    event.preventDefault()
    setLocalError(null)
    if (next !== confirm) {
      setLocalError('The two passwords do not match.')
      return
    }
    mutation.mutate()
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/60" onClick={onClose} aria-hidden />
      <form
        onSubmit={submit}
        className="relative z-10 w-full max-w-sm border border-edge2 bg-panel p-4"
      >
        <h2 className="text-[14px] font-semibold text-ink">Change password</h2>
        <p className="mt-1 text-[12px] text-dim">
          All other sessions are revoked when the password changes, including this one.
        </p>
        <div className="mt-3 space-y-3">
          <Field label="Current password" required>
            <Input
              type="password"
              autoComplete="current-password"
              value={current}
              onChange={(e) => setCurrent(e.target.value)}
            />
          </Field>
          <Field label="New password" required>
            <Input
              type="password"
              autoComplete="new-password"
              value={next}
              onChange={(e) => setNext(e.target.value)}
            />
          </Field>
          <Field label="Repeat new password" required>
            <Input
              type="password"
              autoComplete="new-password"
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
            />
          </Field>
        </div>
        {(localError || mutation.error) && (
          <div className="mt-3 border border-fail/40 bg-fail/5 p-2 text-[12px] text-fail">
            {localError ?? (mutation.error instanceof ApiError ? mutation.error.detail : errorText(mutation.error))}
          </div>
        )}
        <div className="mt-4 flex justify-end gap-2">
          <Button onClick={onClose}>Cancel</Button>
          <Button
            type="submit"
            variant="primary"
            disabled={mutation.isPending || current === '' || next === ''}
          >
            {mutation.isPending ? 'Changing...' : 'Change password'}
          </Button>
        </div>
      </form>
    </div>
  )
}

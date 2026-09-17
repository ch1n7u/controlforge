import { useQuery } from '@tanstack/react-query'
import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  Badge,
  Checkbox,
  ErrorNotice,
  Input,
  Loading,
  PageHeader,
  TableEmptyRow,
  TableWrap,
  Td,
  Th,
  Toolbar,
} from '../components/ui'
import { api, qk } from '../lib/api'
import { daysUntil, fmtDate, fmtRelative } from '../lib/format'
import { expiryState, governanceProblems } from '../lib/scopeGovernance'

export function ScopesPage() {
  const [onlyProblems, setOnlyProblems] = useState(false)
  const [search, setSearch] = useState('')

  const scopes = useQuery({
    queryKey: qk.scopes(),
    queryFn: () => api.scopes(),
    staleTime: 60_000,
  })
  const users = useQuery({
    queryKey: qk.users,
    queryFn: api.users,
    staleTime: 5 * 60_000,
  })
  const userById = useMemo(
    () => new Map((users.data ?? []).map((user) => [user.id, user])),
    [users.data],
  )

  const visible = useMemo(() => {
    const list = scopes.data ?? []
    const needle = search.trim().toLowerCase()
    return list.filter((scope) => {
      if (onlyProblems && governanceProblems(scope).length === 0) return false
      if (!needle) return true
      return (
        scope.name.toLowerCase().includes(needle) ||
        (scope.description ?? '').toLowerCase().includes(needle) ||
        (scope.authorization_ref ?? '').toLowerCase().includes(needle)
      )
    })
  }, [scopes.data, onlyProblems, search])

  const problemCount = (scopes.data ?? []).filter((s) => governanceProblems(s).length > 0).length

  return (
    <div className="space-y-4">
      <PageHeader
        title="Scopes"
        subtitle="Written authorization for the systems you may validate. A run connects only to an address, port and protocol an active scope permits."
      />

      <Toolbar
        trailing={
          scopes.data && scopes.data.length > 0 ? (
            <span className="font-mono text-[12px] text-dim">{visible.length} shown</span>
          ) : undefined
        }
      >
        <Input
          type="search"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search name, description or authorization reference"
          className="w-72"
        />
        <Checkbox
          label="Governance problems only"
          checked={onlyProblems}
          onChange={setOnlyProblems}
        />
        {problemCount > 0 && (
          <Badge
            tone="incon"
            title="Scopes that are expired, broad, inactive or missing an authorization reference"
          >
            {problemCount}
          </Badge>
        )}
        {(search !== '' || onlyProblems) && (
          <button
            type="button"
            onClick={() => {
              setSearch('')
              setOnlyProblems(false)
            }}
            className="text-[12px] text-mute hover:text-ink"
          >
            Clear filters
          </button>
        )}
      </Toolbar>

      {scopes.isPending && <Loading label="Loading scopes" />}
      {scopes.isError && <ErrorNotice error={scopes.error} onRetry={() => void scopes.refetch()} />}

      {scopes.data && (
        <TableWrap>
          <thead>
            <tr>
              <Th>Name</Th>
              <Th align="right">Entries</Th>
              <Th>Expiry</Th>
              <Th>Broad</Th>
              <Th>Authorization reference</Th>
              <Th>Approved by</Th>
              <Th>Active</Th>
            </tr>
          </thead>
          <tbody>
            {visible.length === 0 ? (
              <TableEmptyRow colSpan={7}>
                {scopes.data.length === 0
                  ? 'No scopes have been created yet. A scope is the written authorization a run is checked against: an address range with ports, an expiry and an approver. An administrator creates one and attaches the targets it covers.'
                  : 'No scope matches the current filters.'}
              </TableEmptyRow>
            ) : (
              visible.map((scope) => {
                const expiry = expiryState(scope)
                return (
                  <tr
                    key={scope.id}
                    className={`hover:bg-raise/50 ${expiry === 'expired' ? 'bg-fail/5' : scope.allow_broad ? 'bg-incon/5' : ''}`}
                  >
                    <Td wrap className="min-w-[16rem] max-w-[30rem]">
                      <Link to={`/scopes/${scope.id}`} className="text-accent hover:underline">
                        {scope.name}
                      </Link>
                      {scope.is_lab && (
                        <span className="ml-2">
                          <Badge
                            tone="accent"
                            title="A lab scope may authorize loopback and other internal ranges"
                          >
                            lab
                          </Badge>
                        </span>
                      )}
                    </Td>
                    <Td align="right" mono>
                      {scope.entries.length}
                    </Td>
                    <Td>
                      {expiry === 'expired' ? (
                        <Badge tone="fail" title={`Expired ${fmtDate(scope.expires_at)}`}>
                          expired {fmtRelative(scope.expires_at)}
                        </Badge>
                      ) : expiry === 'soon' ? (
                        <Badge tone="incon" title={`Expires ${fmtDate(scope.expires_at)}`}>
                          expires in {daysUntil(scope.expires_at)}d
                        </Badge>
                      ) : expiry === 'none' ? (
                        <span className="text-dim">no expiry</span>
                      ) : (
                        <span className="font-mono text-[12px] text-mute">{fmtDate(scope.expires_at)}</span>
                      )}
                    </Td>
                    <Td>
                      {scope.allow_broad ? (
                        <Badge tone="incon" title="This scope authorizes broad address ranges - review it before running">
                          broad
                        </Badge>
                      ) : (
                        <span className="text-dim">no</span>
                      )}
                    </Td>
                    <Td mono className={scope.authorization_ref ? 'text-mute' : 'text-fail'}>
                      {scope.authorization_ref ?? 'MISSING'}
                    </Td>
                    <Td mono className="text-mute">
                      {scope.approved_by_user_id === null
                        ? '-'
                        : (userById.get(scope.approved_by_user_id)?.username ??
                          `user #${scope.approved_by_user_id}`)}
                    </Td>
                    <Td>
                      {scope.active ? <span className="text-pass">yes</span> : <span className="text-fail">no</span>}
                    </Td>
                  </tr>
                )
              })
            )}
          </tbody>
        </TableWrap>
      )}
    </div>
  )
}

import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { RunDialog } from '../components/RunDialog'
import {
  AssertionBadge,
  Badge,
  Button,
  EmptyState,
  ErrorNotice,
  KeyValue,
  Loading,
  PageHeader,
  Panel,
  RunStatusBadge,
  SeverityBadge,
  TableEmptyRow,
  TableWrap,
  Td,
  Th,
} from '../components/ui'
import { useAuth } from '../auth/context'
import { api, asPage, qk } from '../lib/api'
import { fmtDate, fmtDateTime, fmtRelative } from '../lib/format'
import { expiryState } from '../lib/scopeGovernance'
import type { RunSummary } from '../lib/types'

export function TargetDetailPage() {
  const params = useParams()
  const targetId = Number(params.id)
  const { isWriter } = useAuth()
  const [runOpen, setRunOpen] = useState(false)

  const target = useQuery({
    queryKey: qk.target(targetId),
    queryFn: () => api.target(targetId),
    staleTime: 60_000,
  })
  const scopes = useQuery({
    queryKey: qk.targetScopes(targetId),
    queryFn: () => api.targetScopes(targetId),
    staleTime: 30_000,
  })
  const runs = useQuery({
    queryKey: qk.runs({ target_id: targetId, limit: 25 }),
    queryFn: () => api.runs({ target_id: targetId, limit: 25 }).then((data) => asPage<RunSummary>(data)),
    staleTime: 10_000,
    retry: false,
  })

  if (target.isPending) return <Loading label="Loading target" />
  if (target.isError) return <ErrorNotice error={target.error} onRetry={() => void target.refetch()} />
  const t = target.data
  // A scope authorizes runs only while it is active and unexpired; an expired or
  // switched-off scope is attached, but covers nothing.
  const attachedScopes = scopes.data ?? []
  const scopesLoaded = !scopes.isPending && !scopes.isError
  const authorized = attachedScopes.some(
    (scope) => scope.active && expiryState(scope) !== 'expired',
  )

  return (
    <div className="space-y-4">
      <PageHeader
        title={t.name}
        subtitle={
          <span className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-[13px] text-ink">
              {t.host}
              {t.port ? `:${t.port}` : ''}
              {t.path}
            </span>
            <Badge tone="mute">{t.target_type}</Badge>
            <SeverityBadge severity={t.criticality} />
            {t.enabled ? <Badge tone="pass">enabled</Badge> : <Badge tone="na">disabled</Badge>}
          </span>
        }
        actions={
          isWriter ? (
            <Button
              variant="primary"
              onClick={() => setRunOpen(true)}
              disabled={!authorized}
              title={authorized ? undefined : 'No active, unexpired scope covers this target'}
            >
              Run a test against this target
            </Button>
          ) : null
        }
      />

      {scopesLoaded && !authorized && (
        <div className="border border-fail/40 bg-fail/5 p-3 text-[13px] text-ink">
          <span className="font-mono text-[12px] font-semibold text-fail">NOT AUTHORIZED - </span>
          {attachedScopes.length === 0
            ? 'no scope covers this target, so no run can reach it. Ask an administrator to attach it to a scope; runs stay disabled until one is attached.'
            : 'every scope attached to this target is expired or inactive, so no run can reach it. Ask an administrator to renew the scope or attach a current one.'}
        </div>
      )}

      <div className="grid gap-3 lg:grid-cols-3">
        <Panel title="Target" className="lg:col-span-2">
          <KeyValue
            items={[
              ['Host', <span key="host" className="font-mono">{t.host}</span>],
              ['Port', <span key="port" className="font-mono">{t.port || 'none'}</span>],
              ['Protocol', <span key="proto" className="font-mono">{t.protocol}</span>],
              ['Path', <span key="path" className="font-mono">{t.path || '/'}</span>],
              ['Owner', t.owner ?? '-'],
              ['Criticality', <SeverityBadge key="crit" severity={t.criticality} />],
              ['Created', fmtDateTime(t.created_at)],
              ['Tags', t.tags.length > 0 ? t.tags.join(', ') : '-'],
            ]}
          />
          {t.notes && (
            <div className="mt-3 border-t border-edge pt-3">
              <div className="text-[11px] tracking-wide text-dim uppercase">Notes</div>
              <p className="mt-1 text-[13px] whitespace-pre-wrap text-ink/90">{t.notes}</p>
            </div>
          )}
        </Panel>

        <Panel title={`Scopes attached (${attachedScopes.length})`}>
          {scopes.isPending && <Loading label="Loading scopes" />}
          {scopes.isError && <ErrorNotice error={scopes.error} onRetry={() => void scopes.refetch()} />}
          {scopes.data &&
            (attachedScopes.length === 0 ? (
              <EmptyState
                title="No scope authorizes this target"
                hint="Ask an administrator to attach it to a scope; runs stay disabled until one is attached."
              />
            ) : (
              <>
                <ul className="space-y-2">
                  {attachedScopes.map((scope) => {
                    const expired = expiryState(scope) === 'expired'
                    return (
                      <li key={scope.id} className="border border-edge bg-panel2 p-2">
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <Link to={`/scopes/${scope.id}`} className="text-[13px] text-accent hover:underline">
                            {scope.name}
                          </Link>
                          <span className="flex items-center gap-1">
                            {!scope.active ? (
                              <Badge tone="na" title="An inactive scope authorizes nothing">
                                inactive
                              </Badge>
                            ) : expired ? (
                              <Badge tone="fail" title={`Expired ${fmtDate(scope.expires_at)}`}>
                                expired
                              </Badge>
                            ) : (
                              <Badge tone="pass">active</Badge>
                            )}
                            {scope.allow_broad && (
                              <Badge tone="incon" title="This scope allows broad address ranges - review it before running">
                                broad
                              </Badge>
                            )}
                          </span>
                        </div>
                        <div className="mt-1 font-mono text-[11px] text-dim">
                          {scope.entries.length} entr{scope.entries.length === 1 ? 'y' : 'ies'}
                          {scope.expires_at ? ` · expires ${fmtDate(scope.expires_at)}` : ' · no expiry'}
                        </div>
                      </li>
                    )
                  })}
                </ul>
                <div className="mt-3 border-t border-edge pt-2 text-[12px] text-dim">
                  A scope authorizes a run only while it is active and unexpired.
                </div>
              </>
            ))}
        </Panel>
      </div>

      <Panel
        title="Recent runs"
        actions={
          <Link to={`/runs?target_id=${t.id}`} className="text-[11px] text-accent hover:underline">
            All runs
          </Link>
        }
      >
        {runs.isPending && <Loading label="Loading runs" />}
        {runs.isError && <ErrorNotice error={runs.error} onRetry={() => void runs.refetch()} />}
        {runs.data && (
          <TableWrap>
            <thead>
              <tr>
                <Th>Run</Th>
                <Th>Test</Th>
                <Th>Engine</Th>
                <Th>Status</Th>
                <Th>Assertion</Th>
                <Th>Queued</Th>
                <Th>Duration</Th>
              </tr>
            </thead>
            <tbody>
              {runs.data.items.length === 0 ? (
                <TableEmptyRow colSpan={7}>
                  No runs have been recorded against this target yet.
                </TableEmptyRow>
              ) : (
                runs.data.items.map((run) => (
                  <tr key={run.id} className="hover:bg-raise/50">
                    <Td mono>
                      <Link to={`/runs/${run.id}`} className="text-accent hover:underline">
                        #{run.id}
                      </Link>
                    </Td>
                    <Td>
                      <span className="font-mono text-[12px] text-mute">{run.test_key}</span>
                    </Td>
                    <Td mono className="text-mute">
                      {run.engine_id}
                    </Td>
                    <Td>
                      <RunStatusBadge status={run.status} />
                    </Td>
                    <Td>
                      <AssertionBadge status={run.assertion_status} />
                    </Td>
                    <Td>{fmtRelative(run.queued_at)}</Td>
                    <Td mono>{run.duration_seconds === null ? '-' : `${run.duration_seconds.toFixed(1)}s`}</Td>
                  </tr>
                ))
              )}
            </tbody>
          </TableWrap>
        )}
      </Panel>

      {runOpen && <RunDialog onClose={() => setRunOpen(false)} fixedTargetId={t.id} />}
    </div>
  )
}

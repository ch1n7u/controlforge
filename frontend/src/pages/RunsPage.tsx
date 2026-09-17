import { useQuery } from '@tanstack/react-query'
import { Link, useSearchParams } from 'react-router-dom'
import { useAuth } from '../auth/context'
import { RunDialog } from '../components/RunDialog'
import {
  AssertionBadge,
  Badge,
  Button,
  ErrorNotice,
  Loading,
  PageHeader,
  Pagination,
  RunStatusBadge,
  Select,
  TableEmptyRow,
  TableWrap,
  Td,
  Th,
  Toolbar,
} from '../components/ui'
import { fetchRuns, api, qk } from '../lib/api'
import { fmtDuration, fmtRelative, humanizeEnum } from '../lib/format'
import { activeRunStatuses, assertionOrder, runStatuses } from '../lib/tones'
import { useState } from 'react'

const PAGE_SIZE = 50

export function RunsPage() {
  const { isWriter } = useAuth()
  const [searchParams, setSearchParams] = useSearchParams()
  const [runOpen, setRunOpen] = useState(false)

  const status = searchParams.get('status') ?? ''
  const testId = searchParams.get('test_id') ?? ''
  const targetId = searchParams.get('target_id') ?? ''
  const engineId = searchParams.get('engine_id') ?? ''
  const assertionFilter = searchParams.get('assertion_status') ?? ''
  const offset = Math.max(0, Number(searchParams.get('offset') ?? '0') || 0)

  function update(key: string, value: string): void {
    const next = new URLSearchParams(searchParams)
    if (value === '') next.delete(key)
    else next.set(key, value)
    if (key !== 'offset') next.delete('offset')
    setSearchParams(next, { replace: true })
  }

  const filters = {
    status: status === '' ? undefined : status,
    test_id: testId === '' ? undefined : Number(testId),
    target_id: targetId === '' ? undefined : Number(targetId),
    engine_id: engineId === '' ? undefined : engineId,
    assertion_status: assertionFilter === '' ? undefined : assertionFilter,
    limit: PAGE_SIZE,
    offset,
  }

  const runs = useQuery({
    queryKey: qk.runs(filters),
    queryFn: () => fetchRuns(filters),
    staleTime: 5_000,
    refetchInterval: (query) =>
      (query.state.data?.items ?? []).some((run) => activeRunStatuses.includes(run.status))
        ? 5_000
        : false,
  })

  const tests = useQuery({
    queryKey: qk.tests({ limit: 1000 }),
    queryFn: () => api.tests({ limit: 1000 }),
    staleTime: 5 * 60_000,
  })
  const targets = useQuery({
    queryKey: qk.targets({ limit: 1000 }),
    queryFn: () => api.targets({ limit: 1000 }),
    staleTime: 5 * 60_000,
  })
  const engines = useQuery({
    queryKey: qk.engines,
    queryFn: api.engines,
    staleTime: 10 * 60_000,
  })

  const items = runs.data?.items ?? []
  const total = runs.data?.total ?? 0
  const hasFilters =
    status !== '' ||
    testId !== '' ||
    targetId !== '' ||
    engineId !== '' ||
    assertionFilter !== ''

  return (
    <div className="space-y-4">
      <PageHeader
        title="Runs"
        subtitle="Every execution of a test version against a target, with the scope decision recorded at run time."
        actions={
          isWriter ? (
            <Button variant="primary" onClick={() => setRunOpen(true)}>
              New run
            </Button>
          ) : null
        }
      />

      <Toolbar
        trailing={
          <>
            <span className="font-mono text-[12px] text-dim">
              {runs.data ? `${items.length} shown of ${total}` : 'Loading...'}
            </span>
            <Button size="sm" onClick={() => void runs.refetch()}>
              Refresh
            </Button>
          </>
        }
      >
        <Select value={status} onChange={(e) => update('status', e.target.value)} className="w-40">
          <option value="">Any status</option>
          {runStatuses.map((candidate) => (
            <option key={candidate} value={candidate}>
              {humanizeEnum(candidate)}
            </option>
          ))}
        </Select>
        <Select value={testId} onChange={(e) => update('test_id', e.target.value)} className="w-64">
          <option value="">Any test</option>
          {(tests.data ?? []).map((test) => (
            <option key={test.id} value={test.id}>
              {test.key} - {test.name}
            </option>
          ))}
        </Select>
        <Select value={targetId} onChange={(e) => update('target_id', e.target.value)} className="w-64">
          <option value="">Any target</option>
          {(targets.data ?? []).map((target) => (
            <option key={target.id} value={target.id}>
              {target.name} ({target.host}
              {target.port ? `:${target.port}` : ''})
            </option>
          ))}
        </Select>
        <Select value={engineId} onChange={(e) => update('engine_id', e.target.value)} className="w-40">
          <option value="">Any engine</option>
          {(engines.data ?? []).map((engine) => (
            <option key={engine.id} value={engine.id}>
              {engine.id}
            </option>
          ))}
        </Select>
        <Select
          value={assertionFilter}
          onChange={(e) => update('assertion_status', e.target.value)}
          className="w-40"
        >
          <option value="">Any assertion</option>
          {assertionOrder.map((candidate) => (
            <option key={candidate} value={candidate}>
              {humanizeEnum(candidate)}
            </option>
          ))}
        </Select>
        {hasFilters && (
          <Button size="sm" onClick={() => setSearchParams(new URLSearchParams(), { replace: true })}>
            Clear filters
          </Button>
        )}
      </Toolbar>

      {runs.isPending && <Loading label="Loading runs" />}
      {runs.isError && <ErrorNotice error={runs.error} onRetry={() => void runs.refetch()} />}

      {runs.data && (
        <>
          <TableWrap>
            <thead>
              <tr>
                <Th align="right">Run</Th>
                <Th>Test</Th>
                <Th>Target</Th>
                <Th>Engine</Th>
                <Th>Status</Th>
                <Th>Assertion</Th>
                <Th>Trigger</Th>
                <Th align="right">Attempt</Th>
                <Th align="right">Duration</Th>
                <Th align="right">Findings</Th>
                <Th>Queued</Th>
              </tr>
            </thead>
            <tbody>
              {items.length === 0 ? (
                <TableEmptyRow colSpan={11}>
                  {hasFilters
                    ? 'No run matches the current filters.'
                    : 'No runs yet. A run executes a published test version against one target and records the scope decision at run time. Start one with New run, or from a test or target page.'}
                </TableEmptyRow>
              ) : (
                items.map((run) => (
                  <tr key={run.id} className="hover:bg-raise/50">
                    <Td align="right" mono>
                      <Link to={`/runs/${run.id}`} className="text-accent hover:underline">
                        #{run.id}
                      </Link>
                    </Td>
                    <Td wrap className="min-w-[16rem] max-w-[30rem]">
                      <Link to={`/tests/${run.test_id}`} className="hover:underline">
                        {run.test_name}
                      </Link>
                      <div className="font-mono text-[11px] text-dim">{run.test_key}</div>
                    </Td>
                    <Td wrap className="min-w-[10rem] max-w-[20rem]">
                      <Link to={`/targets/${run.target_id}`} className="hover:underline">
                        {run.target_name}
                      </Link>
                      <div className="font-mono text-[11px] text-dim">
                        {run.target_host}
                        {run.target_port ? `:${run.target_port}` : ''}
                      </div>
                    </Td>
                    <Td mono className="text-mute">
                      {run.engine_id}
                    </Td>
                    <Td wrap className="max-w-[18rem]">
                      <RunStatusBadge status={run.status} />
                      {run.error_message && (
                        <div className="mt-1 text-[11px] break-words text-fail">{run.error_message}</div>
                      )}
                    </Td>
                    <Td>
                      <AssertionBadge status={run.assertion_status} />
                    </Td>
                    <Td>
                      <Badge tone={run.trigger === 'retest' ? 'accent' : 'mute'}>{run.trigger}</Badge>
                      <div className="mt-1 font-mono text-[11px] text-dim">
                        {run.authorized_by_username ?? '--'}
                      </div>
                    </Td>
                    <Td align="right" mono className="text-mute">
                      {run.attempt}
                    </Td>
                    <Td align="right" mono className="text-mute">
                      {fmtDuration(run.duration_seconds)}
                    </Td>
                    <Td align="right">
                      {run.findings_count > 0 ? (
                        <Link
                          to={`/findings?test_id=${run.test_id}&target_id=${run.target_id}`}
                          className="text-fail hover:underline"
                        >
                          {run.findings_count}
                        </Link>
                      ) : (
                        <span className="text-dim">0</span>
                      )}
                    </Td>
                    <Td className="text-mute">{fmtRelative(run.queued_at)}</Td>
                  </tr>
                ))
              )}
            </tbody>
          </TableWrap>

          <Pagination
            offset={offset}
            limit={PAGE_SIZE}
            total={total}
            onChange={(next) => update('offset', String(next))}
          />
        </>
      )}

      {runOpen && <RunDialog onClose={() => setRunOpen(false)} />}
    </div>
  )
}

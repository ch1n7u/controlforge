import { useQuery } from '@tanstack/react-query'
import { Link, useSearchParams } from 'react-router-dom'
import { Hash } from '../components/Json'
import {
  Badge,
  Button,
  ErrorNotice,
  Input,
  Loading,
  PageHeader,
  Pagination,
  Select,
  TableEmptyRow,
  TableWrap,
  Td,
  Th,
  Toolbar,
} from '../components/ui'
import { api, fetchEvidence, qk } from '../lib/api'
import { fmtBytes, fmtDateTime, fmtRelative } from '../lib/format'

const PAGE_SIZE = 50

const evidenceKinds = ['stdout', 'stderr', 'artifact']

const evidenceKindLabel: Record<string, string> = {
  stdout: 'Standard output',
  stderr: 'Error output',
  artifact: 'Artifact',
}

export function EvidencePage() {
  const [searchParams, setSearchParams] = useSearchParams()
  const runId = searchParams.get('run_id') ?? ''
  const kind = searchParams.get('kind') ?? ''
  const offset = Math.max(0, Number(searchParams.get('offset') ?? '0') || 0)

  function update(key: string, value: string): void {
    const next = new URLSearchParams(searchParams)
    if (value === '') next.delete(key)
    else next.set(key, value)
    if (key !== 'offset') next.delete('offset')
    setSearchParams(next, { replace: true })
  }

  const filters = {
    run_id: runId === '' ? undefined : Number(runId),
    kind: kind === '' ? undefined : kind,
    limit: PAGE_SIZE,
    offset,
  }

  const evidence = useQuery({
    queryKey: qk.evidence(filters),
    queryFn: () => fetchEvidence(filters),
    staleTime: 30_000,
  })
  const contextRun = useQuery({
    queryKey: qk.run(Number(runId) || 0),
    queryFn: () => api.run(Number(runId)),
    enabled: runId !== '',
    staleTime: 60_000,
  })

  const items = evidence.data?.items ?? []
  const total = evidence.data?.total ?? 0
  const hasFilters = runId !== '' || kind !== ''

  return (
    <div className="space-y-4">
      <PageHeader
        title="Evidence"
        subtitle="Every capture a run stores: command output and produced files, kept append-only with a SHA-256 digest taken at write time."
      />

      <Toolbar
        trailing={
          <>
            <span className="font-mono text-[12px] text-dim">
              {evidence.data ? `${items.length} shown of ${total}` : 'Loading...'}
            </span>
            <Button size="sm" onClick={() => void evidence.refetch()}>
              Refresh
            </Button>
          </>
        }
      >
        <Input
          type="number"
          min={1}
          value={runId}
          onChange={(e) => update('run_id', e.target.value)}
          placeholder="Run ID"
          aria-label="Filter by run"
          className="w-28"
        />
        <Select
          value={kind}
          onChange={(e) => update('kind', e.target.value)}
          aria-label="Filter by kind"
          className="w-44"
        >
          <option value="">Any kind</option>
          {evidenceKinds.map((candidate) => (
            <option key={candidate} value={candidate}>
              {evidenceKindLabel[candidate]}
            </option>
          ))}
        </Select>
        {hasFilters && (
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setSearchParams(new URLSearchParams(), { replace: true })}
          >
            Clear filters
          </Button>
        )}
      </Toolbar>

      {runId !== '' && contextRun.data && (
        <div className="border border-edge bg-panel px-3 py-2 text-[12px] text-mute">
          Showing evidence from run{' '}
          <Link
            to={`/runs/${contextRun.data.id}`}
            className="font-mono text-accent hover:underline"
          >
            #{contextRun.data.id}
          </Link>{' '}
          -{' '}
          <Link to={`/tests/${contextRun.data.test_id}`} className="hover:underline">
            {contextRun.data.test_name}
          </Link>{' '}
          <span className="font-mono text-[11px] text-dim">({contextRun.data.test_key})</span> on{' '}
          <Link to={`/targets/${contextRun.data.target_id}`} className="hover:underline">
            {contextRun.data.target_name}
          </Link>{' '}
          <span className="font-mono text-[11px] text-dim">
            ({contextRun.data.target_host}
            {contextRun.data.target_port ? `:${contextRun.data.target_port}` : ''})
          </span>
        </div>
      )}
      {runId !== '' && contextRun.isError && (
        <div className="border border-edge bg-panel px-3 py-2 text-[12px] text-dim">
          Run #{runId} could not be loaded. Evidence is still narrowed to that run; clear the filter
          to see every run.
        </div>
      )}

      {evidence.isPending && <Loading label="Loading evidence" />}
      {evidence.isError && <ErrorNotice error={evidence.error} onRetry={() => void evidence.refetch()} />}

      {evidence.data && (
        <>
          <TableWrap>
            <thead>
              <tr>
                <Th align="right">ID</Th>
                <Th align="right">Run</Th>
                <Th>Kind</Th>
                <Th>Filename</Th>
                <Th>SHA-256</Th>
                <Th align="right">Size</Th>
                <Th>Truncated</Th>
                <Th>Stored</Th>
              </tr>
            </thead>
            <tbody>
              {items.length === 0 ? (
                <TableEmptyRow colSpan={8}>
                  {hasFilters
                    ? 'No evidence matches the current filters. Clear a filter to widen the search.'
                    : 'No evidence yet. Each run stores its command output and any files it produces here, with a digest taken at write time, so the first capture appears when a run finishes.'}
                </TableEmptyRow>
              ) : (
                items.map((item) => (
                  <tr key={item.id} className="hover:bg-raise/50">
                    <Td align="right" mono>
                      <Link to={`/evidence/${item.id}`} className="text-accent hover:underline">
                        #{item.id}
                      </Link>
                    </Td>
                    <Td align="right" mono>
                      <Link to={`/runs/${item.run_id}`} className="text-accent hover:underline">
                        #{item.run_id}
                      </Link>
                    </Td>
                    <Td>
                      <Badge tone="mute" title={evidenceKindLabel[item.kind] ?? item.kind}>
                        {item.kind}
                      </Badge>
                    </Td>
                    <Td wrap mono className="min-w-[12rem] max-w-[26rem]">
                      <Link to={`/evidence/${item.id}`} className="text-ink hover:underline">
                        {item.filename}
                      </Link>
                    </Td>
                    <Td>
                      <Hash value={item.sha256} />
                    </Td>
                    <Td align="right" mono className="text-mute">
                      {fmtBytes(item.size_bytes)}
                    </Td>
                    <Td>
                      {item.truncated ? (
                        <Badge
                          tone="incon"
                          title="The capture reached the run's output limit and was cut; the size and digest describe the stored file, not the full output."
                        >
                          truncated
                        </Badge>
                      ) : (
                        <span className="text-dim">no</span>
                      )}
                    </Td>
                    <Td className="text-mute">
                      <span title={fmtDateTime(item.created_at)}>{fmtRelative(item.created_at)}</span>
                    </Td>
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
    </div>
  )
}

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect, useRef, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { useAuth } from '../auth/context'
import { ArgvView, Hash, JsonBlock } from '../components/Json'
import {
  AssertionBadge,
  Badge,
  Button,
  Checkbox,
  EmptyState,
  ErrorNotice,
  KeyValue,
  Loading,
  PageHeader,
  Panel,
  RunStatusBadge,
  Select,
  SeverityBadge,
  TableEmptyRow,
  TableWrap,
  Td,
  Th,
} from '../components/ui'
import { useRunLog } from '../hooks/useRunLog'
import { api, qk } from '../lib/api'
import { fmtBytes, fmtDateTime, fmtDuration, fmtRelative, fmtTime } from '../lib/format'
import { activeRunStatuses } from '../lib/tones'
import type { LogLine } from '../lib/types'

export function RunDetailPage() {
  const params = useParams()
  const runId = Number(params.id)
  const queryClient = useQueryClient()
  const { isWriter } = useAuth()

  const run = useQuery({
    queryKey: qk.run(runId),
    queryFn: () => api.run(runId),
    staleTime: 5_000,
    refetchInterval: (query) =>
      query.state.data && activeRunStatuses.includes(query.state.data.status) ? 4_000 : false,
  })

  const live = run.data !== undefined && activeRunStatuses.includes(run.data.status)
  const log = useRunLog(runId, {
    live,
    onStatus: (status) => {
      if (!activeRunStatuses.includes(status)) {
        void queryClient.invalidateQueries({ queryKey: qk.run(runId) })
      }
    },
    onDone: () => {
      void queryClient.invalidateQueries({ queryKey: qk.run(runId) })
    },
  })

  const [factsOpen, setFactsOpen] = useState(false)
  const facts = useQuery({
    queryKey: qk.runFacts(runId),
    queryFn: () => api.runFacts(runId),
    enabled: factsOpen,
    staleTime: 60_000,
  })

  const cancel = useMutation({
    mutationFn: () => api.cancelRun(runId),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: qk.run(runId) }),
  })

  if (run.isPending) return <Loading label="Loading run" />
  if (run.isError) return <ErrorNotice error={run.error} onRetry={() => void run.refetch()} />
  const r = run.data
  const scopeSnapshot = r.scope_snapshot

  return (
    <div className="space-y-4">
      <PageHeader
        title={
          <span className="flex flex-wrap items-baseline gap-3">
            <span className="font-mono text-[15px] text-accent">run #{r.id}</span>
            <span>{r.test_name}</span>
          </span>
        }
        subtitle={
          <span className="flex flex-wrap items-center gap-2">
            <RunStatusBadge status={r.status} />
            <AssertionBadge status={r.assertion_status} />
            <Badge tone={r.trigger === 'retest' ? 'accent' : 'mute'}>{r.trigger}</Badge>
            {r.cancel_requested && <Badge tone="incon">Cancel requested</Badge>}
            <Link to={`/tests/${r.test_id}`} className="text-accent hover:underline">
              <span className="font-mono text-[12px]">{r.test_key}</span>
            </Link>
            <span className="text-dim">against</span>
            <Link to={`/targets/${r.target_id}`} className="text-accent hover:underline">
              {r.target_name}
            </Link>
            <span className="font-mono text-[12px] text-mute">
              {r.target_host}
              {r.target_port ? `:${r.target_port}` : ''}
            </span>
            {r.retest_of_finding_id !== null && (
              <Link to={`/findings/${r.retest_of_finding_id}`} className="text-accent hover:underline">
                retest of finding #{r.retest_of_finding_id}
              </Link>
            )}
          </span>
        }
        actions={
          isWriter && live ? (
            <Button
              variant="danger"
              disabled={cancel.isPending || r.cancel_requested}
              onClick={() => {
                if (window.confirm(`Cancel run #${r.id}?`)) cancel.mutate()
              }}
            >
              {r.cancel_requested ? 'Cancellation requested' : 'Cancel run'}
            </Button>
          ) : (
            <Link
              to={`/findings?test_id=${r.test_id}&target_id=${r.target_id}`}
              className="text-[13px] text-accent hover:underline"
            >
              Findings for this test and target
            </Link>
          )
        }
      />

      {cancel.isError && <ErrorNotice title="Cancel failed" error={cancel.error} />}
      {r.error_message && (
        <div className="border border-fail/50 bg-fail/10 p-3">
          <div className="font-mono text-[11px] font-semibold tracking-wide text-fail uppercase">
            Run error
          </div>
          <pre className="mt-1 font-mono text-[12px] break-words whitespace-pre-wrap text-ink/90">
            {r.error_message}
          </pre>
        </div>
      )}

      <LogPane
        lines={log.lines}
        transport={log.transport}
        streamError={log.streamError}
        live={live}
      />

      <div className="grid gap-3 lg:grid-cols-3">
        <Panel title="Timing and result" className="lg:col-span-2">
          <KeyValue
            items={[
              ['Queued', fmtDateTime(r.queued_at)],
              ['Started', fmtDateTime(r.started_at)],
              ['Finished', fmtDateTime(r.finished_at)],
              ['Duration', fmtDuration(r.duration_seconds)],
              ['Attempt', String(r.attempt)],
              ['Exit code', r.exit_code === null ? '-' : String(r.exit_code)],
              ['Timeout', r.timeout_seconds === null ? '-' : `${r.timeout_seconds}s`],
              ['Engine', r.engine_id],
            ]}
          />
        </Panel>

        <Panel title="Scope decision">
          <KeyValue
            columns={1}
            items={[
              [
                'Requested by',
                r.authorized_by_username === null ? (
                  <span className="text-dim">
                    Not recorded - the account that queued this run no longer exists
                  </span>
                ) : (
                  <span className="font-mono text-[12px]">{r.authorized_by_username}</span>
                ),
              ],
            ]}
          />
          <div className="mt-3 border-t border-edge pt-3">
            {scopeSnapshot === null ? (
              <div className="border border-incon/50 bg-incon/10 p-3 text-[12px] text-ink">
                This run recorded no scope snapshot. Without it there is no proof the target address
                was authorized at run time; treat the result as unverified.
              </div>
            ) : (
              <JsonBlock label="Scope snapshot" value={scopeSnapshot} />
            )}
          </div>
        </Panel>
      </div>

      <div className="grid gap-3 lg:grid-cols-2">
        <Panel title="Command line">
          <ArgvView argv={r.argv} />
          <div className="mt-2 text-[11px] text-dim">
            Recorded exactly as executed, one argument at a time, without a shell. What is shown
            here is what ran.
          </div>
        </Panel>

        <Panel title="Resolved addresses">
          {r.resolved_ips === null || r.resolved_ips.length === 0 ? (
            <span className="text-[13px] text-dim">Not recorded</span>
          ) : (
            <ul className="space-y-1">
              {r.resolved_ips.map((ip) => (
                <li key={ip} className="font-mono text-[12px] text-ink">
                  {ip}
                </li>
              ))}
            </ul>
          )}
          <div className="mt-3 border-t border-edge pt-2">
            <div className="mb-1 text-[11px] tracking-wide text-dim uppercase">Tool versions</div>
            {r.tool_versions === null ? (
              <span className="text-[13px] text-dim">Not recorded</span>
            ) : (
              <JsonBlock value={r.tool_versions} />
            )}
          </div>
        </Panel>
      </div>

      <Panel title={`Assertion results (${r.assertion_results.length})`}>
        {r.observed_summary !== null && (
          <div className="mb-3">
            <JsonBlock label="Observed summary" value={r.observed_summary} collapsedHeight={120} />
          </div>
        )}
        <div className="space-y-2">
          {r.assertion_results.length === 0 ? (
            live ? (
              <EmptyState
                title="No assertion results yet"
                hint="They are recorded when the run finishes."
              />
            ) : (
              <EmptyState title="No assertion results were recorded for this run" />
            )
          ) : (
            r.assertion_results.map((result) => (
              <div key={result.id} className="border border-edge bg-panel2">
                <div className="flex flex-wrap items-center gap-2 px-3 py-2">
                  <span className="font-mono text-[12px] text-dim">#{result.assertion_index}</span>
                  <AssertionBadge status={result.status} />
                  <SeverityBadge severity={result.severity} />
                  <span className="text-[12px] text-mute">{fmtDateTime(result.evaluated_at)}</span>
                  <span className="ml-auto font-mono text-[11px] text-dim">
                    {result.fact_ids.length === 0
                      ? 'No facts'
                      : `${result.fact_ids.length} fact${result.fact_ids.length === 1 ? '' : 's'}: ${result.fact_ids.map((id) => `#${id}`).join(', ')}`}
                  </span>
                </div>
                {result.reason && (
                  <div className="border-t border-edge px-3 py-2 text-[12px] break-words text-ink/90">
                    {result.reason}
                  </div>
                )}
                <div className="border-t border-edge p-2">
                  <JsonBlock label="Assertion" value={result.assertion} collapsedHeight={120} />
                </div>
              </div>
            ))
          )}
        </div>
      </Panel>

      <Panel
        title={`Facts (${r.facts_summary.reduce((sum, entry) => sum + entry.count, 0)})`}
        actions={
          factsOpen ? null : (
            <Button size="sm" onClick={() => setFactsOpen(true)}>
              Load facts
            </Button>
          )
        }
      >
        {r.facts_summary.length === 0 ? (
          <div className="text-[12px] text-dim">
            {live ? 'Facts appear here as the engine emits them.' : 'This run produced no facts.'}
          </div>
        ) : (
          <div className="mb-3 flex flex-wrap gap-2">
            {r.facts_summary.map((entry) => (
              <span
                key={entry.fact_type}
                className="border border-edge bg-bg px-2 py-0.5 font-mono text-[11px] text-mute"
              >
                {entry.fact_type} <span className="text-ink">{entry.count}</span>
              </span>
            ))}
          </div>
        )}

        {factsOpen && facts.isPending && <Loading label="Loading facts" />}
        {factsOpen && facts.isError && (
          <ErrorNotice error={facts.error} onRetry={() => void facts.refetch()} />
        )}
        {factsOpen && facts.data && (
          <TableWrap className="border-edge">
            <thead>
              <tr>
                <Th>Type</Th>
                <Th>Subject</Th>
                <Th>Key</Th>
                <Th>Value</Th>
                <Th align="right">Confidence</Th>
                <Th>Detail</Th>
                <Th align="right">Evidence</Th>
              </tr>
            </thead>
            <tbody>
              {facts.data.length === 0 ? (
                <TableEmptyRow colSpan={7}>This run produced no facts.</TableEmptyRow>
              ) : (
                facts.data.map((fact) => (
                  <tr key={fact.id}>
                    <Td mono className="text-mute">
                      {fact.fact_type}
                    </Td>
                    <Td mono>{fact.subject}</Td>
                    <Td mono className="text-mute">
                      {fact.key}
                    </Td>
                    <Td>
                      <JsonBlock value={fact.value} collapsedHeight={80} />
                    </Td>
                    <Td align="right" mono>
                      {fact.confidence.toFixed(2)}
                    </Td>
                    <Td wrap className="max-w-64 text-[12px] text-mute">{fact.detail ?? '-'}</Td>
                    <Td align="right">
                      {fact.evidence_id === null ? (
                        <span className="text-dim">-</span>
                      ) : (
                        <Link
                          to={`/evidence/${fact.evidence_id}`}
                          className="font-mono text-accent hover:underline"
                        >
                          #{fact.evidence_id}
                        </Link>
                      )}
                    </Td>
                  </tr>
                ))
              )}
            </tbody>
          </TableWrap>
        )}
      </Panel>

      <Panel title={`Evidence (${r.evidence.length})`} dense>
        <TableWrap className="border-0">
          <thead>
            <tr>
              <Th>Kind</Th>
              <Th>Filename</Th>
              <Th>SHA-256</Th>
              <Th align="right">Size</Th>
              <Th>Truncated</Th>
              <Th>Created</Th>
            </tr>
          </thead>
          <tbody>
            {r.evidence.length === 0 ? (
              <TableEmptyRow colSpan={6}>This run recorded no evidence.</TableEmptyRow>
            ) : (
              r.evidence.map((item) => (
                <tr key={item.id} className="hover:bg-raise/50">
                  <Td>
                    <Badge tone="mute">{item.kind}</Badge>
                  </Td>
                  <Td wrap className="min-w-[12rem] max-w-[24rem]">
                    <Link to={`/evidence/${item.id}`} className="font-mono text-accent hover:underline">
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
                      <Badge tone="incon" title="Only the beginning of this output was captured">
                        truncated
                      </Badge>
                    ) : (
                      <span className="text-dim">no</span>
                    )}
                  </Td>
                  <Td className="text-mute">{fmtRelative(item.created_at)}</Td>
                </tr>
              ))
            )}
          </tbody>
        </TableWrap>
      </Panel>
    </div>
  )
}

const streamTone: Record<string, string> = {
  stdout: 'text-mute',
  stderr: 'text-fail',
  system: 'text-accent',
}

function LogPane({
  lines,
  transport,
  streamError,
  live,
}: {
  lines: LogLine[]
  transport: 'connecting' | 'sse' | 'polling'
  streamError: string | null
  live: boolean
}) {
  const [follow, setFollow] = useState(true)
  const [streamFilter, setStreamFilter] = useState<'all' | 'stdout' | 'stderr' | 'system'>('all')
  const [copied, setCopied] = useState(false)
  const boxRef = useRef<HTMLDivElement | null>(null)

  const visible = streamFilter === 'all' ? lines : lines.filter((line) => line.stream === streamFilter)

  useEffect(() => {
    if (!follow) return
    const box = boxRef.current
    if (box) box.scrollTop = box.scrollHeight
  }, [visible.length, follow])

  return (
    <Panel
      title={live ? 'Live log' : 'Run log'}
      dense
      actions={
        <>
          <span
            className={`inline-flex items-center gap-1.5 font-mono text-[11px] ${
              transport === 'sse' ? 'text-pass' : transport === 'polling' ? 'text-incon' : 'text-dim'
            }`}
            title={
              transport === 'sse'
                ? 'Output arrives as the engine writes it.'
                : transport === 'polling'
                  ? 'Output is fetched every few seconds.'
                  : 'Opening the run output.'
            }
          >
            <span
              className={`size-1.5 rounded-full ${
                transport === 'sse' ? 'bg-pass' : transport === 'polling' ? 'bg-incon' : 'bg-dim'
              }`}
              aria-hidden
            />
            {transport === 'sse' ? 'live' : transport === 'polling' ? 'auto-refresh' : 'connecting'}
          </span>
          <Select
            value={streamFilter}
            onChange={(e) => setStreamFilter(e.target.value as typeof streamFilter)}
            className="w-32"
          >
            <option value="all">All streams</option>
            <option value="stdout">stdout</option>
            <option value="stderr">stderr</option>
            <option value="system">system</option>
          </Select>
          <Checkbox label="Follow" checked={follow} onChange={setFollow} />
          <Button
            size="sm"
            disabled={visible.length === 0}
            onClick={() => {
              void navigator.clipboard
                .writeText(visible.map((line) => `[${fmtTime(line.ts)}] ${line.stream}: ${line.message}`).join('\n'))
                .then(() => {
                  setCopied(true)
                  window.setTimeout(() => setCopied(false), 1500)
                })
            }}
          >
            {copied ? 'Copied' : 'Copy'}
          </Button>
        </>
      }
    >
      {streamError && (
        <div className="border-b border-incon/40 bg-incon/10 px-3 py-1.5 text-[12px] text-ink">
          Live updates stopped: {streamError}. Retrying in the background, so new lines still appear
          below.
        </div>
      )}
      <div
        ref={boxRef}
        onScroll={(e) => {
          const box = e.currentTarget
          const atBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 40
          if (atBottom !== follow) setFollow(atBottom)
        }}
        className="h-80 overflow-auto bg-bg p-2 font-mono text-[11px] leading-5"
      >
        {visible.length === 0 ? (
          <div className="px-1 py-4 text-center text-dim">
            {live ? 'Waiting for output...' : 'No log lines were recorded for this run.'}
          </div>
        ) : (
          visible.map((line) => (
            <div key={line.id} className="flex gap-2 break-words whitespace-pre-wrap">
              <span className="shrink-0 text-dim">{fmtTime(line.ts)}</span>
              <span className={`shrink-0 uppercase ${streamTone[line.stream] ?? 'text-mute'}`}>
                {line.stream}
              </span>
              <span className={`min-w-0 ${line.stream === 'stderr' ? 'text-fail/90' : 'text-ink/90'}`}>
                {line.message}
              </span>
            </div>
          ))
        )}
      </div>
    </Panel>
  )
}

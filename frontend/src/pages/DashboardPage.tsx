import { useQuery } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { BarList, Donut, RatioBar, TrendChart } from '../components/charts'
import {
  Button,
  EmptyState,
  ErrorNotice,
  LinkButton,
  Loading,
  PageHeader,
  Panel,
  TableEmptyRow,
  TableWrap,
  Td,
  Th,
} from '../components/ui'
import { api, qk } from '../lib/api'
import { fmtRelative, humanizeEnum, pct } from '../lib/format'
import {
  assertionColor,
  assertionLabel,
  assertionOrder,
  severityColor,
  severities,
} from '../lib/tones'
import type { Severity } from '../lib/types'

function count(map: Record<string, number> | undefined, key: string): number {
  const value = map?.[key]
  return typeof value === 'number' ? value : 0
}

/** The small print under a panel: what the numbers above it count. */
function Caption({ children }: { children: ReactNode }) {
  return <p className="mt-2 text-[12px] text-dim">{children}</p>
}

function ViewAll({ to, children = 'View all' }: { to: string; children?: ReactNode }) {
  return (
    <Link to={to} className="text-[11px] text-accent hover:underline">
      {children}
    </Link>
  )
}

export function DashboardPage() {
  const summary = useQuery({
    queryKey: qk.dashboardSummary,
    queryFn: api.dashboardSummary,
    staleTime: 30_000,
    refetchInterval: 60_000,
  })
  const trend = useQuery({
    queryKey: qk.dashboardTrend(30),
    queryFn: () => api.dashboardTrend(30),
    staleTime: 60_000,
  })
  const posture = useQuery({
    queryKey: qk.posture(20),
    queryFn: () => api.postureByControl(20),
    staleTime: 60_000,
  })
  const findingSummary = useQuery({
    queryKey: qk.findingSummary,
    queryFn: api.findingSummary,
    staleTime: 60_000,
  })

  const s = summary.data
  const attention = (posture.data ?? [])
    .filter((row) => row.fail > 0)
    .sort((a, b) => b.fail - a.fail)
    .slice(0, 8)

  const donutSlices = assertionOrder.map((status) => ({
    key: status,
    label: assertionLabel[status],
    value: s?.assertions?.[status] ?? 0,
    color: assertionColor[status],
    to: `/runs?assertion_status=${status}`,
  }))
  const assertionTotal = donutSlices.reduce((sum, slice) => sum + slice.value, 0)

  const openFindings = count(s?.findings.by_status, 'open')
  const triagedFindings = count(s?.findings.by_status, 'triaged')
  const remediatingFindings = count(s?.findings.by_status, 'remediating')
  const overdueTotal = findingSummary.data?.overdue_total ?? 0
  const controlsWithoutCurrentResult = s?.coverage.controls_stale ?? 0
  const unauthorizedTargets = s ? s.targets.total - s.targets.scoped : 0

  return (
    <div className="space-y-4">
      <PageHeader
        title="Overview"
        subtitle={
          s
            ? `Current posture across every enabled control and target, computed ${fmtRelative(s.last_updated)}.`
            : 'Current posture across every enabled control and target.'
        }
        actions={
          <Button
            size="sm"
            onClick={() => {
              void summary.refetch()
              void trend.refetch()
              void posture.refetch()
              void findingSummary.refetch()
            }}
          >
            Refresh
          </Button>
        }
      />

      {summary.isPending && <Loading label="Loading the overview" />}
      {summary.isError && <ErrorNotice error={summary.error} onRetry={() => void summary.refetch()} />}

      {s && (
        <>
          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
            <Panel title="Findings awaiting triage" actions={<ViewAll to="/findings?status=open" />}>
              <div className="flex flex-wrap items-baseline gap-x-2 gap-y-1">
                <span className="font-mono text-2xl text-ink">{openFindings}</span>
                {openFindings === 0 ? (
                  <span className="text-[12px] text-pass">Nothing is waiting for triage.</span>
                ) : (
                  <span className="text-[12px] text-mute">
                    {openFindings === 1 ? 'finding has not been triaged' : 'findings have not been triaged'}
                  </span>
                )}
              </div>
              <div className="mt-1 flex flex-wrap gap-x-3 text-[12px]">
                <Link to="/findings?status=triaged" className="text-mute hover:underline">
                  <span className="font-mono text-ink">{triagedFindings}</span> triaged
                </Link>
                <Link to="/findings?status=remediating" className="text-mute hover:underline">
                  <span className="font-mono text-ink">{remediatingFindings}</span> remediating
                </Link>
              </div>
              <div className="mt-1 text-[12px]">
                {findingSummary.isError ? (
                  <span className="text-dim">Past-due count unavailable.</span>
                ) : overdueTotal > 0 ? (
                  <span className="text-fail">
                    {overdueTotal} unresolved {overdueTotal === 1 ? 'finding is' : 'findings are'} past
                    the due date set during triage
                  </span>
                ) : (
                  <span className="text-dim">No unresolved finding is past its due date.</span>
                )}
              </div>
              <Caption>
                Counted from every finding ever recorded. A finding appears the first time a check
                fails against a target, and waits here until someone triages it.
              </Caption>
            </Panel>

            <Panel title="Runs, last 24 hours" actions={<ViewAll to="/runs" />}>
              <div className="flex flex-wrap items-baseline gap-x-2 gap-y-1">
                <span className="font-mono text-2xl text-ink">{s.runs.last_24h}</span>
                <span className="text-[12px] text-mute">runs queued in the last 24 hours</span>
              </div>
              <div className="mt-1 flex flex-wrap gap-x-3 text-[12px]">
                <Link to="/runs?status=running" className="text-mute hover:underline">
                  <span className="font-mono text-ink">{s.runs.running}</span> running now
                </Link>
                <Link to="/runs?status=queued" className="text-mute hover:underline">
                  <span className="font-mono text-ink">{s.runs.queued}</span> queued now
                </Link>
              </div>
              <div className="mt-1 text-[12px]">
                {s.runs.failed > 0 ? (
                  <Link to="/runs?status=failed" className="text-fail hover:underline">
                    {s.runs.failed} failed and finished inside the same window
                  </Link>
                ) : (
                  <span className="text-dim">No run failed in the last 24 hours.</span>
                )}
              </div>
              <Caption>
                Queued counts cover the last 24 hours, and failures count by when they finished. Runs
                start from the Runs page or from a test page.
              </Caption>
            </Panel>

            <Panel title="Control coverage" actions={<ViewAll to="/controls" />}>
              <div className="flex flex-wrap items-baseline gap-x-2 gap-y-1">
                <span className="font-mono text-2xl text-ink">
                  {s.coverage.controls_with_recent_results}
                  <span className="text-[14px] text-dim">/{s.coverage.controls_total}</span>
                </span>
                <span className="text-[12px] text-mute">enabled controls with a current result</span>
              </div>
              <div className="mt-1">
                <RatioBar
                  ratio={pct(s.coverage.controls_with_recent_results, s.coverage.controls_total)}
                />
              </div>
              <div className="mt-1 text-[12px]">
                {controlsWithoutCurrentResult > 0 ? (
                  <span className="text-incon">
                    {controlsWithoutCurrentResult} enabled{' '}
                    {controlsWithoutCurrentResult === 1 ? 'control has' : 'controls have'} no result
                    inside the freshness window
                  </span>
                ) : (
                  <span className="text-pass">Every enabled control has a current result.</span>
                )}
              </div>
              <Caption>
                A result is current while it is younger than the freshness window in Settings, which
                defaults to 7 days. Coverage fills in as runs evaluate controls.
              </Caption>
            </Panel>

            <Panel title="Targets" actions={<ViewAll to="/targets" />}>
              <div className="flex flex-wrap items-baseline gap-x-2 gap-y-1">
                <span className="font-mono text-2xl text-ink">
                  {s.targets.scoped}
                  <span className="text-[14px] text-dim">/{s.targets.total}</span>
                </span>
                <span className="text-[12px] text-mute">
                  enabled targets authorized by an active scope
                </span>
              </div>
              <div className="mt-1 text-[12px] text-dim">
                {s.targets.total === 0
                  ? 'Add a target and attach it to a scope to begin.'
                  : unauthorizedTargets > 0
                    ? `${unauthorizedTargets} enabled ${
                        unauthorizedTargets === 1 ? 'target is' : 'targets are'
                      } not attached to an active scope and cannot be run.`
                    : 'Every enabled target is attached to an active scope.'}
              </div>
              <Caption>Counts enabled targets only; disabled targets are left out.</Caption>
            </Panel>
          </div>

          <div className="grid gap-3 lg:grid-cols-2">
            <Panel title="Assertion outcomes">
              {assertionTotal === 0 ? (
                <EmptyState
                  title="No assertion results yet"
                  hint="A result appears the first time a run evaluates a test against a target. Each test and target pair is counted once, by its newest result."
                  action={<LinkButton to="/runs">Go to runs</LinkButton>}
                />
              ) : (
                <>
                  <Donut
                    slices={donutSlices}
                    centerLabel="results"
                    centerValue={String(assertionTotal)}
                  />
                  <Caption>
                    The newest result for each test and target pair. Select a segment to see the runs
                    behind it.
                  </Caption>
                </>
              )}
            </Panel>

            <Panel title="Findings">
              <div className="text-[11px] tracking-wide text-dim uppercase">By severity</div>
              <div className="mt-1">
                <BarList
                  bars={severities.map((severity: Severity) => ({
                    key: severity,
                    label: severity,
                    value: count(s.findings.by_severity, severity),
                    color: severityColor[severity],
                    to: `/findings?severity=${severity}`,
                  }))}
                  emptyLabel="No findings recorded yet."
                />
              </div>
              <div className="mt-3 border-t border-edge pt-2">
                <div className="text-[11px] tracking-wide text-dim uppercase">By state</div>
                <div className="mt-1">
                  <BarList
                    bars={[
                      { key: 'open', label: humanizeEnum('open'), value: openFindings, color: 'var(--color-fail)', to: '/findings?status=open' },
                      { key: 'triaged', label: humanizeEnum('triaged'), value: triagedFindings, color: 'var(--color-incon)', to: '/findings?status=triaged' },
                      { key: 'remediating', label: humanizeEnum('remediating'), value: remediatingFindings, color: 'var(--color-accent)', to: '/findings?status=remediating' },
                      { key: 'accepted_risk', label: humanizeEnum('accepted_risk'), value: count(s.findings.by_status, 'accepted_risk'), color: 'var(--color-accent)', to: '/findings?status=accepted_risk' },
                      { key: 'false_positive', label: humanizeEnum('false_positive'), value: count(s.findings.by_status, 'false_positive'), color: 'var(--color-mute)', to: '/findings?status=false_positive' },
                      { key: 'resolved', label: humanizeEnum('resolved'), value: count(s.findings.by_status, 'resolved'), color: 'var(--color-pass)', to: '/findings?status=resolved' },
                    ]}
                    emptyLabel="No findings recorded yet."
                  />
                </div>
              </div>
              <Caption>
                All findings, whatever their state. A finding is recorded the first time a check fails
                against a target.
              </Caption>
            </Panel>
          </div>

          <Panel title="Assertion outcomes per day, last 30 days">
            {trend.isPending && <Loading label="Loading the trend" />}
            {trend.isError && <ErrorNotice error={trend.error} onRetry={() => void trend.refetch()} />}
            {trend.data && <TrendChart days={trend.data.days ?? []} />}
            <Caption>
              Every result evaluated that day, including results that are no longer the newest for
              their test and target. Days without runs are drawn at zero; the chart fills in as runs
              finish.
            </Caption>
          </Panel>

          <Panel title="Controls with failing results">
            <p className="mb-2 text-[12px] text-mute">
              Up to eight controls with the most failing results. Counts use the newest result for
              each test and target pair, so a control is counted once per pair.
            </p>
            {posture.isPending && <Loading label="Loading control results" />}
            {posture.isError && <ErrorNotice error={posture.error} onRetry={() => void posture.refetch()} />}
            {posture.data && (
              <>
                <TableWrap>
                  <thead>
                    <tr>
                      <Th>Control</Th>
                      <Th>Category</Th>
                      <Th align="right">Passing</Th>
                      <Th align="right">Failing</Th>
                      <Th align="right">Inconclusive</Th>
                      <Th>
                        <span title="The share of pass, fail and inconclusive results that reached pass or fail. Not-applicable results are left out.">
                          Decided
                        </span>
                      </Th>
                      <Th>Last result</Th>
                    </tr>
                  </thead>
                  <tbody>
                    {attention.length === 0 ? (
                      <TableEmptyRow colSpan={7}>
                        No control has a failing result right now. A control appears here as soon as
                        one of its tests fails against a target.
                      </TableEmptyRow>
                    ) : (
                      attention.map((row) => (
                        <tr key={row.control_id} className="hover:bg-raise/50">
                          <Td wrap className="min-w-[16rem] max-w-[30rem]">
                            <Link to={`/controls/${row.control_id}`} className="text-accent hover:underline">
                              <span className="font-mono text-[12px]">{row.control_key}</span>{' '}
                              {row.control_title}
                            </Link>
                          </Td>
                          <Td>{row.category ?? '-'}</Td>
                          <Td align="right" mono className="text-mute">
                            {row.pass}
                          </Td>
                          <Td align="right" mono>
                            <Link to={`/findings?control_id=${row.control_id}`} className="text-fail hover:underline">
                              {row.fail}
                            </Link>
                          </Td>
                          <Td align="right" mono className="text-mute">
                            {row.inconclusive}
                          </Td>
                          <Td>
                            <RatioBar ratio={row.coverage_ratio} />
                          </Td>
                          <Td className="text-mute">
                            {row.last_evaluated_at ? fmtRelative(row.last_evaluated_at) : '-'}
                          </Td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </TableWrap>
                <Caption>
                  Decided is the share of pass, fail and inconclusive results that reached pass or
                  fail. N/A results do not count against a control.
                </Caption>
              </>
            )}
          </Panel>
        </>
      )}
    </div>
  )
}

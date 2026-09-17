import { useQueries, useQuery } from '@tanstack/react-query'
import { Link, useParams } from 'react-router-dom'
import { useAuth } from '../auth/context'
import { RatioBar } from '../components/charts'
import {
  AssertionBadge,
  Badge,
  EmptyState,
  ErrorNotice,
  FindingStatusBadge,
  KeyValue,
  LinkButton,
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
import { api, asPage, fetchFindings, qk } from '../lib/api'
import { fmtRelative, humanizeEnum } from '../lib/format'
import type { RunSummary } from '../lib/types'

export function ControlDetailPage() {
  const params = useParams()
  const controlId = Number(params.id)
  const { isWriter } = useAuth()

  const control = useQuery({
    queryKey: qk.control(controlId),
    queryFn: () => api.control(controlId),
    staleTime: 60_000,
  })
  const frameworks = useQuery({
    queryKey: qk.frameworks,
    queryFn: api.frameworks,
    staleTime: 10 * 60_000,
  })
  const tests = useQuery({
    queryKey: qk.tests({ control_id: controlId }),
    queryFn: () => api.tests({ control_id: controlId, limit: 200 }),
    staleTime: 30_000,
  })
  const posture = useQuery({
    queryKey: qk.posture(200),
    queryFn: () => api.postureByControl(200),
    staleTime: 60_000,
  })
  const findings = useQuery({
    queryKey: qk.findings({ control_id: controlId, limit: 10 }),
    queryFn: () => fetchFindings({ control_id: controlId, limit: 10 }),
    staleTime: 30_000,
    retry: false,
  })

  const testIds = tests.data?.map((test) => test.id) ?? []
  const runQueries = useQueries({
    queries: testIds.map((testId) => ({
      queryKey: qk.runs({ test_id: testId, limit: 200 }),
      queryFn: () => api.runs({ test_id: testId, limit: 200 }).then((data) => asPage<RunSummary>(data)),
      staleTime: 15_000,
    })),
  })

  const latestByTarget = new Map<number, RunSummary>()
  for (const result of runQueries) {
    for (const run of result.data?.items ?? []) {
      const existing = latestByTarget.get(run.target_id)
      if (!existing || run.id > existing.id) latestByTarget.set(run.target_id, run)
    }
  }
  const postureRows = [...latestByTarget.values()].sort((a, b) =>
    a.target_name.localeCompare(b.target_name),
  )
  const runsLoading = runQueries.some((result) => result.isPending) && testIds.length > 0
  const runsError = runQueries.find((result) => result.isError)?.error

  const controlPosture = posture.data?.find((row) => row.control_id === controlId)
  const frameworkById = new Map((frameworks.data ?? []).map((f) => [f.id, f]))

  if (control.isPending) return <Loading label="Loading control" />
  if (control.isError) return <ErrorNotice error={control.error} onRetry={() => void control.refetch()} />
  const c = control.data

  return (
    <div className="space-y-4">
      <PageHeader
        title={
          <span className="flex flex-wrap items-baseline gap-3">
            <span className="font-mono text-[15px] text-accent">{c.key}</span>
            <span>{c.title}</span>
          </span>
        }
        subtitle={
          <span className="flex flex-wrap items-center gap-2">
            {c.category && <Badge tone="mute">{humanizeEnum(c.category)}</Badge>}
            <SeverityBadge severity={c.default_severity} />
            {!c.enabled && <Badge tone="na">disabled</Badge>}
            <Link to={`/findings?control_id=${c.id}`} className="text-accent hover:underline">
              Findings for this control
            </Link>
          </span>
        }
      />

      <div className="grid gap-3 lg:grid-cols-3">
        <Panel title="Description" className="lg:col-span-2">
          <p className="text-[13px] whitespace-pre-wrap text-ink/90">
            {c.description ?? 'No description recorded.'}
          </p>
          <div className="mt-3 border-t border-edge pt-3">
            <div className="text-[11px] tracking-wide text-dim uppercase">Expected state</div>
            <p className="mt-1 text-[13px] whitespace-pre-wrap text-ink/90">
              {c.expected_state ?? 'Not recorded.'}
            </p>
          </div>
        </Panel>

        <Panel title="Assertion results">
          {posture.isPending && <Loading label="Loading results" />}
          {posture.isError && <ErrorNotice error={posture.error} />}
          {posture.data &&
            (controlPosture ? (
              <KeyValue
                columns={1}
                items={[
                  ['pass', <span key="pass" className="font-mono text-pass">{controlPosture.pass}</span>],
                  ['fail', <span key="fail" className="font-mono text-fail">{controlPosture.fail}</span>],
                  ['inconclusive', <span key="incon" className="font-mono text-incon">{controlPosture.inconclusive}</span>],
                  ['not applicable', <span key="na" className="font-mono text-na">{controlPosture.not_applicable}</span>],
                  ['coverage', <RatioBar key="cov" ratio={controlPosture.coverage_ratio} />],
                  ['last evaluated', controlPosture.last_evaluated_at ? fmtRelative(controlPosture.last_evaluated_at) : '-'],
                ]}
              />
            ) : (
              <div className="text-[12px] text-dim">
                No assertion has been evaluated for this control yet. Results appear here once a
                run finishes.
              </div>
            ))}
        </Panel>
      </div>

      <Panel title="Remediation guidance" dense>
        <p className="p-3 text-[13px] whitespace-pre-wrap text-ink/90">
          {c.remediation ?? 'No remediation guidance recorded for this control.'}
        </p>
      </Panel>

      <Panel title="Framework references">
        {c.refs.length === 0 ? (
          <div className="text-[12px] text-dim">This control is not mapped to a framework yet.</div>
        ) : (
          <ul className="flex flex-wrap gap-2">
            {c.refs.map((ref) => {
              const framework = frameworkById.get(ref.framework_id)
              return (
                <li key={ref.id} className="border border-edge bg-panel2 px-2 py-1 text-[12px]">
                  <span className="font-mono text-accent">{ref.ref_code}</span>
                  <span className="ml-2 text-mute">{ref.title ?? ''}</span>
                  {framework && <span className="ml-2 text-dim">{framework.key}</span>}
                </li>
              )
            })}
          </ul>
        )}
      </Panel>

      <Panel title={`Validation tests (${tests.data?.length ?? 0})`}>
        {tests.isPending && <Loading label="Loading tests" />}
        {tests.isError && <ErrorNotice error={tests.error} onRetry={() => void tests.refetch()} />}
        {tests.data &&
          (tests.data.length === 0 ? (
            <EmptyState
              title="No test validates this control yet"
              hint="A test collects evidence from your targets and asserts what this control requires."
              action={
                isWriter ? (
                  <LinkButton to="/tests/new" variant="primary">
                    New test
                  </LinkButton>
                ) : undefined
              }
            />
          ) : (
            <TableWrap>
              <thead>
                <tr>
                  <Th>Key</Th>
                  <Th>Name</Th>
                  <Th align="right">Version</Th>
                  <Th>Tags</Th>
                  <Th>Enabled</Th>
                  <Th>Updated</Th>
                </tr>
              </thead>
              <tbody>
                {tests.data.map((test) => (
                  <tr key={test.id} className="hover:bg-raise/50">
                    <Td mono>
                      <Link to={`/tests/${test.id}`} className="text-accent hover:underline">
                        {test.key}
                      </Link>
                    </Td>
                    <Td wrap className="min-w-[16rem] max-w-[30rem]">
                      {test.name}
                    </Td>
                    <Td align="right" mono>
                      v{test.current_version}
                    </Td>
                    <Td mono className="text-mute">
                      {test.tags.length > 0 ? test.tags.join(', ') : '-'}
                    </Td>
                    <Td>{test.enabled ? <span className="text-pass">yes</span> : <span className="text-dim">no</span>}</Td>
                    <Td>{fmtRelative(test.updated_at ?? test.created_at)}</Td>
                  </tr>
                ))}
              </tbody>
            </TableWrap>
          ))}
      </Panel>

      <Panel title="Latest result per target">
        {runsLoading && <Loading label="Loading run history" />}
        {runsError !== null && runsError !== undefined && <ErrorNotice error={runsError} />}
        {!runsLoading && (
          <TableWrap>
            <thead>
              <tr>
                <Th>Target</Th>
                <Th>Latest run</Th>
                <Th>Run status</Th>
                <Th>Assertion</Th>
                <Th>Finished</Th>
              </tr>
            </thead>
            <tbody>
              {postureRows.length === 0 ? (
                <TableEmptyRow colSpan={5}>
                  No run has executed against this control yet. Results appear here after the
                  first run finishes.
                </TableEmptyRow>
              ) : (
                postureRows.map((run) => (
                  <tr key={run.target_id} className="hover:bg-raise/50">
                    <Td wrap className="min-w-[14rem] max-w-[24rem]">
                      <Link to={`/targets/${run.target_id}`} className="text-accent hover:underline">
                        {run.target_name}
                      </Link>
                      <span className="ml-2 font-mono text-[11px] text-dim">
                        {run.target_host}
                        {run.target_port ? `:${run.target_port}` : ''}
                      </span>
                    </Td>
                    <Td mono>
                      <Link to={`/runs/${run.id}`} className="text-accent hover:underline">
                        #{run.id}
                      </Link>
                    </Td>
                    <Td>
                      <RunStatusBadge status={run.status} />
                    </Td>
                    <Td>
                      <AssertionBadge status={run.assertion_status} />
                    </Td>
                    <Td>{run.finished_at ? fmtRelative(run.finished_at) : '-'}</Td>
                  </tr>
                ))
              )}
            </tbody>
          </TableWrap>
        )}
      </Panel>

      <Panel
        title="Recent findings"
        actions={
          <Link to={`/findings?control_id=${c.id}`} className="text-[11px] text-accent hover:underline">
            View all
          </Link>
        }
      >
        {findings.isPending && <Loading label="Loading findings" />}
        {findings.isError && <ErrorNotice error={findings.error} onRetry={() => void findings.refetch()} />}
        {findings.data &&
          (findings.data.items.length === 0 ? (
            <EmptyState
              title="No findings recorded against this control"
              hint="A finding opens here when a run on this control fails its assertion."
            />
          ) : (
            <TableWrap>
              <thead>
                <tr>
                  <Th>Severity</Th>
                  <Th>Title</Th>
                  <Th>Status</Th>
                  <Th>Target</Th>
                  <Th>Last seen</Th>
                </tr>
              </thead>
              <tbody>
                {findings.data.items.map((finding) => (
                  <tr key={finding.id} className="hover:bg-raise/50">
                    <Td>
                      <SeverityBadge severity={finding.severity} />
                    </Td>
                    <Td wrap className="min-w-[18rem] max-w-[34rem]">
                      <Link to={`/findings/${finding.id}`} className="text-accent hover:underline">
                        {finding.title}
                      </Link>
                    </Td>
                    <Td>
                      <FindingStatusBadge status={finding.status} />
                    </Td>
                    <Td wrap className="max-w-[18rem]">
                      {finding.target_name}
                    </Td>
                    <Td>{fmtRelative(finding.last_seen_at)}</Td>
                  </tr>
                ))}
              </tbody>
            </TableWrap>
          ))}
      </Panel>
    </div>
  )
}

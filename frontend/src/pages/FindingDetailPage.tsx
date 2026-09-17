import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { useAuth } from '../auth/context'
import { Hash, JsonBlock, TruncatedText } from '../components/Json'
import {
  AssertionBadge,
  Badge,
  Button,
  ErrorNotice,
  Field,
  FindingStatusBadge,
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
  Textarea,
  Th,
} from '../components/ui'
import { api, qk } from '../lib/api'
import { fmtBytes, fmtDateTime, fmtRelative, humanizeEnum } from '../lib/format'
import { findingStatuses, severities } from '../lib/tones'
import type { FindingStatus, Severity } from '../lib/types'

/** Select value that means "clear the assignee". */
const UNASSIGNED = 'unassigned'

export function FindingDetailPage() {
  const params = useParams()
  const findingId = Number(params.id)
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const { isWriter } = useAuth()

  const finding = useQuery({
    queryKey: qk.finding(findingId),
    queryFn: async () => {
      const data = await api.finding(findingId)
      // Overdue-ness is computed here, at the boundary with the server, rather
      // than during render: it is a function of wall-clock time, not UI state.
      const now = Date.now()
      return {
        ...data,
        overdue: isOverdue(data.timeline, data.status, now),
        timeline: data.timeline.map((entry) => ({
          ...entry,
          overdue: entry.due_at !== null && new Date(entry.due_at).getTime() < now,
        })),
      }
    },
    staleTime: 15_000,
  })

  const lastRunId = finding.data?.last_run_id ?? null
  const lastRun = useQuery({
    queryKey: qk.run(lastRunId ?? 0),
    queryFn: () => api.run(lastRunId ?? 0),
    enabled: lastRunId !== null,
    staleTime: 30_000,
  })
  const users = useQuery({
    queryKey: qk.users,
    queryFn: api.users,
    staleTime: 5 * 60_000,
  })

  const [status, setStatus] = useState<FindingStatus | ''>('')
  const [severity, setSeverity] = useState<Severity | ''>('')
  const [assignedTo, setAssignedTo] = useState('')
  const [note, setNote] = useState('')

  const update = useMutation({
    mutationFn: () => {
      const payload: {
        status?: FindingStatus
        severity?: Severity
        assigned_to?: number | null
        note?: string
      } = {}
      if (status !== '') payload.status = status
      if (severity !== '') payload.severity = severity
      if (assignedTo === UNASSIGNED) {
        payload.assigned_to = null
      } else if (assignedTo !== '') {
        payload.assigned_to = Number(assignedTo)
      }
      if (note.trim() !== '') payload.note = note.trim()
      return api.updateFinding(findingId, payload)
    },
    onSuccess: () => {
      setNote('')
      setStatus('')
      setSeverity('')
      setAssignedTo('')
      void queryClient.invalidateQueries({ queryKey: qk.finding(findingId) })
      void queryClient.invalidateQueries({ queryKey: qk.findings() })
      void queryClient.invalidateQueries({ queryKey: qk.findingSummary })
    },
  })

  const retest = useMutation({
    mutationFn: () => api.retestFinding(findingId),
    onSuccess: (result) => {
      void queryClient.invalidateQueries({ queryKey: qk.finding(findingId) })
      navigate(`/runs/${result.run_id}`)
    },
  })

  if (finding.isPending) return <Loading label="Loading finding" />
  if (finding.isError) return <ErrorNotice error={finding.error} onRetry={() => void finding.refetch()} />
  const f = finding.data

  const activeUsers = (users.data ?? []).filter((user) => user.is_active)
  const assignedUser =
    f.assigned_to === null
      ? null
      : ((users.data ?? []).find((user) => user.id === f.assigned_to) ?? null)
  const assigneeLabel =
    f.assigned_to === null ? 'unassigned' : (assignedUser?.username ?? `user #${f.assigned_to}`)

  const dissentingFactIds = new Set<number>()
  if (lastRun.data) {
    for (const result of lastRun.data.assertion_results) {
      if (result.status === 'pass') {
        for (const id of result.fact_ids) dissentingFactIds.add(id)
      }
    }
  }

  const timeline = [...f.timeline].sort(
    (a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime(),
  )

  return (
    <div className="space-y-4">
      <PageHeader
        title={
          <span className="flex flex-wrap items-baseline gap-3">
            <span className="font-mono text-[15px] text-accent">finding #{f.id}</span>
            <span>{f.title}</span>
          </span>
        }
        subtitle={
          <span className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={f.severity} />
            <FindingStatusBadge status={f.status} />
            {f.overdue && <Badge tone="incon">past due</Badge>}
            <Link to={`/controls/${f.control_id}`} className="font-mono text-[12px] text-accent hover:underline">
              {f.control_key}
            </Link>
            <span className="text-dim">via</span>
            <Link to={`/tests/${f.test_id}`} className="font-mono text-[12px] text-accent hover:underline">
              {f.test_key}
            </Link>
            <span className="text-dim">on</span>
            <Link to={`/targets/${f.target_id}`} className="text-accent hover:underline">
              {f.target_name}
            </Link>
            {f.last_run_id !== null && (
              <>
                <span className="text-dim">last run</span>
                <Link to={`/runs/${f.last_run_id}`} className="font-mono text-[12px] text-accent hover:underline">
                  #{f.last_run_id}
                </Link>
                {lastRun.data && <RunStatusBadge status={lastRun.data.status} />}
                {lastRun.data && <AssertionBadge status={lastRun.data.assertion_status} />}
              </>
            )}
            {f.retest_of_finding_id !== null && (
              <Link to={`/findings/${f.retest_of_finding_id}`} className="text-accent hover:underline">
                retest of #{f.retest_of_finding_id}
              </Link>
            )}
          </span>
        }
        actions={
          isWriter ? (
            <Button variant="primary" disabled={retest.isPending} onClick={() => retest.mutate()}>
              {retest.isPending ? 'Queuing retest...' : 'Retest now'}
            </Button>
          ) : null
        }
      />

      {retest.isError && <ErrorNotice title="Retest failed" error={retest.error} />}

      {f.status === 'open' && (f.severity === 'critical' || f.severity === 'high') && (
        <div className="border border-fail/50 bg-fail/10 p-3 text-[13px] text-ink">
          <span className="font-mono text-[12px] font-semibold text-fail">
            UNTRIAGED {f.severity.toUpperCase()} -{' '}
          </span>
          this failure has not been triaged yet. Assign an owner, set the state, or record why the
          risk is accepted.
        </div>
      )}

      <div className="grid gap-3 lg:grid-cols-2">
        <Panel title="Expected">
          <JsonBlock value={f.expected} collapsedHeight={200} />
        </Panel>
        <Panel title="Observed">
          <JsonBlock value={f.observed} collapsedHeight={200} />
        </Panel>
      </div>

      <Panel title="Why it failed">
        <div className="space-y-3">
          {f.description && (
            <p className="text-[13px] whitespace-pre-wrap text-ink/90">{f.description}</p>
          )}
          {f.reason && (
            <div>
              <div className="mb-1 text-[11px] tracking-wide text-dim uppercase">
                Assertion reason
              </div>
              <pre className="border border-edge bg-bg p-2 font-mono text-[12px] whitespace-pre-wrap text-ink/90">
                {f.reason}
              </pre>
            </div>
          )}
          {!f.description && !f.reason && (
            <span className="text-[12px] text-dim">No description or reason was recorded.</span>
          )}
        </div>
      </Panel>

      <Panel title={`Facts (${f.facts.length})`}>
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
            {f.facts.length === 0 ? (
              <TableEmptyRow colSpan={7}>
                No facts were recorded for this finding. Facts come from the run that produced it.
              </TableEmptyRow>
            ) : (
              f.facts.map((fact) => {
                const dissents = dissentingFactIds.has(fact.id)
                return (
                  <tr key={fact.id} className={dissents ? 'bg-incon/5' : ''}>
                    <Td mono className="text-mute">
                      {fact.fact_type}
                    </Td>
                    <Td mono>{fact.subject}</Td>
                    <Td mono className="text-mute">
                      {fact.key}
                    </Td>
                    <Td wrap className="min-w-[16rem] max-w-[32rem]">
                      <JsonBlock value={fact.value} collapsedHeight={80} />
                    </Td>
                    <Td align="right" mono>
                      {fact.confidence.toFixed(2)}
                    </Td>
                    <Td wrap className="max-w-64 text-[12px] text-mute">
                      {fact.detail ?? '-'}
                      {dissents && (
                        <div className="mt-1">
                          <Badge tone="incon" title="A passing assertion in the same run used this fact">
                            dissenting
                          </Badge>
                        </div>
                      )}
                    </Td>
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
                )
              })
            )}
          </tbody>
        </TableWrap>
        {lastRunId === null ? (
          <p className="mt-2 text-[12px] text-dim">
            This finding has no run recorded, so facts cannot be checked against the assertions
            that ran alongside them.
          </p>
        ) : lastRun.isError ? (
          <p className="mt-2 text-[12px] text-dim">
            Run #{lastRunId} could not be loaded, so facts used by passing assertions are not
            marked.
          </p>
        ) : (
          f.facts.length > 0 && (
            <p className="mt-2 text-[12px] text-dim">
              Highlighted facts were also used by an assertion that passed in run #{lastRunId}.
              Review them before closing the finding: they are evidence that contradicts the failure.
            </p>
          )
        )}
      </Panel>

      <Panel title={`Evidence (${f.evidence.length})`}>
        {f.evidence.length === 0 ? (
          <div className="text-[12px] text-dim">
            No evidence was captured for this finding. Evidence is stored by the run that produced
            the finding.
          </div>
        ) : (
          <div className="space-y-2">
            {f.evidence.map((item) => (
              <div key={item.id} className="border border-edge bg-panel2">
                <div className="flex flex-wrap items-center gap-3 px-3 py-2">
                  <Badge tone="mute">{item.kind}</Badge>
                  <Link to={`/evidence/${item.id}`} className="font-mono text-[12px] text-accent hover:underline">
                    {item.filename}
                  </Link>
                  <Hash value={item.sha256} />
                  <span className="font-mono text-[11px] text-mute">{fmtBytes(item.size_bytes)}</span>
                  {item.truncated && <Badge tone="incon">truncated</Badge>}
                  <span className="ml-auto text-[11px] text-dim">{fmtRelative(item.created_at)}</span>
                </div>
              </div>
            ))}
            <p className="text-[12px] text-dim">
              Digests are recorded when each file is stored and are never rewritten. Open an item
              to re-hash the stored bytes and confirm they are intact.
            </p>
          </div>
        )}
      </Panel>

      <div className="grid gap-3 lg:grid-cols-2">
        {isWriter ? (
          <Panel title="Triage and remediation">
            <div className="space-y-3">
              <div className="grid gap-3 md:grid-cols-2">
                <Field label="Status" hint={`current: ${humanizeEnum(f.status)}`}>
                  <Select value={status} onChange={(e) => setStatus(e.target.value as FindingStatus | '')}>
                    <option value="">Leave unchanged</option>
                    {findingStatuses.map((candidate) => (
                      <option key={candidate} value={candidate}>
                        {humanizeEnum(candidate)}
                      </option>
                    ))}
                  </Select>
                </Field>
                <Field label="Severity" hint={`current: ${f.severity}`}>
                  <Select value={severity} onChange={(e) => setSeverity(e.target.value as Severity | '')}>
                    <option value="">Leave unchanged</option>
                    {severities.map((candidate) => (
                      <option key={candidate} value={candidate}>
                        {candidate}
                      </option>
                    ))}
                  </Select>
                </Field>
              </div>
              <Field
                label="Assignee"
                hint={
                  users.isError
                    ? `current: ${assigneeLabel}. The user list could not be loaded.`
                    : `current: ${assigneeLabel}`
                }
              >
                <Select value={assignedTo} onChange={(e) => setAssignedTo(e.target.value)}>
                  <option value="">Leave unchanged</option>
                  <option value={UNASSIGNED}>Unassigned</option>
                  {activeUsers.map((user) => (
                    <option key={user.id} value={String(user.id)}>
                      {user.username} ({user.role})
                      {user.full_name ? ` - ${user.full_name}` : ''}
                    </option>
                  ))}
                </Select>
              </Field>
              <Field label="Note" hint="Recorded on the timeline, not editable afterwards.">
                <Textarea rows={3} value={note} onChange={(e) => setNote(e.target.value)} />
              </Field>
              {update.isError && <ErrorNotice title="Update rejected" error={update.error} />}
              {update.isSuccess && (
                <div className="border border-pass/40 bg-pass/5 p-2 text-[12px] text-pass">
                  Finding updated. The change is on the timeline below.
                </div>
              )}
              <div className="flex items-center gap-2">
                <Button variant="primary" disabled={update.isPending} onClick={() => update.mutate()}>
                  {update.isPending ? 'Saving...' : 'Apply update'}
                </Button>
                <span className="text-[11px] text-dim">
                  Fields left unchanged keep their current values. A note on its own is added to
                  the timeline.
                </span>
              </div>
            </div>
          </Panel>
        ) : (
          <Panel title="Triage">
            <p className="text-[12px] text-dim">
              Triage, remediation and retests require the analyst or administrator role.
            </p>
          </Panel>
        )}

        <div className="space-y-3">
          <Panel title="Remediation guidance">
            {f.remediation_guidance ? (
              <p className="text-[13px] whitespace-pre-wrap text-ink/90">{f.remediation_guidance}</p>
            ) : (
              <span className="text-[12px] text-dim">
                No remediation guidance is recorded for this control.
              </span>
            )}
          </Panel>

          <Panel title="Lifecycle">
            <KeyValue
              items={[
                ['Occurrences', String(f.occurrences)],
                ['First seen', fmtDateTime(f.first_seen_at)],
                ['Last seen', fmtDateTime(f.last_seen_at)],
                ['Last assertion', f.last_status ?? '-'],
                ['Resolved', f.resolved_at ? fmtDateTime(f.resolved_at) : 'not resolved'],
                ['Assigned', assigneeLabel],
              ]}
            />
          </Panel>
        </div>
      </div>

      <Panel title={`Timeline (${timeline.length})`}>
        {timeline.length === 0 ? (
          <div className="text-[12px] text-dim">
            No timeline entries yet. State changes, notes and due dates are recorded here.
          </div>
        ) : (
          <ol className="space-y-0">
            {timeline.map((entry) => {
              const entryOverdue = entry.overdue
              return (
                <li key={entry.id} className="flex gap-3 border-b border-edge/60 py-2 last:border-b-0">
                  <div className="w-40 shrink-0 font-mono text-[11px] text-dim">
                    {fmtDateTime(entry.created_at)}
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <Badge tone="mute">{entry.kind}</Badge>
                      {entry.from_status !== null && entry.to_status !== null && (
                        <span className="flex items-center gap-1 text-[12px]">
                          <FindingStatusBadge status={entry.from_status} />
                          <span className="text-dim">to</span>
                          <FindingStatusBadge status={entry.to_status} />
                        </span>
                      )}
                      {entry.actor && (
                        <span className="text-[11px] text-dim">by {entry.actor}</span>
                      )}
                      {entry.due_at && (
                        <Badge tone={entryOverdue ? 'fail' : 'mute'}>
                          due {fmtRelative(entry.due_at)}
                        </Badge>
                      )}
                    </div>
                    {entry.note && (
                      <div className="mt-1 text-[12px] whitespace-pre-wrap text-ink/90">
                        <TruncatedText text={entry.note} length={400} />
                      </div>
                    )}
                  </div>
                </li>
              )
            })}
          </ol>
        )}
      </Panel>
    </div>
  )
}

function isOverdue(
  timeline: Array<{ due_at: string | null }>,
  status: FindingStatus,
  now: number,
): boolean {
  if (status === 'resolved' || status === 'false_positive' || status === 'accepted_risk') return false
  return timeline.some((entry) => entry.due_at !== null && new Date(entry.due_at).getTime() < now)
}

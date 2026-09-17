import { useQuery } from '@tanstack/react-query'
import { Link, useSearchParams } from 'react-router-dom'
import {
  Badge,
  Button,
  ErrorNotice,
  FindingStatusBadge,
  Input,
  Loading,
  PageHeader,
  Pagination,
  Select,
  SeverityBadge,
  TableEmptyRow,
  TableWrap,
  Td,
  Th,
  Toolbar,
} from '../components/ui'
import { useDebounced } from '../hooks/useDebounced'
import { api, fetchFindings, qk } from '../lib/api'
import { fmtRelative, humanizeEnum } from '../lib/format'
import { findingStatuses, severities } from '../lib/tones'

const PAGE_SIZE = 50

export function FindingsPage() {
  const [searchParams, setSearchParams] = useSearchParams()

  const status = searchParams.get('status') ?? ''
  const severity = searchParams.get('severity') ?? ''
  const targetId = searchParams.get('target_id') ?? ''
  const controlId = searchParams.get('control_id') ?? ''
  const testId = searchParams.get('test_id') ?? ''
  const search = searchParams.get('q') ?? ''
  const offset = Math.max(0, Number(searchParams.get('offset') ?? '0') || 0)
  const debounced = useDebounced(search, 300)

  function update(key: string, value: string): void {
    const next = new URLSearchParams(searchParams)
    if (value === '') next.delete(key)
    else next.set(key, value)
    if (key !== 'offset') next.delete('offset')
    setSearchParams(next, { replace: true })
  }

  const filters = {
    status: status === '' ? undefined : status,
    severity: severity === '' ? undefined : severity,
    target_id: targetId === '' ? undefined : Number(targetId),
    control_id: controlId === '' ? undefined : Number(controlId),
    test_id: testId === '' ? undefined : Number(testId),
    q: debounced === '' ? undefined : debounced,
    limit: PAGE_SIZE,
    offset,
  }

  const findings = useQuery({
    queryKey: qk.findings(filters),
    queryFn: () => fetchFindings(filters),
    staleTime: 15_000,
  })
  const summary = useQuery({
    queryKey: qk.findingSummary,
    queryFn: api.findingSummary,
    staleTime: 60_000,
  })
  const targets = useQuery({
    queryKey: qk.targets({ limit: 1000 }),
    queryFn: () => api.targets({ limit: 1000 }),
    staleTime: 5 * 60_000,
  })
  const controls = useQuery({
    queryKey: qk.controls({ limit: 1000 }),
    queryFn: () => api.controls({ limit: 1000 }),
    staleTime: 5 * 60_000,
  })
  const users = useQuery({
    queryKey: qk.users,
    queryFn: api.users,
    staleTime: 5 * 60_000,
  })

  // Assignees are stored as user ids; the roster resolves them to names.
  const userById = new Map((users.data ?? []).map((user) => [user.id, user]))

  const items = findings.data?.items ?? []
  const total = findings.data?.total ?? 0
  const hasFilters =
    status !== '' ||
    severity !== '' ||
    targetId !== '' ||
    controlId !== '' ||
    testId !== '' ||
    debounced !== ''

  return (
    <div className="space-y-4">
      <PageHeader
        title="Findings"
        subtitle="Failed checks land here with their expected and observed evidence, a triage state, and a retest path."
      />

      {summary.data && (
        <div className="grid grid-cols-2 gap-3 md:grid-cols-4 lg:grid-cols-6">
          <SummaryTile label="Open" value={summary.data.open_total} tone="fail" />
          <SummaryTile label="Overdue" value={summary.data.overdue_total} tone="incon" />
          {(['critical', 'high', 'medium', 'low'] as const).map((sev) => (
            <SummaryTile
              key={sev}
              label={sev}
              value={summary.data?.by_severity[sev] ?? 0}
              tone={sev === 'critical' ? 'crit' : sev === 'high' ? 'high' : sev === 'medium' ? 'med' : 'low'}
            />
          ))}
        </div>
      )}

      <Toolbar
        trailing={
          <span className="font-mono text-[12px] text-dim">
            {findings.data ? `${items.length} shown of ${total}` : 'Loading...'}
          </span>
        }
      >
        <Input
          type="search"
          value={search}
          onChange={(e) => update('q', e.target.value)}
          placeholder="Search titles"
          className="w-60"
        />
        <Select
          value={status}
          onChange={(e) => update('status', e.target.value)}
          className="w-40"
        >
          <option value="">Any state</option>
          {findingStatuses.map((candidate) => (
            <option key={candidate} value={candidate}>
              {humanizeEnum(candidate)}
            </option>
          ))}
        </Select>
        <Select
          value={severity}
          onChange={(e) => update('severity', e.target.value)}
          className="w-40"
        >
          <option value="">Any severity</option>
          {severities.map((candidate) => (
            <option key={candidate} value={candidate}>
              {candidate}
            </option>
          ))}
        </Select>
        <Select
          value={controlId}
          onChange={(e) => update('control_id', e.target.value)}
          className="w-64"
        >
          <option value="">Any control</option>
          {(controls.data ?? []).map((control) => (
            <option key={control.id} value={control.id}>
              {control.key} - {control.title}
            </option>
          ))}
        </Select>
        <Select
          value={targetId}
          onChange={(e) => update('target_id', e.target.value)}
          className="w-64"
        >
          <option value="">Any target</option>
          {(targets.data ?? []).map((target) => (
            <option key={target.id} value={target.id}>
              {target.name} ({target.host})
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
        {testId !== '' && (
          <Badge tone="accent" title={`Only findings from test #${testId} are listed`}>
            test #{testId}
          </Badge>
        )}
      </Toolbar>

      {findings.isPending && <Loading label="Loading findings" />}
      {findings.isError && <ErrorNotice error={findings.error} onRetry={() => void findings.refetch()} />}

      {findings.data && (
        <>
          <TableWrap>
            <thead>
              <tr>
                <Th align="right">ID</Th>
                <Th>Severity</Th>
                <Th>State</Th>
                <Th>Title</Th>
                <Th>Control</Th>
                <Th>Target</Th>
                <Th align="right">Occurrences</Th>
                <Th>First seen</Th>
                <Th>Last seen</Th>
                <Th align="right">Assigned</Th>
              </tr>
            </thead>
            <tbody>
              {items.length === 0 ? (
                <TableEmptyRow colSpan={10}>
                  {hasFilters
                    ? 'No findings match the current filters. Clear a filter to widen the search.'
                    : 'No findings yet. A finding is recorded the first time a validation test fails against a target. Start a run from a test to produce the first one.'}
                </TableEmptyRow>
              ) : (
                items.map((finding) => (
                  <tr key={finding.id} className="hover:bg-raise/50">
                    <Td align="right" mono>
                      <Link to={`/findings/${finding.id}`} className="text-accent hover:underline">
                        #{finding.id}
                      </Link>
                    </Td>
                    <Td>
                      <SeverityBadge severity={finding.severity} />
                    </Td>
                    <Td>
                      <FindingStatusBadge status={finding.status} />
                    </Td>
                    <Td wrap className="min-w-[18rem] max-w-[34rem]">
                      <Link to={`/findings/${finding.id}`} className="text-ink hover:underline">
                        {finding.title}
                      </Link>
                      <div className="font-mono text-[11px] text-dim">
                        {finding.test_key} on {finding.target_name}
                      </div>
                    </Td>
                    <Td>
                      <Link to={`/controls/${finding.control_id}`} className="font-mono text-[12px] text-mute hover:underline">
                        {finding.control_key}
                      </Link>
                    </Td>
                    <Td>
                      <Link to={`/targets/${finding.target_id}`} className="text-mute hover:underline">
                        {finding.target_name}
                      </Link>
                    </Td>
                    <Td align="right" mono className="text-mute">
                      {finding.occurrences}
                    </Td>
                    <Td className="text-mute">{fmtRelative(finding.first_seen_at)}</Td>
                    <Td className="text-mute">{fmtRelative(finding.last_seen_at)}</Td>
                    <Td align="right" className="text-mute">
                      {finding.assigned_to === null ? (
                        <span className="text-dim">unassigned</span>
                      ) : (
                        (userById.get(finding.assigned_to)?.username ??
                        `user #${finding.assigned_to}`)
                      )}
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

function SummaryTile({
  label,
  value,
  tone,
}: {
  label: string
  value: number
  tone: 'fail' | 'incon' | 'crit' | 'high' | 'med' | 'low'
}) {
  const toneText: Record<typeof tone, string> = {
    fail: 'text-fail',
    incon: 'text-incon',
    crit: 'text-crit',
    high: 'text-high',
    med: 'text-med',
    low: 'text-low',
  }
  return (
    <div className="border border-edge bg-panel px-3 py-2">
      <div className="text-[11px] tracking-wide text-dim uppercase">{label}</div>
      <div className={`mt-0.5 font-mono text-xl ${value > 0 ? toneText[tone] : 'text-dim'}`}>{value}</div>
    </div>
  )
}

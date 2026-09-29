import { useQuery } from '@tanstack/react-query'
import { useState, type ReactNode } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { JsonBlock } from '../components/Json'
import {
  Badge,
  Button,
  Drawer,
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
import { api, fetchAudit, qk } from '../lib/api'
import { fmtDateTime, fmtRelative, humanizeEnum } from '../lib/format'
import type { AuditEntry, User } from '../lib/types'

const PAGE_SIZE = 100

/** The object types the recorder writes today; the filter offers what can appear. */
const entityTypes = ['control', 'finding', 'framework', 'run', 'scope', 'setting', 'target', 'test', 'user']

const entityRoutes: Record<string, string> = {
  control: 'controls',
  finding: 'findings',
  run: 'runs',
  scope: 'scopes',
  target: 'targets',
  test: 'tests',
}

/** Plain-language readings of the reason codes the recorder writes. */
const reasonLabels: Record<string, string> = {
  unknown_user: 'No account with that username',
  locked: 'The account is locked',
  inactive: 'The account is disabled',
  bad_password: 'Wrong password',
  bad_current_password: 'The current password was wrong',
}

const detailLabels: Record<string, string> = {
  username: 'Username',
  reason: 'Reason',
  session_id: 'Session',
  locked_out: 'Account locked out',
  other_sessions_revoked: 'Other sessions signed out',
  assigned_to_user_id: 'Assigned to',
  run_id: 'Run',
  target: 'Target',
  targets: 'Targets',
  source: 'Source',
  role: 'Role',
}

/** A key with no label above still has to read like a label, not like a column. */
function titleizeKey(key: string): string {
  const words = key.replace(/[_-]+/g, ' ').trim()
  return words.charAt(0).toUpperCase() + words.slice(1)
}

function actionTitle(action: string): string {
  const words = action.replace(/[._]/g, ' ').trim()
  return words.charAt(0).toUpperCase() + words.slice(1)
}

/** A short, readable form of a long identifier; the full value stays in the title. */
function shortRef(value: string | null): string {
  if (!value) return '-'
  return value.length > 10 ? `${value.slice(0, 8)}…` : value
}

function DetailRow({ label, value, mono = true }: { label: string; value: ReactNode; mono?: boolean }) {
  return (
    <div>
      <dt className="text-[11px] tracking-wide text-dim uppercase">{label}</dt>
      <dd
        className={`mt-0.5 text-[13px] break-words text-ink ${mono ? 'font-mono text-[12px] break-all' : ''}`}
      >
        {value}
      </dd>
    </div>
  )
}

/** The recorded payload, rendered from its keys rather than dumped as one blob. */
function AuditDetail({
  detail,
  userById,
}: {
  detail: Record<string, unknown>
  userById: Map<number, User>
}) {
  const rows: Array<[string, ReactNode]> = []
  const rest: Record<string, unknown> = {}

  for (const [key, value] of Object.entries(detail)) {
    const label = detailLabels[key] ?? titleizeKey(key)
    if (key === 'reason' && typeof value === 'string') {
      rows.push([
        label,
        <span key={key}>
          {reasonLabels[value] ?? humanizeEnum(value)}{' '}
          <span className="font-mono text-[11px] text-dim">{value}</span>
        </span>,
      ])
    } else if (key === 'assigned_to_user_id') {
      const user = typeof value === 'number' ? userById.get(value) : undefined
      rows.push([
        label,
        value === null
          ? 'nobody'
          : user
            ? `${user.username} (#${String(value)})`
            : `user #${String(value)}`,
      ])
    } else if (key === 'session_id' && typeof value === 'string') {
      rows.push([label, <span key={key} className="font-mono text-[12px] break-all">{value}</span>])
    } else if (typeof value === 'boolean') {
      rows.push([label, value ? 'yes' : 'no'])
    } else if (typeof value === 'string' || typeof value === 'number') {
      rows.push([label, String(value)])
    } else if (value === null) {
      rows.push([label, 'Not set'])
    } else {
      rest[key] = value
    }
  }

  return (
    <div className="space-y-3">
      {rows.length > 0 && (
        <dl className="space-y-2">
          {rows.map(([label, value]) => (
            <DetailRow key={label} label={label} value={value} mono={false} />
          ))}
        </dl>
      )}
      {Object.keys(rest).length > 0 && (
        <div>
          <div className="mb-1 text-[11px] tracking-wide text-dim uppercase">
            Other recorded fields
          </div>
          <JsonBlock value={rest} />
        </div>
      )}
    </div>
  )
}

export function AuditPage() {
  const [searchParams, setSearchParams] = useSearchParams()
  const [selected, setSelected] = useState<AuditEntry | null>(null)

  const actor = searchParams.get('actor_user_id') ?? ''
  const action = searchParams.get('action') ?? ''
  const entityType = searchParams.get('entity_type') ?? ''
  const offset = Math.max(0, Number(searchParams.get('offset') ?? '0') || 0)

  function update(key: string, value: string): void {
    const next = new URLSearchParams(searchParams)
    if (value === '') next.delete(key)
    else next.set(key, value)
    if (key !== 'offset') next.delete('offset')
    setSearchParams(next, { replace: true })
  }

  const filters = {
    actor_user_id: actor === '' ? undefined : Number(actor),
    action: action === '' ? undefined : action,
    entity_type: entityType === '' ? undefined : entityType,
    limit: PAGE_SIZE,
    offset,
  }

  const audit = useQuery({
    queryKey: qk.audit(filters),
    queryFn: () => fetchAudit(filters),
    staleTime: 15_000,
  })
  const users = useQuery({
    queryKey: qk.users,
    queryFn: api.users,
    staleTime: 5 * 60_000,
  })

  const items = audit.data?.items ?? []
  const total = audit.data?.total ?? 0
  const hasFilters = actor !== '' || action !== '' || entityType !== ''
  const userById = new Map((users.data ?? []).map((user) => [user.id, user]))
  const actorInRoster = actor !== '' && userById.has(Number(actor))

  return (
    <div className="space-y-4">
      <PageHeader
        title="Audit log"
        subtitle="Append-only. Every change CONTROLFORGE accepted is recorded here with the account, address and request that made it."
      />

      <Toolbar
        trailing={
          <>
            <span className="font-mono text-[12px] text-dim">
              {audit.data ? `${items.length} shown of ${total}` : 'Loading...'}
            </span>
            <Button size="sm" onClick={() => void audit.refetch()}>
              Refresh
            </Button>
          </>
        }
      >
        <Select
          value={actor}
          onChange={(e) => update('actor_user_id', e.target.value)}
          aria-label="Filter by actor"
          className="w-52"
        >
          <option value="">Any actor</option>
          {(users.data ?? []).map((user) => (
            <option key={user.id} value={user.id}>
              {user.username}
            </option>
          ))}
          {actor !== '' && !actorInRoster && (
            <option value={actor}>user #{actor}</option>
          )}
        </Select>
        <Input
          value={action}
          onChange={(e) => update('action', e.target.value)}
          placeholder="Action, e.g. run.start"
          aria-label="Filter by action"
          title="Matches any entry whose action contains this text"
          className="w-56 font-mono text-[12px]"
        />
        <Select
          value={entityType}
          onChange={(e) => update('entity_type', e.target.value)}
          aria-label="Filter by entity type"
          className="w-44"
        >
          <option value="">Any entity</option>
          {entityTypes.map((candidate) => (
            <option key={candidate} value={candidate}>
              {candidate}
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

      {audit.isPending && <Loading label="Loading the audit log" />}
      {audit.isError && <ErrorNotice error={audit.error} onRetry={() => void audit.refetch()} />}

      {audit.data && (
        <>
          <TableWrap>
            <thead>
              <tr>
                <Th>Time</Th>
                <Th>Actor</Th>
                <Th>Action</Th>
                <Th>Entity</Th>
                <Th>Summary</Th>
                <Th>Address</Th>
                <Th>Request</Th>
              </tr>
            </thead>
            <tbody>
              {items.length === 0 ? (
                <TableEmptyRow colSpan={7}>
                  {hasFilters
                    ? 'No audit entry matches the current filters. Clear a filter to widen the search.'
                    : 'No audit entries yet. Sign-ins, run starts, finding changes and setting updates are recorded here as they happen, and entries are never edited or removed.'}
                </TableEmptyRow>
              ) : (
                items.map((entry) => (
                  <tr
                    key={entry.id}
                    onClick={() => setSelected(entry)}
                    className="cursor-pointer hover:bg-raise/50"
                  >
                    <Td className="text-mute">
                      <span title={fmtDateTime(entry.ts)}>{fmtRelative(entry.ts)}</span>
                    </Td>
                    <Td mono className="text-mute">
                      {entry.actor ?? (entry.actor_user_id === null ? 'system' : `user #${entry.actor_user_id}`)}
                    </Td>
                    <Td mono className="text-ink">
                      {entry.action}
                    </Td>
                    <Td mono className="text-mute">
                      {entry.entity_type ?? '-'}
                      {entry.entity_id !== null && <span className="text-dim"> #{entry.entity_id}</span>}
                    </Td>
                    <Td wrap className="min-w-[16rem] max-w-[32rem] text-[12px] text-mute">
                      {entry.summary ?? '-'}
                    </Td>
                    <Td mono className="text-dim">
                      {entry.ip_address ?? '-'}
                    </Td>
                    <Td mono className="text-dim">
                      <span title={entry.request_id ?? undefined}>{shortRef(entry.request_id)}</span>
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

      <Drawer
        open={selected !== null}
        title={
          selected ? (
            <span className="flex items-baseline gap-2">
              {actionTitle(selected.action)}
              <span className="font-mono text-[11px] text-dim">#{selected.id}</span>
            </span>
          ) : (
            'Audit entry'
          )
        }
        onClose={() => setSelected(null)}
      >
        {selected && (
          <div className="space-y-3">
            <div className="flex flex-wrap items-center gap-2">
              <Badge tone="mute" title="Recorded action name">
                {selected.action}
              </Badge>
              <span className="text-[12px] text-mute">{fmtDateTime(selected.ts)}</span>
            </div>
            <dl className="space-y-2">
              <DetailRow
                label="Actor"
                value={selected.actor ?? (selected.actor_user_id === null ? 'system' : `user #${selected.actor_user_id}`)}
              />
              <DetailRow
                label="Entity"
                value={
                  selected.entity_type === null
                    ? 'Not recorded'
                    : `${selected.entity_type}${selected.entity_id === null ? '' : ` #${selected.entity_id}`}`
                }
                mono={false}
              />
              <DetailRow label="Summary" value={selected.summary ?? 'Not recorded'} mono={false} />
              <DetailRow label="Address" value={selected.ip_address ?? 'Not recorded'} />
              <DetailRow label="User agent" value={selected.user_agent ?? 'Not recorded'} mono={false} />
              <DetailRow label="Request" value={selected.request_id ?? 'Not recorded'} />
            </dl>
            {selected.detail !== null && (
              <div>
                <div className="mb-1 text-[11px] tracking-wide text-dim uppercase">
                  Recorded detail
                </div>
                <AuditDetail detail={selected.detail} userById={userById} />
              </div>
            )}
            {selected.entity_type !== null &&
              selected.entity_id !== null &&
              entityRoutes[selected.entity_type] && (
                <Link
                  to={`/${entityRoutes[selected.entity_type]}/${selected.entity_id}`}
                  className="text-[13px] text-accent hover:underline"
                >
                  Open {selected.entity_type} #{selected.entity_id}
                </Link>
              )}
          </div>
        )}
      </Drawer>
    </div>
  )
}

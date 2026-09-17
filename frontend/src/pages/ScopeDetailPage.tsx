import { useQuery } from '@tanstack/react-query'
import { useParams } from 'react-router-dom'
import {
  Badge,
  ErrorNotice,
  KeyValue,
  Loading,
  PageHeader,
  Panel,
  TableEmptyRow,
  TableWrap,
  Td,
  Th,
} from '../components/ui'
import { api, qk } from '../lib/api'
import { daysUntil, fmtDateTime, fmtRelative } from '../lib/format'
import { expiryState, governanceProblems } from '../lib/scopeGovernance'

export function ScopeDetailPage() {
  const params = useParams()
  const scopeId = Number(params.id)

  const scope = useQuery({
    queryKey: qk.scope(scopeId),
    queryFn: () => api.scope(scopeId),
    staleTime: 30_000,
  })
  const users = useQuery({
    queryKey: qk.users,
    queryFn: api.users,
    staleTime: 5 * 60_000,
  })
  const userById = new Map((users.data ?? []).map((user) => [user.id, user]))

  if (scope.isPending) return <Loading label="Loading scope" />
  if (scope.isError) return <ErrorNotice error={scope.error} onRetry={() => void scope.refetch()} />
  const s = scope.data
  const expiry = expiryState(s)
  const problems = governanceProblems(s)
  const daysToExpiry = daysUntil(s.expires_at)

  return (
    <div className="space-y-4">
      <PageHeader
        title={s.name}
        subtitle={
          <span className="flex flex-wrap items-center gap-2">
            {s.active ? (
              <Badge tone="pass">active</Badge>
            ) : (
              <Badge tone="fail" title="An inactive scope authorizes nothing">
                inactive
              </Badge>
            )}
            {s.is_lab && (
              <Badge tone="accent" title="A lab scope may authorize loopback and other internal ranges">
                lab
              </Badge>
            )}
            {s.allow_broad && (
              <Badge tone="incon" title="This scope authorizes broad address ranges - review it before running">
                broad allowed
              </Badge>
            )}
            {s.authorization_ref ? (
              <span className="font-mono text-[12px] text-mute">
                authorization: {s.authorization_ref}
              </span>
            ) : (
              <Badge tone="fail">No authorization reference</Badge>
            )}
          </span>
        }
      />

      {expiry === 'expired' && (
        <div className="border border-fail/50 bg-fail/10 p-3 text-[13px] text-ink">
          <span className="font-mono text-[12px] font-semibold text-fail">EXPIRED - </span>
          this scope expired {fmtRelative(s.expires_at)} ({fmtDateTime(s.expires_at)}) and
          authorizes nothing until an administrator renews it. Targets that rely on it cannot be
          validated.
        </div>
      )}
      {expiry === 'soon' && (
        <div className="border border-incon/50 bg-incon/10 p-3 text-[13px] text-ink">
          <span className="font-mono text-[12px] font-semibold text-incon">EXPIRING - </span>
          this scope expires in {daysToExpiry} {daysToExpiry === 1 ? 'day' : 'days'} (
          {fmtDateTime(s.expires_at)}). Renew it before then, or runs against its targets will be
          refused.
        </div>
      )}
      {s.allow_broad && (
        <div className="border border-incon/50 bg-incon/10 p-3 text-[13px] text-ink">
          <span className="font-mono text-[12px] font-semibold text-incon">BROAD SCOPE - </span>
          this scope authorizes a broad address range. Runs are still limited to the entries below,
          but a broad range widens the blast radius of a mistake: review them before starting a run.
        </div>
      )}
      {problems.length > 0 && (
        <div className="text-[12px] text-mute">
          Governance flags: <span className="font-mono text-incon">{problems.join(', ')}</span>
        </div>
      )}

      <div className="grid gap-3 lg:grid-cols-3">
        <Panel title="Scope" className="lg:col-span-2">
          <KeyValue
            items={[
              ['Description', s.description ?? '-'],
              ['Authorization reference', s.authorization_ref ?? '-'],
              ['Approved by', s.approved_by_user_id === null
                ? '-'
                : (userById.get(s.approved_by_user_id)?.username ?? `user #${s.approved_by_user_id}`)],
              ['Lab scope', s.is_lab ? 'yes' : 'no'],
              ['Broad ranges allowed', s.allow_broad ? 'yes' : 'no'],
              ['Active', s.active ? 'yes' : 'no'],
              ['Expires', s.expires_at ? fmtDateTime(s.expires_at) : 'no expiry'],
              ['Created', fmtDateTime(s.created_at)],
            ]}
          />
        </Panel>

        <Panel title="Entries">
          <div className="font-mono text-2xl text-ink">{s.entries.length}</div>
          <div className="mt-1 text-[12px] text-dim">
            {s.entries.length === 0
              ? 'No address is authorized through this scope.'
              : 'Authorized addresses and hosts, each with its own ports and protocol.'}
          </div>
          <div className="mt-3 border-t border-edge pt-2 text-[12px] text-mute">
            A run checks its target's pinned address and port against these entries and records the
            decision in the run's scope snapshot.
          </div>
        </Panel>
      </div>

      <Panel title="Authorized entries" dense>
        <TableWrap className="border-0">
          <thead>
            <tr>
              <Th>Kind</Th>
              <Th>Value</Th>
              <Th>Ports</Th>
              <Th>Protocol</Th>
              <Th>Note</Th>
            </tr>
          </thead>
          <tbody>
            {s.entries.length === 0 ? (
              <TableEmptyRow colSpan={5}>
                This scope has no entries, so no address is authorized through it.
              </TableEmptyRow>
            ) : (
              s.entries.map((entry) => (
                <tr key={entry.id}>
                  <Td>
                    <Badge tone="mute">{entry.kind}</Badge>
                  </Td>
                  <Td mono wrap className="min-w-[12rem] max-w-[28rem]">
                    {entry.value}
                  </Td>
                  <Td mono>{entry.ports}</Td>
                  <Td mono className="text-mute">
                    {entry.protocol}
                  </Td>
                  <Td wrap className="min-w-[10rem] max-w-[28rem] text-mute">
                    {entry.note ?? '-'}
                  </Td>
                </tr>
              ))
            )}
          </tbody>
        </TableWrap>
      </Panel>
    </div>
  )
}

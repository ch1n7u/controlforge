import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import {
  Badge,
  Button,
  Checkbox,
  ErrorNotice,
  Field,
  Input,
  KeyValue,
  Loading,
  PageHeader,
  Panel,
  Select,
  TableEmptyRow,
  TableWrap,
  Td,
  Textarea,
  Th,
} from '../components/ui'
import { useAuth } from '../auth/context'
import { api, qk } from '../lib/api'
import { daysUntil, fmtDateTime, fmtRelative } from '../lib/format'
import { expiryState, governanceProblems } from '../lib/scopeGovernance'
import type { Scope, ScopeEntry, ScopeEntryCreate, ScopeEntryKind, ScopeUpdate } from '../lib/types'

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

  const { isAdmin } = useAuth()
  const navigate = useNavigate()
  const queryClient = useQueryClient()

  const [entryKind, setEntryKind] = useState<ScopeEntryKind>('cidr')
  const [entryValue, setEntryValue] = useState('')
  const [entryPorts, setEntryPorts] = useState('')
  const [entryProtocol, setEntryProtocol] = useState('tcp')
  const [entryNote, setEntryNote] = useState('')
  const [entryError, setEntryError] = useState<string | null>(null)

  const addEntry = useMutation({
    mutationFn: (payload: ScopeEntryCreate) => api.addScopeEntry(scopeId, payload),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: qk.scope(scopeId) })
      void queryClient.invalidateQueries({ queryKey: qk.scopes() })
      setEntryValue('')
      setEntryPorts('')
      setEntryNote('')
      setEntryError(null)
    },
  })

  const removeEntry = useMutation({
    mutationFn: (entryId: number) => api.removeScopeEntry(scopeId, entryId),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: qk.scope(scopeId) })
      void queryClient.invalidateQueries({ queryKey: qk.scopes() })
    },
  })

  const updateScope = useMutation({
    mutationFn: (payload: ScopeUpdate) => api.updateScope(scopeId, payload),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: qk.scope(scopeId) })
      void queryClient.invalidateQueries({ queryKey: qk.scopes() })
    },
  })

  const removeScope = useMutation({
    mutationFn: () => api.deleteScope(scopeId),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: qk.scopes() })
      navigate('/scopes')
    },
  })

  function submitEntry(): void {
    const value = entryValue.trim()
    const ports = entryPorts.trim()
    if (value === '' || ports === '') {
      setEntryError('A value and at least one port are both required.')
      return
    }
    const payload: ScopeEntryCreate = { kind: entryKind, value, ports, protocol: entryProtocol }
    const note = entryNote.trim()
    if (note !== '') payload.note = note
    addEntry.mutate(payload)
  }

  function confirmRemove(entry: ScopeEntry): void {
    if (
      window.confirm(
        `Remove entry ${entry.value} (${entry.ports}/${entry.protocol})? Queued and running runs this scope authorizes are cancelled.`,
      )
    ) {
      removeEntry.mutate(entry.id)
    }
  }

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
          {isAdmin
            ? `this scope expired ${fmtRelative(s.expires_at)} (${fmtDateTime(s.expires_at)}) and authorizes nothing - renew it with the edit panel below. Targets that rely on it cannot be validated.`
            : `this scope expired ${fmtRelative(s.expires_at)} (${fmtDateTime(s.expires_at)}) and authorizes nothing until an administrator renews it. Targets that rely on it cannot be validated.`}
        </div>
      )}
      {expiry === 'soon' && (
        <div className="border border-incon/50 bg-incon/10 p-3 text-[13px] text-ink">
          <span className="font-mono text-[12px] font-semibold text-incon">EXPIRING - </span>
          {isAdmin
            ? `this scope expires in ${daysToExpiry} ${daysToExpiry === 1 ? 'day' : 'days'} (${fmtDateTime(s.expires_at)}) - extend it now with the edit panel below, or runs against its targets will be refused.`
            : `this scope expires in ${daysToExpiry} ${daysToExpiry === 1 ? 'day' : 'days'} (${fmtDateTime(s.expires_at)}). Renew it before then, or runs against its targets will be refused.`}
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
              {isAdmin && <Th align="right">Manage</Th>}
            </tr>
          </thead>
          <tbody>
            {s.entries.length === 0 ? (
              <TableEmptyRow colSpan={isAdmin ? 6 : 5}>
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
                  {isAdmin && (
                    <Td align="right">
                      <Button
                        size="sm"
                        variant="danger"
                        disabled={removeEntry.isPending}
                        onClick={() => confirmRemove(entry)}
                      >
                        Remove
                      </Button>
                    </Td>
                  )}
                </tr>
              ))
            )}
          </tbody>
        </TableWrap>
        {removeEntry.isError && (
          <div className="p-3">
            <ErrorNotice title="Remove entry failed" error={removeEntry.error} />
          </div>
        )}
      </Panel>

      {isAdmin && (
        <Panel title="Add an entry">
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <Field label="Kind">
              <Select
                value={entryKind}
                onChange={(e) => setEntryKind(e.target.value as ScopeEntryKind)}
              >
                <option value="cidr">cidr</option>
                <option value="host">host</option>
              </Select>
            </Field>
            <Field
              label="Value"
              required
              hint={entryKind === 'cidr' ? 'An address range, e.g. 10.0.0.0/24.' : 'An IP address or hostname.'}
            >
              <Input
                value={entryValue}
                onChange={(e) => setEntryValue(e.target.value)}
                placeholder={entryKind === 'cidr' ? '10.0.0.0/24' : 'app.internal.example'}
                maxLength={255}
              />
            </Field>
            <Field label="Ports" required hint="Explicit ports or ranges, e.g. 443 or 8000-8100,80.">
              <Input
                value={entryPorts}
                onChange={(e) => setEntryPorts(e.target.value)}
                placeholder="443"
                maxLength={255}
              />
            </Field>
            <Field label="Protocol">
              <Select value={entryProtocol} onChange={(e) => setEntryProtocol(e.target.value)}>
                <option value="tcp">tcp</option>
                <option value="udp">udp</option>
              </Select>
            </Field>
          </div>
          <div className="mt-3">
            <Field label="Note" hint="Why this address is authorized; kept with the audit record.">
              <Input
                value={entryNote}
                onChange={(e) => setEntryNote(e.target.value)}
                maxLength={255}
              />
            </Field>
          </div>
          <div className="mt-3 flex flex-wrap items-center justify-between gap-2">
            <span className="text-[12px] text-dim">
              Entries are policy-checked: loopback and other internal ranges need a lab scope, public
              ranges need an authorization reference, and broad ranges need "broad ranges allowed".
            </span>
            <Button variant="primary" disabled={addEntry.isPending} onClick={submitEntry}>
              {addEntry.isPending ? 'Adding...' : 'Add entry'}
            </Button>
          </div>
          {entryError !== null && (
            <div className="mt-3">
              <ErrorNotice error={new Error(entryError)} />
            </div>
          )}
          {addEntry.isError && (
            <div className="mt-3">
              <ErrorNotice title="Add entry failed" error={addEntry.error} />
            </div>
          )}
        </Panel>
      )}

      {isAdmin && (
        <EditScopeForm
          key={scopeFormKey(s)}
          scope={s}
          saving={updateScope.isPending}
          isError={updateScope.isError}
          error={updateScope.error}
          isSuccess={updateScope.isSuccess}
          onSubmit={(payload) => updateScope.mutate(payload)}
        />
      )}

      {isAdmin && (
        <Panel title="Delete scope">
          <p className="text-[13px] text-mute">
            Deleting this scope removes it and its entries, detaches every target that relies on
            it, and cancels the queued and running runs it authorizes. Targets keep existing; they
            just stop being authorized. The authorization record stays in the audit log.
          </p>
          <div className="mt-3 flex flex-wrap items-center justify-between gap-2">
            <span className="text-[12px] text-dim">
              Runs against the targets this scope covered will be refused until another scope
              authorizes them.
            </span>
            <Button
              variant="danger"
              disabled={removeScope.isPending}
              onClick={() => {
                if (
                  window.confirm(
                    `Delete scope "${s.name}"? Queued and running runs it authorizes are cancelled. This cannot be undone.`,
                  )
                ) {
                  removeScope.mutate()
                }
              }}
            >
              {removeScope.isPending ? 'Deleting...' : 'Delete scope'}
            </Button>
          </div>
          {removeScope.isError && (
            <div className="mt-3">
              <ErrorNotice title="Delete scope failed" error={removeScope.error} />
            </div>
          )}
        </Panel>
      )}
    </div>
  )
}

/**
 * Scopes carry no updated_at, so the stored field values stand in for one: the
 * form remounts, re-reading the saved values, whenever they change.
 */
function scopeFormKey(scope: Scope): string {
  return [
    scope.name,
    scope.description ?? '',
    scope.authorization_ref ?? '',
    scope.expires_at ?? '',
    scope.active,
    scope.allow_broad,
    scope.is_lab,
  ].join('|')
}

/** A Date as the local "YYYY-MM-DDTHH:mm" a datetime-local input expects. */
function localDateTimeValue(date: Date): string {
  const pad = (value: number): string => String(value).padStart(2, '0')
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`
}

function EditScopeForm({
  scope,
  saving,
  isError,
  error,
  isSuccess,
  onSubmit,
}: {
  scope: Scope
  saving: boolean
  isError: boolean
  error: unknown
  isSuccess: boolean
  onSubmit: (payload: ScopeUpdate) => void
}) {
  const [name, setName] = useState(scope.name)
  const [description, setDescription] = useState(scope.description ?? '')
  const [authorizationRef, setAuthorizationRef] = useState(scope.authorization_ref ?? '')
  const [expiresAt, setExpiresAt] = useState(() =>
    scope.expires_at === null ? '' : localDateTimeValue(new Date(scope.expires_at)),
  )
  const [allowBroad, setAllowBroad] = useState(scope.allow_broad)
  const [isLab, setIsLab] = useState(scope.is_lab)
  const [active, setActive] = useState(scope.active)
  const [localError, setLocalError] = useState<string | null>(null)

  function renewByDays(days: number): void {
    const next = new Date()
    next.setDate(next.getDate() + days)
    setExpiresAt(localDateTimeValue(next))
  }

  function renewByYear(): void {
    const next = new Date()
    next.setFullYear(next.getFullYear() + 1)
    setExpiresAt(localDateTimeValue(next))
  }

  function submit(): void {
    const trimmedName = name.trim()
    if (trimmedName === '') {
      setLocalError('Enter a name for this scope.')
      return
    }
    let isoExpiry: string | null = null
    if (expiresAt !== '') {
      const parsed = new Date(expiresAt)
      if (Number.isNaN(parsed.getTime())) {
        setLocalError('The expiry is not a valid date and time.')
        return
      }
      isoExpiry = parsed.toISOString()
    }
    setLocalError(null)
    onSubmit({
      name: trimmedName,
      description: description.trim() === '' ? null : description.trim(),
      authorization_ref: authorizationRef.trim() === '' ? null : authorizationRef.trim(),
      allow_broad: allowBroad,
      is_lab: isLab,
      active,
      expires_at: isoExpiry,
    })
  }

  return (
    <Panel title="Edit scope">
      <div className="grid gap-3 sm:grid-cols-2">
        <Field
          label="Name"
          required
          hint="How this authorization is referenced in the UI and the audit log."
        >
          <Input value={name} onChange={(e) => setName(e.target.value)} maxLength={160} />
        </Field>
        <Field
          label="Authorization reference"
          hint="The ticket or document that authorizes testing these addresses. Required before public ranges can be added; leave empty to remove it."
        >
          <Input
            value={authorizationRef}
            onChange={(e) => setAuthorizationRef(e.target.value)}
            placeholder="ENG-4821"
            maxLength={255}
          />
        </Field>
      </div>
      <div className="mt-3">
        <Field label="Description" hint="Leave empty to remove the description.">
          <Textarea rows={2} value={description} onChange={(e) => setDescription(e.target.value)} />
        </Field>
      </div>
      <div className="mt-3">
        <Field
          label="Expiry"
          hint="Optional. Once it passes, the scope authorizes nothing and runs against its targets are refused. Leave empty for no expiry."
        >
          <Input
            type="datetime-local"
            className="w-60"
            value={expiresAt}
            onChange={(e) => setExpiresAt(e.target.value)}
          />
        </Field>
        <div className="mt-2 flex flex-wrap items-center gap-2">
          <Button size="sm" onClick={() => renewByDays(30)}>
            +30 days
          </Button>
          <Button size="sm" onClick={() => renewByDays(90)}>
            +90 days
          </Button>
          <Button size="sm" onClick={renewByYear}>
            +1 year
          </Button>
          <Button size="sm" disabled={expiresAt === ''} onClick={() => setExpiresAt('')}>
            Clear expiry
          </Button>
          <span className="text-[12px] text-dim">
            Renewing counts from today; nothing is stored until you save.
          </span>
        </div>
      </div>
      <div className="mt-3 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
        <div>
          <Checkbox label="Active" checked={active} onChange={setActive} />
          <p className="mt-1 text-[12px] text-dim">
            An inactive scope authorizes nothing: runs against its targets are refused until it is
            re-activated.
          </p>
        </div>
        <div>
          <Checkbox label="Broad ranges allowed" checked={allowBroad} onChange={setAllowBroad} />
          <p className="mt-1 text-[12px] text-dim">
            Permits ranges such as 10.0.0.0/8 or 0.0.0.0/0. Runs stay limited to the entries
            below, but a broad range widens the blast radius of a mistake.
          </p>
        </div>
        <div>
          <Checkbox label="Lab scope" checked={isLab} onChange={setIsLab} />
          <p className="mt-1 text-[12px] text-dim">
            A lab scope may authorize loopback and other internal ranges that are otherwise
            refused.
          </p>
        </div>
      </div>
      <div className="mt-3 flex flex-wrap items-center justify-between gap-2">
        <span className="text-[12px] text-dim">
          Saving re-checks every entry against these flags: a change that invalidates an entry is
          refused, and queued and running runs this scope authorizes are cancelled.
        </span>
        <Button variant="primary" disabled={saving} onClick={submit}>
          {saving ? 'Saving...' : 'Save scope'}
        </Button>
      </div>
      {localError !== null && (
        <div className="mt-3">
          <ErrorNotice error={new Error(localError)} />
        </div>
      )}
      {isError && (
        <div className="mt-3">
          <ErrorNotice title="Save scope failed" error={error} />
        </div>
      )}
      {isSuccess && (
        <div className="mt-3 border border-pass/40 bg-pass/5 p-2 text-[12px] text-pass">
          Scope saved.
        </div>
      )}
    </Panel>
  )
}

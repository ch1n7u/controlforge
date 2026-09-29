import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { RunDialog } from '../components/RunDialog'
import {
  AssertionBadge,
  Badge,
  Button,
  Checkbox,
  EmptyState,
  ErrorNotice,
  Field,
  Input,
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
import { useAuth } from '../auth/context'
import { api, asPage, qk } from '../lib/api'
import { fmtDate, fmtDateTime, fmtRelative } from '../lib/format'
import { authorizationSuffix, expiryState } from '../lib/scopeGovernance'
import { severities } from '../lib/tones'
import type { RunSummary, Scope, Severity, Target, TargetUpdate } from '../lib/types'

export function TargetDetailPage() {
  const params = useParams()
  const targetId = Number(params.id)
  const queryClient = useQueryClient()
  const navigate = useNavigate()
  const { isWriter, isAdmin } = useAuth()
  const [runOpen, setRunOpen] = useState(false)
  const [attachScopeId, setAttachScopeId] = useState('')

  const target = useQuery({
    queryKey: qk.target(targetId),
    queryFn: () => api.target(targetId),
    staleTime: 60_000,
  })
  const scopes = useQuery({
    queryKey: qk.targetScopes(targetId),
    queryFn: () => api.targetScopes(targetId),
    staleTime: 30_000,
  })
  const runs = useQuery({
    queryKey: qk.runs({ target_id: targetId, limit: 25 }),
    queryFn: () => api.runs({ target_id: targetId, limit: 25 }).then((data) => asPage<RunSummary>(data)),
    staleTime: 10_000,
    retry: false,
  })
  const scopeCatalog = useQuery({
    queryKey: qk.scopes(),
    queryFn: () => api.scopes(),
    enabled: isAdmin,
    staleTime: 60_000,
  })

  const attach = useMutation({
    mutationFn: (scopeId: number) => api.linkTargetScope(targetId, scopeId),
    onSuccess: () => {
      setAttachScopeId('')
      void queryClient.invalidateQueries({ queryKey: qk.targetScopes(targetId) })
    },
  })

  const detach = useMutation({
    mutationFn: (scopeId: number) => api.unlinkTargetScope(targetId, scopeId),
    onSuccess: () => {
      // Detaching cancels the queued and running runs it was authorizing.
      void queryClient.invalidateQueries({ queryKey: qk.targetScopes(targetId) })
      void queryClient.invalidateQueries({ queryKey: qk.runs({ target_id: targetId }) })
    },
  })

  const updateTarget = useMutation({
    mutationFn: (payload: TargetUpdate) => api.updateTarget(targetId, payload),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: qk.target(targetId) })
      void queryClient.invalidateQueries({ queryKey: qk.targets() })
    },
  })

  const removeTarget = useMutation({
    mutationFn: () => api.deleteTarget(targetId),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: qk.targets() })
      navigate('/targets')
    },
  })

  function onDetach(scope: Scope): void {
    const confirmed = window.confirm(
      `Detach scope "${scope.name}"? Queued and running runs it was authorizing are cancelled.`,
    )
    if (confirmed) detach.mutate(scope.id)
  }

  if (target.isPending) return <Loading label="Loading target" />
  if (target.isError) return <ErrorNotice error={target.error} onRetry={() => void target.refetch()} />
  const t = target.data
  // A scope authorizes runs only while it is active and unexpired; an expired or
  // switched-off scope is attached, but covers nothing.
  const attachedScopes = scopes.data ?? []
  const scopesLoaded = !scopes.isPending && !scopes.isError
  const authorized = attachedScopes.some(
    (scope) => scope.active && expiryState(scope) !== 'expired',
  )
  const catalog = scopeCatalog.data ?? []
  const attachedIds = new Set(attachedScopes.map((scope) => scope.id))
  const attachableScopes = catalog.filter((scope) => !attachedIds.has(scope.id))

  return (
    <div className="space-y-4">
      <PageHeader
        title={t.name}
        subtitle={
          <span className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-[13px] text-ink">
              {t.host}
              {t.port ? `:${t.port}` : ''}
              {t.path}
            </span>
            <Badge tone="mute">{t.target_type}</Badge>
            <SeverityBadge severity={t.criticality} />
            {t.enabled ? <Badge tone="pass">enabled</Badge> : <Badge tone="na">disabled</Badge>}
          </span>
        }
        actions={
          isWriter ? (
            <Button
              variant="primary"
              onClick={() => setRunOpen(true)}
              disabled={!authorized}
              title={authorized ? undefined : 'No active, unexpired scope covers this target'}
            >
              Run a test against this target
            </Button>
          ) : null
        }
      />

      {scopesLoaded && !authorized && (
        <div className="border border-fail/40 bg-fail/5 p-3 text-[13px] text-ink">
          <span className="font-mono text-[12px] font-semibold text-fail">NOT AUTHORIZED - </span>
          {attachedScopes.length === 0
            ? 'no scope covers this target, so no run can reach it. Ask an administrator to attach it to a scope; runs stay disabled until one is attached.'
            : 'every scope attached to this target is expired or inactive, so no run can reach it. Ask an administrator to renew the scope or attach a current one.'}
        </div>
      )}

      <div className="grid gap-3 lg:grid-cols-3">
        <Panel title="Target" className="lg:col-span-2">
          <KeyValue
            items={[
              ['Host', <span key="host" className="font-mono">{t.host}</span>],
              ['Port', <span key="port" className="font-mono">{t.port || 'none'}</span>],
              ['Protocol', <span key="proto" className="font-mono">{t.protocol}</span>],
              ['Path', <span key="path" className="font-mono">{t.path || '/'}</span>],
              ['Owner', t.owner ?? '-'],
              ['Criticality', <SeverityBadge key="crit" severity={t.criticality} />],
              ['Created', fmtDateTime(t.created_at)],
              ['Tags', t.tags.length > 0 ? t.tags.join(', ') : '-'],
            ]}
          />
          {t.notes && (
            <div className="mt-3 border-t border-edge pt-3">
              <div className="text-[11px] tracking-wide text-dim uppercase">Notes</div>
              <p className="mt-1 text-[13px] whitespace-pre-wrap text-ink/90">{t.notes}</p>
            </div>
          )}
        </Panel>

        <Panel title={`Scopes attached (${attachedScopes.length})`}>
          {scopes.isPending && <Loading label="Loading scopes" />}
          {scopes.isError && <ErrorNotice error={scopes.error} onRetry={() => void scopes.refetch()} />}
          {scopes.data && (
            <>
              {attachedScopes.length === 0 ? (
                <EmptyState
                  title="No scope authorizes this target"
                  hint={
                    isAdmin
                      ? 'Attach an existing scope below to authorize runs against this target.'
                      : 'Ask an administrator to attach it to a scope; runs stay disabled until one is attached.'
                  }
                />
              ) : (
                <ul className="space-y-2">
                  {attachedScopes.map((scope) => {
                    const expired = expiryState(scope) === 'expired'
                    return (
                      <li key={scope.id} className="border border-edge bg-panel2 p-2">
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <Link to={`/scopes/${scope.id}`} className="text-[13px] text-accent hover:underline">
                            {scope.name}
                          </Link>
                          <span className="flex items-center gap-1">
                            {!scope.active ? (
                              <Badge tone="na" title="An inactive scope authorizes nothing">
                                inactive
                              </Badge>
                            ) : expired ? (
                              <Badge tone="fail" title={`Expired ${fmtDate(scope.expires_at)}`}>
                                expired
                              </Badge>
                            ) : (
                              <Badge tone="pass">active</Badge>
                            )}
                            {scope.allow_broad && (
                              <Badge tone="incon" title="This scope allows broad address ranges - review it before running">
                                broad
                              </Badge>
                            )}
                            {isAdmin && (
                              <Button
                                size="sm"
                                variant="danger"
                                disabled={detach.isPending}
                                onClick={() => onDetach(scope)}
                              >
                                Detach
                              </Button>
                            )}
                          </span>
                        </div>
                        <div className="mt-1 font-mono text-[11px] text-dim">
                          {scope.entries.length} entr{scope.entries.length === 1 ? 'y' : 'ies'}
                          {scope.expires_at ? ` · expires ${fmtDate(scope.expires_at)}` : ' · no expiry'}
                        </div>
                      </li>
                    )
                  })}
                </ul>
              )}

              {detach.isError && (
                <div className="mt-3">
                  <ErrorNotice title="Detach failed" error={detach.error} />
                </div>
              )}

              {isAdmin && (
                <div className="mt-3 border-t border-edge pt-3">
                  <div className="mb-1 text-[11px] tracking-wide text-mute uppercase">
                    Attach a scope
                  </div>
                  {scopeCatalog.isPending ? (
                    <div className="text-[12px] text-dim">Loading scopes...</div>
                  ) : scopeCatalog.isError ? (
                    <ErrorNotice error={scopeCatalog.error} onRetry={() => void scopeCatalog.refetch()} />
                  ) : attachableScopes.length === 0 ? (
                    <p className="text-[12px] text-dim">
                      {catalog.length === 0
                        ? 'No scopes exist yet. A scope defines what a run is allowed to reach; create one from the Scopes page.'
                        : 'Every scope is already attached to this target.'}
                    </p>
                  ) : (
                    <div className="flex items-center gap-2">
                      <Select
                        value={attachScopeId}
                        onChange={(e) => setAttachScopeId(e.target.value)}
                        className="flex-1"
                      >
                        <option value="">Select a scope...</option>
                        {attachableScopes.map((scope) => (
                          <option key={scope.id} value={scope.id}>
                            {scope.name}
                            {authorizationSuffix(scope)}
                          </option>
                        ))}
                      </Select>
                      <Button
                        size="sm"
                        variant="primary"
                        disabled={attachScopeId === '' || attach.isPending}
                        onClick={() => attach.mutate(Number(attachScopeId))}
                      >
                        {attach.isPending ? 'Attaching...' : 'Attach'}
                      </Button>
                    </div>
                  )}
                  {attach.isError && (
                    <div className="mt-2">
                      <ErrorNotice title="Attach failed" error={attach.error} />
                    </div>
                  )}
                </div>
              )}

              <div className="mt-3 border-t border-edge pt-2 text-[12px] text-dim">
                A scope authorizes a run only while it is active and unexpired. The worker's
                firewall allow-list converges within about 15 seconds of a change.
              </div>
            </>
          )}
        </Panel>
      </div>

      <Panel
        title="Recent runs"
        actions={
          <Link to={`/runs?target_id=${t.id}`} className="text-[11px] text-accent hover:underline">
            All runs
          </Link>
        }
      >
        {runs.isPending && <Loading label="Loading runs" />}
        {runs.isError && <ErrorNotice error={runs.error} onRetry={() => void runs.refetch()} />}
        {runs.data && (
          <TableWrap>
            <thead>
              <tr>
                <Th>Run</Th>
                <Th>Test</Th>
                <Th>Engine</Th>
                <Th>Status</Th>
                <Th>Assertion</Th>
                <Th>Queued</Th>
                <Th>Duration</Th>
              </tr>
            </thead>
            <tbody>
              {runs.data.items.length === 0 ? (
                <TableEmptyRow colSpan={7}>
                  No runs have been recorded against this target yet.
                </TableEmptyRow>
              ) : (
                runs.data.items.map((run) => (
                  <tr key={run.id} className="hover:bg-raise/50">
                    <Td mono>
                      <Link to={`/runs/${run.id}`} className="text-accent hover:underline">
                        #{run.id}
                      </Link>
                    </Td>
                    <Td>
                      <span className="font-mono text-[12px] text-mute">{run.test_key}</span>
                    </Td>
                    <Td mono className="text-mute">
                      {run.engine_id}
                    </Td>
                    <Td>
                      <RunStatusBadge status={run.status} />
                    </Td>
                    <Td>
                      <AssertionBadge status={run.assertion_status} />
                    </Td>
                    <Td>{fmtRelative(run.queued_at)}</Td>
                    <Td mono>{run.duration_seconds === null ? '-' : `${run.duration_seconds.toFixed(1)}s`}</Td>
                  </tr>
                ))
              )}
            </tbody>
          </TableWrap>
        )}
      </Panel>

      {isWriter && (
        <EditTargetForm
          key={targetFormKey(t)}
          target={t}
          saving={updateTarget.isPending}
          isError={updateTarget.isError}
          error={updateTarget.error}
          isSuccess={updateTarget.isSuccess}
          onSubmit={(payload) => updateTarget.mutate(payload)}
        />
      )}

      {isAdmin && (
        <Panel title="Delete target">
          <p className="text-[13px] text-mute">
            Deleting this target removes it and the scope links that authorize runs against it. A
            target with any recorded runs or findings cannot be deleted - those records reference
            it and are kept. The deletion is recorded in the audit log.
          </p>
          <div className="mt-3 flex flex-wrap items-center justify-between gap-2">
            <span className="text-[12px] text-dim">
              If this target is no longer maintained, disable it instead: runs against it are
              refused and its history stays readable.
            </span>
            <Button
              variant="danger"
              disabled={removeTarget.isPending}
              onClick={() => {
                if (
                  window.confirm(
                    `Delete target "${t.name}"? Its scope links are removed with it, and a target with recorded runs or findings cannot be deleted. This cannot be undone.`,
                  )
                ) {
                  removeTarget.mutate()
                }
              }}
            >
              {removeTarget.isPending ? 'Deleting...' : 'Delete target'}
            </Button>
          </div>
          {removeTarget.isError && (
            <div className="mt-3">
              <ErrorNotice title="Delete target failed" error={removeTarget.error} />
            </div>
          )}
        </Panel>
      )}

      {runOpen && <RunDialog onClose={() => setRunOpen(false)} fixedTargetId={t.id} />}
    </div>
  )
}

/**
 * The target payload carries no updated_at, so the stored field values stand in
 * for one: the form remounts, re-reading the saved values, whenever they change.
 */
function targetFormKey(target: Target): string {
  return [
    target.name,
    target.host,
    String(target.port),
    target.protocol,
    target.path,
    target.criticality,
    target.tags.join(','),
    target.owner ?? '',
    target.notes ?? '',
    String(target.enabled),
  ].join('|')
}

function EditTargetForm({
  target,
  saving,
  isError,
  error,
  isSuccess,
  onSubmit,
}: {
  target: Target
  saving: boolean
  isError: boolean
  error: unknown
  isSuccess: boolean
  onSubmit: (payload: TargetUpdate) => void
}) {
  const [name, setName] = useState(target.name)
  const [host, setHost] = useState(target.host)
  const [port, setPort] = useState(target.port === 0 ? '' : String(target.port))
  const [protocol, setProtocol] = useState(target.protocol)
  const [path, setPath] = useState(target.path)
  const [criticality, setCriticality] = useState<Severity>(target.criticality)
  const [owner, setOwner] = useState(target.owner ?? '')
  const [tagText, setTagText] = useState(target.tags.join(', '))
  const [notes, setNotes] = useState(target.notes ?? '')
  const [enabled, setEnabled] = useState(target.enabled)
  const [localError, setLocalError] = useState<string | null>(null)

  function submit(): void {
    const trimmedName = name.trim()
    if (trimmedName === '') {
      setLocalError('Enter a name for this target.')
      return
    }
    const trimmedHost = host.trim()
    if (trimmedHost === '') {
      setLocalError('Enter the host name or IP address this target is reached at.')
      return
    }
    const portNumber = port.trim() === '' ? 0 : Number(port.trim())
    if (!Number.isInteger(portNumber) || portNumber < 0 || portNumber > 65535) {
      setLocalError(
        'Port must be a whole number between 0 and 65535, or empty for a host-level target.',
      )
      return
    }
    setLocalError(null)
    onSubmit({
      name: trimmedName,
      host: trimmedHost,
      port: portNumber,
      protocol,
      path: path.trim(),
      tags: splitList(tagText),
      criticality,
      owner: owner.trim() === '' ? null : owner.trim(),
      notes: notes.trim() === '' ? null : notes.trim(),
      enabled,
    })
  }

  return (
    <Panel title="Edit target">
      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="Name" required hint="How this target is named in runs, findings and reports.">
          <Input value={name} onChange={(e) => setName(e.target.value)} maxLength={160} />
        </Field>
        <Field
          label="Host"
          required
          hint="Hostname or IP address. It is resolved and pinned when a run starts, so a name cannot re-resolve to something else mid-run."
        >
          <Input value={host} onChange={(e) => setHost(e.target.value)} maxLength={255} />
        </Field>
      </div>
      <div className="mt-3 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
        <Field label="Port" hint="Empty or 0 for a host-level target.">
          <Input
            type="number"
            min={0}
            max={65535}
            value={port}
            onChange={(e) => setPort(e.target.value)}
            placeholder="8081"
          />
        </Field>
        <Field label="Protocol">
          <Select value={protocol} onChange={(e) => setProtocol(e.target.value)}>
            {protocol !== 'tcp' && protocol !== 'udp' && (
              <option value={protocol}>{protocol}</option>
            )}
            <option value="tcp">tcp</option>
            <option value="udp">udp</option>
          </Select>
        </Field>
        <Field label="Type" hint="Fixed when the target is created; it cannot be changed.">
          <span className="block py-1 font-mono text-[13px] text-mute">{target.target_type}</span>
        </Field>
      </div>
      <div className="mt-3">
        <Field label="Path" hint="For web apps and APIs; leave empty for a bare host.">
          <Input
            value={path}
            onChange={(e) => setPath(e.target.value)}
            placeholder="/login"
            maxLength={255}
          />
        </Field>
      </div>
      <div className="mt-3 grid gap-3 sm:grid-cols-2">
        <Field label="Criticality">
          <Select value={criticality} onChange={(e) => setCriticality(e.target.value as Severity)}>
            {severities.map((level) => (
              <option key={level} value={level}>
                {level}
              </option>
            ))}
          </Select>
        </Field>
        <Field label="Owner" hint="Who is responsible for this target. Leave empty to clear it.">
          <Input value={owner} onChange={(e) => setOwner(e.target.value)} maxLength={160} />
        </Field>
      </div>
      <div className="mt-3">
        <Field label="Tags" hint="Comma-separated; tests can select targets by tag.">
          <Input
            value={tagText}
            onChange={(e) => setTagText(e.target.value)}
            placeholder="lab, web"
          />
        </Field>
      </div>
      <div className="mt-3">
        <Field label="Notes" hint="Leave empty to clear the notes.">
          <Textarea rows={3} value={notes} onChange={(e) => setNotes(e.target.value)} />
        </Field>
      </div>
      <div className="mt-3">
        <Checkbox label="Enabled" checked={enabled} onChange={setEnabled} />
        <p className="mt-1 text-[12px] text-dim">
          Starting a run against a disabled target is refused, and a run queued before it was
          disabled is cancelled when the worker picks it up.
        </p>
      </div>
      <div className="mt-3 flex flex-wrap items-center justify-between gap-2">
        <span className="text-[12px] text-dim">
          Changing the host or port changes where future runs connect; the scope is re-checked when
          a run is picked up, so runs against a target moved outside its scopes are refused.
        </span>
        <Button variant="primary" disabled={saving} onClick={submit}>
          {saving ? 'Saving...' : 'Save target'}
        </Button>
      </div>
      {localError !== null && (
        <div className="mt-3">
          <ErrorNotice error={new Error(localError)} />
        </div>
      )}
      {isError && (
        <div className="mt-3">
          <ErrorNotice title="Save target failed" error={error} />
        </div>
      )}
      {isSuccess && (
        <div className="mt-3 border border-pass/40 bg-pass/5 p-2 text-[12px] text-pass">
          Target saved.
        </div>
      )}
    </Panel>
  )
}

function splitList(text: string): string[] {
  return text
    .split(',')
    .map((part) => part.trim())
    .filter((part) => part !== '')
}

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Button,
  Checkbox,
  ErrorNotice,
  Field,
  Input,
  LinkButton,
  PageHeader,
  Panel,
  Select,
  Textarea,
} from '../components/ui'
import { useAuth } from '../auth/context'
import { api, qk } from '../lib/api'
import { authorizationSuffix } from '../lib/scopeGovernance'
import { severities, targetTypes } from '../lib/tones'
import type { Severity, TargetCreate, TargetType } from '../lib/types'

export function NewTargetPage() {
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const { isAdmin } = useAuth()

  const scopes = useQuery({
    queryKey: qk.scopes(),
    queryFn: () => api.scopes(),
    enabled: isAdmin,
    staleTime: 60_000,
  })

  const [name, setName] = useState('')
  const [host, setHost] = useState('')
  const [port, setPort] = useState('')
  const [protocol, setProtocol] = useState('tcp')
  const [path, setPath] = useState('')
  const [targetType, setTargetType] = useState<TargetType>('host')
  const [criticality, setCriticality] = useState<Severity>('medium')
  const [owner, setOwner] = useState('')
  const [tagText, setTagText] = useState('')
  const [notes, setNotes] = useState('')
  const [enabled, setEnabled] = useState(true)
  const [scopeId, setScopeId] = useState('')
  const [localError, setLocalError] = useState<string | null>(null)
  // Set when the target was created but attaching the chosen scope failed. The
  // target exists, so the form must stop offering to create it a second time.
  const [linkFailure, setLinkFailure] = useState<{ id: number; error: unknown } | null>(null)

  const create = useMutation({
    mutationFn: async (payload: TargetCreate) => {
      const target = await api.createTarget(payload)
      if (scopeId !== '') {
        try {
          await api.linkTargetScope(target.id, Number(scopeId))
        } catch (error) {
          return { target, linkError: error }
        }
      }
      return { target, linkError: null }
    },
    onSuccess: (result) => {
      void queryClient.invalidateQueries({ queryKey: qk.targets() })
      if (result.linkError === null) {
        void queryClient.invalidateQueries({ queryKey: qk.targetScopes(result.target.id) })
        navigate(`/targets/${result.target.id}`)
      } else {
        setLinkFailure({ id: result.target.id, error: result.linkError })
      }
    },
  })

  function submit(): void {
    if (name.trim() === '') {
      setLocalError('Enter a name for this target.')
      return
    }
    if (host.trim() === '') {
      setLocalError('Enter the host name or IP address this target is reached at.')
      return
    }
    const portNumber = port.trim() === '' ? 0 : Number(port.trim())
    if (!Number.isInteger(portNumber) || portNumber < 0 || portNumber > 65535) {
      setLocalError('Port must be a whole number between 0 and 65535, or empty for a host-level target.')
      return
    }
    setLocalError(null)
    setLinkFailure(null)
    const payload: TargetCreate = {
      name: name.trim(),
      host: host.trim(),
      target_type: targetType,
      port: portNumber,
      protocol: protocol.trim(),
      path: path.trim(),
      tags: splitList(tagText),
      criticality,
      enabled,
    }
    if (owner.trim() !== '') payload.owner = owner.trim()
    if (notes.trim() !== '') payload.notes = notes.trim()
    create.mutate(payload)
  }

  const scopeOptions = scopes.data ?? []

  return (
    <div className="space-y-4">
      <PageHeader
        title="New target"
        subtitle="A host, web app or service under validation. A target can only be run while an active, unexpired scope authorizes its address and port."
      />

      <div className="grid gap-3 lg:grid-cols-3">
        <Panel title="Endpoint">
          <div className="space-y-3">
            <Field label="Name" required hint="How this target is named in runs, findings and reports.">
              <Input
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="Lab nginx (weak headers)"
                maxLength={160}
              />
            </Field>
            <Field
              label="Host"
              required
              hint="Hostname or IP address. It is resolved when a run is queued and pinned, so a name cannot re-resolve to something else mid-run."
            >
              <Input
                value={host}
                onChange={(e) => setHost(e.target.value)}
                placeholder="127.0.0.1"
                maxLength={255}
              />
            </Field>
            <div className="grid grid-cols-2 gap-3">
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
                  <option value="tcp">tcp</option>
                  <option value="udp">udp</option>
                </Select>
              </Field>
            </div>
            <Field label="Path" hint="For web apps and APIs; leave empty for a bare host.">
              <Input
                value={path}
                onChange={(e) => setPath(e.target.value)}
                placeholder="/login"
                maxLength={255}
              />
            </Field>
            <Field label="Type">
              <Select
                value={targetType}
                onChange={(e) => setTargetType(e.target.value as TargetType)}
              >
                {targetTypes.map((type) => (
                  <option key={type} value={type}>
                    {type}
                  </option>
                ))}
              </Select>
            </Field>
          </div>
        </Panel>

        <Panel title="Classification">
          <div className="space-y-3">
            <Field label="Criticality">
              <Select
                value={criticality}
                onChange={(e) => setCriticality(e.target.value as Severity)}
              >
                {severities.map((level) => (
                  <option key={level} value={level}>
                    {level}
                  </option>
                ))}
              </Select>
            </Field>
            <Field label="Owner" hint="Who is responsible for this target.">
              <Input value={owner} onChange={(e) => setOwner(e.target.value)} maxLength={160} />
            </Field>
            <Field label="Tags" hint="Comma-separated; tests can select targets by tag.">
              <Input
                value={tagText}
                onChange={(e) => setTagText(e.target.value)}
                placeholder="lab, web"
              />
            </Field>
            <Field label="Notes">
              <Textarea rows={3} value={notes} onChange={(e) => setNotes(e.target.value)} />
            </Field>
            <Checkbox label="Enabled" checked={enabled} onChange={setEnabled} />
          </div>
        </Panel>

        <Panel title="Authorization">
          {!isAdmin ? (
            <p className="text-[12px] text-dim">
              Attaching a scope is an administrator action. This target will be registered without
              one; runs stay disabled until an administrator attaches a scope to it from the
              target's page.
            </p>
          ) : scopes.isPending ? (
            <div className="text-[12px] text-dim">Loading scopes...</div>
          ) : scopes.isError ? (
            <ErrorNotice error={scopes.error} onRetry={() => void scopes.refetch()} />
          ) : scopeOptions.length === 0 ? (
            <p className="text-[12px] text-dim">
              No scopes exist yet. A scope defines what a run is allowed to reach; create one from
              the Scopes page before this target can be validated.
            </p>
          ) : (
            <div className="space-y-3">
              <p className="text-[12px] text-dim">
                Attach an existing scope to authorize runs against this target. Without one the
                target is registered but cannot be reached.
              </p>
              <Field label="Scope" hint="Only an active, unexpired scope authorizes a run.">
                <Select value={scopeId} onChange={(e) => setScopeId(e.target.value)}>
                  <option value="">Leave unauthorized for now</option>
                  {scopeOptions.map((scope) => (
                    <option key={scope.id} value={scope.id}>
                      {scope.name}
                      {authorizationSuffix(scope)}
                    </option>
                  ))}
                </Select>
              </Field>
              {scopeId !== '' && (
                <p className="text-[11px] text-dim">
                  The worker's firewall allow-list converges within about 15 seconds, so a run
                  started immediately may not reach the target yet.
                </p>
              )}
            </div>
          )}
        </Panel>
      </div>

      {localError && <ErrorNotice error={new Error(localError)} />}
      {create.isError && <ErrorNotice error={create.error} />}
      {linkFailure !== null && (
        <ErrorNotice title="Target created, but the scope was not attached" error={linkFailure.error} />
      )}

      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="text-[12px] text-dim">
          {linkFailure !== null
            ? `Target #${linkFailure.id} exists; attach a scope from its page.`
            : 'Registering a target is not authorization: runs stay disabled until a scope is attached.'}
        </span>
        <div className="flex gap-2">
          <Button onClick={() => navigate('/targets')}>Cancel</Button>
          {linkFailure === null ? (
            <Button variant="primary" disabled={create.isPending} onClick={submit}>
              {create.isPending ? 'Creating...' : 'Create target'}
            </Button>
          ) : (
            <LinkButton to={`/targets/${linkFailure.id}`} variant="primary">
              Open the target
            </LinkButton>
          )}
        </div>
      </div>
    </div>
  )
}

function splitList(text: string): string[] {
  return text
    .split(',')
    .map((part) => part.trim())
    .filter((part) => part !== '')
}

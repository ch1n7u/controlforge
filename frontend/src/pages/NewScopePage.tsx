import { useMutation, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Button,
  Checkbox,
  ErrorNotice,
  Field,
  Input,
  PageHeader,
  Panel,
  Select,
  Textarea,
} from '../components/ui'
import { useAuth } from '../auth/context'
import { api, qk } from '../lib/api'
import type { ScopeCreate, ScopeEntryCreate, ScopeEntryKind } from '../lib/types'

interface EntryRow {
  key: string
  kind: ScopeEntryKind
  value: string
  ports: string
  protocol: string
  note: string
}

let entryKeyCounter = 0

function blankEntry(): EntryRow {
  entryKeyCounter += 1
  return {
    key: `entry-${entryKeyCounter}`,
    kind: 'cidr',
    value: '',
    ports: '',
    protocol: 'tcp',
    note: '',
  }
}

export function NewScopePage() {
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const { isAdmin } = useAuth()

  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [authorizationRef, setAuthorizationRef] = useState('')
  const [expiresAt, setExpiresAt] = useState('')
  const [allowBroad, setAllowBroad] = useState(false)
  const [isLab, setIsLab] = useState(false)
  const [rows, setRows] = useState<EntryRow[]>(() => [blankEntry()])
  const [localError, setLocalError] = useState<string | null>(null)

  const create = useMutation({
    mutationFn: (payload: ScopeCreate) => api.createScope(payload),
    onSuccess: (scope) => {
      void queryClient.invalidateQueries({ queryKey: qk.scopes() })
      navigate(`/scopes/${scope.id}`)
    },
  })

  function updateRow(key: string, patch: Partial<EntryRow>): void {
    setRows((current) => current.map((row) => (row.key === key ? { ...row, ...patch } : row)))
  }

  function submit(): void {
    if (name.trim() === '') {
      setLocalError('Enter a name for this scope.')
      return
    }
    const entries: ScopeEntryCreate[] = []
    for (let index = 0; index < rows.length; index += 1) {
      const row = rows[index]
      const value = row.value.trim()
      const ports = row.ports.trim()
      if (value === '' && ports === '') continue
      if (value === '' || ports === '') {
        setLocalError(`Entry ${index + 1}: a value and at least one port are both required, or leave the row empty.`)
        return
      }
      const entry: ScopeEntryCreate = { kind: row.kind, value, ports, protocol: row.protocol }
      const note = row.note.trim()
      if (note !== '') entry.note = note
      entries.push(entry)
    }
    let isoExpiry: string | undefined
    if (expiresAt !== '') {
      const parsed = new Date(expiresAt)
      if (Number.isNaN(parsed.getTime())) {
        setLocalError('The expiry is not a valid date and time.')
        return
      }
      isoExpiry = parsed.toISOString()
    }
    setLocalError(null)
    const payload: ScopeCreate = {
      name: name.trim(),
      allow_broad: allowBroad,
      is_lab: isLab,
      entries,
    }
    if (description.trim() !== '') payload.description = description.trim()
    if (authorizationRef.trim() !== '') payload.authorization_ref = authorizationRef.trim()
    if (isoExpiry !== undefined) payload.expires_at = isoExpiry
    create.mutate(payload)
  }

  if (!isAdmin) {
    return (
      <div className="space-y-4">
        <PageHeader
          title="New scope"
          subtitle="The written authorization a run is checked against: address ranges with ports, an expiry and the person who approved it."
        />
        <Panel title="Administrator action">
          <p className="text-[13px] text-mute">
            Creating a scope is an administrator action: a scope is the written authorization every
            run is checked against, so only an administrator can define one. Ask an administrator to
            create it and attach the targets it covers.
          </p>
        </Panel>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      <PageHeader
        title="New scope"
        subtitle="The written authorization a run is checked against: address ranges with ports, an expiry and the person who approved it."
      />

      <div className="grid gap-3 lg:grid-cols-3">
        <Panel title="Scope" className="lg:col-span-2">
          <div className="space-y-3">
            <Field label="Name" required hint="How this authorization is referenced in the UI and the audit log.">
              <Input
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="Acme internal assessment 2026-Q3"
                maxLength={160}
              />
            </Field>
            <Field label="Description">
              <Textarea rows={2} value={description} onChange={(e) => setDescription(e.target.value)} />
            </Field>
            <Field
              label="Authorization reference"
              hint="The ticket or document that authorizes testing these addresses. Required before public ranges can be added."
            >
              <Input
                value={authorizationRef}
                onChange={(e) => setAuthorizationRef(e.target.value)}
                placeholder="ENG-4821"
                maxLength={255}
              />
            </Field>
            <Field
              label="Expiry"
              hint="Optional. Once it passes, the scope authorizes nothing and runs against its targets are refused."
            >
              <Input
                type="datetime-local"
                value={expiresAt}
                onChange={(e) => setExpiresAt(e.target.value)}
              />
            </Field>
          </div>
        </Panel>

        <Panel title="Policy">
          <div className="space-y-4">
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
            <p className="border-t border-edge pt-3 text-[12px] text-dim">
              An administrator approves a scope by creating it; the record shows who did.
            </p>
          </div>
        </Panel>
      </div>

      <Panel title="Authorized entries">
        <p className="mb-3 text-[12px] text-dim">
          A scope authorizes; it does not discover. Runs reach only the addresses, ports and
          protocols listed here.
        </p>
        <div className="space-y-4">
          {rows.map((row, index) => (
            <div key={row.key} className="border border-edge p-3">
              <div className="mb-2 flex items-center justify-between">
                <span className="text-[11px] tracking-wide text-mute uppercase">
                  Entry {index + 1}
                </span>
                <Button size="sm" variant="danger" onClick={() => setRows((current) => current.filter((r) => r.key !== row.key))}>
                  Remove
                </Button>
              </div>
              <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
                <Field label="Kind">
                  <Select
                    value={row.kind}
                    onChange={(e) => updateRow(row.key, { kind: e.target.value as ScopeEntryKind })}
                  >
                    <option value="cidr">cidr</option>
                    <option value="host">host</option>
                  </Select>
                </Field>
                <Field
                  label="Value"
                  required
                  hint={row.kind === 'cidr' ? 'An address range, e.g. 10.0.0.0/24.' : 'An IP address or hostname.'}
                >
                  <Input
                    value={row.value}
                    onChange={(e) => updateRow(row.key, { value: e.target.value })}
                    placeholder={row.kind === 'cidr' ? '10.0.0.0/24' : 'app.internal.example'}
                    maxLength={255}
                  />
                </Field>
                <Field label="Ports" required hint="Explicit ports or ranges, e.g. 443 or 8000-8100,80.">
                  <Input
                    value={row.ports}
                    onChange={(e) => updateRow(row.key, { ports: e.target.value })}
                    placeholder="443"
                    maxLength={255}
                  />
                </Field>
                <Field label="Protocol">
                  <Select
                    value={row.protocol}
                    onChange={(e) => updateRow(row.key, { protocol: e.target.value })}
                  >
                    <option value="tcp">tcp</option>
                    <option value="udp">udp</option>
                  </Select>
                </Field>
              </div>
              <div className="mt-3">
                <Field label="Note" hint="Why this address is authorized; kept with the audit record.">
                  <Input
                    value={row.note}
                    onChange={(e) => updateRow(row.key, { note: e.target.value })}
                    maxLength={255}
                  />
                </Field>
              </div>
            </div>
          ))}
        </div>
        <div className="mt-3">
          <Button onClick={() => setRows((current) => [...current, blankEntry()])}>
            Add another entry
          </Button>
        </div>
      </Panel>

      {localError !== null && <ErrorNotice error={new Error(localError)} />}
      {create.isError && <ErrorNotice error={create.error} />}

      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="text-[12px] text-dim">
          Creating a scope is the approval: it is recorded with your name, and every entry is
          policy-checked before anything is written.
        </span>
        <div className="flex gap-2">
          <Button onClick={() => navigate('/scopes')}>Cancel</Button>
          <Button variant="primary" disabled={create.isPending} onClick={submit}>
            {create.isPending ? 'Creating...' : 'Create scope'}
          </Button>
        </div>
      </div>
    </div>
  )
}

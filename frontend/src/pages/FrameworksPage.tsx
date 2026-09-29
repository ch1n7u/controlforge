import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { useAuth } from '../auth/context'
import {
  Badge,
  Button,
  Checkbox,
  ErrorNotice,
  Field,
  Input,
  Loading,
  PageHeader,
  Panel,
  TableEmptyRow,
  TableWrap,
  Td,
  Textarea,
  Th,
} from '../components/ui'
import { api, qk } from '../lib/api'
import type { Framework, FrameworkCreate, FrameworkUpdate } from '../lib/types'

const keyPattern = /^[A-Za-z0-9._-]{1,64}$/

const keyHint =
  '1-64 characters: letters, digits, dot, underscore or dash. It cannot be changed later.'

function emptyToNull(value: string): string | null {
  const trimmed = value.trim()
  return trimmed === '' ? null : trimmed
}

export function FrameworksPage() {
  const { isWriter, isAdmin } = useAuth()
  const queryClient = useQueryClient()

  const frameworks = useQuery({
    queryKey: qk.frameworks,
    queryFn: api.frameworks,
    staleTime: 60_000,
  })

  const [newKey, setNewKey] = useState('')
  const [newName, setNewName] = useState('')
  const [newVersion, setNewVersion] = useState('')
  const [newSource, setNewSource] = useState('')
  const [newDescription, setNewDescription] = useState('')
  const [newEnabled, setNewEnabled] = useState(true)
  const [createError, setCreateError] = useState<string | null>(null)

  const [editId, setEditId] = useState<number | null>(null)
  const [editName, setEditName] = useState('')
  const [editVersion, setEditVersion] = useState('')
  const [editSource, setEditSource] = useState('')
  const [editDescription, setEditDescription] = useState('')
  const [editEnabled, setEditEnabled] = useState(true)
  const [editError, setEditError] = useState<string | null>(null)

  const create = useMutation({
    mutationFn: (payload: FrameworkCreate) => api.createFramework(payload),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: qk.frameworks })
      setNewKey('')
      setNewName('')
      setNewVersion('')
      setNewSource('')
      setNewDescription('')
      setNewEnabled(true)
      setCreateError(null)
    },
  })

  const update = useMutation({
    mutationFn: (vars: { id: number; payload: FrameworkUpdate }) =>
      api.updateFramework(vars.id, vars.payload),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: qk.frameworks })
      closeEditor()
    },
  })

  const remove = useMutation({
    mutationFn: (id: number) => api.deleteFramework(id),
    onSuccess: (_data, id) => {
      void queryClient.invalidateQueries({ queryKey: qk.frameworks })
      // The delete cascades away this framework's mappings on controls.
      void queryClient.invalidateQueries({ queryKey: ['controls'] })
      if (editId === id) closeEditor()
    },
  })

  const rows = frameworks.data ?? []
  const editing = rows.find((f) => f.id === editId) ?? null
  const originalName = editing?.name ?? ''
  const dirty =
    editing !== null &&
    (editName.trim() !== originalName.trim() ||
      editVersion.trim() !== (editing.version ?? '').trim() ||
      editSource.trim() !== (editing.source ?? '').trim() ||
      editDescription.trim() !== (editing.description ?? '').trim() ||
      editEnabled !== editing.enabled)

  function startEdit(framework: Framework): void {
    update.reset()
    setEditId(framework.id)
    setEditName(framework.name)
    setEditVersion(framework.version ?? '')
    setEditSource(framework.source ?? '')
    setEditDescription(framework.description ?? '')
    setEditEnabled(framework.enabled)
    setEditError(null)
  }

  function closeEditor(): void {
    setEditId(null)
    setEditError(null)
  }

  function submitCreate(): void {
    const key = newKey.trim()
    if (!keyPattern.test(key)) {
      setCreateError('Enter a key of 1-64 characters: letters, digits, dot, underscore or dash.')
      return
    }
    if (newName.trim() === '') {
      setCreateError('Enter a name.')
      return
    }
    setCreateError(null)
    const payload: FrameworkCreate = { key, name: newName.trim(), enabled: newEnabled }
    if (newVersion.trim() !== '') payload.version = newVersion.trim()
    if (newSource.trim() !== '') payload.source = newSource.trim()
    if (newDescription.trim() !== '') payload.description = newDescription.trim()
    create.mutate(payload)
  }

  function submitEdit(): void {
    if (editing === null) return
    if (editName.trim() === '') {
      setEditError('Enter a name.')
      return
    }
    setEditError(null)
    const payload: FrameworkUpdate = {
      name: editName.trim(),
      version: emptyToNull(editVersion),
      source: emptyToNull(editSource),
      description: emptyToNull(editDescription),
      enabled: editEnabled,
    }
    update.mutate({ id: editing.id, payload })
  }

  function confirmDelete(framework: Framework): void {
    if (
      window.confirm(
        `Delete framework "${framework.name}"? Every mapping from a control into this framework is deleted with it; the controls themselves stay. This cannot be undone.`,
      )
    ) {
      remove.mutate(framework.id)
    }
  }

  return (
    <div className="space-y-4">
      <PageHeader
        title="Frameworks"
        subtitle="The external catalogues (for example OWASP ASVS or the CIS Linux benchmark) that controls map into. Each reference on a control names the framework and its own requirement code."
      />

      {frameworks.isPending && <Loading label="Loading frameworks" />}
      {frameworks.isError && (
        <ErrorNotice error={frameworks.error} onRetry={() => void frameworks.refetch()} />
      )}

      {frameworks.data && (
        <TableWrap>
          <thead>
            <tr>
              <Th>Key</Th>
              <Th>Name</Th>
              <Th>Version</Th>
              <Th>Source</Th>
              <Th>Enabled</Th>
              <Th align="right">Manage</Th>
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 ? (
              <TableEmptyRow colSpan={6}>
                No frameworks have been created yet. A framework is the external catalogue a
                control maps into, such as OWASP ASVS or the CIS Linux benchmark; the references
                on the control pages are shown under it.
              </TableEmptyRow>
            ) : (
              rows.map((f) => (
                <tr key={f.id} className={f.id === editId ? 'bg-raise/50' : 'hover:bg-raise/50'}>
                  <Td mono className="text-ink">
                    {f.key}
                  </Td>
                  <Td wrap className="min-w-[14rem] max-w-[30rem]">
                    {f.name}
                    {f.description && <div className="text-[12px] text-dim">{f.description}</div>}
                  </Td>
                  <Td mono className="text-mute">
                    {f.version ?? '-'}
                  </Td>
                  <Td wrap className="max-w-[22rem] break-words text-mute">
                    {f.source ?? '-'}
                  </Td>
                  <Td>
                    {f.enabled ? (
                      <Badge tone="pass">enabled</Badge>
                    ) : (
                      <Badge tone="na">disabled</Badge>
                    )}
                  </Td>
                  <Td align="right">
                    {isWriter ? (
                      <span className="flex justify-end gap-1">
                        <Button size="sm" disabled={f.id === editId} onClick={() => startEdit(f)}>
                          Edit
                        </Button>
                        {isAdmin && (
                          <Button
                            size="sm"
                            variant="danger"
                            disabled={remove.isPending}
                            onClick={() => confirmDelete(f)}
                          >
                            Delete
                          </Button>
                        )}
                      </span>
                    ) : (
                      <span className="text-dim">-</span>
                    )}
                  </Td>
                </tr>
              ))
            )}
          </tbody>
        </TableWrap>
      )}

      {remove.isError && <ErrorNotice title="Delete failed" error={remove.error} />}

      {editing && (
        <Panel title={`Edit ${editing.key}`}>
          <div className="grid gap-3 sm:grid-cols-2">
            <Field label="Key" hint="The key is fixed at creation and cannot be changed.">
              <Input value={editing.key} disabled readOnly />
            </Field>
            <Field label="Name" required>
              <Input
                value={editName}
                maxLength={255}
                onChange={(e) => setEditName(e.target.value)}
              />
            </Field>
            <Field label="Version" hint="Leave empty to clear the version.">
              <Input
                value={editVersion}
                maxLength={64}
                onChange={(e) => setEditVersion(e.target.value)}
              />
            </Field>
            <Field label="Source" hint="Leave empty to clear the source.">
              <Input
                value={editSource}
                maxLength={255}
                onChange={(e) => setEditSource(e.target.value)}
              />
            </Field>
            <div className="sm:col-span-2">
              <Field label="Description" hint="Leave empty to clear the description.">
                <Textarea
                  rows={2}
                  value={editDescription}
                  onChange={(e) => setEditDescription(e.target.value)}
                />
              </Field>
            </div>
            <div className="flex items-end pb-1">
              <Checkbox label="Enabled" checked={editEnabled} onChange={setEditEnabled} />
            </div>
          </div>
          {editError !== null && (
            <div className="mt-3">
              <ErrorNotice title="Update blocked" error={new Error(editError)} />
            </div>
          )}
          {update.isError && (
            <div className="mt-3">
              <ErrorNotice title="Update failed" error={update.error} />
            </div>
          )}
          <div className="mt-3 flex justify-end gap-2">
            <Button onClick={closeEditor}>Cancel</Button>
            <Button
              variant="primary"
              disabled={!dirty || update.isPending}
              onClick={submitEdit}
            >
              {update.isPending ? 'Saving...' : 'Save changes'}
            </Button>
          </div>
        </Panel>
      )}

      {isWriter && (
        <Panel title="Add a framework">
          <div className="grid gap-3 sm:grid-cols-2">
            <Field label="Key" required hint={keyHint}>
              <Input
                value={newKey}
                maxLength={64}
                autoComplete="off"
                onChange={(e) => setNewKey(e.target.value)}
              />
            </Field>
            <Field label="Name" required>
              <Input
                value={newName}
                maxLength={255}
                onChange={(e) => setNewName(e.target.value)}
              />
            </Field>
            <Field
              label="Version"
              hint="The catalogue revision the references were taken from, for example 4.0.3 or Rev. 5."
            >
              <Input
                value={newVersion}
                maxLength={64}
                onChange={(e) => setNewVersion(e.target.value)}
              />
            </Field>
            <Field label="Source" hint="Where the catalogue lives, usually the publisher's URL.">
              <Input
                value={newSource}
                maxLength={255}
                onChange={(e) => setNewSource(e.target.value)}
              />
            </Field>
            <div className="sm:col-span-2">
              <Field label="Description">
                <Textarea
                  rows={2}
                  value={newDescription}
                  onChange={(e) => setNewDescription(e.target.value)}
                />
              </Field>
            </div>
            <div className="flex items-end pb-1">
              <Checkbox label="Enabled" checked={newEnabled} onChange={setNewEnabled} />
            </div>
          </div>
          {createError !== null && (
            <div className="mt-3">
              <ErrorNotice title="Cannot create the framework" error={new Error(createError)} />
            </div>
          )}
          {create.isError && (
            <div className="mt-3">
              <ErrorNotice title="Create failed" error={create.error} />
            </div>
          )}
          <div className="mt-3 flex flex-wrap items-center justify-between gap-2">
            <span className="text-[12px] text-dim">
              Keys are unique, so a create is refused if one already exists. Once created, the key
              stays fixed; every other field can be edited later.
            </span>
            <Button variant="primary" disabled={create.isPending} onClick={submitCreate}>
              {create.isPending ? 'Creating...' : 'Create framework'}
            </Button>
          </div>
        </Panel>
      )}
    </div>
  )
}

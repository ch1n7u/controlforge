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
  Select,
  TableEmptyRow,
  TableWrap,
  Td,
  Th,
} from '../components/ui'
import { api, qk } from '../lib/api'
import { fmtDateTime, fmtRelative } from '../lib/format'
import type { Role, User, UserCreate, UserUpdate } from '../lib/types'

const roleOptions: Role[] = ['viewer', 'analyst', 'admin']

const roleTone: Record<Role, 'mute' | 'pass' | 'accent'> = {
  viewer: 'mute',
  analyst: 'pass',
  admin: 'accent',
}

const roleHint =
  'Administrators manage users, scopes and settings; analysts start runs and change configuration; viewers are read-only.'

export function UsersPage() {
  const { isAdmin, user: me } = useAuth()
  const queryClient = useQueryClient()

  const users = useQuery({
    queryKey: qk.users,
    queryFn: api.allUsers,
    enabled: isAdmin,
    staleTime: 30_000,
  })

  const [newUsername, setNewUsername] = useState('')
  const [newFullName, setNewFullName] = useState('')
  const [newRole, setNewRole] = useState<Role>('viewer')
  const [newPassword, setNewPassword] = useState('')
  const [createError, setCreateError] = useState<string | null>(null)

  const [editId, setEditId] = useState<number | null>(null)
  const [editFullName, setEditFullName] = useState('')
  const [editRole, setEditRole] = useState<Role>('viewer')
  const [editActive, setEditActive] = useState(true)
  const [editPassword, setEditPassword] = useState('')
  const [editError, setEditError] = useState<string | null>(null)

  const create = useMutation({
    mutationFn: (payload: UserCreate) => api.createUser(payload),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: qk.users })
      setNewUsername('')
      setNewFullName('')
      setNewRole('viewer')
      setNewPassword('')
      setCreateError(null)
    },
  })

  const update = useMutation({
    mutationFn: (vars: { id: number; payload: UserUpdate }) =>
      api.updateUser(vars.id, vars.payload),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: qk.users })
      closeEditor()
    },
  })

  const rows = users.data ?? []
  const editing = rows.find((u) => u.id === editId) ?? null
  const isSelf = editing !== null && me?.id === editing.id
  const originalFullName = editing?.full_name ?? ''
  const dirty =
    editing !== null &&
    (editFullName.trim() !== originalFullName.trim() ||
      editRole !== editing.role ||
      editActive !== editing.is_active ||
      editPassword !== '')
  // Demoting or deactivating yourself could leave the platform without an
  // administrator; the server refuses too, but the form should not offer it.
  const selfLockout = isSelf && (editRole !== 'admin' || !editActive)

  function startEdit(user: User): void {
    update.reset()
    setEditId(user.id)
    setEditFullName(user.full_name ?? '')
    setEditRole(user.role)
    setEditActive(user.is_active)
    setEditPassword('')
    setEditError(null)
  }

  function closeEditor(): void {
    setEditId(null)
    setEditPassword('')
    setEditError(null)
  }

  function submitCreate(): void {
    if (newUsername.trim() === '') {
      setCreateError('Enter a username.')
      return
    }
    if (newPassword === '') {
      setCreateError('Set an initial password for this account.')
      return
    }
    setCreateError(null)
    const payload: UserCreate = {
      username: newUsername.trim(),
      role: newRole,
      password: newPassword,
    }
    if (newFullName.trim() !== '') payload.full_name = newFullName.trim()
    create.mutate(payload)
  }

  function submitEdit(): void {
    if (editing === null) return
    if (selfLockout) {
      setEditError('You cannot demote or deactivate your own account.')
      return
    }
    setEditError(null)
    const payload: UserUpdate = {
      full_name: editFullName.trim() === '' ? null : editFullName.trim(),
      role: editRole,
      is_active: editActive,
    }
    if (editPassword !== '') payload.password = editPassword
    update.mutate({ id: editing.id, payload })
  }

  if (!isAdmin) {
    return (
      <div className="space-y-4">
        <PageHeader
          title="Users"
          subtitle="Who can sign in to CONTROLFORGE and what they may change."
        />
        <Panel title="Administrator action">
          <p className="text-[13px] text-dim">
            Managing user accounts requires an administrator. Ask an administrator if you need a
            role change or a password reset.
          </p>
        </Panel>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      <PageHeader
        title="Users"
        subtitle="Who can sign in to CONTROLFORGE and what they may change. Every operator works from their own account, so the audit log names who did what."
      />

      {users.isPending && <Loading label="Loading users" />}
      {users.isError && <ErrorNotice error={users.error} onRetry={() => void users.refetch()} />}

      {users.data && (
        <TableWrap>
          <thead>
            <tr>
              <Th>User</Th>
              <Th>Role</Th>
              <Th>Status</Th>
              <Th>Last sign-in</Th>
              <Th align="right">Manage</Th>
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 ? (
              <TableEmptyRow colSpan={5}>No user accounts exist yet.</TableEmptyRow>
            ) : (
              rows.map((u) => (
                <tr key={u.id} className={u.id === editId ? 'bg-raise/50' : 'hover:bg-raise/50'}>
                  <Td>
                    <span className="font-mono text-[13px] text-ink">{u.username}</span>
                    {u.full_name && <div className="text-[12px] text-dim">{u.full_name}</div>}
                  </Td>
                  <Td>
                    <Badge tone={roleTone[u.role]}>{u.role}</Badge>
                  </Td>
                  <Td>
                    <span className="flex flex-wrap items-center gap-1">
                      {u.is_active ? (
                        <Badge tone="pass">active</Badge>
                      ) : (
                        <Badge tone="na" title="An inactive account cannot sign in">
                          inactive
                        </Badge>
                      )}
                      {u.must_change_password && (
                        <Badge
                          tone="incon"
                          title="Still signing in with a password an administrator set"
                        >
                          must change password
                        </Badge>
                      )}
                      {me?.id === u.id && <Badge tone="mute">you</Badge>}
                    </span>
                  </Td>
                  <Td className="text-mute">
                    {u.last_login_at ? (
                      <span title={fmtDateTime(u.last_login_at)}>
                        {fmtRelative(u.last_login_at)}
                      </span>
                    ) : (
                      <span className="text-dim">never</span>
                    )}
                  </Td>
                  <Td align="right">
                    <Button size="sm" disabled={u.id === editId} onClick={() => startEdit(u)}>
                      Edit
                    </Button>
                  </Td>
                </tr>
              ))
            )}
          </tbody>
        </TableWrap>
      )}

      {editing && (
        <Panel title={`Edit ${editing.username}`}>
          <div className="grid gap-3 sm:grid-cols-2">
            <Field label="Full name">
              <Input value={editFullName} onChange={(e) => setEditFullName(e.target.value)} />
            </Field>
            <Field label="Role" hint={isSelf ? 'You cannot change your own role.' : roleHint}>
              <Select
                value={editRole}
                onChange={(e) => setEditRole(e.target.value as Role)}
                disabled={isSelf}
              >
                {roleOptions.map((role) => (
                  <option key={role} value={role}>
                    {role}
                  </option>
                ))}
              </Select>
            </Field>
            <Field
              label="Set a new password"
              hint="Leave blank to keep the current password. At least 12 characters with upper and lower case and a digit; setting one revokes every session on this account and the user must change it at next sign-in."
            >
              <Input
                type="password"
                autoComplete="new-password"
                value={editPassword}
                onChange={(e) => setEditPassword(e.target.value)}
              />
            </Field>
            <div className="flex items-end pb-1">
              <Checkbox
                label="Active"
                checked={editActive}
                disabled={isSelf}
                onChange={setEditActive}
              />
            </div>
          </div>
          {isSelf && (
            <p className="mt-2 text-[12px] text-dim">
              You cannot deactivate or demote your own account, so the platform always keeps at
              least one administrator.
            </p>
          )}
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
              disabled={!dirty || selfLockout || update.isPending}
              onClick={submitEdit}
            >
              {update.isPending ? 'Saving...' : 'Save changes'}
            </Button>
          </div>
        </Panel>
      )}

      <Panel title="Add a user">
        <div className="grid gap-3 sm:grid-cols-2">
          <Field
            label="Username"
            required
            hint="3-64 characters: letters, digits, dot, underscore or dash. It cannot be changed later."
          >
            <Input
              value={newUsername}
              onChange={(e) => setNewUsername(e.target.value)}
              autoComplete="off"
            />
          </Field>
          <Field label="Full name">
            <Input value={newFullName} onChange={(e) => setNewFullName(e.target.value)} />
          </Field>
          <Field label="Role" hint={roleHint}>
            <Select value={newRole} onChange={(e) => setNewRole(e.target.value as Role)}>
              {roleOptions.map((role) => (
                <option key={role} value={role}>
                  {role}
                </option>
              ))}
            </Select>
          </Field>
          <Field
            label="Initial password"
            required
            hint="At least 12 characters with upper and lower case and a digit. The user must change it at first sign-in."
          >
            <Input
              type="password"
              autoComplete="new-password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
            />
          </Field>
        </div>
        {createError !== null && (
          <div className="mt-3">
            <ErrorNotice title="Cannot create the account" error={new Error(createError)} />
          </div>
        )}
        {create.isError && (
          <div className="mt-3">
            <ErrorNotice title="Create failed" error={create.error} />
          </div>
        )}
        <div className="mt-3 flex flex-wrap items-center justify-between gap-2">
          <span className="text-[12px] text-dim">
            Passwords are hashed on the server; nobody can read one back, only reset it.
          </span>
          <Button variant="primary" disabled={create.isPending} onClick={submitCreate}>
            {create.isPending ? 'Creating...' : 'Create user'}
          </Button>
        </div>
      </Panel>
    </div>
  )
}

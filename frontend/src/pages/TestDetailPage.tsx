import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { useAuth } from '../auth/context'
import { JsonBlock } from '../components/Json'
import { RunDialog } from '../components/RunDialog'
import { TestVersionForm } from '../components/TestVersionForm'
import {
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
  SeverityBadge,
  Textarea,
} from '../components/ui'
import { api, qk } from '../lib/api'
import { fmtDateTime, fmtRelative } from '../lib/format'
import { emptyDraft, buildTestVersion, type TestVersionDraft } from '../lib/testVersion'
import { targetTypes } from '../lib/tones'
import type { Target, TargetType, ValidationTestDetail } from '../lib/types'

interface Selector {
  target_ids: number[]
  tags: string[]
  target_types: TargetType[]
}

/** The stored selector is free-form data; read it defensively. */
function readSelector(value: unknown): Selector {
  if (typeof value !== 'object' || value === null) {
    return { target_ids: [], tags: [], target_types: [] }
  }
  const record = value as Record<string, unknown>
  const ids = Array.isArray(record.target_ids)
    ? record.target_ids.filter(isNumber)
    : []
  const tags = Array.isArray(record.tags) ? record.tags.filter(isString) : []
  const types = Array.isArray(record.target_types)
    ? record.target_types.filter(isTargetType)
    : []
  return { target_ids: ids, tags, target_types: types }
}

function isNumber(value: unknown): value is number {
  return typeof value === 'number'
}

function isString(value: unknown): value is string {
  return typeof value === 'string'
}

function isTargetType(value: unknown): value is TargetType {
  return typeof value === 'string' && (targetTypes as string[]).includes(value)
}

export function TestDetailPage() {
  const params = useParams()
  const testId = Number(params.id)
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const { isWriter } = useAuth()

  const test = useQuery({
    queryKey: qk.test(testId),
    queryFn: () => api.test(testId),
    staleTime: 15_000,
  })
  const engines = useQuery({
    queryKey: qk.engines,
    queryFn: api.engines,
    staleTime: 10 * 60_000,
  })
  const controls = useQuery({
    queryKey: qk.controls({ limit: 1000 }),
    queryFn: () => api.controls({ limit: 1000 }),
    staleTime: 5 * 60_000,
  })
  const targets = useQuery({
    queryKey: qk.targets({ limit: 1000 }),
    queryFn: () => api.targets({ limit: 1000 }),
    staleTime: 5 * 60_000,
  })
  const users = useQuery({
    queryKey: qk.users,
    queryFn: api.users,
    staleTime: 5 * 60_000,
  })

  const [draft, setDraft] = useState<TestVersionDraft>(emptyDraft())
  const [publishOpen, setPublishOpen] = useState(false)
  const [runOpen, setRunOpen] = useState(false)
  const [localError, setLocalError] = useState<string | null>(null)

  const publish = useMutation({
    mutationFn: () => {
      const built = buildTestVersion(draft)
      if ('error' in built) return Promise.reject(new Error(built.error))
      return api.createTestVersion(testId, built.payload)
    },
    onSuccess: () => {
      setPublishOpen(false)
      setDraft(emptyDraft())
      setLocalError(null)
      void queryClient.invalidateQueries({ queryKey: qk.test(testId) })
    },
  })

  const updateMeta = useMutation({
    mutationFn: (payload: Record<string, unknown>) => api.updateTest(testId, payload),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: qk.test(testId) }),
  })

  const remove = useMutation({
    mutationFn: () => api.deleteTest(testId),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: qk.tests() })
      navigate('/tests')
    },
  })

  if (test.isPending) return <Loading label="Loading test" />
  if (test.isError) return <ErrorNotice error={test.error} onRetry={() => void test.refetch()} />
  const t = test.data
  const control = controls.data?.find((c) => c.id === t.control_id)
  const userById = new Map((users.data ?? []).map((user) => [user.id, user]))
  const selector = readSelector(t.target_selector)
  const versions = [...t.versions].sort((a, b) => b.version - a.version)
  const current = t.versions.find((v) => v.version === t.current_version)

  return (
    <div className="space-y-4">
      <PageHeader
        title={
          <span className="flex flex-wrap items-baseline gap-3">
            <span className="font-mono text-[15px] text-accent">{t.key}</span>
            <span>{t.name}</span>
          </span>
        }
        subtitle={
          <span className="flex flex-wrap items-center gap-2">
            {control && (
              <Link to={`/controls/${control.id}`} className="text-accent hover:underline">
                <span className="font-mono text-[12px]">{control.key}</span>
              </Link>
            )}
            <Badge tone="mute">v{t.current_version} current</Badge>
            {current && <SeverityBadge severity={current.severity} />}
            {current && <Badge tone="accent">{current.engine_id}</Badge>}
            {t.enabled ? <Badge tone="pass">enabled</Badge> : <Badge tone="na">disabled</Badge>}
            <Link to={`/runs?test_id=${t.id}`} className="text-accent hover:underline">
              Run history
            </Link>
          </span>
        }
        actions={
          isWriter ? (
            <>
              <Button variant="primary" onClick={() => setRunOpen(true)}>
                Run this test
              </Button>
              <Button onClick={() => setPublishOpen((v) => !v)}>
                {publishOpen ? 'Cancel new version' : 'Publish new version'}
              </Button>
              <Button
                variant="danger"
                onClick={() => {
                  if (
                    window.confirm(
                      `Delete test ${t.key}? Tests with recorded runs cannot be deleted.`,
                    )
                  ) {
                    remove.mutate()
                  }
                }}
                disabled={remove.isPending}
              >
                Delete
              </Button>
            </>
          ) : null
        }
      />

      {remove.isError && <ErrorNotice title="Delete refused" error={remove.error} />}

      {publishOpen && (
        <Panel title={`Publish version v${t.current_version + 1}`}>
          <p className="mb-3 border border-incon/40 bg-incon/10 p-2 text-[12px] text-ink">
            Versions are immutable. This publishes a new version; every existing run and finding
            keeps pointing at the version it was recorded against.
          </p>
          <TestVersionForm
            engines={engines.data}
            enginesLoading={engines.isPending}
            enginesError={engines.error ?? null}
            control={control ?? null}
            draft={draft}
            onChange={setDraft}
          />
          {(localError !== null || publish.isError) && (
            <div className="mt-3">
              <ErrorNotice error={localError !== null ? new Error(localError) : publish.error} />
            </div>
          )}
          <div className="mt-4 flex justify-end gap-2">
            <Button onClick={() => setPublishOpen(false)}>Cancel</Button>
            <Button
              variant="primary"
              disabled={publish.isPending}
              onClick={() => {
                const built = buildTestVersion(draft)
                if ('error' in built) {
                  setLocalError(built.error)
                  return
                }
                setLocalError(null)
                publish.mutate()
              }}
            >
              {publish.isPending ? 'Publishing...' : 'Publish version'}
            </Button>
          </div>
        </Panel>
      )}

      <div className="grid gap-3 lg:grid-cols-3">
        <div className="space-y-3 lg:col-span-2">
          <Panel title={`Version history (${versions.length})`}>
            <ul className="space-y-2">
              {versions.map((version) => (
                <li key={version.id} className="border border-edge bg-panel2">
                  <details>
                    <summary className="flex cursor-pointer flex-wrap items-center gap-2 px-3 py-2 hover:bg-raise">
                      <span className="font-mono text-[13px] text-ink">v{version.version}</span>
                      {version.version === t.current_version && (
                        <Badge tone="accent">current</Badge>
                      )}
                      <span className="font-mono text-[12px] text-mute">{version.engine_id}</span>
                      <SeverityBadge severity={version.severity} />
                      <span className="text-[12px] text-dim">
                        {fmtDateTime(version.created_at)}
                        {version.created_by_user_id !== null
                          ? ` · ${userById.get(version.created_by_user_id)?.username ?? `user #${version.created_by_user_id}`}`
                          : ''}
                      </span>
                      {version.note && (
                        <span className="w-full text-[12px] text-mute">Note: {version.note}</span>
                      )}
                    </summary>
                    <div className="space-y-2 border-t border-edge p-3">
                      <JsonBlock label="Engine parameters" value={version.engine_params} />
                      <JsonBlock label="Assertion" value={version.assertion} />
                    </div>
                  </details>
                </li>
              ))}
            </ul>
          </Panel>

          {t.description && (
            <Panel title="Description">
              <p className="text-[13px] whitespace-pre-wrap text-ink/90">{t.description}</p>
            </Panel>
          )}
        </div>

        <div className="space-y-3">
          <Panel title="Metadata">
            <KeyValue
              columns={1}
              items={[
                ['Created', fmtDateTime(t.created_at)],
                ['Updated', t.updated_at ? fmtRelative(t.updated_at) : '-'],
                ['Tags', t.tags.length > 0 ? t.tags.join(', ') : '-'],
                [
                  'Pinned targets',
                  selector.target_ids.length > 0
                    ? selector.target_ids.map((id) => `#${id}`).join(', ')
                    : 'any target',
                ],
                ['Target tags', selector.tags.length > 0 ? selector.tags.join(', ') : 'any target'],
                [
                  'Target types',
                  selector.target_types.length > 0 ? selector.target_types.join(', ') : 'any target',
                ],
              ]}
            />
          </Panel>

          {isWriter && (
            <MetadataForm
              key={t.updated_at ?? t.created_at}
              test={t}
              targets={targets.data ?? []}
              targetsLoading={targets.isPending}
              saving={updateMeta.isPending}
              isError={updateMeta.isError}
              error={updateMeta.error}
              isSuccess={updateMeta.isSuccess}
              onSubmit={(payload) => updateMeta.mutate(payload)}
            />
          )}

          {!isWriter && (
            <Panel title="Read-only">
              <EmptyState
                title="Viewer role"
                hint="Authoring tests and starting runs needs the analyst or administrator role."
              />
            </Panel>
          )}
        </div>
      </div>

      {runOpen && <RunDialog onClose={() => setRunOpen(false)} fixedTestId={t.id} />}
    </div>
  )
}

function MetadataForm({
  test,
  targets,
  targetsLoading,
  saving,
  isError,
  error,
  isSuccess,
  onSubmit,
}: {
  test: ValidationTestDetail
  targets: Target[]
  targetsLoading: boolean
  saving: boolean
  isError: boolean
  error: unknown
  isSuccess: boolean
  onSubmit: (payload: Record<string, unknown>) => void
}) {
  const initial = readSelector(test.target_selector)
  const [name, setName] = useState(test.name)
  const [description, setDescription] = useState(test.description ?? '')
  const [tagText, setTagText] = useState(test.tags.join(', '))
  const [selectorTags, setSelectorTags] = useState(initial.tags.join(', '))
  const [selectorTypes, setSelectorTypes] = useState<TargetType[]>(initial.target_types)
  const [selectorIds, setSelectorIds] = useState<number[]>(initial.target_ids)
  const [enabled, setEnabled] = useState(test.enabled)

  return (
    <Panel title="Edit metadata">
      <div className="space-y-3">
        <Field label="Name" required>
          <Input value={name} onChange={(e) => setName(e.target.value)} />
        </Field>
        <Field label="Description">
          <Textarea
            rows={3}
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            className="text-[12px]"
          />
        </Field>
        <Field label="Tags" hint="Comma-separated">
          <Input value={tagText} onChange={(e) => setTagText(e.target.value)} />
        </Field>

        <div>
          <div className="mb-1 text-[11px] tracking-wide text-mute uppercase">Target types</div>
          <div className="flex flex-wrap gap-3">
            {targetTypes.map((type) => (
              <Checkbox
                key={type}
                label={type}
                checked={selectorTypes.includes(type)}
                onChange={(checked) =>
                  setSelectorTypes((current) =>
                    checked ? [...current, type] : current.filter((t) => t !== type),
                  )
                }
              />
            ))}
          </div>
        </div>

        <Field label="Target tags" hint="Comma-separated; leave empty to match every target">
          <Input value={selectorTags} onChange={(e) => setSelectorTags(e.target.value)} />
        </Field>

        <div>
          <div className="mb-1 flex items-center justify-between">
            <span className="text-[11px] tracking-wide text-mute uppercase">
              Specific targets
            </span>
            <span className="font-mono text-[11px] text-dim">{selectorIds.length} pinned</span>
          </div>
          <div className="max-h-40 overflow-auto border border-edge bg-bg">
            {targetsLoading ? (
              <div className="px-2 py-3 text-center text-[12px] text-dim">Loading targets...</div>
            ) : targets.length === 0 ? (
              <div className="px-2 py-3 text-center text-[12px] text-dim">
                No targets exist yet.
              </div>
            ) : (
              targets.map((target) => (
                <label
                  key={target.id}
                  className="flex cursor-pointer items-center gap-2 border-b border-edge/50 px-2 py-1 text-[12px] last:border-b-0 hover:bg-raise"
                >
                  <input
                    type="checkbox"
                    className="size-3.5 accent-[var(--color-accent)]"
                    checked={selectorIds.includes(target.id)}
                    onChange={() =>
                      setSelectorIds((current) =>
                        current.includes(target.id)
                          ? current.filter((id) => id !== target.id)
                          : [...current, target.id],
                      )
                    }
                  />
                  <span className="text-ink">{target.name}</span>
                  <span className="font-mono text-dim">
                    {target.host}
                    {target.port ? `:${target.port}` : ''}
                  </span>
                </label>
              ))
            )}
          </div>
        </div>

        <Checkbox label="Enabled" checked={enabled} onChange={setEnabled} />

        {isError && <ErrorNotice error={error} />}
        {isSuccess && (
          <div className="border border-pass/40 bg-pass/5 p-2 text-[12px] text-pass">
            Metadata saved.
          </div>
        )}
        <Button
          variant="primary"
          disabled={saving || name.trim() === ''}
          onClick={() =>
            onSubmit({
              name: name.trim(),
              description,
              tags: splitList(tagText),
              target_selector: {
                target_ids: selectorIds,
                tags: splitList(selectorTags),
                target_types: selectorTypes,
              },
              enabled,
            })
          }
        >
          {saving ? 'Saving...' : 'Save metadata'}
        </Button>
        <p className="text-[11px] text-dim">
          Name, description, tags and target filters can be edited at any time. What the test runs
          is fixed per version - publish a new version to change it.
        </p>
      </div>
    </Panel>
  )
}

function splitList(text: string): string[] {
  return text
    .split(',')
    .map((part) => part.trim())
    .filter((part) => part !== '')
}

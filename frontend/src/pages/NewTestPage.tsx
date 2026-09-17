import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { TestVersionForm } from '../components/TestVersionForm'
import {
  Button,
  Checkbox,
  ErrorNotice,
  Field,
  Input,
  Loading,
  PageHeader,
  Panel,
  Select,
  Textarea,
} from '../components/ui'
import { api, qk } from '../lib/api'
import { buildTestVersion, emptyDraft, type TestVersionDraft } from '../lib/testVersion'
import { targetTypes } from '../lib/tones'
import type { TargetType, ValidationTestCreate } from '../lib/types'

const KEY_PATTERN = /^[A-Za-z0-9._-]+$/

export function NewTestPage() {
  const navigate = useNavigate()
  const queryClient = useQueryClient()

  const engines = useQuery({ queryKey: qk.engines, queryFn: api.engines, staleTime: 10 * 60_000 })
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

  const [key, setKey] = useState('')
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [controlId, setControlId] = useState('')
  const [tagText, setTagText] = useState('')
  const [enabled, setEnabled] = useState(true)
  const [selectorTypes, setSelectorTypes] = useState<TargetType[]>([])
  const [selectorTags, setSelectorTags] = useState('')
  const [selectorIds, setSelectorIds] = useState<number[]>([])
  const [draft, setDraft] = useState<TestVersionDraft>(emptyDraft())
  const [localError, setLocalError] = useState<string | null>(null)

  const control = (controls.data ?? []).find((c) => c.id === Number(controlId)) ?? null

  const create = useMutation({
    mutationFn: (payload: ValidationTestCreate) => api.createTest(payload),
    onSuccess: (created) => {
      void queryClient.invalidateQueries({ queryKey: qk.tests() })
      navigate(`/tests/${created.id}`)
    },
  })

  function submit(): void {
    if (key.trim() === '' || !KEY_PATTERN.test(key.trim())) {
      setLocalError('Enter a key using letters, digits, dot, underscore or dash only.')
      return
    }
    if (name.trim() === '') {
      setLocalError('Enter a name for this test.')
      return
    }
    if (controlId === '') {
      setLocalError('Choose the control this test validates.')
      return
    }
    if (!control) {
      setLocalError('That control is no longer available. Choose one from the list.')
      return
    }
    const built = buildTestVersion(draft)
    if ('error' in built) {
      setLocalError(built.error)
      return
    }
    setLocalError(null)
    const payload: ValidationTestCreate = {
      key: key.trim(),
      name: name.trim(),
      control_id: control.id,
      tags: splitList(tagText),
      target_selector: {
        target_ids: selectorIds,
        tags: splitList(selectorTags),
        target_types: selectorTypes,
      },
      enabled,
      version: built.payload,
    }
    if (description.trim() !== '') payload.description = description.trim()
    create.mutate(payload)
  }

  return (
    <div className="space-y-4">
      <PageHeader
        title="New test"
        subtitle="A validation test checks whether a target meets one control. Choose the control it proves, the targets it applies to, and what the check must find."
      />

      <div className="grid gap-3 lg:grid-cols-3">
        <Panel title="Details" className="lg:col-span-1">
          <div className="space-y-3">
            <Field
              label="Key"
              required
              hint="Short identifier used in run history and reports, for example TLS-HSTS-MAX-AGE. Letters, digits, dot, underscore and dash only."
            >
              <Input
                value={key}
                onChange={(e) => setKey(e.target.value)}
                placeholder="TLS-HSTS-MAX-AGE"
              />
            </Field>
            <Field label="Name" required>
              <Input value={name} onChange={(e) => setName(e.target.value)} />
            </Field>
            <Field label="Description">
              <Textarea rows={3} value={description} onChange={(e) => setDescription(e.target.value)} />
            </Field>
            <Field label="Control" required hint="Each test produces evidence for exactly one control.">
              {controls.isPending ? (
                <Loading label="Loading controls" />
              ) : (
                <Select value={controlId} onChange={(e) => setControlId(e.target.value)}>
                  <option value="">Select a control...</option>
                  {(controls.data ?? []).map((c) => (
                    <option key={c.id} value={c.id}>
                      {c.key} - {c.title}
                    </option>
                  ))}
                </Select>
              )}
            </Field>
            {controls.isError && <ErrorNotice error={controls.error} onRetry={() => void controls.refetch()} />}
            <Field label="Tags" hint="Comma-separated">
              <Input value={tagText} onChange={(e) => setTagText(e.target.value)} />
            </Field>
            <Checkbox label="Enabled" checked={enabled} onChange={setEnabled} />
          </div>
        </Panel>

        <Panel title="Targets it runs against" className="lg:col-span-1">
          <div className="space-y-3">
            <p className="text-[12px] text-dim">
              Which targets this test applies to. Leave a filter empty to match every target; a
              target must match every filter you set.
            </p>
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
            <Field label="Tags" hint="Comma-separated; leave empty to match every target">
              <Input value={selectorTags} onChange={(e) => setSelectorTags(e.target.value)} />
            </Field>
            <div>
              <div className="mb-1 flex items-center justify-between">
                <span className="text-[11px] tracking-wide text-mute uppercase">Specific targets</span>
                <span className="font-mono text-[11px] text-dim">{selectorIds.length} pinned</span>
              </div>
              <div className="max-h-40 overflow-auto border border-edge bg-bg">
                {targets.isPending ? (
                  <div className="px-2 py-3 text-center text-[12px] text-dim">Loading targets...</div>
                ) : (targets.data ?? []).length === 0 ? (
                  <div className="px-2 py-3 text-center text-[12px] text-dim">
                    No targets are registered yet.
                  </div>
                ) : (
                  (targets.data ?? []).map((target) => (
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
          </div>
        </Panel>

        <Panel title="What it checks" className="lg:col-span-1">
          <p className="mb-3 text-[12px] text-dim">
            Choose the engine that gathers the evidence, then state the condition that evidence
            must satisfy.
          </p>
          <TestVersionForm
            engines={engines.data}
            enginesLoading={engines.isPending}
            enginesError={engines.error ?? null}
            control={control}
            draft={draft}
            onChange={setDraft}
          />
        </Panel>
      </div>

      {(localError || create.isError) && (
        <ErrorNotice error={localError ? new Error(localError) : create.error} />
      )}

      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="text-[12px] text-dim">Creating the test publishes its first version.</span>
        <div className="flex gap-2">
          <Button onClick={() => navigate('/tests')}>Cancel</Button>
          <Button variant="primary" disabled={create.isPending} onClick={submit}>
            {create.isPending ? 'Creating...' : 'Create test'}
          </Button>
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

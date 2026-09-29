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
import { severities } from '../lib/tones'
import type { ControlCreate, Severity } from '../lib/types'

export function NewControlPage() {
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const { isWriter } = useAuth()

  const [key, setKey] = useState('')
  const [title, setTitle] = useState('')
  const [category, setCategory] = useState('')
  const [description, setDescription] = useState('')
  const [expectedState, setExpectedState] = useState('')
  const [defaultSeverity, setDefaultSeverity] = useState<Severity>('medium')
  const [remediation, setRemediation] = useState('')
  const [enabled, setEnabled] = useState(true)
  const [localError, setLocalError] = useState<string | null>(null)

  const create = useMutation({
    mutationFn: (payload: ControlCreate) => api.createControl(payload),
    onSuccess: (control) => {
      void queryClient.invalidateQueries({ queryKey: qk.controls() })
      navigate(`/controls/${control.id}`)
    },
  })

  function submit(): void {
    if (key.trim() === '') {
      setLocalError('Enter a key for this control.')
      return
    }
    if (title.trim() === '') {
      setLocalError('Enter a title for this control.')
      return
    }
    setLocalError(null)
    const payload: ControlCreate = {
      key: key.trim(),
      title: title.trim(),
      default_severity: defaultSeverity,
      enabled,
    }
    if (category.trim() !== '') payload.category = category.trim()
    if (description.trim() !== '') payload.description = description.trim()
    if (expectedState.trim() !== '') payload.expected_state = expectedState.trim()
    if (remediation.trim() !== '') payload.remediation = remediation.trim()
    create.mutate(payload)
  }

  if (!isWriter) {
    return (
      <div className="space-y-4">
        <PageHeader
          title="New control"
          subtitle="A control is the secure state a target is held to; a test asserts what it requires and a run decides whether it holds."
        />
        <Panel title="Writer action">
          <p className="text-[13px] text-mute">
            Creating a control is a writer action: an analyst or administrator defines the secure
            state that tests assert against. Ask one to create it and map it to the frameworks it
            satisfies.
          </p>
        </Panel>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      <PageHeader
        title="New control"
        subtitle="A control is the secure state a target is held to; a test asserts what it requires and a run decides whether it holds."
      />

      <div className="grid gap-3 lg:grid-cols-3">
        <Panel title="Identity" className="lg:col-span-2">
          <div className="space-y-3">
            <Field
              label="Key"
              required
              hint="The stable identifier tests and the API refer to. It cannot be changed after the control is created."
            >
              <Input
                value={key}
                onChange={(e) => setKey(e.target.value)}
                placeholder="AC-2"
                maxLength={80}
              />
            </Field>
            <Field
              label="Title"
              required
              hint="What this control requires, in the words of the framework it comes from."
            >
              <Input
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                placeholder="Account management"
                maxLength={255}
              />
            </Field>
            <Field label="Category" hint="Groups controls on the Controls page and in reports.">
              <Input
                value={category}
                onChange={(e) => setCategory(e.target.value)}
                placeholder="access_control"
                maxLength={80}
              />
            </Field>
          </div>
        </Panel>

        <Panel title="Severity and state">
          <div className="space-y-4">
            <Field
              label="Default severity"
              hint="What a failing assertion on this control reports as, unless the test carries its own severity."
            >
              <Select
                value={defaultSeverity}
                onChange={(e) => setDefaultSeverity(e.target.value as Severity)}
              >
                {severities.map((level) => (
                  <option key={level} value={level}>
                    {level}
                  </option>
                ))}
              </Select>
            </Field>
            <div>
              <Checkbox label="Enabled" checked={enabled} onChange={setEnabled} />
              <p className="mt-1 text-[12px] text-dim">
                A disabled control stays in the catalogue, marked as disabled in lists and on its
                page.
              </p>
            </div>
          </div>
        </Panel>
      </div>

      <Panel title="Description and guidance">
        <div className="space-y-3">
          <Field label="Description" hint="What this control is about and why it matters.">
            <Textarea
              rows={3}
              value={description}
              onChange={(e) => setDescription(e.target.value)}
            />
          </Field>
          <Field
            label="Expected state"
            hint="The state that satisfies this control, written so it can be checked."
          >
            <Textarea
              rows={3}
              value={expectedState}
              onChange={(e) => setExpectedState(e.target.value)}
            />
          </Field>
          <Field
            label="Remediation guidance"
            hint="How to bring a failing target back to the expected state."
          >
            <Textarea
              rows={3}
              value={remediation}
              onChange={(e) => setRemediation(e.target.value)}
            />
          </Field>
        </div>
      </Panel>

      {localError !== null && <ErrorNotice error={new Error(localError)} />}
      {create.isError && <ErrorNotice error={create.error} />}

      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="text-[12px] text-dim">
          The key is how tests and the API refer to this control, so it cannot be changed later.
          Creating a control validates nothing by itself: tests and runs decide whether targets
          satisfy it.
        </span>
        <div className="flex gap-2">
          <Button onClick={() => navigate('/controls')}>Cancel</Button>
          <Button variant="primary" disabled={create.isPending} onClick={submit}>
            {create.isPending ? 'Creating...' : 'Create control'}
          </Button>
        </div>
      </div>
    </div>
  )
}

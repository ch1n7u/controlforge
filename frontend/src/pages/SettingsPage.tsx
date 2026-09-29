import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { useAuth } from '../auth/context'
import { JsonBlock } from '../components/Json'
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
  Textarea,
} from '../components/ui'
import { api, qk } from '../lib/api'
import { fmtBytes, fmtDateTime, fmtDuration } from '../lib/format'
import { severities } from '../lib/tones'
import type { Setting, User } from '../lib/types'

/** The storage key of a settings group, as it appears in the audit log. */
function SettingKey({ name }: { name: string }) {
  return (
    <span
      className="font-mono text-[11px] text-dim"
      title="Name of this settings group in the audit log"
    >
      {name}
    </span>
  )
}

function severityLabel(value: string): string {
  return value.charAt(0).toUpperCase() + value.slice(1)
}

export function SettingsPage() {
  const { isAdmin } = useAuth()
  const queryClient = useQueryClient()

  const settings = useQuery({
    queryKey: qk.settings,
    queryFn: api.settings,
    staleTime: 30_000,
  })
  const health = useQuery({
    queryKey: qk.health,
    queryFn: api.health,
    staleTime: 15_000,
    refetchInterval: 30_000,
  })
  const users = useQuery({
    queryKey: qk.users,
    queryFn: api.users,
    staleTime: 5 * 60_000,
  })

  const byKey = new Map((settings.data ?? []).map((setting) => [setting.key, setting]))
  const known = ['safety', 'runner', 'staleness']
  const extra = (settings.data ?? []).filter((setting) => !known.includes(setting.key))
  const userById = new Map((users.data ?? []).map((user) => [user.id, user]))

  const save = useMutation({
    mutationFn: ({ key, value }: { key: string; value: Record<string, unknown> }) =>
      api.putSetting(key, value),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: qk.settings }),
  })

  return (
    <div className="space-y-4">
      <PageHeader
        title="Settings"
        subtitle="Switches and limits that apply to new work as soon as they are saved. Only administrators can change them, and every change is recorded in the audit log."
      />

      {!isAdmin && (
        <div className="border border-edge2 bg-panel px-3 py-2 text-[12px] text-mute">
          Your account does not have the administrator role, so these settings are read-only here.
          Ask an administrator to make a change.
        </div>
      )}

      {save.isError && <ErrorNotice title="Setting rejected" error={save.error} />}

      <div className="grid gap-3 lg:grid-cols-3">
        <Panel title="Health">
          {health.isPending && <Loading label="Loading health" />}
          {health.isError && <ErrorNotice error={health.error} onRetry={() => void health.refetch()} />}
          {health.data && (
            <div className="space-y-3">
              <div className="flex flex-wrap items-center gap-2">
                <Badge tone={health.data.status === 'ok' ? 'pass' : 'fail'} dot>
                  platform {health.data.status}
                </Badge>
                <span className="font-mono text-[12px] text-mute">v{health.data.version}</span>
                <Badge tone={health.data.database.ok ? 'pass' : 'fail'} dot>
                  database {health.data.database.ok ? 'ok' : 'unavailable'}
                </Badge>
              </div>
              {health.data.database.error && (
                <pre className="border border-fail/40 bg-fail/5 p-2 font-mono text-[12px] whitespace-pre-wrap text-ink/90">
                  {health.data.database.error}
                </pre>
              )}
              <KeyValue
                columns={1}
                items={[
                  ['Safe mode', health.data.safe_mode ? 'on' : 'off'],
                  ['Kill switch', health.data.kill_switch ? 'on' : 'off'],
                ]}
              />
              <p className="text-[11px] text-dim">
                Re-checked every 30 seconds. A red dot means the platform is not fully healthy; the
                sidebar shows the same state on every page.
              </p>
            </div>
          )}
        </Panel>

        <Panel title="This install" className="lg:col-span-2">
          <p className="text-[12px] text-mute">
            CONTROLFORGE runs entirely on this host. Runs, evidence and findings stay here, and the
            only traffic that leaves is what a run sends to the targets you authorize.
          </p>
          <div className="mt-3">
            <KeyValue
              columns={1}
              items={[
                ['Reach', 'This host only; nothing is sent to a cloud service'],
                ['Scope enforcement', 'Decided per run and recorded in the run scope snapshot'],
                ['Evidence store', 'Append-only; the digest is recorded when the file is written'],
              ]}
            />
          </div>
        </Panel>
      </div>

      {settings.isPending && <Loading label="Loading settings" />}
      {settings.isError && (
        <ErrorNotice error={settings.error} onRetry={() => void settings.refetch()} />
      )}

      {byKey.get('safety') && (
        <SafetyEditor
          key={`safety-${JSON.stringify(byKey.get('safety')?.value ?? {})}`}
          setting={byKey.get('safety') as Setting}
          canWrite={isAdmin}
          saving={save.isPending}
          userById={userById}
          onSave={(value) => save.mutate({ key: 'safety', value })}
        />
      )}
      {byKey.get('runner') && (
        <RunnerEditor
          key={`runner-${JSON.stringify(byKey.get('runner')?.value ?? {})}`}
          setting={byKey.get('runner') as Setting}
          canWrite={isAdmin}
          saving={save.isPending}
          userById={userById}
          onSave={(value) => save.mutate({ key: 'runner', value })}
        />
      )}
      {byKey.get('staleness') && (
        <StalenessEditor
          key={`staleness-${JSON.stringify(byKey.get('staleness')?.value ?? {})}`}
          setting={byKey.get('staleness') as Setting}
          canWrite={isAdmin}
          saving={save.isPending}
          userById={userById}
          onSave={(value) => save.mutate({ key: 'staleness', value })}
        />
      )}
      {extra.map((setting) => (
        <GenericEditor
          key={`${setting.key}-${JSON.stringify(setting.value)}`}
          setting={setting}
          canWrite={isAdmin}
          saving={save.isPending}
          userById={userById}
          onSave={(value) => save.mutate({ key: setting.key, value })}
        />
      ))}
    </div>
  )
}

type EditorProps = {
  setting: Setting
  canWrite: boolean
  saving: boolean
  userById: Map<number, User>
  onSave: (value: Record<string, unknown>) => void
}

function SettingHeader({ setting, userById }: { setting: Setting; userById: Map<number, User> }) {
  const changedBy =
    setting.updated_by_user_id === null
      ? null
      : (userById.get(setting.updated_by_user_id)?.username ?? `user #${setting.updated_by_user_id}`)
  return (
    <div className="flex flex-wrap items-center gap-2 text-[11px] text-dim">
      {setting.is_default ? (
        <>
          <Badge tone="mute" title="This group has never been changed">
            default
          </Badge>
          <span>Built-in defaults; no change has been saved for this group.</span>
        </>
      ) : (
        <>
          <Badge tone="accent">saved</Badge>
          <span>
            Last saved {fmtDateTime(setting.updated_at)}
            {changedBy === null ? '' : ` by ${changedBy}`}
          </span>
        </>
      )}
    </div>
  )
}

function NumberField({
  label,
  hint,
  value,
  min,
  max,
  disabled,
  onChange,
}: {
  label: string
  hint: string
  value: number
  min: number
  max: number
  disabled: boolean
  onChange: (value: number) => void
}) {
  const invalid = !Number.isInteger(value) || value < min || value > max
  return (
    <Field label={label} hint={invalid ? `Enter a whole number between ${min} and ${max}.` : hint}>
      <Input
        type="number"
        min={min}
        max={max}
        value={Number.isFinite(value) ? value : ''}
        disabled={disabled}
        onChange={(e) => onChange(Number(e.target.value))}
        className={invalid ? 'border-fail' : ''}
      />
    </Field>
  )
}

function SaveRow({
  setting,
  dirty,
  canWrite,
  saving,
  valid,
  userById,
  onSave,
}: {
  setting: Setting
  dirty: boolean
  canWrite: boolean
  saving: boolean
  valid: boolean
  userById: Map<number, User>
  onSave: () => void
}) {
  return (
    <div className="flex flex-wrap items-center gap-3 border-t border-edge pt-3">
      <Button
        variant="primary"
        disabled={!canWrite || !dirty || !valid || saving}
        onClick={onSave}
      >
        {saving ? 'Saving...' : dirty ? 'Save changes' : 'Saved'}
      </Button>
      {!valid && <span className="text-[12px] text-fail">Fix the highlighted fields first.</span>}
      {dirty && valid && (
        <span className="text-[12px] text-incon">
          Unsaved changes. Saving writes every field in this group together.
        </span>
      )}
      <span className="ml-auto">
        <SettingHeader setting={setting} userById={userById} />
      </span>
    </div>
  )
}

function SafetyEditor({ setting, canWrite, saving, userById, onSave }: EditorProps) {
  const initial = setting.value as {
    kill_switch?: boolean
    safe_mode?: boolean
    max_concurrent_runs?: number
  }
  const [killSwitch, setKillSwitch] = useState(initial.kill_switch ?? false)
  const [safeMode, setSafeMode] = useState(initial.safe_mode ?? true)
  const [maxConcurrent, setMaxConcurrent] = useState(initial.max_concurrent_runs ?? 2)

  const current = { kill_switch: killSwitch, safe_mode: safeMode, max_concurrent_runs: maxConcurrent }
  const valid = Number.isInteger(maxConcurrent) && maxConcurrent >= 1 && maxConcurrent <= 16
  const dirty = JSON.stringify(current) !== JSON.stringify(initial)

  return (
    <Panel title="Run safety" actions={<SettingKey name="safety" />}>
      <div className="space-y-4">
        <div className="grid gap-4 md:grid-cols-3">
          <div className="space-y-3 border border-edge bg-panel2 p-3">
            <Checkbox
              label="Kill switch: stop starting new runs"
              checked={killSwitch}
              disabled={!canWrite}
              onChange={setKillSwitch}
            />
            <p className="text-[11px] text-dim">
              While on, no queued run is started. Runs already executing are left to finish or
              cancelled by hand from the Runs page, and queued runs wait until the switch is off.
            </p>
          </div>
          <div className="space-y-3 border border-edge bg-panel2 p-3">
            <Checkbox
              label="Safe mode: non-intrusive checks only"
              checked={safeMode}
              disabled={!canWrite}
              onChange={setSafeMode}
            />
            <p className="text-[11px] text-dim">
              While on, engines use their non-intrusive arguments, which gather facts without
              changing the target. Turning it off allows intrusive arguments that can modify or
              disrupt a target.
            </p>
            {!safeMode && (
              <div className="border border-incon/50 bg-incon/10 p-2 text-[12px] text-ink">
                Safe mode is off. Runs from here on may send intrusive arguments; make sure the
                scopes you run against still authorize what will be sent.
              </div>
            )}
          </div>
          <NumberField
            label="Max concurrent runs"
            hint="How many runs may execute at the same time. A queued run waits for a free slot (1-16)."
            value={maxConcurrent}
            min={1}
            max={16}
            disabled={!canWrite}
            onChange={setMaxConcurrent}
          />
        </div>
        {killSwitch && (
          <div className="border border-fail/50 bg-fail/10 p-3 text-[13px] text-ink">
            <span className="font-mono text-[12px] font-semibold text-fail">KILL SWITCH - </span>
            with this saved, no new run is started and queued runs stay queued until the switch is
            released.
          </div>
        )}
        <SaveRow
          setting={setting}
          dirty={dirty}
          canWrite={canWrite}
          saving={saving}
          valid={valid}
          userById={userById}
          onSave={() => onSave(current)}
        />
      </div>
    </Panel>
  )
}

function RunnerEditor({ setting, canWrite, saving, userById, onSave }: EditorProps) {
  const initial = setting.value as {
    default_timeout_seconds?: number
    max_attempts?: number
    lease_seconds?: number
    max_output_bytes?: number
  }
  const [timeoutSeconds, setTimeoutSeconds] = useState(initial.default_timeout_seconds ?? 300)
  const [maxAttempts, setMaxAttempts] = useState(initial.max_attempts ?? 2)
  const [leaseSeconds, setLeaseSeconds] = useState(initial.lease_seconds ?? 120)
  const [maxOutputBytes, setMaxOutputBytes] = useState(initial.max_output_bytes ?? 4 * 1024 * 1024)

  const current = {
    default_timeout_seconds: timeoutSeconds,
    max_attempts: maxAttempts,
    lease_seconds: leaseSeconds,
    max_output_bytes: maxOutputBytes,
  }
  const valid =
    timeoutSeconds >= 10 &&
    timeoutSeconds <= 3600 &&
    maxAttempts >= 1 &&
    maxAttempts <= 5 &&
    leaseSeconds >= 30 &&
    leaseSeconds <= 1800 &&
    maxOutputBytes >= 64 * 1024 &&
    maxOutputBytes <= 64 * 1024 * 1024
  const dirty = JSON.stringify(current) !== JSON.stringify(initial)

  return (
    <Panel title="Run limits" actions={<SettingKey name="runner" />}>
      <div className="space-y-4">
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          <NumberField
            label="Default timeout (seconds)"
            hint="How long one run may execute before it is stopped (10-3600). A test version that sets its own timeout wins over this."
            value={timeoutSeconds}
            min={10}
            max={3600}
            disabled={!canWrite}
            onChange={setTimeoutSeconds}
          />
          <NumberField
            label="Max attempts"
            hint="How many times a run is tried before it is marked dead (1-5)."
            value={maxAttempts}
            min={1}
            max={5}
            disabled={!canWrite}
            onChange={setMaxAttempts}
          />
          <NumberField
            label="Lease (seconds)"
            hint="How long a run may go without a check-in from its worker before it is treated as abandoned and freed (30-1800)."
            value={leaseSeconds}
            min={30}
            max={1800}
            disabled={!canWrite}
            onChange={setLeaseSeconds}
          />
          <NumberField
            label="Max output bytes"
            hint={`Cap on the output kept for each stream of a run; anything beyond it is cut and marked truncated. Currently ${fmtBytes(maxOutputBytes)} (64 KiB-64 MiB).`}
            value={maxOutputBytes}
            min={64 * 1024}
            max={64 * 1024 * 1024}
            disabled={!canWrite}
            onChange={setMaxOutputBytes}
          />
        </div>
        <SaveRow
          setting={setting}
          dirty={dirty}
          canWrite={canWrite}
          saving={saving}
          valid={valid}
          userById={userById}
          onSave={() => onSave(current)}
        />
      </div>
    </Panel>
  )
}

function StalenessEditor({ setting, canWrite, saving, userById, onSave }: EditorProps) {
  const initial = setting.value as {
    max_age_hours?: number
    on_breach?: string
    severity_floor?: string
  }
  const [maxAgeHours, setMaxAgeHours] = useState(initial.max_age_hours ?? 168)
  const [onBreach, setOnBreach] = useState(initial.on_breach ?? 'mark_stale')
  const [severityFloor, setSeverityFloor] = useState(initial.severity_floor ?? 'medium')

  const current = { max_age_hours: maxAgeHours, on_breach: onBreach, severity_floor: severityFloor }
  const valid = Number.isInteger(maxAgeHours) && maxAgeHours >= 1 && maxAgeHours <= 8760
  const dirty = JSON.stringify(current) !== JSON.stringify(initial)

  return (
    <Panel title="Result freshness" actions={<SettingKey name="staleness" />}>
      <div className="space-y-4">
        <div className="grid gap-4 md:grid-cols-3">
          <NumberField
            label="Max age (hours)"
            hint={`A result stops counting as current after this, and the control shows as needing a fresh check. Currently ${fmtDuration(maxAgeHours * 3600)} (1-8760 hours).`}
            value={maxAgeHours}
            min={1}
            max={8760}
            disabled={!canWrite}
            onChange={setMaxAgeHours}
          />
          <Field
            label="When a result passes its max age"
            hint={
              onBreach === 'queue_run'
                ? 'A fresh run of the test is started against the target automatically.'
                : 'The result is kept, but the control stops counting as current on the overview.'
            }
          >
            <Select
              value={onBreach}
              disabled={!canWrite}
              onChange={(e) => setOnBreach(e.target.value)}
            >
              <option value="mark_stale">Mark it stale</option>
              <option value="queue_run">Queue a re-run</option>
            </Select>
          </Field>
          <Field
            label="Severity floor"
            hint="Findings below this severity are still recorded, but they are not raised for attention."
          >
            <Select
              value={severityFloor}
              disabled={!canWrite}
              onChange={(e) => setSeverityFloor(e.target.value)}
            >
              {severities.map((severity) => (
                <option key={severity} value={severity}>
                  {severityLabel(severity)}
                </option>
              ))}
            </Select>
          </Field>
        </div>
        <SaveRow
          setting={setting}
          dirty={dirty}
          canWrite={canWrite}
          saving={saving}
          valid={valid}
          userById={userById}
          onSave={() => onSave(current)}
        />
      </div>
    </Panel>
  )
}

function GenericEditor({ setting, canWrite, saving, userById, onSave }: EditorProps) {
  const [text, setText] = useState(JSON.stringify(setting.value, null, 2))
  const [parseError, setParseError] = useState<string | null>(null)

  const dirty = text !== JSON.stringify(setting.value, null, 2)

  function submit(): void {
    let parsed: unknown
    try {
      parsed = JSON.parse(text)
    } catch (err) {
      const reason =
        err instanceof Error ? err.message.replace(/\s*in JSON/g, '') : 'unexpected format'
      setParseError(
        `The value could not be read: ${reason}. Check for a missing bracket or quote, then save again.`,
      )
      return
    }
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      setParseError('The value must be a set of named fields.')
      return
    }
    setParseError(null)
    onSave(parsed as Record<string, unknown>)
  }

  return (
    <Panel title={setting.key} actions={<SettingKey name={setting.key} />}>
      <div className="space-y-3">
        <p className="text-[12px] text-dim">
          This group has no editor of its own, so its stored value is shown below and can be changed
          as text. A value the platform refuses is reported here, and nothing is changed until it is
          accepted.
        </p>
        <div>
          <div className="mb-1 text-[11px] tracking-wide text-dim uppercase">Stored value</div>
          <JsonBlock value={setting.value} collapsedHeight={100} />
        </div>
        <Field label="Value" hint="The full stored value, as text. Saving replaces all of it.">
          <Textarea
            rows={6}
            value={text}
            disabled={!canWrite}
            onChange={(e) => {
              setText(e.target.value)
              setParseError(null)
            }}
          />
        </Field>
        {parseError && <ErrorNotice title="Value not accepted" error={new Error(parseError)} />}
        <SaveRow
          setting={setting}
          dirty={dirty}
          canWrite={canWrite}
          saving={saving}
          valid={parseError === null}
          userById={userById}
          onSave={submit}
        />
      </div>
    </Panel>
  )
}

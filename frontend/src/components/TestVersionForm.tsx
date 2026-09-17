import { draftForEngine, type TestVersionDraft } from '../lib/testVersion'
import { severities } from '../lib/tones'
import type { Control, Engine } from '../lib/types'
import { AssertionEditor } from './AssertionEditor'
import { SchemaForm } from './SchemaForm'
import { ErrorNotice, Field, Input, Loading, Select } from './ui'

/**
 * The executable half of a test: engine, typed params (rendered from the
 * engine's params_schema), the assertion and the failure severity.
 */
export function TestVersionForm({
  engines,
  enginesError,
  enginesLoading,
  control,
  draft,
  onChange,
}: {
  engines: Engine[] | undefined
  enginesLoading: boolean
  enginesError: unknown
  control: Control | null
  draft: TestVersionDraft
  onChange: (draft: TestVersionDraft) => void
}) {
  const engine = engines?.find((e) => e.id === draft.engine_id) ?? null

  return (
    <div className="space-y-4">
      {enginesLoading && <Loading label="Loading the engine catalogue" />}
      {enginesError !== null && enginesError !== undefined && (
        <ErrorNotice title="Engine catalogue unavailable" error={enginesError} />
      )}
      {engines && (
        <Field
          label="Engine"
          required
          hint={engine ? engine.description : 'The engine determines which facts the assertion can test.'}
        >
          <Select
            value={draft.engine_id}
            onChange={(e) => {
              const next = engines.find((candidate) => candidate.id === e.target.value)
              onChange(next ? draftForEngine(next) : { ...draft, engine_id: '', engine_params: {} })
            }}
          >
            <option value="">Select an engine...</option>
            {engines.map((candidate) => (
              <option key={candidate.id} value={candidate.id}>
                {candidate.id} - {candidate.title}
              </option>
            ))}
          </Select>
        </Field>
      )}

      {engine && (
        <>
          <div className="grid gap-3 md:grid-cols-2">
            <div className="border border-edge bg-panel2 p-3">
              <h3 className="mb-2 text-[11px] font-semibold tracking-wide text-mute uppercase">
                Engine parameters
              </h3>
              <SchemaForm
                key={draft.engine_id}
                schema={engine.params_schema}
                value={draft.engine_params}
                onChange={(engine_params) => onChange({ ...draft, engine_params })}
              />
            </div>
            <div className="space-y-2 border border-edge bg-panel2 p-3">
              <h3 className="text-[11px] font-semibold tracking-wide text-mute uppercase">
                Engine notes
              </h3>
              <p className="text-[12px] text-mute">{engine.notes}</p>
              <dl className="space-y-1 text-[12px]">
                <div className="flex gap-2">
                  <dt className="w-28 text-dim">Runs against</dt>
                  <dd className="font-mono text-ink">{engine.target_types.join(', ')}</dd>
                </div>
                <div className="flex gap-2">
                  <dt className="w-28 text-dim">Timeout</dt>
                  <dd className="font-mono text-ink">{engine.default_timeout}s default</dd>
                </div>
                <div className="flex gap-2">
                  <dt className="w-28 text-dim">Changes target</dt>
                  <dd className="font-mono text-ink">{engine.mutating ? 'yes' : 'no'}</dd>
                </div>
              </dl>
            </div>
          </div>

          <AssertionEditor
            key={draft.engine_id}
            text={draft.assertion_text}
            onChange={(assertion_text) => onChange({ ...draft, assertion_text })}
            engine={engine}
          />

          <div className="grid gap-3 md:grid-cols-2">
            <Field
              label="Severity on failure"
              hint={
                draft.severity === '' && control
                  ? `Inherits the control's default severity (${control.default_severity}).`
                  : 'Overrides the control default for this test.'
              }
            >
              <Select
                value={draft.severity}
                onChange={(e) => onChange({ ...draft, severity: e.target.value as TestVersionDraft['severity'] })}
              >
                <option value="">(inherit from control)</option>
                {severities.map((severity) => (
                  <option key={severity} value={severity}>
                    {severity}
                  </option>
                ))}
              </Select>
            </Field>
            <Field label="Version note" hint="Why this version exists — stored with it and never edited.">
              <Input
                value={draft.note}
                onChange={(e) => onChange({ ...draft, note: e.target.value })}
                placeholder="e.g. require HSTS max-age >= 15552000"
              />
            </Field>
          </div>
        </>
      )}
    </div>
  )
}

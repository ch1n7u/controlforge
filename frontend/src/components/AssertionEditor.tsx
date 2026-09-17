import { useState } from 'react'
import type { Engine } from '../lib/types'
import { Button, Field, Select, Textarea } from './ui'

const SELECTION_OPS = ['exists', 'not_exists', 'count_eq', 'count_gte', 'count_lte'] as const
const COMPARISON_OPS = [
  'eq',
  'ne',
  'in',
  'not_in',
  'contains',
  'not_contains',
  'matches',
  'not_matches',
  'gt',
  'gte',
  'lt',
  'lte',
] as const

/**
 * A deliberately small JSON editor for assertions. The grammar is declarative
 * (see backend core/assertions.py): groups all/any, conditions select facts and
 * apply one operator. The API validates far more than this editor can, and its
 * error message is shown verbatim.
 */
export function AssertionEditor({
  text,
  onChange,
  engine,
  error,
}: {
  text: string
  onChange: (text: string) => void
  engine: Engine | null
  error?: string | null
}) {
  const [touched, setTouched] = useState(false)
  // The parent remounts this editor when the engine changes, so the first fact
  // type of the current engine is always a safe initial selection.
  const [factType, setFactType] = useState(() => engine?.fact_types[0] ?? '')
  const [op, setOp] = useState<string>('exists')

  const parseError = (() => {
    if (text.trim() === '') return touched ? 'Assertion is required.' : null
    try {
      const parsed: unknown = JSON.parse(text)
      if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
        return 'The assertion must be a JSON object.'
      }
      return null
    } catch (err) {
      return err instanceof Error ? `Not valid JSON: ${err.message}` : 'Not valid JSON.'
    }
  })()

  const insertSkeleton = () => {
    const fact = factType || engine?.fact_types[0] || 'fact_type'
    const leaf: Record<string, unknown> = { fact, op }
    if (!SELECTION_OPS.includes(op as (typeof SELECTION_OPS)[number])) {
      leaf.value = '<expected value>'
    }
    if (text.trim() !== '' && !window.confirm('Replace the current assertion with the new condition?')) {
      return
    }
    onChange(JSON.stringify(leaf, null, 2))
  }

  return (
    <div className="space-y-2">
      <Field
        label="Assertion"
        required
        hint={
          engine
            ? `A condition is {"fact": ..., "op": ..., "value": ...}; {"all": [...]} requires every condition, {"any": [...]} accepts one. This engine reports: ${engine.fact_types.join(', ')}.`
            : 'Select an engine to see which facts this test can assert.'
        }
        error={parseError ?? error ?? null}
      >
        <Textarea
          rows={10}
          value={text}
          spellCheck={false}
          onChange={(e) => {
            setTouched(true)
            onChange(e.target.value)
          }}
          className="text-[12px] leading-5"
        />
      </Field>

      <div className="flex flex-wrap items-end gap-2 border border-edge bg-panel2 p-2">
        <div className="min-w-40 flex-1">
          <span className="mb-1 block text-[11px] tracking-wide text-mute uppercase">Fact</span>
          <Select value={factType} onChange={(e) => setFactType(e.target.value)}>
            {(engine?.fact_types ?? []).map((fact) => (
              <option key={fact} value={fact}>
                {fact}
              </option>
            ))}
          </Select>
        </div>
        <div className="min-w-36">
          <span className="mb-1 block text-[11px] tracking-wide text-mute uppercase">Operator</span>
          <Select value={op} onChange={(e) => setOp(e.target.value)}>
            <optgroup label="Selection">
              {SELECTION_OPS.map((name) => (
                <option key={name} value={name}>
                  {name}
                </option>
              ))}
            </optgroup>
            <optgroup label="Comparison">
              {COMPARISON_OPS.map((name) => (
                <option key={name} value={name}>
                  {name}
                </option>
              ))}
            </optgroup>
          </Select>
        </div>
        <Button onClick={insertSkeleton}>Insert condition</Button>
        <Button
          onClick={() => {
            try {
              onChange(JSON.stringify(JSON.parse(text), null, 2))
            } catch {
              /* parse error already shown above */
            }
          }}
        >
          Format
        </Button>
      </div>
    </div>
  )
}

import { useState } from 'react'
import { nodeType, patternChoices, sortedProperties, unwrapNode } from '../lib/schema'
import type { JsonSchemaNode } from '../lib/types'
import { Checkbox, Field, Input, Select, Textarea } from './ui'

/**
 * Renders a form from an engine's params_schema (pydantic-generated JSON
 * Schema). Types are never coerced silently: what is on screen is what is sent,
 * and the API's rejection is shown verbatim.
 */
export function SchemaForm({
  schema,
  value,
  onChange,
}: {
  schema: JsonSchemaNode
  value: Record<string, unknown>
  onChange: (next: Record<string, unknown>) => void
}) {
  const properties = sortedProperties(schema)
  if (properties.length === 0) {
    return <div className="text-[12px] text-dim">This engine takes no parameters.</div>
  }

  const setField = (name: string, fieldValue: unknown) => {
    const next = { ...value }
    if (fieldValue === undefined) {
      delete next[name]
    } else {
      next[name] = fieldValue
    }
    onChange(next)
  }

  return (
    <div className="space-y-3">
      {properties.map(([name, raw]) => (
        <SchemaField
          key={name}
          name={name}
          raw={raw}
          required={schema.required?.includes(name) ?? false}
          value={value[name]}
          onChange={(v) => setField(name, v)}
        />
      ))}
    </div>
  )
}

function SchemaField({
  name,
  raw,
  required,
  value,
  onChange,
}: {
  name: string
  raw: JsonSchemaNode
  required: boolean
  value: unknown
  onChange: (value: unknown) => void
}) {
  const { node, nullable } = unwrapNode(raw)
  const type = nodeType(node)
  const title = node.title ?? name
  const hint = node.description ?? (nullable ? 'Optional' : undefined)

  if (type === 'boolean') {
    return (
      <div>
        <Checkbox
          label={title}
          checked={value === true}
          onChange={(checked) => onChange(checked)}
        />
        {hint && <div className="mt-0.5 ml-5 text-[11px] text-dim">{hint}</div>}
      </div>
    )
  }

  if (type === 'integer' || type === 'number') {
    const constraints = [
      node.minimum !== undefined ? `min ${node.minimum}` : null,
      node.maximum !== undefined ? `max ${node.maximum}` : null,
    ]
      .filter(Boolean)
      .join(', ')
    return (
      <Field label={title} required={required} hint={[hint, constraints].filter(Boolean).join(' · ')}>
        <Input
          type="number"
          step={type === 'integer' ? 1 : 'any'}
          min={node.minimum}
          max={node.maximum}
          value={value === undefined || value === null ? '' : String(value)}
          onChange={(e) => {
            const text = e.target.value
            if (text === '') {
              onChange(undefined)
              return
            }
            const parsed = Number(text)
            if (Number.isNaN(parsed)) return
            onChange(parsed)
          }}
        />
      </Field>
    )
  }

  if (type === 'array') {
    return (
      <StringListField
        title={title}
        required={required}
        hint={hint}
        itemEnum={node.items?.enum}
        value={Array.isArray(value) ? (value as unknown[]) : []}
        onChange={onChange}
      />
    )
  }

  if (node.enum && node.enum.length > 0) {
    return (
      <Field label={title} required={required} hint={hint}>
        <Select
          value={value === undefined || value === null ? '' : String(value)}
          onChange={(e) => onChange(e.target.value === '' ? undefined : e.target.value)}
        >
          {!required && <option value="">(not set)</option>}
          {node.enum.map((option) => (
            <option key={String(option)} value={String(option)}>
              {String(option)}
            </option>
          ))}
        </Select>
      </Field>
    )
  }

  if (type === 'string') {
    const choices = patternChoices(node.pattern)
    if (choices) {
      return (
        <Field label={title} required={required} hint={hint}>
          <Select
            value={value === undefined || value === null ? '' : String(value)}
            onChange={(e) => onChange(e.target.value === '' ? undefined : e.target.value)}
          >
            <option value="">{required ? 'Select a value...' : '(not set)'}</option>
            {choices.map((choice) => (
              <option key={choice} value={choice}>
                {choice}
              </option>
            ))}
          </Select>
        </Field>
      )
    }
    return (
      <Field label={title} required={required} hint={hint}>
        <Input
          value={value === undefined || value === null ? '' : String(value)}
          onChange={(e) => onChange(e.target.value === '' ? undefined : e.target.value)}
          className="font-mono text-[12px]"
        />
      </Field>
    )
  }

  // Fallback: an opaque object schema edited as JSON.
  return <JsonField title={title} hint={hint} value={value} onChange={onChange} />
}

function StringListField({
  title,
  required,
  hint,
  itemEnum,
  value,
  onChange,
}: {
  title: string
  required: boolean
  hint?: string
  itemEnum?: unknown[]
  value: unknown[]
  onChange: (value: unknown) => void
}) {
  const asText = (list: unknown[]) => list.map(String).join(', ')
  // Local text so a half-typed list ("a, b,") survives until it parses. The
  // parent remounts this form when the engine changes (see TestVersionForm's
  // key), so no prop-sync effect is needed or wanted here.
  const [text, setText] = useState(() => asText(value))

  const enumError =
    itemEnum && itemEnum.length > 0
      ? parseList(text).find((item) => !itemEnum.map(String).includes(item))
      : undefined

  return (
    <Field
      label={title}
      required={required}
      hint={[hint, 'Comma-separated list'].filter(Boolean).join(' · ')}
      error={enumError ? `"${enumError}" is not one of: ${itemEnum?.map(String).join(', ')}.` : null}
    >
      <Input
        value={text}
        onChange={(e) => {
          setText(e.target.value)
          onChange(parseList(e.target.value))
        }}
        className="font-mono text-[12px]"
      />
    </Field>
  )
}

function parseList(text: string): string[] {
  return text
    .split(',')
    .map((part) => part.trim())
    .filter((part) => part !== '')
}

function JsonField({
  title,
  hint,
  value,
  onChange,
}: {
  title: string
  hint?: string
  value: unknown
  onChange: (value: unknown) => void
}) {
  const [text, setText] = useState(() => (value === undefined ? '' : JSON.stringify(value, null, 2)))
  const [error, setError] = useState<string | null>(null)
  return (
    <Field label={title} hint={hint} error={error}>
      <Textarea
        rows={4}
        value={text}
        onChange={(e) => {
          setText(e.target.value)
          if (e.target.value.trim() === '') {
            setError(null)
            onChange(undefined)
            return
          }
          try {
            onChange(JSON.parse(e.target.value))
            setError(null)
          } catch (err) {
            setError(err instanceof Error ? `Not valid JSON: ${err.message}` : 'Not valid JSON.')
          }
        }}
      />
    </Field>
  )
}

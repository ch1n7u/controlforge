/** Small helpers for reading pydantic-generated JSON schemas. */

import type { JsonSchemaNode } from './types'

/** AnyOf with null (an optional field) resolves to the real branch. */
export function unwrapNode(node: JsonSchemaNode): { node: JsonSchemaNode; nullable: boolean } {
  if (node.anyOf && node.anyOf.length > 0) {
    const nullable = node.anyOf.some((branch) => branch.type === 'null')
    const real = node.anyOf.find((branch) => branch.type !== 'null' && branch.$ref === undefined)
    const ref = node.anyOf.find((branch) => branch.$ref !== undefined)
    return { node: real ?? ref ?? node, nullable }
  }
  return { node, nullable: false }
}

export function nodeType(node: JsonSchemaNode): string {
  const { node: real } = unwrapNode(node)
  if (Array.isArray(real.type)) {
    const first = real.type.find((t) => t !== 'null')
    return first ?? 'string'
  }
  if (real.type) return real.type
  if (real.enum) return 'enum'
  return 'object'
}

/** Seed a params object from the schema's declared defaults. */
export function defaultsFromSchema(schema: JsonSchemaNode): Record<string, unknown> {
  const out: Record<string, unknown> = {}
  const properties = schema.properties ?? {}
  for (const [name, raw] of Object.entries(properties)) {
    const { node } = unwrapNode(raw)
    if (node.default !== undefined) {
      out[name] = node.default
    } else if (node.enum && node.enum.length > 0) {
      out[name] = node.enum[0]
    }
  }
  return out
}

export function sortedProperties(
  schema: JsonSchemaNode,
): Array<[string, JsonSchemaNode]> {
  return Object.entries(schema.properties ?? {})
}

/**
 * A pattern that is nothing but a literal alternation (`^(GET|HEAD)$`) is a
 * fixed set of accepted values wearing a regex costume - it is how pydantic
 * spells "one of these words". A dropdown is the honest control for that;
 * anything with real regex structure stays a free text field.
 */
export function patternChoices(pattern: string | null | undefined): string[] | null {
  if (!pattern) return null
  const match = /^\^\(([^()]+)\)\$$/.exec(pattern)
  if (!match) return null
  const choices = match[1].split('|')
  if (choices.length < 2 || choices.some((choice) => !/^[A-Za-z0-9_.:-]+$/.test(choice))) {
    return null
  }
  return choices
}

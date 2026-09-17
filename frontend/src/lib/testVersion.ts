/** Draft state and payload building for test versions (authoring forms). */

import { defaultsFromSchema } from './schema'
import type { Engine, Severity, TestVersionCreate } from './types'

export interface TestVersionDraft {
  engine_id: string
  engine_params: Record<string, unknown>
  assertion_text: string
  /** Empty string means "inherit the control's severity". */
  severity: Severity | ''
  note: string
}

export function emptyDraft(): TestVersionDraft {
  return {
    engine_id: '',
    engine_params: {},
    assertion_text: '',
    severity: '',
    note: '',
  }
}

export function draftForEngine(engine: Engine): TestVersionDraft {
  return {
    engine_id: engine.id,
    engine_params: defaultsFromSchema(engine.params_schema),
    assertion_text: '',
    severity: '',
    note: '',
  }
}

export function buildTestVersion(
  draft: TestVersionDraft,
): { payload: TestVersionCreate } | { error: string } {
  if (draft.engine_id === '') return { error: 'Choose an engine.' }
  if (draft.assertion_text.trim() === '') return { error: 'Enter an assertion before saving.' }
  let assertion: unknown
  try {
    assertion = JSON.parse(draft.assertion_text)
  } catch (err) {
    return { error: `Not valid JSON: ${err instanceof Error ? err.message : 'parse error'}` }
  }
  if (typeof assertion !== 'object' || assertion === null || Array.isArray(assertion)) {
    return { error: 'The assertion must be a JSON object.' }
  }
  const payload: TestVersionCreate = {
    engine_id: draft.engine_id,
    engine_params: draft.engine_params,
    assertion: assertion as Record<string, unknown>,
  }
  if (draft.severity !== '') payload.severity = draft.severity
  if (draft.note.trim() !== '') payload.note = draft.note.trim()
  return { payload }
}

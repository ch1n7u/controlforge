import { useMutation, useQuery } from '@tanstack/react-query'
import { useMemo, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { api, qk } from '../lib/api'
import type { RunSummary, Target } from '../lib/types'
import { Button, EmptyState, ErrorNotice, Field, Input, Loading, Modal, Select } from './ui'

/**
 * Queue one run per selected target for a chosen test. Used from the Runs page,
 * a target's detail page (target fixed) and a test's detail page (test fixed).
 */
export function RunDialog({
  onClose,
  fixedTestId,
  fixedTargetId,
}: {
  onClose: () => void
  fixedTestId?: number
  fixedTargetId?: number
}) {
  const navigate = useNavigate()
  const [testId, setTestId] = useState<number | null>(fixedTestId ?? null)
  const [targetIds, setTargetIds] = useState<number[]>(fixedTargetId !== undefined ? [fixedTargetId] : [])
  const [filter, setFilter] = useState('')

  const tests = useQuery({
    queryKey: qk.tests({ enabled: true, limit: 1000 }),
    queryFn: () => api.tests({ enabled: true, limit: 1000 }),
    staleTime: 60_000,
  })
  const targets = useQuery({
    queryKey: qk.targets({ enabled: true, limit: 1000 }),
    queryFn: () => api.targets({ enabled: true, limit: 1000 }),
    staleTime: 60_000,
  })

  const mutation = useMutation({
    mutationFn: () => api.startRun(testId ?? 0, targetIds),
    onSuccess: (result) => {
      const first: RunSummary | undefined = result.runs?.[0]
      onClose()
      if (first) {
        navigate(`/runs/${first.id}`)
      } else {
        navigate('/runs')
      }
    },
  })

  const visibleTargets = useMemo(() => {
    const list = targets.data ?? []
    const needle = filter.trim().toLowerCase()
    if (!needle) return list
    return list.filter(
      (t) =>
        t.name.toLowerCase().includes(needle) ||
        t.host.toLowerCase().includes(needle) ||
        t.tags.some((tag) => tag.toLowerCase().includes(needle)),
    )
  }, [targets.data, filter])

  const toggleTarget = (target: Target) => {
    setTargetIds((current) =>
      current.includes(target.id)
        ? current.filter((id) => id !== target.id)
        : [...current, target.id],
    )
  }

  const canSubmit = testId !== null && targetIds.length > 0 && !mutation.isPending

  return (
    <Modal title="Queue a validation run" onClose={onClose} width="max-w-2xl">
      <div className="space-y-4">
        {tests.isPending && <Loading label="Loading tests" />}
        {tests.isError && <ErrorNotice error={tests.error} onRetry={() => void tests.refetch()} />}
        {tests.data && tests.data.length === 0 && (
          <EmptyState
            title="No enabled tests exist yet"
            hint="Author a test under Tests first; a run needs a published test version to execute."
          />
        )}

        <Field label="Test" required hint="Each selected target gets its own run, sharing this test version.">
          <Select
            value={testId ?? ''}
            disabled={fixedTestId !== undefined}
            onChange={(e) => setTestId(e.target.value ? Number(e.target.value) : null)}
          >
            <option value="">Select a test...</option>
            {(tests.data ?? []).map((test) => (
              <option key={test.id} value={test.id}>
                {test.key} - {test.name} (v{test.current_version})
              </option>
            ))}
          </Select>
        </Field>

        {fixedTargetId === undefined ? (
          <div>
            <div className="mb-1 flex items-center justify-between">
              <span className="text-[11px] tracking-wide text-mute uppercase">
                Targets
                <span aria-hidden className="ml-1 text-dim">
                  *
                </span>
                <span className="sr-only"> (required)</span>
              </span>
              <span className="font-mono text-[11px] text-dim">{targetIds.length} selected</span>
            </div>
            <Input
              type="search"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              placeholder="Filter by name, host or tag"
              className="mb-1"
            />
            {targets.isPending && <Loading label="Loading targets" />}
            {targets.isError && <ErrorNotice error={targets.error} onRetry={() => void targets.refetch()} />}
            <div className="max-h-56 overflow-auto border border-edge">
              {visibleTargets.length === 0 ? (
                <div className="px-3 py-4 text-center text-[12px] text-dim">
                  {(targets.data ?? []).length === 0
                    ? 'No target is enabled for validation. Register one under Targets and attach it to a scope.'
                    : 'No target matches this filter.'}
                </div>
              ) : (
                <ul>
                  {visibleTargets.map((target) => (
                    <li key={target.id} className="border-b border-edge/60 last:border-b-0">
                      <label className="flex cursor-pointer items-center gap-2 px-2 py-1.5 hover:bg-raise">
                        <input
                          type="checkbox"
                          checked={targetIds.includes(target.id)}
                          onChange={() => toggleTarget(target)}
                          className="size-3.5 accent-[var(--color-accent)]"
                        />
                        <span className="text-[13px] text-ink">{target.name}</span>
                        <span className="font-mono text-[12px] text-mute">
                          {target.host}
                          {target.port ? `:${target.port}` : ''}
                        </span>
                        <span className="ml-auto font-mono text-[11px] text-dim">{target.target_type}</span>
                      </label>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </div>
        ) : (
          <div className="text-[12px] text-dim">
            Running against this target. You can also start runs from the{' '}
            <Link to="/runs" className="text-accent hover:underline">
              Runs
            </Link>{' '}
            page.
          </div>
        )}

        {mutation.isError && <ErrorNotice error={mutation.error} />}

        <div className="flex items-center justify-between gap-2">
          <span className="text-[12px] text-dim">
            Each run is limited to the addresses and ports the target's scope authorizes.
          </span>
          <div className="flex gap-2">
            <Button onClick={onClose}>Cancel</Button>
            <Button variant="primary" disabled={!canSubmit} onClick={() => mutation.mutate()}>
              {mutation.isPending
                ? 'Queuing...'
                : targetIds.length === 1
                  ? 'Queue run'
                  : 'Queue runs'}
            </Button>
          </div>
        </div>
      </div>
    </Modal>
  )
}

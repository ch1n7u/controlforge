import { useEffect, useRef, useState } from 'react'
import { api } from '../lib/api'
import { runStatuses } from '../lib/tones'
import type { LogLine, RunStatus, StreamKind } from '../lib/types'

/**
 * Live run log.
 *
 * Primary transport is the SSE stream (`GET /api/runs/{id}/stream`), which
 * carries `log` / `status` / `done` events. If EventSource fails (proxy,
 * stream closed early, run finished between polls) the hook falls back to
 * polling `GET /api/runs/{id}/log?after_id=` and keeps going: the log is the
 * operator's only window into what a run actually did, so it must never
 * silently go dark.
 */

const POLL_MS = 2000
const MAX_LINES = 5000

export interface RunLogState {
  lines: LogLine[]
  transport: 'connecting' | 'sse' | 'polling'
  streamError: string | null
  lastEventAt: string | null
}

function emptyLog(): RunLogState {
  return { lines: [], transport: 'connecting', streamError: null, lastEventAt: null }
}

export function useRunLog(
  runId: number,
  opts: {
    /** True while the run is queued/running: keep the stream open. */
    live: boolean
    onStatus?: (status: RunStatus) => void
    onDone?: () => void
  },
) {
  // The state carries the run it belongs to. Reading it for a different run
  // returns an empty log instead of the previous run's lines, so switching
  // runs needs no reset effect (and no cascading render).
  const [stored, setStored] = useState<RunLogState & { runId: number }>(() => ({
    ...emptyLog(),
    runId,
  }))
  const lastIdRef = useRef(0)
  const statusRef = useRef(opts.onStatus)
  const doneRef = useRef(opts.onDone)
  const live = opts.live

  useEffect(() => {
    statusRef.current = opts.onStatus
    doneRef.current = opts.onDone
  })

  useEffect(() => {
    let cancelled = false
    let source: EventSource | null = null
    let pollTimer: number | null = null
    lastIdRef.current = 0

    function patch(fields: Partial<Omit<RunLogState, 'lines'>> & { lines?: LogLine[] }): void {
      setStored((prev) => ({
        ...(prev.runId === runId ? prev : emptyLog()),
        ...fields,
        runId,
      }))
    }

    function merge(incoming: LogLine[]): void {
      if (incoming.length === 0) return
      for (const line of incoming) {
        if (line.id > lastIdRef.current) lastIdRef.current = line.id
      }
      setStored((prev) => {
        const base = prev.runId === runId ? prev.lines : []
        const byId = new Map(base.map((line) => [line.id, line]))
        for (const line of incoming) byId.set(line.id, line)
        const merged = [...byId.values()].sort((a, b) => a.id - b.id)
        return {
          runId,
          lines: merged.length > MAX_LINES ? merged.slice(merged.length - MAX_LINES) : merged,
          transport: prev.runId === runId ? prev.transport : 'connecting',
          streamError: prev.runId === runId ? prev.streamError : null,
          lastEventAt: new Date().toISOString(),
        }
      })
    }

    async function initialHistory(): Promise<void> {
      try {
        const history = await api.runLog(runId, 0, 2000)
        if (!cancelled) merge(history)
      } catch (err) {
        if (!cancelled) {
          patch({ streamError: err instanceof Error ? err.message : 'Could not load the run log.' })
        }
      }
    }

    async function pollOnce(): Promise<void> {
      try {
        const fresh = await api.runLog(runId, lastIdRef.current, 2000)
        if (cancelled) return
        merge(fresh)
        patch({ transport: 'polling', streamError: null })
      } catch (err) {
        if (cancelled) return
        patch({
          transport: 'polling',
          streamError: err instanceof Error ? err.message : 'Could not refresh the run log.',
        })
      }
    }

    function startPolling(): void {
      if (pollTimer !== null) return
      patch({ transport: 'polling' })
      void pollOnce()
      pollTimer = window.setInterval(() => void pollOnce(), POLL_MS)
    }

    function handlePayload(raw: string): void {
      let parsed: unknown
      try {
        parsed = JSON.parse(raw)
      } catch {
        return
      }
      if (typeof parsed !== 'object' || parsed === null) return
      const record = parsed as Record<string, unknown>
      const type = typeof record.type === 'string' ? record.type : ''
      if (type === 'status') {
        const status = asRunStatus(record.status)
        if (status) statusRef.current?.(status)
        return
      }
      if (type === 'done') {
        doneRef.current?.()
        return
      }
      const line = asLogLine(parsed)
      if (line) merge([line])
    }

    function openStream(): void {
      source = new EventSource(api.runStreamUrl(runId))
      source.onopen = () => {
        if (cancelled) return
        patch({ transport: 'sse', streamError: null })
      }
      source.onmessage = (event: MessageEvent<string>) => handlePayload(event.data)
      const namedEvents = ['log', 'status', 'done'] as const
      for (const name of namedEvents) {
        source.addEventListener(name, (event) => {
          const data = (event as MessageEvent<string>).data
          if (name === 'log' || data.includes('"type"')) {
            handlePayload(data)
          } else {
            // The event name carries the type; synthesise it for the dispatcher.
            handlePayload(JSON.stringify({ type: name, ...safeObject(data) }))
          }
        })
      }
      source.onerror = () => {
        if (cancelled) return
        source?.close()
        source = null
        if (live) {
          patch({ transport: 'polling', streamError: null })
          startPolling()
        } else {
          patch({
            transport: 'polling',
            streamError: 'Live updates stopped; the log was completed from the server.',
          })
        }
      }
    }

    void (async () => {
      await initialHistory()
      if (cancelled) return
      if (live) {
        openStream()
      } else {
        // Terminal run: poll until two consecutive empty responses so lines
        // written just after we arrived are still caught.
        let emptyStreak = 0
        for (let attempt = 0; attempt < 5 && emptyStreak < 2 && !cancelled; attempt += 1) {
          const before = lastIdRef.current
          await pollOnce()
          if (cancelled) return
          emptyStreak = lastIdRef.current === before ? emptyStreak + 1 : 0
          if (emptyStreak < 2) await sleep(POLL_MS)
        }
      }
    })()

    return () => {
      cancelled = true
      source?.close()
      if (pollTimer !== null) window.clearInterval(pollTimer)
    }
  }, [runId, live])

  return stored.runId === runId ? stored : emptyLog()
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => window.setTimeout(resolve, ms))
}

function safeObject(data: string): Record<string, unknown> {
  try {
    const parsed: unknown = JSON.parse(data)
    if (typeof parsed === 'object' && parsed !== null) return parsed as Record<string, unknown>
  } catch {
    return {}
  }
  return {}
}

export function asRunStatus(value: unknown): RunStatus | null {
  if (typeof value === 'string' && (runStatuses as readonly string[]).includes(value)) {
    return value as RunStatus
  }
  return null
}

export function asLogLine(value: unknown): LogLine | null {
  if (typeof value !== 'object' || value === null) return null
  const record = value as Record<string, unknown>
  if (typeof record.id !== 'number') return null
  if (typeof record.message !== 'string' && typeof record.line !== 'string') return null
  const streams: StreamKind[] = ['stdout', 'stderr', 'system']
  const stream =
    typeof record.stream === 'string' && (streams as string[]).includes(record.stream)
      ? (record.stream as StreamKind)
      : 'system'
  return {
    id: record.id,
    ts: typeof record.ts === 'string' ? record.ts : new Date().toISOString(),
    stream,
    level: typeof record.level === 'string' ? record.level : 'info',
    message:
      typeof record.message === 'string'
        ? record.message
        : typeof record.line === 'string'
          ? record.line
          : '',
  }
}

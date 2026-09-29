import { useQuery } from '@tanstack/react-query'
import { useState, type ReactNode } from 'react'
import { Link, useParams } from 'react-router-dom'
import { ArgvView, Hash, JsonBlock } from '../components/Json'
import {
  Badge,
  Button,
  ErrorNotice,
  KeyValue,
  Loading,
  PageHeader,
  Panel,
} from '../components/ui'
import { api, fetchEvidenceContent, qk } from '../lib/api'
import { fmtBytes, fmtDateTime } from '../lib/format'

const PREVIEW_CHARS = 200_000

const evidenceKindLabel: Record<string, string> = {
  stdout: 'Standard output',
  stderr: 'Error output',
  artifact: 'Artifact',
}

/** A digest shown short, with the full value one copy away. */
function DigestValue({ value, label }: { value: string | null | undefined; label: string }) {
  const [copied, setCopied] = useState(false)
  if (!value) return <span className="text-dim">not recorded</span>
  const copy = (): void => {
    void navigator.clipboard.writeText(value).then(() => {
      setCopied(true)
      window.setTimeout(() => setCopied(false), 1500)
    })
  }
  return (
    <span className="inline-flex flex-wrap items-center gap-2">
      <Hash value={value} length={20} />
      <button
        type="button"
        onClick={copy}
        title={`Copy the full digest for ${label}`}
        className="border border-edge2 px-1.5 py-px text-[11px] text-mute hover:bg-raise hover:text-ink"
      >
        {copied ? 'Copied' : 'Copy'}
      </button>
    </span>
  )
}

function str(value: unknown): string | null {
  return typeof value === 'string' ? value : null
}

function num(value: unknown): number | null {
  return typeof value === 'number' ? value : null
}

const DETAIL_KEYS = ['engine', 'target', 'argv', 'truncated', 'original_size_bytes', 'original_sha256']

export function EvidenceDetailPage() {
  const params = useParams()
  const evidenceId = Number(params.id)

  const item = useQuery({
    queryKey: qk.evidenceItem(evidenceId),
    queryFn: () => api.evidenceItem(evidenceId),
    staleTime: 30_000,
  })

  const [preview, setPreview] = useState<string | null>(null)
  const [previewNote, setPreviewNote] = useState<string | null>(null)
  const [previewBusy, setPreviewBusy] = useState(false)
  const [previewError, setPreviewError] = useState<unknown>(null)
  const [downloadBusy, setDownloadBusy] = useState(false)

  if (item.isPending) return <Loading label="Loading evidence" />
  if (item.isError) return <ErrorNotice error={item.error} onRetry={() => void item.refetch()} />
  const e = item.data
  const verification = e.verification

  const textish =
    e.mime.startsWith('text/') ||
    e.mime.includes('json') ||
    e.mime.includes('xml') ||
    e.mime.includes('csv') ||
    e.kind === 'stdout' ||
    e.kind === 'stderr'

  const detail = e.detail
  const engine = str(detail?.engine)
  const target = str(detail?.target)
  const rawArgv: unknown = detail?.argv
  const argv = Array.isArray(rawArgv) ? rawArgv.map(String) : null
  const detailTruncated = detail?.truncated === true
  const originalSize = num(detail?.original_size_bytes)
  const originalSha = str(detail?.original_sha256)
  const extraDetail = detail
    ? Object.fromEntries(Object.entries(detail).filter(([key]) => !DETAIL_KEYS.includes(key)))
    : {}

  const integrityItems: Array<[string, ReactNode]> = [
    ['Digest recorded at write', <DigestValue key="recorded" value={e.sha256} label="this evidence" />],
    ['Digest of the stored file', <DigestValue key="stored" value={verification.sha256} label="the stored file" />],
    ['Size recorded at write', fmtBytes(e.size_bytes)],
    ['Size of the stored file', verification.size_bytes === null ? 'not present' : fmtBytes(verification.size_bytes)],
  ]
  if (!verification.intact) {
    integrityItems.push(
      ['File present', verification.exists ? 'yes' : 'no'],
      ['Size matches the record', verification.size_matches ? 'yes' : 'no'],
    )
  }

  const captureItems: Array<[string, ReactNode]> = [
    ['Engine', engine ?? '-'],
    ['Target', target ?? '-'],
  ]
  if (detailTruncated) {
    captureItems.push(
      ['Output before truncation', originalSize === null ? '-' : fmtBytes(originalSize)],
      ['Digest before truncation', <DigestValue key="orig" value={originalSha} label="the untruncated output" />],
    )
  }

  async function loadPreview(): Promise<void> {
    setPreviewBusy(true)
    setPreviewError(null)
    try {
      const result = await fetchEvidenceContent(evidenceId)
      const text = await result.blob.text()
      if (text.length > PREVIEW_CHARS) {
        setPreview(text.slice(0, PREVIEW_CHARS))
        setPreviewNote(
          `Showing the first ${PREVIEW_CHARS.toLocaleString()} characters of ${text.length.toLocaleString()}. Download for the full capture.`,
        )
      } else {
        setPreview(text)
        setPreviewNote(null)
      }
      if (!result.intact) {
        setPreviewNote((prev) =>
          `${prev ? `${prev} ` : ''}The preview does not match the recorded digest, so it is not the original capture.`,
        )
      }
    } catch (err) {
      setPreviewError(err)
    } finally {
      setPreviewBusy(false)
    }
  }

  async function download(): Promise<void> {
    setDownloadBusy(true)
    setPreviewError(null)
    try {
      const result = await fetchEvidenceContent(evidenceId)
      const url = URL.createObjectURL(result.blob)
      const anchor = document.createElement('a')
      anchor.href = url
      anchor.download = e.filename
      document.body.appendChild(anchor)
      anchor.click()
      anchor.remove()
      window.setTimeout(() => URL.revokeObjectURL(url), 10_000)
    } catch (err) {
      setPreviewError(err)
    } finally {
      setDownloadBusy(false)
    }
  }

  return (
    <div className="space-y-4">
      <PageHeader
        title={
          <span className="flex flex-wrap items-baseline gap-3">
            <span>Evidence #{e.id}</span>
            <span className="font-mono text-[14px] text-mute">{e.filename}</span>
          </span>
        }
        subtitle={
          <span className="flex flex-wrap items-center gap-2">
            <Badge tone="mute">{evidenceKindLabel[e.kind] ?? e.kind}</Badge>
            <span className="font-mono text-[12px] text-mute">{e.mime}</span>
            <span className="text-dim">stored by</span>
            <Link to={`/runs/${e.run_id}`} className="font-mono text-[12px] text-accent hover:underline">
              run #{e.run_id}
            </Link>
            {e.truncated && (
              <Badge tone="incon" title="The capture reached the run's output limit and was cut">
                truncated capture
              </Badge>
            )}
          </span>
        }
        actions={
          <>
            <Button variant="primary" disabled={downloadBusy} onClick={() => void download()}>
              {downloadBusy ? 'Preparing...' : 'Download'}
            </Button>
            <Link
              to={`/evidence?run_id=${e.run_id}`}
              className="text-[13px] text-accent hover:underline"
            >
              All evidence from this run
            </Link>
          </>
        }
      />

      {!verification.intact && (
        <div className="border-2 border-fail bg-fail/15 p-3">
          <div className="font-mono text-[12px] font-semibold tracking-wide text-fail uppercase">
            Integrity check failed - this capture has changed
          </div>
          <p className="mt-1 text-[13px] text-ink">
            The file stored for this evidence does not match the digest recorded when the run wrote
            it. Evidence is written once and never modified, so this should not happen; treat the
            content as unverified and check the evidence store before relying on this capture.
          </p>
          <p className="mt-2 flex flex-wrap items-center gap-x-2 text-[12px] text-ink/90">
            <span className="text-mute">Recorded digest</span>
            <DigestValue value={e.sha256} label="this evidence" />
          </p>
          <p className="mt-1 text-[12px] text-ink/90">
            <span className="text-mute">File on disk</span>{' '}
            {verification.exists ? 'present, but its bytes differ' : 'missing'}
          </p>
        </div>
      )}

      <div className="grid gap-3 lg:grid-cols-3">
        <Panel title="Integrity check" className="lg:col-span-2">
          <div className="space-y-3">
            <div className="flex flex-wrap items-center gap-3">
              {verification.intact ? (
                <Badge tone="pass" dot>
                  verified intact
                </Badge>
              ) : (
                <Badge tone="fail" dot>
                  changed since it was stored
                </Badge>
              )}
              <span className="text-[12px] text-mute">
                Checked against the stored file when this page loaded.
              </span>
              <Button size="sm" onClick={() => void item.refetch()} disabled={item.isFetching}>
                {item.isFetching ? 'Checking...' : 'Check again'}
              </Button>
            </div>

            <p className="text-[13px] text-ink">
              {verification.intact
                ? 'The stored file matches both the digest and the size recorded when the run wrote it. This is exactly what was captured.'
                : 'The stored file no longer matches the digest recorded at write time. Until the evidence store is checked, treat this capture as unverified.'}
            </p>

            <KeyValue items={integrityItems} />

            <p className="text-[12px] text-dim">
              Evidence is written once and never changed, so any mismatch means the store itself was
              altered outside CONTROLFORGE.
            </p>
          </div>
        </Panel>

        <Panel title="Capture details">
          <KeyValue
            columns={1}
            items={[
              ['Run', <Link key="run" to={`/runs/${e.run_id}`} className="text-accent hover:underline">run #{e.run_id}</Link>],
              ['Kind', evidenceKindLabel[e.kind] ?? e.kind],
              ['Filename', <span key="fn" className="font-mono text-[12px] break-all">{e.filename}</span>],
              ['Content type', e.mime],
              ['Size', fmtBytes(e.size_bytes)],
              ['Output limit', e.truncated ? 'reached - the stored file holds the first part of the output' : 'not reached'],
              ['Stored', fmtDateTime(e.created_at)],
            ]}
          />
        </Panel>
      </div>

      {e.truncated && (
        <div className="border border-incon/50 bg-incon/10 p-3 text-[13px] text-ink">
          <span className="font-mono text-[12px] font-semibold text-incon">TRUNCATED - </span>
          this capture hit the run's output limit, so the stored file holds only the first part of the
          engine's output. The digest and size above describe the stored file, not the full output.
        </div>
      )}

      {detail !== null && (
        <Panel title="What was recorded with this capture">
          <div className="space-y-3">
            <KeyValue items={captureItems} />
            <div>
              <div className="mb-1 text-[11px] tracking-wide text-dim uppercase">
                Command line
              </div>
              <ArgvView argv={argv} />
            </div>
            {Object.keys(extraDetail).length > 0 && (
              <div>
                <div className="mb-1 text-[11px] tracking-wide text-dim uppercase">
                  Other recorded fields
                </div>
                <JsonBlock value={extraDetail} />
              </div>
            )}
          </div>
        </Panel>
      )}

      <Panel
        title="Content"
        actions={
          textish ? (
            <Button size="sm" disabled={previewBusy} onClick={() => void loadPreview()}>
              {previewBusy ? 'Loading...' : preview === null ? 'Load preview' : 'Reload preview'}
            </Button>
          ) : (
            <span className="text-[11px] text-dim">download only</span>
          )
        }
      >
        {!textish && preview === null ? (
          <div className="text-[12px] text-dim">
            This capture is stored as {e.mime} and is offered as a download only. The digest above
            identifies its contents.
          </div>
        ) : previewError !== null ? (
          <ErrorNotice title="Preview failed" error={previewError} />
        ) : preview === null ? (
          <div className="text-[12px] text-dim">
            Loading the preview re-checks the served bytes against the recorded digest, so you can
            read the capture without downloading it.
          </div>
        ) : (
          <div className="space-y-2">
            {previewNote && (
              <div className="border border-incon/40 bg-incon/10 px-3 py-1.5 text-[12px] text-ink">
                {previewNote}
              </div>
            )}
            <pre className="max-h-[32rem] overflow-auto border border-edge bg-bg p-2 font-mono text-[12px] whitespace-pre-wrap text-ink/90">
              {preview}
            </pre>
          </div>
        )}
      </Panel>
    </div>
  )
}

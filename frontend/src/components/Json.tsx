/** Expandable displays for JSON blobs, digests and long machine strings. */

import { useState, type ReactNode } from 'react'

export function JsonBlock({
  value,
  label,
  collapsedHeight = 160,
}: {
  value: unknown
  label?: string
  collapsedHeight?: number
}) {
  const [expanded, setExpanded] = useState(false)
  let text: string
  try {
    text = JSON.stringify(value, null, 2) ?? 'null'
  } catch {
    text = String(value)
  }
  const long = text.length > 240 || text.split('\n').length > 8
  const shown = expanded || !long ? text : clip(text, 320)
  return (
    <div className="border border-edge bg-bg">
      {(label || long) && (
        <div className="flex items-center justify-between border-b border-edge px-2 py-1">
          <span className="font-mono text-[11px] text-dim">{label ?? 'JSON'}</span>
          {long && (
            <button
              type="button"
              onClick={() => setExpanded((v) => !v)}
              className="text-[11px] text-mute hover:text-ink"
            >
              {expanded ? 'Collapse' : `Expand (${text.length.toLocaleString()} characters)`}
            </button>
          )}
        </div>
      )}
      <pre
        className="overflow-auto p-2 font-mono text-[12px] whitespace-pre text-ink/90"
        style={{ maxHeight: expanded ? undefined : collapsedHeight }}
      >
        {shown}
      </pre>
    </div>
  )
}

function clip(text: string, max: number): string {
  return text.length > max ? `${text.slice(0, max)}...` : text
}

export function Hash({ value, length = 12 }: { value: string | null | undefined; length?: number }) {
  const [expanded, setExpanded] = useState(false)
  if (!value) return <span className="text-dim">-</span>
  const short = value.length > length ? `${value.slice(0, length)}...` : value
  return (
    <button
      type="button"
      title={value}
      onClick={() => setExpanded((v) => !v)}
      className="font-mono text-[12px] break-all text-mute hover:text-ink"
    >
      {expanded ? value : short}
    </button>
  )
}

export function TruncatedText({
  text,
  length = 80,
  className = '',
}: {
  text: string | null | undefined
  length?: number
  className?: string
}) {
  const [expanded, setExpanded] = useState(false)
  if (text === null || text === undefined || text === '') return <span className="text-dim">-</span>
  const long = text.length > length
  return (
    <span className={className}>
      {expanded || !long ? text : `${text.slice(0, length)}...`}
      {long && (
        <button
          type="button"
          onClick={() => setExpanded((v) => !v)}
          className="ml-1 text-[11px] text-accent hover:underline"
        >
          {expanded ? 'Show less' : 'Show more'}
        </button>
      )}
    </span>
  )
}

/** One argv element, shell-quoted for copy-paste fidelity (display only). */
function quoteArg(arg: string): string {
  if (/^[A-Za-z0-9_@%+=:,./-]+$/.test(arg)) return arg
  return `'${arg.replace(/'/g, `'\\''`)}'`
}

export function ArgvView({ argv }: { argv: string[] | null | undefined }) {
  const [copied, setCopied] = useState(false)
  if (!argv || argv.length === 0) {
    return <span className="text-dim">Not recorded</span>
  }
  const line = argv.map(quoteArg).join(' ')
  const copy = () => {
    void navigator.clipboard.writeText(line).then(() => {
      setCopied(true)
      window.setTimeout(() => setCopied(false), 1500)
    })
  }
  return (
    <div className="border border-edge bg-bg">
      <div className="flex items-center justify-between border-b border-edge px-2 py-1">
        <span className="font-mono text-[11px] text-dim">
          {argv.length} {argv.length === 1 ? 'argument' : 'arguments'} · run without a shell
        </span>
        <button type="button" onClick={copy} className="text-[11px] text-mute hover:text-ink">
          {copied ? 'Copied' : 'Copy'}
        </button>
      </div>
      <pre className="overflow-x-auto p-2 font-mono text-[12px] whitespace-pre text-ink/90">
        {line}
      </pre>
    </div>
  )
}

export function InlineCode({ children, title }: { children: ReactNode; title?: string }) {
  return (
    <code title={title} className="bg-raise px-1 py-px font-mono text-[12px] text-ink/90">
      {children}
    </code>
  )
}

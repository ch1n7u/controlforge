/** Shared UI primitives: badges, panels, tables, form controls, states. */

import type {
  ButtonHTMLAttributes,
  InputHTMLAttributes,
  ReactNode,
  SelectHTMLAttributes,
  TextareaHTMLAttributes,
} from 'react'
import { Link } from 'react-router-dom'
import { ApiError } from '../lib/api'
import { errorText } from '../lib/errors'
import { humanizeEnum } from '../lib/format'
import type {
  AssertionStatus,
  FindingStatus,
  RunStatus,
  Severity,
} from '../lib/types'
import {
  assertionLabel,
  assertionTone,
  findingStatusTone,
  runLabel,
  runTone,
  severityTone,
  type Tone,
} from '../lib/tones'

// ------------------------------------------------------------------ tone --

const toneClass: Record<Tone, string> = {
  pass: 'text-pass border-pass/40 bg-pass/10',
  fail: 'text-fail border-fail/40 bg-fail/10',
  incon: 'text-incon border-incon/40 bg-incon/10',
  na: 'text-na border-na/40 bg-na/10',
  accent: 'text-accent border-accent/40 bg-accent/10',
  mute: 'text-mute border-edge2 bg-raise/60',
  crit: 'text-crit border-crit/50 bg-crit/15',
  high: 'text-high border-high/50 bg-high/10',
  med: 'text-med border-med/50 bg-med/10',
  low: 'text-low border-low/50 bg-low/10',
  info: 'text-info border-edge2 bg-raise/60',
  blue: 'text-accent border-accent/50 bg-accent/15',
}

const dotClass: Record<Tone, string> = {
  pass: 'bg-pass',
  fail: 'bg-fail',
  incon: 'bg-incon',
  na: 'bg-na',
  accent: 'bg-accent',
  mute: 'bg-mute',
  crit: 'bg-crit',
  high: 'bg-high',
  med: 'bg-med',
  low: 'bg-low',
  info: 'bg-info',
  blue: 'bg-accent',
}

export function Badge({
  tone,
  children,
  title,
  dot = false,
}: {
  tone: Tone
  children: ReactNode
  title?: string
  dot?: boolean
}) {
  return (
    <span
      title={title}
      className={`inline-flex items-center gap-1.5 whitespace-nowrap border px-1.5 py-px font-mono text-[11px] leading-4 font-medium tracking-wide uppercase ${toneClass[tone]}`}
    >
      {dot && <span aria-hidden className={`size-1.5 rounded-full ${dotClass[tone]}`} />}
      {children}
    </span>
  )
}

export function AssertionBadge({ status }: { status: AssertionStatus | null | undefined }) {
  if (!status) return <span className="text-dim">-</span>
  return <Badge tone={assertionTone[status]}>{assertionLabel[status]}</Badge>
}

export function RunStatusBadge({ status }: { status: RunStatus }) {
  return (
    <Badge tone={runTone[status]} dot>
      {runLabel[status]}
    </Badge>
  )
}

export function SeverityBadge({ severity }: { severity: Severity | null | undefined }) {
  if (!severity) return <span className="text-dim">-</span>
  return <Badge tone={severityTone[severity]}>{severity}</Badge>
}

export function FindingStatusBadge({ status }: { status: FindingStatus }) {
  return <Badge tone={findingStatusTone[status]}>{humanizeEnum(status)}</Badge>
}

// ---------------------------------------------------------------- layout --

export function Panel({
  title,
  actions,
  children,
  className = '',
  dense = false,
}: {
  title?: ReactNode
  actions?: ReactNode
  children: ReactNode
  className?: string
  dense?: boolean
}) {
  return (
    <section className={`border border-edge bg-panel ${className}`}>
      {(title || actions) && (
        <header className="flex min-h-9 items-center justify-between gap-3 border-b border-edge px-3 py-1.5">
          <h2 className="text-[12px] font-semibold tracking-wide text-mute uppercase">{title}</h2>
          {actions && <div className="flex items-center gap-2">{actions}</div>}
        </header>
      )}
      <div className={dense ? '' : 'p-3'}>{children}</div>
    </section>
  )
}

export function PageHeader({
  title,
  subtitle,
  actions,
}: {
  title: ReactNode
  subtitle?: ReactNode
  actions?: ReactNode
}) {
  return (
    <div className="mb-4 flex flex-wrap items-end justify-between gap-3">
      <div>
        <h1 className="text-lg font-semibold text-ink">{title}</h1>
        {subtitle && <div className="mt-0.5 text-[13px] text-mute">{subtitle}</div>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  )
}

/** The filter/action bar that sits directly above a list. */
export function Toolbar({
  children,
  trailing,
  className = '',
}: {
  children: ReactNode
  trailing?: ReactNode
  className?: string
}) {
  return (
    <div className={`mb-4 flex flex-wrap items-center gap-2 ${className}`}>
      {children}
      {trailing && <div className="ml-auto flex flex-wrap items-center gap-2">{trailing}</div>}
    </div>
  )
}

export function KeyValue({
  items,
  columns = 2,
}: {
  items: Array<[string, ReactNode]>
  columns?: number
}) {
  return (
    <dl
      className="grid gap-x-6 gap-y-2"
      style={{ gridTemplateColumns: `repeat(${columns}, minmax(0, 1fr))` }}
    >
      {items.map(([label, value], index) => (
        <div key={`${label}-${index}`} className="min-w-0">
          <dt className="text-[11px] tracking-wide text-dim uppercase">{label}</dt>
          <dd className="mt-0.5 min-w-0 text-[13px] break-words text-ink">{value}</dd>
        </div>
      ))}
    </dl>
  )
}

// ---------------------------------------------------------------- tables --

export function TableWrap({ children, className = '' }: { children: ReactNode; className?: string }) {
  return (
    <div className={`overflow-auto border border-edge bg-panel ${className}`}>
      <table className="w-full text-left text-[13px]">{children}</table>
    </div>
  )
}

export function Th({
  children,
  className = '',
  align = 'left',
}: {
  children?: ReactNode
  className?: string
  align?: 'left' | 'right'
}) {
  return (
    <th
      className={`sticky top-0 z-10 border-b border-edge bg-panel2 px-3 py-2 text-[11px] font-semibold tracking-wider whitespace-nowrap text-mute uppercase ${align === 'right' ? 'text-right' : ''} ${className}`}
    >
      {children}
    </th>
  )
}

export function Td({
  children,
  className = '',
  align = 'left',
  mono = false,
  wrap = false,
  colSpan,
}: {
  children?: ReactNode
  className?: string
  align?: 'left' | 'right'
  mono?: boolean
  /** Descriptive cells (titles, reasons) opt into wrapping; identifiers do not. */
  wrap?: boolean
  colSpan?: number
}) {
  return (
    <td
      colSpan={colSpan}
      className={`border-b border-edge/60 px-3 py-1.5 align-top ${wrap ? '' : 'whitespace-nowrap'} ${align === 'right' ? 'text-right' : ''} ${mono ? 'font-mono text-[12px]' : ''} ${className}`}
    >
      {children}
    </td>
  )
}

export function TableEmptyRow({ colSpan, children }: { colSpan: number; children: ReactNode }) {
  return (
    <tr>
      <td colSpan={colSpan} className="px-3 py-6 text-center text-[13px] text-dim">
        {children}
      </td>
    </tr>
  )
}

// ---------------------------------------------------------------- states --

export function Spinner({ className = '' }: { className?: string }) {
  return (
    <svg
      className={`inline-block size-3.5 animate-spin ${className}`}
      viewBox="0 0 24 24"
      fill="none"
      aria-hidden
    >
      <circle cx="12" cy="12" r="10" stroke="currentColor" strokeOpacity="0.25" strokeWidth="3" />
      <path d="M22 12a10 10 0 0 0-10-10" stroke="currentColor" strokeWidth="3" strokeLinecap="round" />
    </svg>
  )
}

export function Loading({ label = 'Loading' }: { label?: string }) {
  return (
    <div className="flex items-center gap-2 px-1 py-6 text-[13px] text-mute">
      <Spinner />
      {label}...
    </div>
  )
}

export function ErrorNotice({
  error,
  onRetry,
  title,
}: {
  error: unknown
  onRetry?: () => void
  title?: string
}) {
  const status = error instanceof ApiError ? error.status : 0
  return (
    <div className="border border-fail/40 bg-fail/5 p-3">
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <span className="font-mono text-[11px] font-semibold tracking-wide text-fail uppercase">
            {title ?? 'Request failed'}
          </span>
          {status > 0 && (
            <span className="font-mono text-[11px] text-mute">HTTP {status}</span>
          )}
        </div>
        {onRetry && (
          <button
            type="button"
            onClick={onRetry}
            className="border border-edge2 px-2 py-0.5 text-[11px] text-mute hover:bg-raise hover:text-ink"
          >
            Retry
          </button>
        )}
      </div>
      <pre className="mt-2 overflow-x-auto font-mono text-[12px] whitespace-pre-wrap text-ink/90">
        {errorText(error)}
      </pre>
    </div>
  )
}

export function EmptyState({
  title,
  hint,
  action,
}: {
  title: string
  hint?: string
  action?: ReactNode
}) {
  return (
    <div className="border border-dashed border-edge2 px-4 py-8 text-center">
      <div className="text-[13px] font-medium text-mute">{title}</div>
      {hint && <div className="mx-auto mt-1 max-w-md text-[12px] text-dim">{hint}</div>}
      {action && <div className="mt-3 flex justify-center">{action}</div>}
    </div>
  )
}

// --------------------------------------------------------------- controls --

type ButtonVariant = 'primary' | 'ghost' | 'danger' | 'subtle'

const buttonClass: Record<ButtonVariant, string> = {
  primary: 'bg-accent text-bg border-accent hover:bg-accent2 hover:border-accent2 font-medium',
  ghost: 'border-edge2 text-ink hover:bg-raise',
  danger: 'border-fail/50 text-fail hover:bg-fail/10',
  subtle: 'border-transparent text-mute hover:text-ink hover:bg-raise',
}

export function Button({
  variant = 'ghost',
  size = 'md',
  className = '',
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: ButtonVariant
  size?: 'sm' | 'md'
}) {
  const sizeClass = size === 'sm' ? 'px-2 py-0.5 text-[12px]' : 'px-2.5 py-1 text-[13px]'
  return (
    <button
      type="button"
      {...props}
      className={`inline-flex items-center gap-1.5 border whitespace-nowrap disabled:cursor-not-allowed disabled:opacity-40 ${sizeClass} ${buttonClass[variant]} ${className}`}
    />
  )
}

export function LinkButton({
  to,
  children,
  variant = 'ghost',
  className = '',
  title,
}: {
  to: string
  children: ReactNode
  variant?: ButtonVariant
  className?: string
  title?: string
}) {
  return (
    <Link
      to={to}
      title={title}
      className={`inline-flex items-center gap-1.5 border px-2.5 py-1 text-[13px] whitespace-nowrap ${buttonClass[variant]} ${className}`}
    >
      {children}
    </Link>
  )
}

// No width here: `w-full` in this string collides with a caller's `w-40`, and
// which one Tailwind emits last is an accident of generated-CSS order, not of
// class order in the markup. Width is resolved per component instead.
const fieldBase =
  'border border-edge2 bg-bg px-2 py-1 text-[13px] text-ink placeholder:text-dim focus:border-accent disabled:opacity-40'

const WIDTH_CLASS = /(^|\s)(w-|min-w-|max-w-)/

/** A caller who asked for a width gets it; otherwise the field fills its row. */
function widthFor(className: string): string {
  return WIDTH_CLASS.test(className) ? '' : 'w-full'
}

export function Input({ className = '', ...props }: InputHTMLAttributes<HTMLInputElement>) {
  return <input {...props} className={`${fieldBase} ${widthFor(className)} ${className}`} />
}

export function Select({
  className = '',
  children,
  ...props
}: SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <select {...props} className={`${fieldBase} ${widthFor(className)} ${className}`}>
      {children}
    </select>
  )
}

export function Textarea({
  className = '',
  ...props
}: TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return (
    <textarea
      {...props}
      className={`${fieldBase} ${widthFor(className)} font-mono text-[12px] ${className}`}
    />
  )
}

export function Field({
  label,
  hint,
  required = false,
  children,
  error,
}: {
  label: string
  hint?: ReactNode
  required?: boolean
  children: ReactNode
  error?: string | null
}) {
  return (
    <label className="block">
      <span className="mb-1 block text-[11px] tracking-wide text-mute uppercase">
        {label}
        {required && (
          <>
            <span aria-hidden className="ml-1 text-dim">
              *
            </span>
            <span className="sr-only"> (required)</span>
          </>
        )}
      </span>
      {children}
      {hint && <span className="mt-1 block text-[11px] text-dim">{hint}</span>}
      {error && <span className="mt-1 block text-[11px] text-fail">{error}</span>}
    </label>
  )
}

export function Checkbox({
  label,
  checked,
  onChange,
  disabled = false,
}: {
  label: string
  checked: boolean
  onChange: (checked: boolean) => void
  disabled?: boolean
}) {
  return (
    <label className="inline-flex cursor-pointer items-center gap-2 text-[13px] text-ink">
      <input
        type="checkbox"
        checked={checked}
        disabled={disabled}
        onChange={(e) => onChange(e.target.checked)}
        className="size-3.5 accent-[var(--color-accent)]"
      />
      {label}
    </label>
  )
}

// ------------------------------------------------------------- pagination --

export function Pagination({
  offset,
  limit,
  total,
  onChange,
}: {
  offset: number
  limit: number
  total: number
  onChange: (offset: number) => void
}) {
  const page = Math.floor(offset / limit) + 1
  const pages = Math.max(1, Math.ceil(total / limit))
  return (
    <div className="flex items-center justify-between gap-3 px-1 py-2 text-[12px] text-mute">
      <span>
        {total === 0
          ? '0 rows'
          : `${offset + 1}-${Math.min(offset + limit, total)} of ${total}`}
      </span>
      <div className="flex items-center gap-1">
        <button
          type="button"
          disabled={offset === 0}
          onClick={() => onChange(Math.max(0, offset - limit))}
          className="border border-edge2 px-2 py-0.5 hover:bg-raise disabled:cursor-not-allowed disabled:opacity-40"
        >
          Prev
        </button>
        <span className="px-1 font-mono">
          {page}/{pages}
        </span>
        <button
          type="button"
          disabled={offset + limit >= total}
          onClick={() => onChange(offset + limit)}
          className="border border-edge2 px-2 py-0.5 hover:bg-raise disabled:cursor-not-allowed disabled:opacity-40"
        >
          Next
        </button>
      </div>
    </div>
  )
}

// ----------------------------------------------------------------- drawer --

export function Modal({
  title,
  onClose,
  children,
  width = 'max-w-lg',
}: {
  title: ReactNode
  onClose: () => void
  children: ReactNode
  width?: string
}) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/60" onClick={onClose} aria-hidden />
      <div className={`relative z-10 w-full ${width} max-h-[85vh] overflow-y-auto border border-edge2 bg-panel`}>
        <header className="sticky top-0 z-10 flex items-center justify-between border-b border-edge bg-panel2 px-4 py-2">
          <h2 className="text-[13px] font-semibold text-ink">{title}</h2>
          <button
            type="button"
            onClick={onClose}
            className="border border-edge2 px-2 py-0.5 text-[12px] text-mute hover:bg-raise hover:text-ink"
          >
            Close
          </button>
        </header>
        <div className="p-4">{children}</div>
      </div>
    </div>
  )
}

export function Drawer({
  open,
  title,
  onClose,
  children,
}: {
  open: boolean
  title: ReactNode
  onClose: () => void
  children: ReactNode
}) {
  if (!open) return null
  return (
    <div className="fixed inset-0 z-40 flex justify-end">
      <div
        className="absolute inset-0 bg-black/60"
        onClick={onClose}
        aria-hidden
      />
      <div className="relative z-10 h-full w-full max-w-xl overflow-y-auto border-l border-edge bg-panel">
        <header className="sticky top-0 z-10 flex items-center justify-between border-b border-edge bg-panel2 px-4 py-2">
          <h2 className="text-[13px] font-semibold text-ink">{title}</h2>
          <button
            type="button"
            onClick={onClose}
            className="border border-edge2 px-2 py-0.5 text-[12px] text-mute hover:bg-raise hover:text-ink"
          >
            Close
          </button>
        </header>
        <div className="p-4">{children}</div>
      </div>
    </div>
  )
}

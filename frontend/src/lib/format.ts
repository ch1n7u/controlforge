/** Display formatting helpers. All times come from the API as ISO strings. */

const pad = (n: number): string => String(n).padStart(2, '0')

export function fmtDateTime(iso: string | null | undefined): string {
  if (!iso) return '-'
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
}

export function fmtDate(iso: string | null | undefined): string {
  if (!iso) return '-'
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`
}

export function fmtTime(iso: string | null | undefined): string {
  if (!iso) return '-'
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
}

export function fmtRelative(iso: string | null | undefined, now?: number): string {
  if (!iso) return '-'
  const t = new Date(iso).getTime()
  if (Number.isNaN(t)) return iso
  const ref = now ?? Date.now()
  const delta = Math.round((ref - t) / 1000)
  const abs = Math.abs(delta)
  const suffix = delta >= 0 ? 'ago' : 'from now'
  if (abs < 45) return delta >= 0 ? 'just now' : 'in a moment'
  if (abs < 3600) return `${Math.round(abs / 60)}m ${suffix}`
  if (abs < 86400) return `${Math.round(abs / 3600)}h ${suffix}`
  if (abs < 2592000) return `${Math.round(abs / 86400)}d ${suffix}`
  return `${Math.round(abs / 2592000)}mo ${suffix}`
}

export function fmtDuration(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined) return '-'
  if (seconds < 1) return `${Math.round(seconds * 1000)}ms`
  if (seconds < 60) return `${seconds.toFixed(seconds < 10 ? 1 : 0)}s`
  const total = Math.round(seconds)
  const m = Math.floor(total / 60)
  const s = total % 60
  if (m < 60) return `${m}m ${pad(s)}s`
  const h = Math.floor(m / 60)
  return `${h}h ${pad(m % 60)}m`
}

export function fmtBytes(bytes: number | null | undefined): string {
  if (bytes === null || bytes === undefined) return '-'
  if (bytes < 1024) return `${bytes} B`
  const units = ['KiB', 'MiB', 'GiB']
  let value = bytes / 1024
  let i = 0
  while (value >= 1024 && i < units.length - 1) {
    value /= 1024
    i += 1
  }
  return `${value.toFixed(1)} ${units[i]}`
}

export function shortDigest(digest: string | null | undefined, length = 12): string {
  if (!digest) return '-'
  return digest.length > length ? `${digest.slice(0, length)}...` : digest
}

/** Whole days from now until an ISO timestamp; negative when already past. */
export function daysUntil(iso: string | null | undefined): number | null {
  if (!iso) return null
  const t = new Date(iso).getTime()
  if (Number.isNaN(t)) return null
  return Math.ceil((t - Date.now()) / 86400000)
}

export function pct(numerator: number, denominator: number): number {
  if (denominator <= 0) return 0
  return Math.max(0, Math.min(1, numerator / denominator))
}

export function fmtPercent(ratio: number | null | undefined, digits = 0): string {
  if (ratio === null || ratio === undefined || Number.isNaN(ratio)) return '-'
  return `${(ratio * 100).toFixed(digits)}%`
}

export function humanizeEnum(value: string | null | undefined): string {
  if (!value) return '-'
  return value.replace(/_/g, ' ')
}

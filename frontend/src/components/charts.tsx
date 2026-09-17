/** Hand-rolled SVG/HTML charts. No chart library by design. */

import { useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { fmtDate, fmtPercent, pct } from '../lib/format'
import type { TrendDay } from '../lib/types'

export interface Slice {
  key: string
  label: string
  value: number
  color: string
  to?: string
}

// ----------------------------------------------------------------- donut --

export function Donut({
  slices,
  size = 168,
  thickness = 26,
  centerLabel,
  centerValue,
}: {
  slices: Slice[]
  size?: number
  thickness?: number
  centerLabel: string
  centerValue: string
}) {
  const total = slices.reduce((sum, s) => sum + s.value, 0)
  const radius = (size - thickness) / 2
  const circumference = 2 * Math.PI * radius
  let consumed = 0

  return (
    <div className="flex items-center gap-5">
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} role="img" aria-label={centerLabel}>
        <g transform={`rotate(-90 ${size / 2} ${size / 2})`}>
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            stroke="var(--color-edge)"
            strokeWidth={thickness}
          />
          {total > 0 &&
            slices.map((slice) => {
              if (slice.value <= 0) return null
              const length = (slice.value / total) * circumference
              const offset = -consumed
              consumed += length
              const circle = (
                <circle
                  cx={size / 2}
                  cy={size / 2}
                  r={radius}
                  fill="none"
                  stroke={slice.color}
                  strokeWidth={thickness}
                  strokeDasharray={`${length} ${circumference - length}`}
                  strokeDashoffset={offset}
                  className={slice.to ? 'cursor-pointer' : undefined}
                  tabIndex={slice.to ? 0 : undefined}
                  aria-label={`${slice.label}: ${slice.value}`}
                >
                  <title>{`${slice.label}: ${slice.value} (${fmtPercent(pct(slice.value, total), 1)})`}</title>
                </circle>
              )
              return slice.to ? (
                <Link key={slice.key} to={slice.to} aria-label={`${slice.label}: ${slice.value}`}>
                  {circle}
                </Link>
              ) : (
                <g key={slice.key}>{circle}</g>
              )
            })}
        </g>
        <text
          x="50%"
          y="47%"
          textAnchor="middle"
          className="fill-ink font-mono"
          style={{ fontSize: 22, fontWeight: 600 }}
        >
          {centerValue}
        </text>
        <text
          x="50%"
          y="61%"
          textAnchor="middle"
          className="fill-dim"
          style={{ fontSize: 10, letterSpacing: 1, textTransform: 'uppercase' }}
        >
          {centerLabel}
        </text>
      </svg>
      <DonutLegend slices={slices} total={total} />
    </div>
  )
}

export function DonutLegend({ slices, total }: { slices: Slice[]; total?: number }) {
  const sum = total ?? slices.reduce((acc, s) => acc + s.value, 0)
  return (
    <ul className="min-w-0 flex-1 space-y-1">
      {slices.map((slice) => {
        const row = (
          <>
            <span aria-hidden className="size-2 shrink-0" style={{ background: slice.color }} />
            <span className="flex-1 truncate text-[12px] text-mute">{slice.label}</span>
            <span className="font-mono text-[12px] text-ink">{slice.value}</span>
            <span className="w-12 text-right font-mono text-[11px] text-dim">
              {fmtPercent(pct(slice.value, sum), 1)}
            </span>
          </>
        )
        return (
          <li key={slice.key}>
            {slice.to ? (
              <Link
                to={slice.to}
                className="flex items-center gap-2 px-1 py-0.5 hover:bg-raise"
              >
                {row}
              </Link>
            ) : (
              <span className="flex items-center gap-2 px-1 py-0.5">{row}</span>
            )}
          </li>
        )
      })}
    </ul>
  )
}

// --------------------------------------------------------------- bar list --

export function BarList({
  bars,
  emptyLabel = 'no data',
}: {
  bars: Array<{ key: string; label: string; value: number; color: string; to?: string }>
  emptyLabel?: string
}) {
  const max = Math.max(1, ...bars.map((b) => b.value))
  if (bars.every((b) => b.value === 0)) {
    return <div className="py-4 text-center text-[12px] text-dim">{emptyLabel}</div>
  }
  return (
    <ul className="space-y-1.5">
      {bars.map((bar) => {
        const inner = (
          <>
            <span className="w-20 shrink-0 text-[12px] text-mute">{bar.label}</span>
            <span className="h-3 flex-1 border border-edge bg-bg">
              <span
                className="block h-full"
                style={{ width: `${(bar.value / max) * 100}%`, background: bar.color }}
              />
            </span>
            <span className="w-10 shrink-0 text-right font-mono text-[12px] text-ink">
              {bar.value}
            </span>
          </>
        )
        return (
          <li key={bar.key}>
            {bar.to ? (
              <Link to={bar.to} className="flex items-center gap-2 px-1 py-0.5 hover:bg-raise">
                {inner}
              </Link>
            ) : (
              <span className="flex items-center gap-2 px-1 py-0.5">{inner}</span>
            )}
          </li>
        )
      })}
    </ul>
  )
}

export function RatioBar({ ratio, className = '' }: { ratio: number; className?: string }) {
  return (
    <span className={`inline-flex items-center gap-1.5 ${className}`}>
      <span className="h-1.5 w-16 border border-edge bg-bg">
        <span
          className="block h-full bg-accent"
          style={{ width: `${Math.round(pct(ratio, 1) * 100)}%` }}
        />
      </span>
      <span className="font-mono text-[11px] text-mute">{fmtPercent(ratio)}</span>
    </span>
  )
}

// ------------------------------------------------------------ trend chart --

const SERIES = [
  { key: 'pass' as const, label: 'pass', color: 'var(--color-pass)' },
  { key: 'fail' as const, label: 'fail', color: 'var(--color-fail)' },
  { key: 'inconclusive' as const, label: 'inconclusive', color: 'var(--color-incon)' },
]

const W = 720
const H = 220
const PAD_X = 36
const PAD_Y = 18

export function TrendChart({ days }: { days: TrendDay[] }) {
  const [hover, setHover] = useState<number | null>(null)
  const svgRef = useRef<SVGSVGElement | null>(null)

  if (days.length === 0) {
    return (
      <div className="py-10 text-center text-[12px] text-dim">
        No daily assertion results have been recorded yet.
      </div>
    )
  }

  const maxY = Math.max(
    1,
    ...days.map((d) => Math.max(d.pass, d.fail, d.inconclusive, d.not_applicable)),
  )
  const step = days.length > 1 ? (W - PAD_X * 2) / (days.length - 1) : 0
  const x = (i: number) => PAD_X + i * step
  const y = (v: number) => H - PAD_Y - (v / maxY) * (H - PAD_Y * 2)

  const gridLines = [0, 0.25, 0.5, 0.75, 1]

  const onMove = (event: React.MouseEvent<SVGSVGElement>) => {
    const rect = svgRef.current?.getBoundingClientRect()
    if (!rect || rect.width === 0) return
    const ratio = (event.clientX - rect.left) / rect.width
    const px = ratio * W
    const index = Math.round((px - PAD_X) / (step || 1))
    setHover(Math.max(0, Math.min(days.length - 1, index)))
  }

  const hovered = hover !== null ? days[hover] : null

  return (
    <div className="relative">
      <div className="mb-2 flex items-center gap-4">
        {SERIES.map((series) => (
          <span key={series.key} className="flex items-center gap-1.5 text-[11px] text-mute">
            <span aria-hidden className="size-2" style={{ background: series.color }} />
            {series.label}
          </span>
        ))}
      </div>
      <svg
        ref={svgRef}
        viewBox={`0 0 ${W} ${H}`}
        className="h-auto w-full"
        role="img"
        aria-label="Daily assertion outcomes, pass / fail / inconclusive"
        onMouseMove={onMove}
        onMouseLeave={() => setHover(null)}
      >
        {gridLines.map((frac) => {
          const gy = y(maxY * frac)
          return (
            <g key={frac}>
              <line x1={PAD_X} x2={W - PAD_X} y1={gy} y2={gy} stroke="var(--color-edge)" strokeWidth="1" />
              <text x={PAD_X - 6} y={gy + 3} textAnchor="end" className="fill-dim" style={{ fontSize: 10 }}>
                {Math.round(maxY * frac)}
              </text>
            </g>
          )
        })}
        {SERIES.map((series) => (
          <polyline
            key={series.key}
            fill="none"
            stroke={series.color}
            strokeWidth="1.5"
            points={days.map((d, i) => `${x(i)},${y(d[series.key])}`).join(' ')}
          />
        ))}
        {hover !== null && hovered && (
          <g>
            <line
              x1={x(hover)}
              x2={x(hover)}
              y1={PAD_Y}
              y2={H - PAD_Y}
              stroke="var(--color-edge2)"
              strokeDasharray="3 3"
            />
            {SERIES.map((series) => (
              <circle
                key={series.key}
                cx={x(hover)}
                cy={y(hovered[series.key])}
                r="3"
                fill={series.color}
              />
            ))}
          </g>
        )}
        {days.map((d, i) => {
          const showLabel = i === 0 || i === days.length - 1 || (step > 0 && i % Math.max(1, Math.ceil(days.length / 6)) === 0)
          if (!showLabel) return null
          return (
            <text
              key={d.date}
              x={x(i)}
              y={H - 4}
              textAnchor="middle"
              className="fill-dim"
              style={{ fontSize: 10 }}
            >
              {fmtDate(d.date).slice(5)}
            </text>
          )
        })}
      </svg>
      {hover !== null && hovered && (
        <div
          className="pointer-events-none absolute top-6 z-10 border border-edge2 bg-raise px-2 py-1 shadow-lg"
          style={{
            left: `${Math.min(88, Math.max(2, ((x(hover) - PAD_X) / (W - PAD_X * 2)) * 100))}%`,
          }}
        >
          <div className="font-mono text-[11px] text-ink">{fmtDate(hovered.date)}</div>
          {SERIES.map((series) => (
            <div key={series.key} className="flex items-center gap-2 font-mono text-[11px]">
              <span aria-hidden className="size-1.5" style={{ background: series.color }} />
              <span className="text-mute">{series.label}</span>
              <span className="text-ink">{hovered[series.key]}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

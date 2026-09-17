import { useQuery } from '@tanstack/react-query'
import { Fragment, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  Button,
  EmptyState,
  ErrorNotice,
  Input,
  Loading,
  PageHeader,
  Select,
  SeverityBadge,
  TableEmptyRow,
  TableWrap,
  Td,
  Th,
  Toolbar,
} from '../components/ui'
import { useDebounced } from '../hooks/useDebounced'
import { api, qk } from '../lib/api'
import { humanizeEnum } from '../lib/format'
import type { Framework, FrameworkRef } from '../lib/types'

function refTooltip(ref: FrameworkRef, framework: Framework | undefined): string {
  const source = framework
    ? `${framework.name}${framework.version ? ` ${framework.version}` : ''}`
    : null
  return [source, ref.title].filter(Boolean).join(' — ')
}

export function ControlsPage() {
  const [search, setSearch] = useState('')
  const [category, setCategory] = useState('')
  const debouncedSearch = useDebounced(search, 300)

  // The unfiltered list doubles as the source of category options.
  const all = useQuery({
    queryKey: qk.controls({ limit: 1000 }),
    queryFn: () => api.controls({ limit: 1000 }),
    staleTime: 5 * 60_000,
  })

  const filters = { q: debouncedSearch, category, limit: 1000 }
  const list = useQuery({
    queryKey: qk.controls(filters),
    queryFn: () => api.controls(filters),
    staleTime: 60_000,
  })

  // A bare ref code ("6.1") means nothing without the framework it belongs to.
  const frameworks = useQuery({
    queryKey: qk.frameworks,
    queryFn: api.frameworks,
    staleTime: 10 * 60_000,
  })
  const frameworkById = useMemo(
    () => new Map((frameworks.data ?? []).map((f) => [f.id, f])),
    [frameworks.data],
  )

  const categories = useMemo(() => {
    const set = new Set<string>()
    for (const control of all.data ?? []) {
      if (control.category) set.add(control.category)
    }
    return [...set].sort()
  }, [all.data])

  const hasFilters = debouncedSearch !== '' || category !== ''

  return (
    <div className="space-y-4">
      <PageHeader
        title="Controls"
        subtitle="The security controls this platform validates, with the framework references they map to."
      />

      <Toolbar
        trailing={
          list.data ? (
            <span className="font-mono text-[12px] text-dim">{list.data.length} shown</span>
          ) : null
        }
      >
        <Input
          type="search"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search key or title"
          className="w-64"
        />
        <Select
          value={category}
          onChange={(e) => setCategory(e.target.value)}
          className="w-56"
          aria-label="Filter by category"
        >
          <option value="">All categories</option>
          {categories.map((name) => (
            <option key={name} value={name}>
              {humanizeEnum(name)}
            </option>
          ))}
        </Select>
        {hasFilters && (
          <Button
            size="sm"
            onClick={() => {
              setSearch('')
              setCategory('')
            }}
          >
            Clear filters
          </Button>
        )}
      </Toolbar>

      {list.isPending && <Loading label="Loading controls" />}
      {list.isError && <ErrorNotice error={list.error} onRetry={() => void list.refetch()} />}

      {list.data &&
        (list.data.length === 0 && !hasFilters ? (
          <EmptyState
            title="No controls yet"
            hint="Controls describe the secure state a target is held to. They come from the framework catalogue that ships with the platform."
          />
        ) : (
          <TableWrap>
            <thead>
              <tr>
                <Th>Key</Th>
                <Th>Title</Th>
                <Th>Category</Th>
                <Th>Default severity</Th>
                <Th>Framework refs</Th>
                <Th>Enabled</Th>
              </tr>
            </thead>
            <tbody>
              {list.data.length === 0 ? (
                <TableEmptyRow colSpan={6}>No control matches the current filters.</TableEmptyRow>
              ) : (
                list.data.map((control) => (
                  <tr key={control.id} className="hover:bg-raise/50">
                    <Td mono>
                      <Link to={`/controls/${control.id}`} className="text-accent hover:underline">
                        {control.key}
                      </Link>
                    </Td>
                    <Td wrap className="min-w-[18rem] max-w-[34rem]">
                      {control.title}
                    </Td>
                    <Td className="text-mute">{humanizeEnum(control.category)}</Td>
                    <Td>
                      <SeverityBadge severity={control.default_severity} />
                    </Td>
                    <Td mono className="text-mute">
                      {control.refs.length === 0 ? (
                        <span className="text-dim">Not mapped</span>
                      ) : (
                        control.refs.map((ref, index) => {
                          const framework = frameworkById.get(ref.framework_id)
                          return (
                            <Fragment key={ref.id}>
                              {index > 0 && <span className="text-dim"> · </span>}
                              <span title={refTooltip(ref, framework)}>
                                {framework && <span className="text-dim">{framework.key} </span>}
                                {ref.ref_code}
                              </span>
                            </Fragment>
                          )
                        })
                      )}
                    </Td>
                    <Td>
                      {control.enabled ? (
                        <span className="text-pass">yes</span>
                      ) : (
                        <span className="text-dim">no</span>
                      )}
                    </Td>
                  </tr>
                ))
              )}
            </tbody>
          </TableWrap>
        ))}
    </div>
  )
}

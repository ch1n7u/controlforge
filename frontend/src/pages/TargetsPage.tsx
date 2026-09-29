import { useQuery } from '@tanstack/react-query'
import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { RunDialog } from '../components/RunDialog'
import {
  Badge,
  Button,
  ErrorNotice,
  Input,
  LinkButton,
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
import { useAuth } from '../auth/context'
import { api, qk } from '../lib/api'
import { targetTypes } from '../lib/tones'
import type { Target } from '../lib/types'

export function TargetsPage() {
  const { isWriter } = useAuth()
  const [search, setSearch] = useState('')
  const [typeFilter, setTypeFilter] = useState('')
  const [runTarget, setRunTarget] = useState<Target | null>(null)

  const targets = useQuery({
    queryKey: qk.targets({ limit: 1000 }),
    queryFn: () => api.targets({ limit: 1000 }),
    staleTime: 60_000,
  })

  const visible = useMemo(() => {
    const list = targets.data ?? []
    const needle = search.trim().toLowerCase()
    return list.filter((target) => {
      if (typeFilter && target.target_type !== typeFilter) return false
      if (!needle) return true
      return (
        target.name.toLowerCase().includes(needle) ||
        target.host.toLowerCase().includes(needle) ||
        target.tags.some((tag) => tag.toLowerCase().includes(needle)) ||
        (target.owner ?? '').toLowerCase().includes(needle)
      )
    })
  }, [targets.data, search, typeFilter])

  return (
    <div className="space-y-4">
      <PageHeader
        title="Targets"
        subtitle="Hosts, web apps and services under validation. A target can only be run while an active scope authorizes its address and port."
        actions={
          isWriter ? (
            <LinkButton to="/targets/new" variant="primary">
              New target
            </LinkButton>
          ) : null
        }
      />

      <Toolbar
        trailing={
          (targets.data?.length ?? 0) > 0 ? (
            <span className="font-mono text-[12px] text-dim">
              {visible.length}/{targets.data?.length ?? 0} shown
            </span>
          ) : undefined
        }
      >
        <Input
          type="search"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search name, host, tag or owner"
          className="w-64"
        />
        <Select value={typeFilter} onChange={(e) => setTypeFilter(e.target.value)} className="w-40">
          <option value="">All types</option>
          {targetTypes.map((type) => (
            <option key={type} value={type}>
              {type}
            </option>
          ))}
        </Select>
        {(search !== '' || typeFilter !== '') && (
          <button
            type="button"
            onClick={() => {
              setSearch('')
              setTypeFilter('')
            }}
            className="text-[12px] text-mute hover:text-ink"
          >
            Clear filters
          </button>
        )}
      </Toolbar>

      {targets.isPending && <Loading label="Loading targets" />}
      {targets.isError && <ErrorNotice error={targets.error} onRetry={() => void targets.refetch()} />}

      {targets.data && (
        <TableWrap>
          <thead>
            <tr>
              <Th>Name</Th>
              <Th>Endpoint</Th>
              <Th>Type</Th>
              <Th>Criticality</Th>
              <Th>Tags</Th>
              <Th>Owner</Th>
              <Th>Enabled</Th>
              <Th align="right">Actions</Th>
            </tr>
          </thead>
          <tbody>
            {visible.length === 0 ? (
              <TableEmptyRow colSpan={8}>
                {targets.data.length === 0
                  ? isWriter
                    ? 'No targets have been registered yet. Use New target to register a host, then attach a scope so it can be validated.'
                    : 'No targets have been registered yet. A target is registered by an analyst or administrator, and can be validated only while a scope authorizes it.'
                  : 'No target matches the current filters.'}
              </TableEmptyRow>
            ) : (
              visible.map((target) => (
                <tr key={target.id} className="hover:bg-raise/50">
                  <Td wrap className="min-w-[16rem] max-w-[30rem]">
                    <Link to={`/targets/${target.id}`} className="text-accent hover:underline">
                      {target.name}
                    </Link>
                  </Td>
                  <Td wrap mono className="min-w-[12rem] max-w-[28rem]">
                    {target.host}
                    {target.port ? `:${target.port}` : ''}
                    {target.path ? target.path : ''}
                  </Td>
                  <Td>
                    <Badge tone="mute">{target.target_type}</Badge>
                  </Td>
                  <Td>
                    <SeverityBadge severity={target.criticality} />
                  </Td>
                  <Td mono className="text-mute">
                    {target.tags.length > 0 ? target.tags.join(', ') : '-'}
                  </Td>
                  <Td wrap>{target.owner ?? '-'}</Td>
                  <Td>
                    {target.enabled ? (
                      <span className="text-pass">yes</span>
                    ) : (
                      <span className="text-dim">no</span>
                    )}
                  </Td>
                  <Td align="right">
                    {isWriter && (
                      <Button size="sm" onClick={() => setRunTarget(target)}>
                        Run a test
                      </Button>
                    )}
                  </Td>
                </tr>
              ))
            )}
          </tbody>
        </TableWrap>
      )}

      {targets.data && targets.data.length > 0 && (
        <div className="text-[12px] text-dim">
          Every run is authorized per address and port against the scopes attached to the target,
          and only scopes that are active and unexpired count. Open a target to see its scopes.
        </div>
      )}

      {runTarget && (
        <RunDialog onClose={() => setRunTarget(null)} fixedTargetId={runTarget.id} />
      )}
    </div>
  )
}

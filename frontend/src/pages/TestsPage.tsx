import { useQuery } from '@tanstack/react-query'
import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useAuth } from '../auth/context'
import {
  Button,
  EmptyState,
  ErrorNotice,
  Input,
  LinkButton,
  Loading,
  PageHeader,
  Select,
  TableEmptyRow,
  TableWrap,
  Td,
  Th,
  Toolbar,
} from '../components/ui'
import { useDebounced } from '../hooks/useDebounced'
import { api, qk } from '../lib/api'
import { fmtRelative } from '../lib/format'

export function TestsPage() {
  const { isWriter } = useAuth()
  const [search, setSearch] = useState('')
  const [controlId, setControlId] = useState('')
  const [enabled, setEnabled] = useState('')
  const debounced = useDebounced(search, 300)

  const controls = useQuery({
    queryKey: qk.controls({ limit: 1000 }),
    queryFn: () => api.controls({ limit: 1000 }),
    staleTime: 5 * 60_000,
  })
  const filters = {
    q: debounced,
    control_id: controlId === '' ? undefined : Number(controlId),
    enabled: enabled === '' ? undefined : enabled === 'true',
    limit: 1000,
  }
  const tests = useQuery({
    queryKey: qk.tests(filters),
    queryFn: () => api.tests(filters),
    staleTime: 30_000,
  })

  const controlById = new Map((controls.data ?? []).map((control) => [control.id, control]))
  const hasFilters = search !== '' || controlId !== '' || enabled !== ''

  return (
    <div className="space-y-4">
      <PageHeader
        title="Tests"
        subtitle="Each test validates one control. Published versions are immutable, so every run and finding stays tied to exactly what executed."
        actions={isWriter ? <LinkButton to="/tests/new" variant="primary">New test</LinkButton> : null}
      />

      <Toolbar
        trailing={
          tests.data ? (
            <span className="font-mono text-[12px] text-dim">{tests.data.length} shown</span>
          ) : null
        }
      >
        <Input
          type="search"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search key or name"
          className="w-56"
        />
        <Select
          value={controlId}
          onChange={(e) => setControlId(e.target.value)}
          className="w-72"
          aria-label="Filter by control"
        >
          <option value="">All controls</option>
          {(controls.data ?? []).map((control) => (
            <option key={control.id} value={control.id}>
              {control.key} - {control.title}
            </option>
          ))}
        </Select>
        <Select
          value={enabled}
          onChange={(e) => setEnabled(e.target.value)}
          className="w-36"
          aria-label="Filter by state"
        >
          <option value="">Any state</option>
          <option value="true">Enabled</option>
          <option value="false">Disabled</option>
        </Select>
        {hasFilters && (
          <Button
            size="sm"
            onClick={() => {
              setSearch('')
              setControlId('')
              setEnabled('')
            }}
          >
            Clear filters
          </Button>
        )}
      </Toolbar>

      {tests.isPending && <Loading label="Loading tests" />}
      {tests.isError && <ErrorNotice error={tests.error} onRetry={() => void tests.refetch()} />}

      {tests.data &&
        (tests.data.length === 0 && !hasFilters ? (
          <EmptyState
            title="No tests yet"
            hint="A validation test checks one control against your targets. Create the first one to start producing results."
            action={
              isWriter ? (
                <LinkButton to="/tests/new" variant="primary">
                  New test
                </LinkButton>
              ) : undefined
            }
          />
        ) : (
          <TableWrap>
            <thead>
              <tr>
                <Th>Key</Th>
                <Th>Name</Th>
                <Th>Control</Th>
                <Th align="right">Version</Th>
                <Th>Tags</Th>
                <Th>Enabled</Th>
                <Th>Updated</Th>
              </tr>
            </thead>
            <tbody>
              {tests.data.length === 0 ? (
                <TableEmptyRow colSpan={7}>No test matches the current filters.</TableEmptyRow>
              ) : (
                tests.data.map((test) => {
                  const control = controlById.get(test.control_id)
                  return (
                    <tr key={test.id} className="hover:bg-raise/50">
                      <Td mono>
                        <Link to={`/tests/${test.id}`} className="text-accent hover:underline">
                          {test.key}
                        </Link>
                      </Td>
                      <Td wrap className="min-w-[18rem] max-w-[34rem]">
                        {test.name}
                      </Td>
                      <Td>
                        {control ? (
                          <Link to={`/controls/${control.id}`} className="text-mute hover:underline">
                            <span className="font-mono text-[12px]">{control.key}</span>
                          </Link>
                        ) : (
                          <span className="font-mono text-[12px] text-dim">#{test.control_id}</span>
                        )}
                      </Td>
                      <Td align="right" mono>
                        v{test.current_version}
                      </Td>
                      <Td mono className="text-mute">
                        {test.tags.length > 0 ? test.tags.join(', ') : '-'}
                      </Td>
                      <Td>
                        {test.enabled ? (
                          <span className="text-pass">yes</span>
                        ) : (
                          <span className="text-dim">no</span>
                        )}
                      </Td>
                      <Td>{fmtRelative(test.updated_at ?? test.created_at)}</Td>
                    </tr>
                  )
                })
              )}
            </tbody>
          </TableWrap>
        ))}
    </div>
  )
}

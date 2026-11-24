import {
  ChevronLeft,
  ChevronRight,
  CircleAlert,
  Download,
  RefreshCw,
  RotateCcw,
  Search,
  X,
} from "lucide-react"
import { useEffect, useMemo, useState, type FormEvent } from "react"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Card } from "@/components/ui/card"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import {
  InputGroup,
  InputGroupAddon,
  InputGroupButton,
  InputGroupInput,
} from "@/components/ui/input-group"
import { Label } from "@/components/ui/label"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Switch } from "@/components/ui/switch"
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group"
import { DataTable } from "@/components/data-table/data-table"
import { PageHeader } from "@/components/shared/page-header"
import {
  AUDIT_COLUMN_LABELS,
  createAuditColumns,
} from "@/features/audit/audit-columns"
import { AuditDetailSheet } from "@/features/audit/audit-detail-sheet"
import { useAuditPageQuery } from "@/hooks/use-console-queries"
import {
  getErrorMessage,
  type AuditEntry,
  type AuditQueryParams,
} from "@/lib/api"
import {
  exportAuditAsCsv,
  exportAuditAsJson,
  formatLatency,
} from "@/lib/format"
import { useActiveProfile } from "@/lib/profile-context"

interface AuditPageProps {
  initialSearch?: string
  initialPlatform?: string
}

export function AuditPage({ initialSearch, initialPlatform }: AuditPageProps) {
  const { activeProfile, activeProfileMeta } = useActiveProfile()
  const [searchInput, setSearchInput] = useState(initialSearch ?? "")
  const [search, setSearch] = useState(initialSearch ?? "")
  const [platform, setPlatform] = useState(initialPlatform ?? "all")
  const [decision, setDecision] = useState("all")
  const [cursors, setCursors] = useState<number[]>([])
  const [autoRefresh, setAutoRefresh] = useState(false)
  const [selected, setSelected] = useState<AuditEntry | null>(null)

  const platforms = activeProfileMeta?.platforms ?? []

  useEffect(() => {
    setPlatform("all")
    setCursors([])
    setSelected(null)
  }, [activeProfile])

  useEffect(() => {
    if (initialSearch !== undefined) {
      setSearchInput(initialSearch)
      setSearch(initialSearch)
      setCursors([])
    }
  }, [initialSearch])

  useEffect(() => {
    if (initialPlatform) {
      setPlatform(initialPlatform)
      setCursors([])
    }
  }, [initialPlatform])

  const queryParams = useMemo<AuditQueryParams>(() => {
    const params: AuditQueryParams = {}
    if (activeProfile) params.profile = activeProfile
    if (platform !== "all") params.platform = platform
    if (decision !== "all") params.decision = decision
    if (search) params.search = search
    const before = cursors.at(-1)
    if (before !== undefined) params.before = before
    return params
  }, [activeProfile, platform, decision, search, cursors])

  const auditQuery = useAuditPageQuery(queryParams, {
    autoRefresh: autoRefresh && cursors.length === 0,
    enabled: Boolean(activeProfile),
  })

  const events = auditQuery.data?.events ?? []
  const columns = useMemo(
    () => createAuditColumns((entry) => setSelected(entry)),
    []
  )

  const pageStats = useMemo(() => {
    const deny = events.filter((e) => e.decision === "deny").length
    const avgLatency =
      events.length > 0
        ? Math.round(
            events.reduce((acc, ev) => acc + ev.latency_ms, 0) / events.length
          )
        : null
    return { total: events.length, deny, avgLatency }
  }, [events])

  const hasActiveFilters =
    platform !== "all" || decision !== "all" || search.length > 0

  function handleSearchSubmit(event: FormEvent) {
    event.preventDefault()
    setSearch(searchInput.trim())
    setCursors([])
  }

  function resetFilters() {
    setSearchInput("")
    setSearch("")
    setPlatform("all")
    setDecision("all")
    setCursors([])
  }

  return (
    <div className="flex flex-col gap-5">
      <PageHeader
        title="审计日志"
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <div className="flex items-center gap-2 px-1">
              <Switch
                id="audit-auto-refresh"
                checked={autoRefresh}
                onCheckedChange={setAutoRefresh}
                disabled={cursors.length > 0}
              />
              <Label
                htmlFor="audit-auto-refresh"
                className="cursor-pointer text-xs font-normal text-muted-foreground"
              >
                自动刷新
              </Label>
            </div>

            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button
                  variant="outline"
                  size="sm"
                  disabled={events.length === 0}
                >
                  <Download />
                  导出
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                <DropdownMenuItem onSelect={() => exportAuditAsCsv(events)}>
                  导出 CSV
                </DropdownMenuItem>
                <DropdownMenuItem onSelect={() => exportAuditAsJson(events)}>
                  导出 JSON
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>

            <Button
              variant="outline"
              size="sm"
              onClick={() => {
                setCursors([])
                void auditQuery.refetch()
              }}
              disabled={auditQuery.isFetching}
            >
              <RefreshCw
                className={auditQuery.isFetching ? "animate-spin" : undefined}
              />
              刷新
            </Button>
          </div>
        }
      />

      <Card className="min-w-0 gap-0 overflow-hidden py-0 shadow-xs">
        {auditQuery.isError && (
          <div className="border-b p-4 sm:px-5">
            <Alert variant="destructive" role="alert">
              <CircleAlert />
              <AlertDescription>
                {getErrorMessage(auditQuery.error)}
              </AlertDescription>
            </Alert>
          </div>
        )}

        <DataTable
          columns={columns}
          data={events}
          loading={auditQuery.isLoading}
          enableColumnVisibility
          columnLabels={AUDIT_COLUMN_LABELS}
          initialColumnVisibility={{ client_ip: false }}
          onRowClick={(entry) => setSelected(entry)}
          selectedRowId={(entry) => selected?.id === entry.id}
          emptyTitle="暂无匹配的审计记录"
          emptyDescription={
            hasActiveFilters
              ? "调整筛选条件后重试。"
              : "当前 Profile 产生代理流量后将在此显示。"
          }
          emptyAction={
            hasActiveFilters ? (
              <Button variant="outline" size="sm" onClick={resetFilters}>
                <RotateCcw />
                重置筛选
              </Button>
            ) : undefined
          }
          toolbar={
            <>
              <form
                onSubmit={handleSearchSubmit}
                className="w-full min-w-[200px] sm:max-w-xs"
              >
                <InputGroup className="h-8">
                  <InputGroupAddon>
                    <Search className="size-3.5" aria-hidden="true" />
                  </InputGroupAddon>
                  <InputGroupInput
                    placeholder="搜索主机、路径、用户或会话…"
                    aria-label="搜索审计日志"
                    value={searchInput}
                    maxLength={120}
                    onChange={(e) => {
                      const next = e.target.value
                      setSearchInput(next)
                      if (!next) {
                        setSearch("")
                        setCursors([])
                      }
                    }}
                  />
                  {searchInput && (
                    <InputGroupAddon align="inline-end">
                      <InputGroupButton
                        type="button"
                        size="icon-xs"
                        aria-label="清空搜索"
                        onClick={() => {
                          setSearchInput("")
                          setSearch("")
                          setCursors([])
                        }}
                      >
                        <X className="size-3" />
                      </InputGroupButton>
                    </InputGroupAddon>
                  )}
                  <InputGroupAddon align="inline-end">
                    <InputGroupButton type="submit" size="xs">
                      搜索
                    </InputGroupButton>
                  </InputGroupAddon>
                </InputGroup>
              </form>

              {platforms.length > 1 && (
                <Select
                  value={platform}
                  onValueChange={(value) => {
                    setPlatform(value)
                    setCursors([])
                  }}
                >
                  <SelectTrigger
                    size="sm"
                    className="w-36 font-mono text-xs"
                    aria-label="按平台筛选"
                  >
                    <SelectValue placeholder="全部平台" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">全部平台</SelectItem>
                    {platforms.map((p) => (
                      <SelectItem key={p.id} value={p.id} className="text-xs">
                        {p.id === p.provider_id ? p.provider_name : p.id}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              )}

              <ToggleGroup
                type="single"
                variant="outline"
                size="sm"
                value={decision}
                onValueChange={(value) => {
                  if (!value) return
                  setDecision(value)
                  setCursors([])
                }}
                aria-label="按判定结果筛选"
              >
                <ToggleGroupItem value="all" className="text-xs">
                  全部
                </ToggleGroupItem>
                <ToggleGroupItem value="allow" className="text-xs">
                  允许
                </ToggleGroupItem>
                <ToggleGroupItem value="deny" className="text-xs">
                  拒绝
                </ToggleGroupItem>
              </ToggleGroup>

              {hasActiveFilters && (
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  onClick={resetFilters}
                  className="h-8 px-2 text-xs text-muted-foreground"
                >
                  <X className="size-3.5" />
                  重置
                </Button>
              )}
            </>
          }
          footer={
            <>
              <div className="flex flex-wrap items-center gap-x-2.5 gap-y-1 tabular-nums">
                <span>
                  第 {cursors.length + 1} 页 · {pageStats.total} 条
                </span>
                {pageStats.deny > 0 && (
                  <span className="text-destructive">
                    {pageStats.deny} 条拒绝
                  </span>
                )}
                {pageStats.avgLatency !== null && (
                  <span>均耗 {formatLatency(pageStats.avgLatency)}</span>
                )}
                {cursors.length > 0 && (
                  <Button
                    type="button"
                    variant="link"
                    size="xs"
                    className="h-auto p-0 text-xs"
                    onClick={() => setCursors([])}
                  >
                    回到最新
                  </Button>
                )}
              </div>

              <div className="flex items-center gap-2">
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  disabled={cursors.length === 0 || auditQuery.isFetching}
                  onClick={() => setCursors((prev) => prev.slice(0, -1))}
                >
                  <ChevronLeft />
                  上一页
                </Button>
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  disabled={!auditQuery.data?.next || auditQuery.isFetching}
                  onClick={() => {
                    const nextCursor = auditQuery.data?.next
                    if (nextCursor) setCursors((prev) => [...prev, nextCursor])
                  }}
                >
                  下一页
                  <ChevronRight />
                </Button>
              </div>
            </>
          }
        />
      </Card>

      <AuditDetailSheet
        event={selected}
        onClose={() => setSelected(null)}
        onQuickFilter={(filter) => {
          if (filter.search !== undefined) {
            setSearchInput(filter.search)
            setSearch(filter.search)
          }
          setCursors([])
          setSelected(null)
        }}
      />
    </div>
  )
}

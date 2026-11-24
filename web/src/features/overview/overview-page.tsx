import {
  ArrowRight,
  Blocks,
  CircleAlert,
  Plus,
  RefreshCw,
} from "lucide-react"
import { useMemo, useState } from "react"
import { Bar, BarChart, CartesianGrid, XAxis, YAxis } from "recharts"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import {
  ChartContainer,
  ChartTooltip,
  ChartTooltipContent,
  type ChartConfig,
} from "@/components/ui/chart"
import {
  Empty,
  EmptyContent,
  EmptyDescription,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle,
} from "@/components/ui/empty"
import { Skeleton } from "@/components/ui/skeleton"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs"
import {
  DecisionBadge,
  MethodBadge,
  StatusCodeBadge,
} from "@/components/shared/decision-badge"
import { PageHeader } from "@/components/shared/page-header"
import { ProviderIcon } from "@/components/shared/provider-icon"
import { AuditDetailSheet } from "@/features/audit/audit-detail-sheet"
import { useRecentAuditQuery } from "@/hooks/use-console-queries"
import type { AppRoute } from "@/hooks/use-hash-route"
import { getErrorMessage, type AuditEntry } from "@/lib/api"
import { useAuth } from "@/lib/auth"
import { formatLatency, formatRelativeTime } from "@/lib/format"
import { useI18n } from "@/lib/i18n"
import { useActiveProfile } from "@/lib/profile-context"
import { cn } from "@/lib/utils"

interface OverviewPageProps {
  onNavigate: (route: AppRoute, params?: Record<string, string>) => void
}

export function OverviewPage({ onNavigate }: OverviewPageProps) {
  const { session, refreshContext } = useAuth()
  const { activeProfile, activeProfileMeta, setCreateDialogOpen } =
    useActiveProfile()
  const { locale, t } = useI18n()
  const recentAudit = useRecentAuditQuery(activeProfile)
  const [chartTab, setChartTab] = useState<"latency" | "hosts">("latency")
  const [selectedEvent, setSelectedEvent] = useState<AuditEntry | null>(null)

  const latencyChartConfig = useMemo(
    () =>
      ({
        latency: {
          label: t("overview.chartLatencyLabel"),
          color: "var(--foreground)",
        },
      }) satisfies ChartConfig,
    [t]
  )

  const hostChartConfig = useMemo(
    () =>
      ({
        allow: {
          label: t("common.allow"),
          color: "var(--foreground)",
        },
        deny: {
          label: t("common.deny"),
          color: "var(--destructive)",
        },
      }) satisfies ChartConfig,
    [t]
  )

  const events = recentAudit.data?.events ?? []
  const platforms = activeProfileMeta?.platforms ?? []

  const stats = useMemo(() => {
    const total = events.length
    const allow = events.filter((e) => e.decision === "allow").length
    const deny = events.filter((e) => e.decision === "deny").length
    const allowRate = total > 0 ? Math.round((allow / total) * 100) : null
    const avgLatency =
      total > 0
        ? Math.round(events.reduce((s, e) => s + e.latency_ms, 0) / total)
        : null
    const maxLatency =
      total > 0 ? Math.max(...events.map((e) => e.latency_ms)) : null
    return { total, allow, deny, allowRate, avgLatency, maxLatency }
  }, [events])

  const latencySeries = useMemo(
    () =>
      [...events]
        .slice(0, 20)
        .reverse()
        .map((ev) => ({
          id: `#${ev.id}`,
          latency: ev.latency_ms,
        })),
    [events]
  )

  const hostSeries = useMemo(() => {
    const map = new Map<
      string,
      { host: string; allow: number; deny: number; total: number }
    >()
    for (const ev of events) {
      const entry = map.get(ev.target_host) ?? {
        host: ev.target_host,
        allow: 0,
        deny: 0,
        total: 0,
      }
      if (ev.decision === "deny") entry.deny += 1
      else entry.allow += 1
      entry.total += 1
      map.set(ev.target_host, entry)
    }
    return [...map.values()].sort((a, b) => b.total - a.total).slice(0, 6)
  }, [events])

  if (!session) return null

  if (!activeProfileMeta) {
    return (
      <div className="flex flex-col gap-5">
        <PageHeader title={t("nav.overview")} />
        <Card className="shadow-xs">
          <Empty className="border-0 py-16">
            <EmptyHeader>
              <EmptyMedia variant="icon">
                <Blocks />
              </EmptyMedia>
              <EmptyTitle className="text-base">
                {t("overview.emptyTitle")}
              </EmptyTitle>
              <EmptyDescription>
                {session.context.admin
                  ? t("overview.emptyAdmin")
                  : t("overview.emptyMember")}
              </EmptyDescription>
            </EmptyHeader>
            {session.context.admin && (
              <EmptyContent>
                <Button size="sm" onClick={() => setCreateDialogOpen(true)}>
                  <Plus />
                  {t("overview.createFirst")}
                </Button>
              </EmptyContent>
            )}
          </Empty>
        </Card>
      </div>
    )
  }

  return (
    <div className="flex flex-col gap-5">
      <PageHeader
        title={t("nav.overview")}
        description={activeProfileMeta.description || undefined}
        actions={
          <Button
            variant="outline"
            size="sm"
            onClick={() => {
              void Promise.all([refreshContext(), recentAudit.refetch()])
            }}
            disabled={recentAudit.isFetching}
          >
            <RefreshCw
              className={recentAudit.isFetching ? "animate-spin" : undefined}
            />
            {t("common.refresh")}
          </Button>
        }
      />

      {recentAudit.isError && (
        <Alert variant="destructive" role="alert">
          <CircleAlert />
          <AlertDescription>{getErrorMessage(recentAudit.error)}</AlertDescription>
        </Alert>
      )}

      {/* Key Metrics */}
      <div className="grid grid-cols-2 overflow-hidden rounded-xl border bg-card shadow-xs sm:grid-cols-4 sm:divide-x">
        <div className="space-y-1 p-4 sm:p-5">
          <p className="text-xs text-muted-foreground">
            {t("overview.metricRecent")}
          </p>
          {recentAudit.isLoading ? (
            <Skeleton className="h-7 w-14" />
          ) : (
            <p className="text-2xl font-semibold tracking-tight tabular-nums">
              {stats.total}
            </p>
          )}
          <p className="text-xs text-muted-foreground">
            {stats.allowRate !== null
              ? t("overview.metricAllowRate", { rate: stats.allowRate })
              : t("overview.metricNoSamples")}
          </p>
        </div>

        <div className="space-y-1 border-l p-4 sm:border-l-0 sm:p-5">
          <p className="text-xs text-muted-foreground">
            {t("overview.metricDenied")}
          </p>
          {recentAudit.isLoading ? (
            <Skeleton className="h-7 w-14" />
          ) : (
            <p
              className={cn(
                "text-2xl font-semibold tracking-tight tabular-nums",
                stats.deny > 0 ? "text-destructive" : "text-foreground"
              )}
            >
              {stats.deny}
            </p>
          )}
          <p className="text-xs text-muted-foreground">
            {stats.deny > 0
              ? t("overview.metricHasDenies")
              : t("overview.metricNoDenies")}
          </p>
        </div>

        <div className="space-y-1 border-t p-4 sm:border-t-0 sm:p-5">
          <p className="text-xs text-muted-foreground">
            {t("overview.metricAvgLatency")}
          </p>
          {recentAudit.isLoading ? (
            <Skeleton className="h-7 w-20" />
          ) : (
            <p className="text-2xl font-semibold tracking-tight tabular-nums">
              {stats.avgLatency !== null ? formatLatency(stats.avgLatency) : "—"}
            </p>
          )}
          <p className="text-xs text-muted-foreground tabular-nums">
            {stats.maxLatency !== null
              ? t("overview.metricPeakLatency", {
                  value: formatLatency(stats.maxLatency),
                })
              : t("overview.metricWaiting")}
          </p>
        </div>

        <div className="space-y-1 border-l border-t p-4 sm:border-l-0 sm:border-t-0 sm:p-5">
          <p className="text-xs text-muted-foreground">
            {t("overview.metricPlatforms")}
          </p>
          <p className="text-2xl font-semibold tracking-tight tabular-nums">
            {platforms.length}
          </p>
          <p className="text-xs text-muted-foreground">
            {activeProfileMeta.fallback === "deny"
              ? t("overview.fallbackWhitelist")
              : t("overview.fallbackPassthrough")}
          </p>
        </div>
      </div>

      {/* Mounted Platforms Summary Grid */}
      <Card className="shadow-xs">
        <CardHeader className="flex flex-row items-center justify-between gap-2 pb-3">
          <div>
            <CardTitle className="text-sm font-medium">
              {t("overview.mountedPlatforms")}
            </CardTitle>
            <CardDescription className="text-xs">
              {t("overview.mountedPlatformsDesc")}
            </CardDescription>
          </div>
          <Button
            variant="ghost"
            size="sm"
            className="h-7 text-xs text-muted-foreground hover:text-foreground"
            onClick={() => onNavigate("platforms")}
          >
            {session.context.admin
              ? t("overview.managePlatforms")
              : t("overview.viewPlatforms")}
            <ArrowRight className="size-3.5" />
          </Button>
        </CardHeader>
        <CardContent>
          {platforms.length === 0 ? (
            <div className="flex flex-col items-center justify-center gap-3 rounded-lg border border-dashed py-8 text-center">
              <p className="text-xs text-muted-foreground">
                {t("overview.noPlatforms")}
              </p>
              {session.context.admin && (
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => onNavigate("platforms")}
                >
                  <Plus />
                  {t("overview.addPlatform")}
                </Button>
              )}
            </div>
          ) : (
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
              {platforms.map((plat) => {
                const missingSecret = plat.secrets.some((s) => !s.configured)
                return (
                  <button
                    key={plat.id}
                    type="button"
                    onClick={() =>
                      onNavigate("platforms", { platform: plat.id })
                    }
                    className="group flex flex-col gap-2.5 rounded-lg border bg-background p-3.5 text-left transition-colors hover:border-foreground/25 hover:bg-muted/30"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex min-w-0 items-center gap-2">
                        <ProviderIcon
                          icon={plat.provider_icon}
                          providerId={plat.provider_id}
                          name={plat.provider_name}
                          size="sm"
                        />
                        <div className="min-w-0">
                          <div className="truncate text-sm font-medium leading-tight">
                            {plat.id === plat.provider_id
                              ? plat.provider_name
                              : plat.id}
                          </div>
                          <div className="truncate font-mono text-[11px] text-muted-foreground">
                            {plat.id === plat.provider_id
                              ? plat.id
                              : plat.provider_name}
                          </div>
                        </div>
                      </div>
                      <span
                        className={cn(
                          "shrink-0 text-[11px]",
                          missingSecret
                            ? "text-warning"
                            : "text-muted-foreground"
                        )}
                      >
                        {plat.secrets.length === 0
                          ? t("overview.secretNone")
                          : missingSecret
                            ? t("overview.secretPending")
                            : t("overview.secretReady")}
                      </span>
                    </div>

                    <div className="flex flex-wrap gap-1">
                      {plat.inject_hosts.slice(0, 3).map((host) => (
                        <code
                          key={host}
                          className="rounded bg-muted px-1.5 py-0.5 font-mono text-[11px] text-muted-foreground"
                        >
                          {host}
                        </code>
                      ))}
                      {plat.inject_hosts.length > 3 && (
                        <span className="text-[11px] text-muted-foreground">
                          +{plat.inject_hosts.length - 3}
                        </span>
                      )}
                    </div>

                    <div className="mt-auto flex items-center justify-between pt-0.5 text-[11px] text-muted-foreground">
                      <span>
                        {plat.preset
                          ? t("overview.presetLabel", { name: plat.preset })
                          : t("overview.noPreset")}
                        {plat.custom_rule_count > 0
                          ? ` · ${t("overview.ruleCount", { count: plat.custom_rule_count })}`
                          : ""}
                      </span>
                      <ArrowRight className="size-3 opacity-0 transition-opacity group-hover:opacity-100" />
                    </div>
                  </button>
                )
              })}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Latency / Host Distribution Chart */}
      <Card className="shadow-xs">
        <CardHeader className="flex flex-row items-center justify-between gap-3 pb-2">
          <div className="space-y-0.5">
            <CardTitle className="text-sm font-medium">
              {t("overview.trafficTitle")}
            </CardTitle>
            <CardDescription className="text-xs tabular-nums">
              {stats.total > 0
                ? t("overview.trafficSummary", {
                    total: stats.total,
                    avg: formatLatency(stats.avgLatency ?? 0),
                    max: formatLatency(stats.maxLatency ?? 0),
                  })
                : t("overview.trafficEmpty")}
            </CardDescription>
          </div>
          <Tabs
            value={chartTab}
            onValueChange={(v) => setChartTab(v as "latency" | "hosts")}
          >
            <TabsList className="h-8">
              <TabsTrigger value="latency" className="px-2.5 text-xs">
                {t("overview.chartLatency")}
              </TabsTrigger>
              <TabsTrigger value="hosts" className="px-2.5 text-xs">
                {t("overview.chartHosts")}
              </TabsTrigger>
            </TabsList>
          </Tabs>
        </CardHeader>
        <CardContent>
          {recentAudit.isLoading ? (
            <Skeleton className="h-[200px] w-full rounded-lg" />
          ) : events.length === 0 ? (
            <div className="flex h-[180px] items-center justify-center text-xs text-muted-foreground">
              {t("overview.chartEmpty")}
            </div>
          ) : chartTab === "latency" ? (
            <ChartContainer
              config={latencyChartConfig}
              className="h-[200px] w-full"
            >
              <BarChart
                data={latencySeries}
                margin={{ top: 8, right: 8, left: -18, bottom: 0 }}
              >
                <CartesianGrid vertical={false} strokeDasharray="3 3" />
                <XAxis
                  dataKey="id"
                  tickLine={false}
                  axisLine={false}
                  tickMargin={8}
                  fontSize={11}
                />
                <YAxis
                  tickLine={false}
                  axisLine={false}
                  tickMargin={6}
                  fontSize={11}
                />
                <ChartTooltip
                  content={
                    <ChartTooltipContent
                      formatter={(val) => `${val} ms`}
                      indicator="dot"
                    />
                  }
                />
                <Bar
                  dataKey="latency"
                  fill="var(--color-latency)"
                  radius={[3, 3, 0, 0]}
                  maxBarSize={22}
                  isAnimationActive={false}
                />
              </BarChart>
            </ChartContainer>
          ) : (
            <ChartContainer
              config={hostChartConfig}
              className="h-[200px] w-full"
            >
              <BarChart
                data={hostSeries}
                layout="vertical"
                margin={{ top: 4, right: 16, left: 4, bottom: 0 }}
              >
                <CartesianGrid horizontal={false} strokeDasharray="3 3" />
                <XAxis
                  type="number"
                  allowDecimals={false}
                  tickLine={false}
                  axisLine={false}
                  fontSize={11}
                />
                <YAxis
                  type="category"
                  dataKey="host"
                  width={150}
                  tickLine={false}
                  axisLine={false}
                  fontSize={11}
                />
                <ChartTooltip content={<ChartTooltipContent />} />
                <Bar
                  dataKey="allow"
                  stackId="a"
                  fill="var(--color-allow)"
                  radius={[0, 2, 2, 0]}
                  barSize={14}
                  isAnimationActive={false}
                />
                <Bar
                  dataKey="deny"
                  stackId="a"
                  fill="var(--color-deny)"
                  radius={[0, 2, 2, 0]}
                  barSize={14}
                  isAnimationActive={false}
                />
              </BarChart>
            </ChartContainer>
          )}
        </CardContent>
      </Card>

      {/* Recent Requests */}
      <Card className="overflow-hidden shadow-xs">
        <CardHeader className="flex flex-row items-center justify-between gap-2 pb-3">
          <CardTitle className="text-sm font-medium">
            {t("overview.recentRequests")}
          </CardTitle>
          <Button
            variant="ghost"
            size="sm"
            className="h-7 text-xs text-muted-foreground hover:text-foreground"
            onClick={() => onNavigate("audit")}
          >
            {t("overview.allLogs")}
            <ArrowRight className="size-3.5" />
          </Button>
        </CardHeader>

        <CardContent className="px-0 pb-0">
          {recentAudit.isLoading ? (
            <div className="space-y-2 px-5 pb-5">
              {Array.from({ length: 4 }).map((_, i) => (
                <Skeleton key={i} className="h-10 w-full" />
              ))}
            </div>
          ) : events.length === 0 ? (
            <div className="px-5 py-10 text-center text-xs text-muted-foreground">
              {t("overview.noRecentRequests")}
            </div>
          ) : (
            <div className="overflow-x-auto border-t">
              <Table>
                <TableHeader>
                  <TableRow className="bg-muted/30 hover:bg-muted/30">
                    <TableHead className="w-[100px] pl-5 text-xs font-medium text-muted-foreground">
                      {t("overview.colPlatform")}
                    </TableHead>
                    <TableHead className="text-xs font-medium text-muted-foreground">
                      {t("overview.colRequest")}
                    </TableHead>
                    <TableHead className="text-xs font-medium text-muted-foreground">
                      {t("overview.colUser")}
                    </TableHead>
                    <TableHead className="text-xs font-medium text-muted-foreground">
                      {t("overview.colDecision")}
                    </TableHead>
                    <TableHead className="text-right text-xs font-medium text-muted-foreground">
                      {t("overview.colLatency")}
                    </TableHead>
                    <TableHead className="pr-5 text-right text-xs font-medium text-muted-foreground">
                      {t("overview.colTime")}
                    </TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {events.slice(0, 8).map((ev) => (
                    <TableRow
                      key={ev.id}
                      onClick={() => setSelectedEvent(ev)}
                      className="cursor-pointer"
                    >
                      <TableCell className="pl-5">
                        {ev.platform_id ? (
                          <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-[11px]">
                            {ev.platform_id}
                          </code>
                        ) : (
                          <span className="text-xs text-muted-foreground">—</span>
                        )}
                      </TableCell>
                      <TableCell>
                        <div className="flex min-w-0 max-w-md items-center gap-2">
                          <MethodBadge method={ev.http_method} />
                          <span className="truncate font-mono text-xs">
                            {ev.target_host}
                            {ev.http_path && (
                              <span className="text-muted-foreground">
                                {ev.http_path}
                              </span>
                            )}
                          </span>
                        </div>
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">
                        {ev.user_email}
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center gap-2">
                          <DecisionBadge decision={ev.decision} />
                          <StatusCodeBadge code={ev.status_code} />
                        </div>
                      </TableCell>
                      <TableCell className="text-right font-mono text-xs text-muted-foreground tabular-nums">
                        {formatLatency(ev.latency_ms)}
                      </TableCell>
                      <TableCell className="pr-5 text-right text-xs text-muted-foreground">
                        {formatRelativeTime(ev.occurred_at, locale)}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>

      <AuditDetailSheet
        event={selectedEvent}
        onClose={() => setSelectedEvent(null)}
        onQuickFilter={(filter) => {
          setSelectedEvent(null)
          onNavigate("audit", filter.search ? { q: filter.search } : undefined)
        }}
      />
    </div>
  )
}

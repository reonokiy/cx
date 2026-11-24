import type { ColumnDef } from "@tanstack/react-table"
import { ChevronRight } from "lucide-react"
import { Button } from "@/components/ui/button"
import {
  DecisionBadge,
  MethodBadge,
  RouteTierBadge,
  StatusCodeBadge,
} from "@/components/shared/decision-badge"
import type { AuditEntry } from "@/lib/api"
import { formatDateTime, formatLatency } from "@/lib/format"
import { translate, type Locale } from "@/lib/i18n"

export function getAuditColumnLabels(locale: Locale): Record<string, string> {
  return {
    occurred_at: translate(locale, "audit.colOccurredAt"),
    platform_id: translate(locale, "audit.colPlatform"),
    request: translate(locale, "audit.colTargetRequest"),
    actor: translate(locale, "audit.colActor"),
    route_tier: translate(locale, "audit.colRouteTier"),
    decision: translate(locale, "audit.colDecisionStatus"),
    client_ip: translate(locale, "audit.colClientIp"),
    latency_ms: translate(locale, "audit.colLatency"),
  }
}

export function createAuditColumns(
  locale: Locale,
  onInspect: (entry: AuditEntry) => void
): ColumnDef<AuditEntry>[] {
  return [
    {
      id: "occurred_at",
      accessorKey: "occurred_at",
      header: translate(locale, "audit.colTime"),
      cell: ({ row }) => (
        <span className="whitespace-nowrap font-mono text-xs text-muted-foreground tabular-nums">
          {formatDateTime(row.original.occurred_at, locale)}
        </span>
      ),
    },
    {
      id: "platform_id",
      accessorKey: "platform_id",
      header: translate(locale, "audit.colPlatform"),
      cell: ({ row }) =>
        row.original.platform_id ? (
          <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-[11px] text-foreground">
            {row.original.platform_id}
          </code>
        ) : (
          <span className="text-xs text-muted-foreground">—</span>
        ),
    },
    {
      id: "request",
      header: translate(locale, "audit.colRequest"),
      enableHiding: false,
      cell: ({ row }) => {
        const ev = row.original
        return (
          <div className="min-w-0 max-w-[24rem] space-y-0.5">
            <div className="flex items-center gap-1.5">
              <MethodBadge method={ev.http_method} />
              <span className="truncate font-mono text-xs font-medium text-foreground">
                {ev.target_host}
                {ev.target_port !== 443 ? `:${ev.target_port}` : ""}
              </span>
            </div>
            {ev.http_path && (
              <p className="truncate pl-[54px] font-mono text-xs text-muted-foreground">
                {ev.http_path}
              </p>
            )}
          </div>
        )
      },
    },
    {
      id: "actor",
      header: translate(locale, "audit.colActor"),
      cell: ({ row }) => (
        <span className="truncate text-sm">{row.original.user_email}</span>
      ),
    },
    {
      id: "route_tier",
      accessorKey: "route_tier",
      header: translate(locale, "audit.colRouteTier"),
      cell: ({ row }) => <RouteTierBadge tier={row.original.route_tier} />,
    },
    {
      id: "decision",
      accessorKey: "decision",
      header: translate(locale, "audit.colDecisionHeader"),
      enableHiding: false,
      cell: ({ row }) => (
        <div className="flex items-center gap-2">
          <DecisionBadge decision={row.original.decision} />
          <StatusCodeBadge code={row.original.status_code} />
        </div>
      ),
    },
    {
      id: "client_ip",
      accessorKey: "client_ip",
      header: translate(locale, "audit.colClientIp"),
      cell: ({ row }) => (
        <span className="font-mono text-xs text-muted-foreground tabular-nums">
          {row.original.client_ip}
        </span>
      ),
    },
    {
      id: "latency_ms",
      accessorKey: "latency_ms",
      header: () => (
        <div className="text-right">{translate(locale, "audit.colLatency")}</div>
      ),
      cell: ({ row }) => (
        <div className="text-right font-mono text-xs text-muted-foreground tabular-nums">
          {formatLatency(row.original.latency_ms)}
        </div>
      ),
    },
    {
      id: "actions",
      enableHiding: false,
      header: () => (
        <span className="sr-only">{translate(locale, "audit.colDetail")}</span>
      ),
      cell: ({ row }) => (
        <div className="flex justify-end">
          <Button
            type="button"
            variant="ghost"
            size="icon-xs"
            aria-label={translate(locale, "audit.inspectAria", {
              id: row.original.id,
            })}
            onClick={(e) => {
              e.stopPropagation()
              onInspect(row.original)
            }}
          >
            <ChevronRight className="size-4 text-muted-foreground" />
          </Button>
        </div>
      ),
    },
  ]
}

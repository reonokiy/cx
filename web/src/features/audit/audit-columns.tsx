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

export const AUDIT_COLUMN_LABELS: Record<string, string> = {
  occurred_at: "发生时间",
  platform_id: "平台",
  request: "目标请求",
  actor: "用户",
  route_tier: "路由层级",
  decision: "判定与状态",
  client_ip: "客户端 IP",
  latency_ms: "耗时",
}

export function createAuditColumns(
  onInspect: (entry: AuditEntry) => void
): ColumnDef<AuditEntry>[] {
  return [
    {
      id: "occurred_at",
      accessorKey: "occurred_at",
      header: "时间",
      cell: ({ row }) => (
        <span className="whitespace-nowrap font-mono text-xs text-muted-foreground tabular-nums">
          {formatDateTime(row.original.occurred_at)}
        </span>
      ),
    },
    {
      id: "platform_id",
      accessorKey: "platform_id",
      header: "平台",
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
      header: "请求",
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
      header: "用户",
      cell: ({ row }) => (
        <span className="truncate text-sm">{row.original.user_email}</span>
      ),
    },
    {
      id: "route_tier",
      accessorKey: "route_tier",
      header: "路由层级",
      cell: ({ row }) => <RouteTierBadge tier={row.original.route_tier} />,
    },
    {
      id: "decision",
      accessorKey: "decision",
      header: "判定 / 状态",
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
      header: "客户端 IP",
      cell: ({ row }) => (
        <span className="font-mono text-xs text-muted-foreground tabular-nums">
          {row.original.client_ip}
        </span>
      ),
    },
    {
      id: "latency_ms",
      accessorKey: "latency_ms",
      header: () => <div className="text-right">耗时</div>,
      cell: ({ row }) => (
        <div className="text-right font-mono text-xs text-muted-foreground tabular-nums">
          {formatLatency(row.original.latency_ms)}
        </div>
      ),
    },
    {
      id: "actions",
      enableHiding: false,
      header: () => <span className="sr-only">详情</span>,
      cell: ({ row }) => (
        <div className="flex justify-end">
          <Button
            type="button"
            variant="ghost"
            size="icon-xs"
            aria-label={`查看记录 #${row.original.id}`}
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

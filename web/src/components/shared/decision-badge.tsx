import { Badge } from "@/components/ui/badge"
import { cn } from "@/lib/utils"

export function DecisionBadge({
  decision,
  className,
}: {
  decision: string
  className?: string
}) {
  if (decision === "allow") {
    return (
      <span
        className={cn(
          "inline-flex items-center gap-1.5 text-xs font-medium text-muted-foreground",
          className
        )}
      >
        <span className="size-1.5 rounded-full bg-success" aria-hidden="true" />
        允许
      </span>
    )
  }
  if (decision === "deny") {
    return (
      <Badge
        variant="outline"
        className={cn(
          "h-5 gap-1.5 rounded-md border-destructive/30 bg-destructive/8 px-1.5 font-medium text-destructive",
          className
        )}
      >
        <span
          className="size-1.5 rounded-full bg-destructive"
          aria-hidden="true"
        />
        拒绝
      </Badge>
    )
  }
  return (
    <span className={cn("text-xs text-muted-foreground", className)}>
      {decision}
    </span>
  )
}

export function MethodBadge({
  method,
  className,
}: {
  method: string | null | undefined
  className?: string
}) {
  const normalized = (method || "TCP").toUpperCase()
  const tone =
    normalized === "DELETE"
      ? "text-destructive"
      : normalized === "POST" || normalized === "PUT" || normalized === "PATCH"
        ? "text-foreground"
        : "text-muted-foreground"

  return (
    <span
      className={cn(
        "inline-block w-12 shrink-0 font-mono text-xs font-medium tracking-tight",
        tone,
        className
      )}
    >
      {normalized}
    </span>
  )
}

export function StatusCodeBadge({
  code,
  className,
}: {
  code: number | null | undefined
  className?: string
}) {
  if (code == null) {
    return (
      <span className="font-mono text-xs text-muted-foreground tabular-nums">
        —
      </span>
    )
  }
  const tone =
    code >= 500
      ? "text-destructive"
      : code >= 400
        ? "text-warning"
        : "text-muted-foreground"

  return (
    <span className={cn("font-mono text-xs tabular-nums", tone, className)}>
      {code}
    </span>
  )
}

const ROUTE_TIER_LABELS: Record<string, string> = {
  inject: "L7 注入",
  server_tunnel: "L4 透传",
  server_http_passthrough: "HTTP 透传",
  client_passthrough: "直连",
  deny: "拒绝",
}

export function RouteTierBadge({
  tier,
  className,
}: {
  tier: string
  className?: string
}) {
  return (
    <span className={cn("text-xs text-muted-foreground", className)}>
      {ROUTE_TIER_LABELS[tier] ?? tier}
    </span>
  )
}

import { Badge } from "@/components/ui/badge"
import { useI18n, type MessageKey } from "@/lib/i18n"
import { cn } from "@/lib/utils"

export function DecisionBadge({
  decision,
  className,
}: {
  decision: string
  className?: string
}) {
  const { t } = useI18n()

  if (decision === "allow") {
    return (
      <span
        className={cn(
          "inline-flex items-center gap-1.5 text-xs font-medium text-muted-foreground",
          className
        )}
      >
        <span className="size-1.5 rounded-full bg-success" aria-hidden="true" />
        {t("common.allow")}
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
        {t("common.deny")}
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

const ROUTE_TIER_KEYS: Record<string, MessageKey> = {
  inject: "tier.inject",
  server_tunnel: "tier.server_tunnel",
  server_http_passthrough: "tier.server_http_passthrough",
  client_passthrough: "tier.client_passthrough",
  deny: "tier.deny",
}

export function RouteTierBadge({
  tier,
  className,
}: {
  tier: string
  className?: string
}) {
  const { t } = useI18n()
  const key = ROUTE_TIER_KEYS[tier]
  return (
    <span className={cn("text-xs text-muted-foreground", className)}>
      {key ? t(key) : tier}
    </span>
  )
}

import {
  Ban,
  Filter,
  Globe,
  Network,
  ShieldAlert,
  User,
} from "lucide-react"
import { useState } from "react"
import { toast } from "sonner"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Separator } from "@/components/ui/separator"
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet"
import { CopyButton } from "@/components/shared/copy-button"
import {
  DecisionBadge,
  MethodBadge,
  RouteTierBadge,
  StatusCodeBadge,
} from "@/components/shared/decision-badge"
import { useRevokeSessionMutation } from "@/hooks/use-console-queries"
import { getErrorMessage, type AuditEntry } from "@/lib/api"
import { formatDateTime, formatLatency, formatRelativeTime } from "@/lib/format"
import { useI18n } from "@/lib/i18n"

interface AuditDetailSheetProps {
  event: AuditEntry | null
  onClose: () => void
  onQuickFilter?: (filter: { profile?: string; search?: string }) => void
}

function DetailRow({
  label,
  value,
  mono = false,
  copyValue,
  copyLabel,
}: {
  label: string
  value: React.ReactNode
  mono?: boolean
  copyValue?: string
  copyLabel?: string
}) {
  return (
    <div className="flex items-start justify-between gap-3 py-2 text-sm">
      <span className="shrink-0 text-xs text-muted-foreground">{label}</span>
      <div className="flex min-w-0 items-center justify-end gap-1.5 text-right">
        <span
          className={
            mono ? "break-all font-mono text-xs" : "break-all text-xs font-medium"
          }
        >
          {value}
        </span>
        {copyValue && <CopyButton value={copyValue} label={copyLabel} />}
      </div>
    </div>
  )
}

export function AuditDetailSheet({
  event,
  onClose,
  onQuickFilter,
}: AuditDetailSheetProps) {
  const { locale, t } = useI18n()
  const [confirmRevoke, setConfirmRevoke] = useState(false)
  const revokeSession = useRevokeSessionMutation()

  const requestLine = event
    ? `${event.http_method ?? "TCP"} ${event.target_host}:${event.target_port}${event.http_path ?? ""}`
    : ""

  async function handleRevokeSession() {
    if (!event) return
    try {
      await revokeSession.mutateAsync(event.session_id)
      toast.success(t("auditDetail.toastRevoked", { id: event.session_id }))
      setConfirmRevoke(false)
    } catch (err) {
      toast.error(getErrorMessage(err))
    }
  }

  return (
    <>
      <Sheet open={Boolean(event)} onOpenChange={(open) => !open && onClose()}>
        <SheetContent className="flex w-full flex-col gap-0 p-0 sm:max-w-lg">
          {event && (
            <>
              <SheetHeader className="border-b px-6 py-5">
                <div className="flex flex-wrap items-center gap-2 pr-6">
                  <DecisionBadge decision={event.decision} />
                  <MethodBadge method={event.http_method} />
                  <StatusCodeBadge code={event.status_code} />
                  <Badge variant="outline" className="font-mono text-[11px]">
                    #{event.id}
                  </Badge>
                </div>
                <SheetTitle className="mt-2 break-all font-mono text-sm">
                  {event.target_host}
                  {event.target_port !== 443 ? `:${event.target_port}` : ""}
                </SheetTitle>
                <SheetDescription className="tabular-nums">
                  {formatDateTime(event.occurred_at, locale)} (
                  {formatRelativeTime(event.occurred_at, locale)})
                </SheetDescription>
              </SheetHeader>

              <div className="min-w-0 flex-1 overflow-y-auto">
                <div className="space-y-5 p-6">
                  {event.deny_reason && (
                    <Alert variant="destructive">
                      <ShieldAlert />
                      <AlertTitle>{t("auditDetail.denyReason")}</AlertTitle>
                      <AlertDescription className="break-all font-mono text-xs">
                        {event.deny_reason}
                      </AlertDescription>
                    </Alert>
                  )}

                  {/* Request summary card */}
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <h3 className="flex items-center gap-1.5 text-xs font-medium text-muted-foreground">
                        <Globe className="size-3.5" />
                        {t("auditDetail.requestDetails")}
                      </h3>
                      <CopyButton
                        value={requestLine}
                        label={t("auditDetail.copyRequestLine")}
                        size="xs"
                        variant="outline"
                        showLabel
                      />
                    </div>
                    <div className="divide-y rounded-lg border bg-muted/30 px-3.5 py-1">
                      <DetailRow
                        label={t("auditDetail.targetHost")}
                        value={`${event.target_host}:${event.target_port}`}
                        mono
                        copyValue={event.target_host}
                        copyLabel={t("auditDetail.copyLabel", {
                          label: t("auditDetail.targetHost"),
                        })}
                      />
                      <DetailRow
                        label={t("auditDetail.httpMethod")}
                        value={
                          event.http_method ?? t("auditDetail.tcpPassthrough")
                        }
                        mono
                      />
                      <DetailRow
                        label={t("auditDetail.requestPath")}
                        value={event.http_path ?? "—"}
                        mono
                        copyValue={event.http_path ?? undefined}
                        copyLabel={t("auditDetail.copyLabel", {
                          label: t("auditDetail.requestPath"),
                        })}
                      />
                      <DetailRow
                        label={t("auditDetail.upstreamStatus")}
                        value={<StatusCodeBadge code={event.status_code} />}
                      />
                      <DetailRow
                        label={t("auditDetail.latency")}
                        value={formatLatency(event.latency_ms)}
                        mono
                      />
                    </div>
                  </div>

                  {/* Identity & routing card */}
                  <div className="space-y-2">
                    <h3 className="flex items-center gap-1.5 text-xs font-medium text-muted-foreground">
                      <User className="size-3.5" />
                      {t("auditDetail.identityRouting")}
                    </h3>
                    <div className="divide-y rounded-lg border bg-muted/30 px-3.5 py-1">
                      <DetailRow
                        label={t("auditDetail.userEmail")}
                        value={event.user_email}
                        copyValue={event.user_email}
                        copyLabel={t("auditDetail.copyLabel", {
                          label: t("auditDetail.userEmail"),
                        })}
                      />
                      <DetailRow
                        label={t("auditDetail.profile")}
                        value={event.profile_name}
                        mono
                      />
                      {event.platform_id && (
                        <DetailRow
                          label={t("auditDetail.platform")}
                          value={event.platform_id}
                          mono
                        />
                      )}
                      <DetailRow
                        label={t("auditDetail.routeTier")}
                        value={<RouteTierBadge tier={event.route_tier} />}
                      />
                      <DetailRow
                        label={t("auditDetail.clientIp")}
                        value={event.client_ip}
                        mono
                        copyValue={event.client_ip}
                        copyLabel={t("auditDetail.copyLabel", {
                          label: t("auditDetail.clientIp"),
                        })}
                      />
                      <DetailRow
                        label={t("auditDetail.sessionId")}
                        value={event.session_id}
                        mono
                        copyValue={event.session_id}
                        copyLabel={t("auditDetail.copyLabel", {
                          label: t("auditDetail.sessionId"),
                        })}
                      />
                    </div>
                  </div>

                  {onQuickFilter && (
                    <>
                      <Separator />
                      <div className="space-y-2.5">
                        <h3 className="flex items-center gap-1.5 text-xs font-medium text-muted-foreground">
                          <Filter className="size-3.5" />
                          {t("auditDetail.quickFilter")}
                        </h3>
                        <div className="flex flex-wrap gap-2">
                          <Button
                            type="button"
                            variant="outline"
                            size="sm"
                            onClick={() =>
                              onQuickFilter({ search: event.target_host })
                            }
                          >
                            <Globe className="size-3.5" />
                            {t("auditDetail.onlyThisHost")}
                          </Button>
                          <Button
                            type="button"
                            variant="outline"
                            size="sm"
                            onClick={() =>
                              onQuickFilter({ search: event.session_id })
                            }
                          >
                            <Network className="size-3.5" />
                            {t("auditDetail.traceSession")}
                          </Button>
                        </div>
                      </div>
                    </>
                  )}

                  <Separator />

                  <div className="flex items-center justify-between gap-3 rounded-lg border border-destructive/25 bg-destructive/5 p-3.5">
                    <div className="space-y-0.5">
                      <p className="text-xs font-medium">
                        {t("auditDetail.revokeTitle")}
                      </p>
                      <p className="text-[11px] text-muted-foreground">
                        {t("auditDetail.revokeDesc")}
                      </p>
                    </div>
                    <Button
                      type="button"
                      variant="destructive"
                      size="sm"
                      onClick={() => setConfirmRevoke(true)}
                      disabled={revokeSession.isPending}
                    >
                      <Ban className="size-3.5" />
                      {t("auditDetail.revokeButton")}
                    </Button>
                  </div>
                </div>
              </div>
            </>
          )}
        </SheetContent>
      </Sheet>

      <AlertDialog open={confirmRevoke} onOpenChange={setConfirmRevoke}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>
              {t("auditDetail.revokeConfirmTitle")}
            </AlertDialogTitle>
            <AlertDialogDescription>
              {t("auditDetail.revokeConfirmBefore")}{" "}
              <code className="rounded bg-muted px-1 py-0.5 font-mono text-xs text-foreground">
                {event?.session_id}
              </code>{" "}
              {t("auditDetail.revokeConfirmAfter")}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={revokeSession.isPending}>
              {t("common.cancel")}
            </AlertDialogCancel>
            <AlertDialogAction
              onClick={(e) => {
                e.preventDefault()
                void handleRevokeSession()
              }}
              disabled={revokeSession.isPending}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {revokeSession.isPending
                ? t("auditDetail.revoking")
                : t("auditDetail.confirmRevoke")}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}

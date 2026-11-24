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
}: {
  label: string
  value: React.ReactNode
  mono?: boolean
  copyValue?: string
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
        {copyValue && <CopyButton value={copyValue} label={`复制${label}`} />}
      </div>
    </div>
  )
}

export function AuditDetailSheet({
  event,
  onClose,
  onQuickFilter,
}: AuditDetailSheetProps) {
  const [confirmRevoke, setConfirmRevoke] = useState(false)
  const revokeSession = useRevokeSessionMutation()

  const requestLine = event
    ? `${event.http_method ?? "TCP"} ${event.target_host}:${event.target_port}${event.http_path ?? ""}`
    : ""

  async function handleRevokeSession() {
    if (!event) return
    try {
      await revokeSession.mutateAsync(event.session_id)
      toast.success(`已吊销会话 ${event.session_id}`)
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
                  {formatDateTime(event.occurred_at)}（
                  {formatRelativeTime(event.occurred_at)}）
                </SheetDescription>
              </SheetHeader>

              <div className="min-w-0 flex-1 overflow-y-auto">
                <div className="space-y-5 p-6">
                  {event.deny_reason && (
                    <Alert variant="destructive">
                      <ShieldAlert />
                      <AlertTitle>策略拒绝原因</AlertTitle>
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
                        请求详情
                      </h3>
                      <CopyButton
                        value={requestLine}
                        label="复制请求行"
                        size="xs"
                        variant="outline"
                        showLabel
                      />
                    </div>
                    <div className="rounded-lg border bg-muted/30 px-3.5 py-1 divide-y">
                      <DetailRow
                        label="目标主机"
                        value={`${event.target_host}:${event.target_port}`}
                        mono
                        copyValue={event.target_host}
                      />
                      <DetailRow
                        label="HTTP 方法"
                        value={event.http_method ?? "TCP（L4 透传）"}
                        mono
                      />
                      <DetailRow
                        label="请求路径"
                        value={event.http_path ?? "—"}
                        mono
                        copyValue={event.http_path ?? undefined}
                      />
                      <DetailRow
                        label="上游状态码"
                        value={<StatusCodeBadge code={event.status_code} />}
                      />
                      <DetailRow
                        label="处理耗时"
                        value={formatLatency(event.latency_ms)}
                        mono
                      />
                    </div>
                  </div>

                  {/* Identity & routing card */}
                  <div className="space-y-2">
                    <h3 className="flex items-center gap-1.5 text-xs font-medium text-muted-foreground">
                      <User className="size-3.5" />
                      身份与路由上下文
                    </h3>
                    <div className="rounded-lg border bg-muted/30 px-3.5 py-1 divide-y">
                      <DetailRow
                        label="用户邮箱"
                        value={event.user_email}
                        copyValue={event.user_email}
                      />
                      <DetailRow
                        label="Profile"
                        value={event.profile_name}
                        mono
                      />
                      {event.platform_id && (
                        <DetailRow
                          label="平台"
                          value={event.platform_id}
                          mono
                        />
                      )}
                      <DetailRow
                        label="路由层级"
                        value={<RouteTierBadge tier={event.route_tier} />}
                      />
                      <DetailRow
                        label="客户端 IP"
                        value={event.client_ip}
                        mono
                        copyValue={event.client_ip}
                      />
                      <DetailRow
                        label="会话 ID"
                        value={event.session_id}
                        mono
                        copyValue={event.session_id}
                      />
                    </div>
                  </div>

                  {onQuickFilter && (
                    <>
                      <Separator />
                      <div className="space-y-2.5">
                        <h3 className="flex items-center gap-1.5 text-xs font-medium text-muted-foreground">
                          <Filter className="size-3.5" />
                          快捷筛选
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
                            仅看此主机
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
                            追踪此会话
                          </Button>
                        </div>
                      </div>
                    </>
                  )}

                  <Separator />

                  <div className="flex items-center justify-between gap-3 rounded-lg border border-destructive/25 bg-destructive/5 p-3.5">
                    <div className="space-y-0.5">
                      <p className="text-xs font-medium">安全响应 · 吊销会话</p>
                      <p className="text-[11px] text-muted-foreground">
                        立即将该会话加入吊销列表，阻断后续 QUIC 请求。
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
                      吊销会话
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
            <AlertDialogTitle>确认吊销此会话？</AlertDialogTitle>
            <AlertDialogDescription>
              会话{" "}
              <code className="rounded bg-muted px-1 py-0.5 font-mono text-xs text-foreground">
                {event?.session_id}
              </code>{" "}
              将被服务端立即吊销，持有该会话令牌的客户端连接将无法继续代理请求。此操作无法撤销。
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={revokeSession.isPending}>
              取消
            </AlertDialogCancel>
            <AlertDialogAction
              onClick={(e) => {
                e.preventDefault()
                void handleRevokeSession()
              }}
              disabled={revokeSession.isPending}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {revokeSession.isPending ? "正在吊销…" : "确认吊销"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  )
}

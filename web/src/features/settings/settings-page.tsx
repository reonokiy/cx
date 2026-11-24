import {
  CircleAlert,
  KeyRound,
  KeySquare,
  Save,
  SlidersHorizontal,
  Trash2,
} from "lucide-react"
import { useEffect, useState, type FormEvent } from "react"
import { toast } from "sonner"
import { Alert, AlertDescription } from "@/components/ui/alert"
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
import { Button } from "@/components/ui/button"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import {
  Empty,
  EmptyDescription,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle,
} from "@/components/ui/empty"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Skeleton } from "@/components/ui/skeleton"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Textarea } from "@/components/ui/textarea"
import { PageHeader } from "@/components/shared/page-header"
import { ScopedTokensTab } from "@/features/keys/scoped-tokens-tab"
import { VirtualKeysTab } from "@/features/keys/virtual-keys-tab"
import {
  useDeleteProfileMutation,
  useProfileDetailQuery,
  useUpdateProfileMutation,
} from "@/hooks/use-console-queries"
import { getErrorMessage, type DefaultRouteAction } from "@/lib/api"
import { useAuth } from "@/lib/auth"
import { formatDateTime } from "@/lib/format"
import { useActiveProfile } from "@/lib/profile-context"

function splitTokens(raw: string): string[] {
  return raw
    .split(/[\s,]+/)
    .map((s) => s.trim())
    .filter(Boolean)
}

function splitLines(raw: string): string[] {
  return raw
    .split("\n")
    .map((s) => s.trim())
    .filter(Boolean)
}

function ProfileSettingsTab({ onDeleted }: { onDeleted: () => void }) {
  const { activeProfile } = useActiveProfile()
  const detailQuery = useProfileDetailQuery(activeProfile)
  const updateProfile = useUpdateProfileMutation(activeProfile)
  const deleteProfile = useDeleteProfileMutation()

  const detail = detailQuery.data

  const [description, setDescription] = useState("")
  const [groupsRaw, setGroupsRaw] = useState("")
  const [usersRaw, setUsersRaw] = useState("")
  const [denyHostsRaw, setDenyHostsRaw] = useState("")
  const [fallback, setFallback] =
    useState<DefaultRouteAction>("client_passthrough")
  const [confirmDelete, setConfirmDelete] = useState(false)
  const [error, setError] = useState("")

  useEffect(() => {
    if (!detail) return
    setDescription(detail.description)
    setGroupsRaw(detail.allowed_groups.join(", "))
    setUsersRaw(detail.allowed_users.join(", "))
    setDenyHostsRaw(detail.deny_hosts.join("\n"))
    setFallback(detail.fallback)
    setError("")
  }, [detail])

  if (detailQuery.isLoading || !detail) {
    return <Skeleton className="h-72 max-w-2xl rounded-xl" />
  }

  async function handleSave(e: FormEvent) {
    e.preventDefault()
    if (!detail) return
    setError("")
    try {
      await updateProfile.mutateAsync({
        revision: detail.revision,
        description: description.trim(),
        allowed_groups: splitTokens(groupsRaw),
        allowed_users: splitTokens(usersRaw),
        deny_hosts: splitLines(denyHostsRaw),
        fallback,
        platforms: detail.platforms.map((p) => p.spec),
      })
      toast.success(`已保存 Profile ${detail.name} 的设置`)
    } catch (err) {
      const msg = getErrorMessage(err)
      setError(msg)
      toast.error(msg)
    }
  }

  async function handleDelete() {
    if (!detail) return
    try {
      await deleteProfile.mutateAsync(detail.name)
      toast.success(`已删除 Profile ${detail.name}`)
      setConfirmDelete(false)
      onDeleted()
    } catch (err) {
      toast.error(getErrorMessage(err))
    }
  }

  return (
    <div className="max-w-2xl space-y-5">
      <Card className="shadow-xs">
        <CardHeader>
          <CardTitle className="text-sm font-medium">
            基本配置与访问权限
          </CardTitle>
          <CardDescription className="text-xs tabular-nums">
            最后由 {detail.updated_by} 更新于 {formatDateTime(detail.updated_at)}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSave} className="space-y-4">
            <div className="space-y-1.5">
              <Label htmlFor="settings-desc" className="text-xs">
                说明
              </Label>
              <Input
                id="settings-desc"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="该 Profile 的适用场景说明"
              />
            </div>

            <div className="grid gap-3 sm:grid-cols-2">
              <div className="space-y-1.5">
                <Label htmlFor="settings-groups" className="text-xs">
                  允许访问的 OIDC 用户组（逗号分隔）
                </Label>
                <Input
                  id="settings-groups"
                  value={groupsRaw}
                  onChange={(e) => setGroupsRaw(e.target.value)}
                  placeholder="eng, cx-admins"
                  className="font-mono text-xs"
                />
              </div>

              <div className="space-y-1.5">
                <Label htmlFor="settings-users" className="text-xs">
                  额外允许的用户邮箱（可选，逗号分隔）
                </Label>
                <Input
                  id="settings-users"
                  value={usersRaw}
                  onChange={(e) => setUsersRaw(e.target.value)}
                  placeholder="alice@example.com"
                  className="font-mono text-xs"
                />
              </div>
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="settings-fallback" className="text-xs">
                未匹配域名兜底策略
              </Label>
              <Select
                value={fallback}
                onValueChange={(v) => setFallback(v as DefaultRouteAction)}
              >
                <SelectTrigger id="settings-fallback" className="max-w-xs">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="client_passthrough">
                    客户端直连（默认）
                  </SelectItem>
                  <SelectItem value="deny">严格拒绝（仅放行已挂载平台域名）</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="settings-deny-hosts" className="text-xs">
                全局黑名单域名（可选，每行一个）
              </Label>
              <Textarea
                id="settings-deny-hosts"
                rows={3}
                value={denyHostsRaw}
                onChange={(e) => setDenyHostsRaw(e.target.value)}
                placeholder="blocked.example.com"
                className="font-mono text-xs"
              />
            </div>

            {error && (
              <Alert variant="destructive" role="alert">
                <CircleAlert />
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            )}

            <Button type="submit" size="sm" disabled={updateProfile.isPending}>
              <Save />
              {updateProfile.isPending ? "保存中…" : "保存设置"}
            </Button>
          </form>
        </CardContent>
      </Card>

      <Card className="border-destructive/30 shadow-xs">
        <CardContent className="flex flex-col justify-between gap-3 py-4 sm:flex-row sm:items-center">
          <div className="space-y-0.5">
            <p className="text-sm font-medium">删除 Profile</p>
            <p className="text-xs text-muted-foreground">
              将永久移除 <code className="font-mono">{detail.name}</code> 及其下所有平台绑定与规则（不删除历史审计日志与加密凭据本身）。
            </p>
          </div>
          <Button
            type="button"
            variant="destructive"
            size="sm"
            onClick={() => setConfirmDelete(true)}
            disabled={deleteProfile.isPending}
          >
            <Trash2 />
            删除 Profile
          </Button>
        </CardContent>
      </Card>

      <AlertDialog open={confirmDelete} onOpenChange={setConfirmDelete}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>确认删除 Profile {detail.name}？</AlertDialogTitle>
            <AlertDialogDescription>
              删除后，使用该 Profile 的新会话将立即失效，此操作无法撤销。
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deleteProfile.isPending}>
              取消
            </AlertDialogCancel>
            <AlertDialogAction
              onClick={(e) => {
                e.preventDefault()
                void handleDelete()
              }}
              disabled={deleteProfile.isPending}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {deleteProfile.isPending ? "删除中…" : "确认删除"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}

export function SettingsPage({
  initialTab,
  onProfileDeleted,
}: {
  initialTab?: string
  onProfileDeleted: () => void
}) {
  const { session } = useAuth()
  const { activeProfile } = useActiveProfile()
  const isAdmin = Boolean(session?.context.admin)

  const defaultTab =
    initialTab === "vkeys" || initialTab === "tokens"
      ? initialTab
      : isAdmin
        ? "profile"
        : "vkeys"

  const [tab, setTab] = useState(defaultTab)

  useEffect(() => {
    if (initialTab === "profile" || initialTab === "vkeys" || initialTab === "tokens") {
      setTab(initialTab)
    }
  }, [initialTab])

  if (!activeProfile) {
    return (
      <div className="flex flex-col gap-5">
        <PageHeader title="设置与令牌" />
        <Card className="shadow-xs">
          <Empty className="border-0 py-14">
            <EmptyHeader>
              <EmptyMedia variant="icon">
                <SlidersHorizontal />
              </EmptyMedia>
              <EmptyTitle className="text-base">尚未选择 Profile</EmptyTitle>
              <EmptyDescription>
                请先在左上角新建或选择一个 Profile。
              </EmptyDescription>
            </EmptyHeader>
          </Empty>
        </Card>
      </div>
    )
  }

  return (
    <div className="flex flex-col gap-5">
      <PageHeader title="设置与令牌" />

      <Tabs value={tab} onValueChange={setTab} className="space-y-4">
        <TabsList>
          {isAdmin && (
            <TabsTrigger value="profile" className="gap-1.5">
              <SlidersHorizontal className="size-3.5" />
              Profile 设置
            </TabsTrigger>
          )}
          <TabsTrigger value="vkeys" className="gap-1.5">
            <KeyRound className="size-3.5" />
            虚拟密钥
          </TabsTrigger>
          <TabsTrigger value="tokens" className="gap-1.5">
            <KeySquare className="size-3.5" />
            限定令牌
          </TabsTrigger>
        </TabsList>

        {isAdmin && (
          <TabsContent value="profile">
            <ProfileSettingsTab onDeleted={onProfileDeleted} />
          </TabsContent>
        )}

        <TabsContent value="vkeys">
          <VirtualKeysTab />
        </TabsContent>

        <TabsContent value="tokens">
          <ScopedTokensTab />
        </TabsContent>
      </Tabs>
    </div>
  )
}

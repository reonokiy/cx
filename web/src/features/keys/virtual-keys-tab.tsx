import { CircleAlert, KeyRound, ShieldCheck } from "lucide-react"
import { useEffect, useState, type FormEvent } from "react"
import { toast } from "sonner"
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
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
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
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group"
import { CopyButton } from "@/components/shared/copy-button"
import { ProviderIcon } from "@/components/shared/provider-icon"
import { useCreateVirtualKeyMutation } from "@/hooks/use-console-queries"
import { getErrorMessage, type CreateVirtualKeyResponse } from "@/lib/api"
import { formatDateTime } from "@/lib/format"
import { useActiveProfile } from "@/lib/profile-context"

const TTL_PRESETS = [
  { label: "1 小时", seconds: "3600" },
  { label: "24 小时", seconds: "86400" },
  { label: "7 天", seconds: "604800" },
  { label: "30 天", seconds: "2592000" },
] as const

export function VirtualKeysTab() {
  const { activeProfile, activeProfileMeta, canIssueKeys } = useActiveProfile()
  const createKey = useCreateVirtualKeyMutation()

  const platforms = activeProfileMeta?.platforms ?? []
  const [platformId, setPlatformId] = useState(platforms[0]?.id ?? "")
  const [ttlSecs, setTtlSecs] = useState("86400")
  const [issued, setIssued] = useState<CreateVirtualKeyResponse | null>(null)
  const [error, setError] = useState("")

  useEffect(() => {
    setPlatformId(platforms[0]?.id ?? "")
    setError("")
  }, [activeProfile, platforms])

  if (!activeProfile || !canIssueKeys) {
    return (
      <Card className="shadow-xs">
        <Empty className="border-0 py-14">
          <EmptyHeader>
            <EmptyMedia variant="icon">
              <KeyRound />
            </EmptyMedia>
            <EmptyTitle className="text-base">无法签发虚拟密钥</EmptyTitle>
            <EmptyDescription>
              {activeProfile
                ? `当前账号无权为 ${activeProfile} 签发虚拟密钥。`
                : "请先选择一个 Profile。"}
            </EmptyDescription>
          </EmptyHeader>
        </Empty>
      </Card>
    )
  }

  if (platforms.length === 0) {
    return (
      <Card className="shadow-xs">
        <Empty className="border-0 py-14">
          <EmptyHeader>
            <EmptyMedia variant="icon">
              <KeyRound />
            </EmptyMedia>
            <EmptyTitle className="text-base">尚未挂载平台</EmptyTitle>
            <EmptyDescription>
              请先在「平台与规则」中为 {activeProfile} 添加至少一个平台。
            </EmptyDescription>
          </EmptyHeader>
        </Empty>
      </Card>
    )
  }

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    if (!platformId) return
    setError("")
    try {
      const res = await createKey.mutateAsync({
        profile: activeProfile,
        platform: platformId,
        ttl_secs: Number(ttlSecs),
      })
      setIssued(res)
      toast.success(`已为 ${activeProfile} / ${res.platform} 生成虚拟密钥`)
    } catch (err) {
      const msg = getErrorMessage(err)
      setError(msg)
      toast.error(msg)
    }
  }

  return (
    <>
      <Card className="max-w-xl shadow-xs">
        <CardHeader>
          <CardTitle className="text-sm font-medium">
            静态虚拟密钥（占位假密钥）
          </CardTitle>
          <CardDescription className="text-xs">
            日常运行 <code className="font-mono">cx exec</code> 会自动注入临时虚拟密钥；仅当工具或{" "}
            <code className="font-mono">.env</code> 需写入固定占位字符串时按需签发。
          </CardDescription>
        </CardHeader>

        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-1.5">
              <Label htmlFor="vk-platform" className="text-xs">
                目标平台
              </Label>
              <Select
                value={platformId}
                onValueChange={setPlatformId}
                disabled={createKey.isPending}
              >
                <SelectTrigger id="vk-platform" className="font-mono text-xs">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {platforms.map((p) => (
                    <SelectItem key={p.id} value={p.id}>
                      <span className="flex items-center gap-2">
                        <ProviderIcon
                          icon={p.provider_icon}
                          providerId={p.provider_id}
                          name={p.provider_name}
                          size="xs"
                          framed={false}
                        />
                        <span>
                          {p.id === p.provider_id ? p.provider_name : p.id}
                        </span>
                        <span className="font-mono text-[11px] text-muted-foreground">
                          {p.id === p.provider_id ? p.id : p.provider_name}
                        </span>
                      </span>
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div className="space-y-1.5">
              <Label className="text-xs">有效期</Label>
              <div>
                <ToggleGroup
                  type="single"
                  variant="outline"
                  size="sm"
                  value={ttlSecs}
                  onValueChange={(v) => v && setTtlSecs(v)}
                >
                  {TTL_PRESETS.map((preset) => (
                    <ToggleGroupItem
                      key={preset.seconds}
                      value={preset.seconds}
                      className="px-3 text-xs"
                    >
                      {preset.label}
                    </ToggleGroupItem>
                  ))}
                </ToggleGroup>
              </div>
            </div>

            {error && (
              <Alert variant="destructive" role="alert">
                <CircleAlert />
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            )}

            <Button type="submit" size="sm" disabled={createKey.isPending}>
              <KeyRound />
              {createKey.isPending ? "生成中…" : "生成虚拟密钥"}
            </Button>
          </form>
        </CardContent>
      </Card>

      <Dialog
        open={Boolean(issued)}
        onOpenChange={(open) => {
          if (!open) setIssued(null)
        }}
      >
        {issued && (
          <DialogContent className="sm:max-w-lg">
            <DialogHeader>
              <div className="mb-1 flex items-center gap-2">
                <ShieldCheck className="size-4 text-success" />
                <DialogTitle>虚拟密钥已生成</DialogTitle>
              </div>
              <DialogDescription>
                明文仅显示一次；脱离你的 <code className="font-mono">cx exec</code> 隧道无法调用真实上游。
              </DialogDescription>
            </DialogHeader>

            <div className="space-y-3">
              <div className="flex items-center gap-2">
                <Input
                  readOnly
                  value={issued.virtual_key}
                  onFocus={(e) => e.target.select()}
                  className="font-mono text-xs"
                />
                <CopyButton
                  value={issued.virtual_key}
                  label="复制"
                  variant="default"
                  size="sm"
                  showLabel
                />
              </div>
              <p className="text-xs text-muted-foreground tabular-nums">
                Profile：<code className="font-mono">{issued.profile}</code> · 平台：
                <code className="font-mono">{issued.platform}</code>
                {issued.expires_at
                  ? ` · 到期：${formatDateTime(issued.expires_at)}`
                  : ""}
              </p>
            </div>

            <DialogFooter>
              <Button size="sm" onClick={() => setIssued(null)}>
                完成
              </Button>
            </DialogFooter>
          </DialogContent>
        )}
      </Dialog>
    </>
  )
}

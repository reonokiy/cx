import { Plus } from "lucide-react"
import { useEffect, useState, type FormEvent } from "react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { ProviderIcon } from "@/components/shared/provider-icon"
import { useCreateProfileMutation } from "@/hooks/use-console-queries"
import {
  getErrorMessage,
  type DefaultRouteAction,
  type PlatformSpec,
  type ProviderCatalogEntry,
} from "@/lib/api"
import { useActiveProfile } from "@/lib/profile-context"

const IDENTIFIER_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/

function buildDefaultPlatformSpec(
  profileName: string,
  provider: ProviderCatalogEntry
): PlatformSpec {
  const defaultPreset = provider.presets.readonly
    ? "readonly"
    : provider.presets.full
      ? "full"
      : (Object.keys(provider.presets)[0] ?? null)

  const secrets: PlatformSpec["secrets"] = {}
  for (const field of provider.secret_fields) {
    secrets[field] = {
      source: "db",
      scope: "shared",
      name: `${profileName}/${provider.id}`,
    }
  }

  return {
    id: provider.id,
    provider_id: provider.id,
    params: {},
    secrets,
    preset: defaultPreset,
    rules: [],
    routing: {},
    allow_insecure_http: false,
  }
}

export function CreateProfileDialog({
  open,
  onOpenChange,
  onCreated,
}: {
  open: boolean
  onOpenChange: (open: boolean) => void
  onCreated?: (name: string) => void
}) {
  const { providers, setActiveProfile } = useActiveProfile()
  const createProfile = useCreateProfileMutation()

  const namedProviders = providers.filter((p) => !p.allow_multiple)

  const [name, setName] = useState("")
  const [description, setDescription] = useState("")
  const [groupsRaw, setGroupsRaw] = useState("eng, cx-admins")
  const [fallback, setFallback] =
    useState<DefaultRouteAction>("client_passthrough")
  const [selectedProviders, setSelectedProviders] = useState<string[]>([])
  const [error, setError] = useState("")

  useEffect(() => {
    if (open) {
      setName("")
      setDescription("")
      setGroupsRaw("eng, cx-admins")
      setFallback("client_passthrough")
      setSelectedProviders([])
      setError("")
    }
  }, [open])

  function toggleProvider(id: string) {
    setSelectedProviders((prev) =>
      prev.includes(id) ? prev.filter((item) => item !== id) : [...prev, id]
    )
  }

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    const cleanName = name.trim().toLowerCase()
    if (!IDENTIFIER_RE.test(cleanName)) {
      setError("名称需由小写字母或数字开头，仅可包含 a-z、0-9、.、_、-。")
      return
    }
    const groups = groupsRaw
      .split(/[\s,]+/)
      .map((s) => s.trim())
      .filter(Boolean)
    if (groups.length === 0) {
      setError("请至少填写一个允许访问的 OIDC 用户组（如 eng 或 *）。")
      return
    }

    const platforms: PlatformSpec[] = selectedProviders
      .map((pid) => namedProviders.find((p) => p.id === pid))
      .filter((p): p is ProviderCatalogEntry => Boolean(p))
      .map((p) => buildDefaultPlatformSpec(cleanName, p))

    setError("")
    try {
      const created = await createProfile.mutateAsync({
        name: cleanName,
        description: description.trim(),
        allowed_groups: groups,
        allowed_users: [],
        deny_hosts: [],
        fallback,
        platforms,
      })
      setActiveProfile(created.name)
      toast.success(`已创建 Profile ${created.name}`)
      onOpenChange(false)
      onCreated?.(created.name)
    } catch (err) {
      setError(getErrorMessage(err))
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>新建 Profile</DialogTitle>
          <DialogDescription>
            Profile 对应一个使用场景，可按需挂载多个上游平台与独立规则。
          </DialogDescription>
        </DialogHeader>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-1.5">
            <Label htmlFor="create-profile-name">名称</Label>
            <Input
              id="create-profile-name"
              placeholder="例如 coding-agent 或 dev"
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="font-mono text-sm"
              autoFocus
            />
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="create-profile-desc">
              说明 <span className="font-normal text-muted-foreground">（可选）</span>
            </Label>
            <Input
              id="create-profile-desc"
              placeholder="例如 日常研发与 AI 代理环境"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
            />
          </div>

          <div className="grid gap-3 sm:grid-cols-2">
            <div className="space-y-1.5">
              <Label htmlFor="create-profile-groups">允许的用户组</Label>
              <Input
                id="create-profile-groups"
                placeholder="eng, cx-admins"
                value={groupsRaw}
                onChange={(e) => setGroupsRaw(e.target.value)}
                className="font-mono text-xs"
              />
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="create-profile-fallback">未匹配域名兜底</Label>
              <Select
                value={fallback}
                onValueChange={(v) => setFallback(v as DefaultRouteAction)}
              >
                <SelectTrigger id="create-profile-fallback">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="client_passthrough">客户端直连</SelectItem>
                  <SelectItem value="deny">严格拒绝（白名单）</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>

          {namedProviders.length > 0 && (
            <div className="space-y-2">
              <Label>
                初始挂载平台{" "}
                <span className="font-normal text-muted-foreground">
                  （创建后仍可随时增删或添加自定义 HTTP）
                </span>
              </Label>
              <div className="grid gap-2 sm:grid-cols-2">
                {namedProviders.map((provider) => {
                  const checked = selectedProviders.includes(provider.id)
                  return (
                    <label
                      key={provider.id}
                      className="flex cursor-pointer items-center gap-2.5 rounded-md border px-3 py-2 text-left transition-colors hover:bg-muted/40"
                    >
                      <Checkbox
                        checked={checked}
                        onCheckedChange={() => toggleProvider(provider.id)}
                      />
                      <ProviderIcon
                        icon={provider.icon}
                        providerId={provider.id}
                        name={provider.name}
                        size="sm"
                      />
                      <div className="min-w-0">
                        <div className="truncate text-xs font-medium">
                          {provider.name}
                        </div>
                        <div className="truncate font-mono text-[11px] text-muted-foreground">
                          {provider.id}
                        </div>
                      </div>
                    </label>
                  )
                })}
              </div>
            </div>
          )}

          {error && (
            <p className="text-xs text-destructive" role="alert">
              {error}
            </p>
          )}

          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={() => onOpenChange(false)}
              disabled={createProfile.isPending}
            >
              取消
            </Button>
            <Button type="submit" disabled={createProfile.isPending}>
              <Plus />
              {createProfile.isPending ? "创建中…" : "创建 Profile"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

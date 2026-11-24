import {
  ArrowDown,
  ArrowUp,
  Blocks,
  ChevronDown,
  ChevronRight,
  CircleAlert,
  Copy,
  Eye,
  EyeOff,
  Pencil,
  Plus,
  RefreshCw,
  Save,
  Trash2,
} from "lucide-react"
import { useEffect, useMemo, useState, type FormEvent } from "react"
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
  EmptyContent,
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
import { Separator } from "@/components/ui/separator"
import { Skeleton } from "@/components/ui/skeleton"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { DecisionBadge } from "@/components/shared/decision-badge"
import { PageHeader } from "@/components/shared/page-header"
import { ProviderIcon } from "@/components/shared/provider-icon"
import { PlatformSimulator } from "@/features/platforms/platform-simulator"
import { RuleEditorDialog } from "@/features/policies/rule-editor-dialog"
import {
  useProfileDetailQuery,
  useUpdateProfileMutation,
  useUpsertSecretMutation,
} from "@/hooks/use-console-queries"
import {
  getErrorMessage,
  type PlatformDetail,
  type PlatformSpec,
  type PolicyRule,
  type ProfileDetail,
  type ProviderCatalogEntry,
  type SecretBinding,
  type SecretMeta,
  type SecretScope,
} from "@/lib/api"
import { useAuth } from "@/lib/auth"
import { formatDateTime } from "@/lib/format"
import { useActiveProfile } from "@/lib/profile-context"
import { cn } from "@/lib/utils"

const IDENTIFIER_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/
const NEW_GENERIC_KEY = "__new_generic__"

function suggestEnvVar(id: string): string {
  const clean = id
    .replace(/[^a-zA-Z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "")
    .toUpperCase()
  return clean ? `${clean}_TOKEN` : "API_TOKEN"
}

interface PlatformsPageProps {
  initialPlatform?: string
  openAdd?: boolean
}

type Selection =
  | { kind: "provider"; providerId: string }
  | { kind: "custom"; platformId: string }
  | { kind: "new_generic" }

function PresetRulesTable({ rules }: { rules: PolicyRule[] }) {
  return (
    <div className="mt-3 overflow-x-auto rounded-md border bg-background">
      <Table>
        <TableHeader>
          <TableRow className="bg-muted/30 hover:bg-muted/30">
            <TableHead className="w-[84px] text-xs">动作</TableHead>
            <TableHead className="w-[120px] text-xs">方法</TableHead>
            <TableHead className="text-xs">主机</TableHead>
            <TableHead className="text-xs">路径</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {rules.map((rule, idx) => (
            <TableRow key={idx}>
              <TableCell>
                <DecisionBadge decision={rule.effect} />
              </TableCell>
              <TableCell className="font-mono text-xs">
                {rule.methods.join(", ") || "*"}
              </TableCell>
              <TableCell className="font-mono text-xs">
                {rule.hosts.join(", ") || "*"}
              </TableCell>
              <TableCell className="font-mono text-xs text-muted-foreground">
                {rule.paths.join(", ") || "/**"}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  )
}

function SecretValueForm({
  secretName,
  scope,
  field,
  configured,
  updatedAt,
  encryptionReady,
}: {
  secretName: string
  scope: SecretScope
  field: string
  configured: boolean
  updatedAt: number | null
  encryptionReady: boolean
}) {
  const upsertSecret = useUpsertSecretMutation()
  const [value, setValue] = useState("")
  const [revealed, setRevealed] = useState(false)

  async function handleSave(e: FormEvent) {
    e.preventDefault()
    if (!value.trim()) {
      toast.error(`请输入 ${field}`)
      return
    }
    try {
      await upsertSecret.mutateAsync({
        name: secretName,
        scope,
        fields: { [field]: value },
      })
      setValue("")
      setRevealed(false)
      toast.success(`已加密保存凭据 ${secretName}`)
    } catch (err) {
      toast.error(getErrorMessage(err))
    }
  }

  return (
    <form onSubmit={handleSave} className="space-y-2.5 pt-2">
      <div className="flex items-center justify-between gap-2 text-xs">
        <Label
          htmlFor={`secret-val-${secretName}-${field}`}
          className="font-mono text-xs"
        >
          {field}
        </Label>
        <span
          className={cn(
            "text-[11px]",
            configured ? "text-muted-foreground" : "text-warning"
          )}
        >
          {configured && updatedAt
            ? `已配置 · ${formatDateTime(updatedAt)}`
            : configured
              ? "已配置"
              : "尚未录入密钥"}
        </span>
      </div>

      <div className="flex gap-2">
        <div className="relative flex-1">
          <Input
            id={`secret-val-${secretName}-${field}`}
            type={revealed ? "text" : "password"}
            value={value}
            onChange={(e) => setValue(e.target.value)}
            placeholder={
              configured
                ? `输入新的 ${field} 以覆盖（服务端不回显明文）`
                : `输入 ${field}`
            }
            disabled={!encryptionReady || upsertSecret.isPending}
            autoComplete="off"
            className="pr-9 font-mono text-xs"
          />
          <Button
            type="button"
            variant="ghost"
            size="icon-xs"
            aria-label={revealed ? "隐藏" : "显示"}
            onClick={() => setRevealed((r) => !r)}
            className="absolute right-1.5 top-1/2 -translate-y-1/2 text-muted-foreground"
          >
            {revealed ? (
              <EyeOff className="size-3.5" />
            ) : (
              <Eye className="size-3.5" />
            )}
          </Button>
        </div>

        <Button
          type="submit"
          size="sm"
          disabled={!encryptionReady || upsertSecret.isPending || !value.trim()}
        >
          <Save className="size-3.5" />
          {upsertSecret.isPending ? "保存中…" : "保存密钥"}
        </Button>
      </div>
    </form>
  )
}

/**
 * Inline panel to enable an unmounted named Provider or create a new `generic-http` instance
 * directly inside the unified Platforms workspace (no modal detour).
 */
function EnableProviderPanel({
  profileName,
  provider,
  isAdmin,
  existingPlatformIds,
  sharedSecrets,
  submitting,
  onEnable,
}: {
  profileName: string
  provider: ProviderCatalogEntry
  isAdmin: boolean
  existingPlatformIds: string[]
  sharedSecrets: SecretMeta[]
  submitting: boolean
  onEnable: (platform: PlatformSpec) => Promise<void>
}) {
  const isCustomHttp = provider.allow_multiple
  const presetNames = Object.keys(provider.presets)
  const defaultPreset = provider.presets.readonly
    ? "readonly"
    : provider.presets.full
      ? "full"
      : (presetNames[0] ?? "none")

  const [customId, setCustomId] = useState("")
  const [params, setParams] = useState<Record<string, string>>(() => {
    const initial: Record<string, string> = {}
    for (const p of provider.params) {
      if (p.default) initial[p.name] = p.default
    }
    return initial
  })
  const [preset, setPreset] = useState(defaultPreset)
  const [showPresetPreview, setShowPresetPreview] = useState(false)
  const [secretScope, setSecretScope] = useState<SecretScope>("shared")
  const [secretName, setSecretName] = useState(
    isCustomHttp ? "" : `${profileName}/${provider.id}`
  )
  const [error, setError] = useState("")

  const presetRules =
    preset !== "none" ? (provider.presets[preset] ?? []) : []

  function handleCustomIdChange(val: string) {
    const clean = val.toLowerCase()
    setCustomId(clean)
    if (isCustomHttp) {
      setParams((prev) => ({ ...prev, env_var: suggestEnvVar(clean) }))
      setSecretName(
        secretScope === "shared"
          ? clean
            ? `${profileName}/${clean}`
            : ""
          : clean
      )
    }
  }

  function handleScopeChange(nextScope: SecretScope) {
    setSecretScope(nextScope)
    const effectiveId = isCustomHttp ? customId.trim() : provider.id
    if (!effectiveId) return
    setSecretName(
      nextScope === "shared" ? `${profileName}/${effectiveId}` : effectiveId
    )
  }

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    const id = isCustomHttp ? customId.trim().toLowerCase() : provider.id
    if (!IDENTIFIER_RE.test(id)) {
      setError("平台标识需由小写字母或数字开头，仅支持 a-z、0-9、.、_、-。")
      return
    }
    if (existingPlatformIds.includes(id)) {
      setError(`当前 Profile 中已存在名为 ${id} 的平台。`)
      return
    }

    const cleanedParams: Record<string, string> = {}
    for (const paramDef of provider.params) {
      const val = (params[paramDef.name] ?? "").trim()
      if (paramDef.required && !val) {
        setError(`请填写必填参数 ${paramDef.name}。`)
        return
      }
      if (val && (paramDef.required || val !== (paramDef.default ?? ""))) {
        cleanedParams[paramDef.name] = val
      }
    }

    const secrets: PlatformSpec["secrets"] = {}
    if (provider.secret_fields.length > 0) {
      const targetName =
        secretName.trim() ||
        (secretScope === "shared" ? `${profileName}/${id}` : id)
      for (const field of provider.secret_fields) {
        secrets[field] = {
          source: "db",
          scope: secretScope,
          name: targetName,
        }
      }
    }

    setError("")
    try {
      await onEnable({
        id,
        provider_id: provider.id,
        params: cleanedParams,
        secrets,
        preset: preset === "none" ? null : preset,
        rules: [],
        routing: {},
        allow_insecure_http: false,
      })
    } catch (err) {
      setError(getErrorMessage(err))
    }
  }

  return (
    <Card className="min-w-0 shadow-xs">
      <CardHeader className="border-b pb-4">
        <div className="flex items-start gap-3">
          <ProviderIcon
            icon={provider.icon}
            providerId={provider.id}
            name={provider.name}
            size="lg"
          />
          <div className="min-w-0 flex-1 space-y-1">
            <div className="flex flex-wrap items-center gap-2">
              <CardTitle className="text-base font-semibold">
                {isCustomHttp ? `新增 ${provider.name}` : provider.name}
              </CardTitle>
              <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-[11px] text-muted-foreground">
                {provider.id}
              </code>
              {!isCustomHttp && (
                <span className="rounded border px-1.5 py-0.5 text-[11px] text-muted-foreground">
                  未启用
                </span>
              )}
            </div>
            <CardDescription className="text-xs">
              {provider.description}
            </CardDescription>
          </div>
        </div>
      </CardHeader>

      <CardContent className="space-y-5 pt-5">
        {provider.default_inject_hosts.length > 0 && !isCustomHttp && (
          <div className="space-y-1.5 text-xs">
            <span className="text-muted-foreground">默认注入域名</span>
            <div className="flex flex-wrap gap-1.5">
              {provider.default_inject_hosts.map((host) => (
                <code
                  key={host}
                  className="rounded bg-muted px-2 py-0.5 font-mono text-[11px]"
                >
                  {host}
                </code>
              ))}
            </div>
          </div>
        )}

        {!isAdmin ? (
          <div className="rounded-lg border border-dashed p-5 text-xs text-muted-foreground">
            当前 Profile 尚未启用 {provider.name}，如需开通请联系管理员配置。
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="space-y-4">
            {isCustomHttp && (
              <div className="space-y-1.5">
                <Label htmlFor="inline-custom-id" className="text-xs">
                  自定义平台标识
                </Label>
                <Input
                  id="inline-custom-id"
                  placeholder="例如 jira 或 internal-api"
                  value={customId}
                  onChange={(e) => handleCustomIdChange(e.target.value)}
                  className="max-w-sm font-mono text-xs"
                  autoFocus
                />
              </div>
            )}

            {provider.params.length > 0 && (
              <div className="grid gap-3 sm:grid-cols-2">
                {provider.params.map((p) => (
                  <div key={p.name} className="space-y-1.5">
                    <Label
                      htmlFor={`enable-param-${p.name}`}
                      className="font-mono text-xs"
                    >
                      {p.name}
                      {p.required && (
                        <span className="ml-1 text-destructive">*</span>
                      )}
                    </Label>
                    <Input
                      id={`enable-param-${p.name}`}
                      value={params[p.name] ?? ""}
                      placeholder={p.default ?? "必填"}
                      onChange={(e) =>
                        setParams((prev) => ({
                          ...prev,
                          [p.name]: e.target.value,
                        }))
                      }
                      className="h-8 font-mono text-xs"
                    />
                  </div>
                ))}
              </div>
            )}

            <div className="rounded-lg border bg-muted/20 p-3.5">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div className="flex items-center gap-3">
                  <Label
                    htmlFor="enable-platform-preset"
                    className="text-xs font-medium"
                  >
                    策略预设
                  </Label>
                  <Select value={preset} onValueChange={setPreset}>
                    <SelectTrigger
                      id="enable-platform-preset"
                      size="sm"
                      className="w-44 font-mono text-xs"
                    >
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {presetNames.map((name) => (
                        <SelectItem
                          key={name}
                          value={name}
                          className="font-mono text-xs"
                        >
                          {name}
                        </SelectItem>
                      ))}
                      <SelectItem value="none">不使用预设（默认拒绝）</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                {presetRules.length > 0 && (
                  <Button
                    type="button"
                    variant="ghost"
                    size="xs"
                    className="text-xs text-muted-foreground"
                    onClick={() => setShowPresetPreview((v) => !v)}
                  >
                    {showPresetPreview ? (
                      <ChevronDown className="size-3.5" />
                    ) : (
                      <ChevronRight className="size-3.5" />
                    )}
                    预设内置规则 ({presetRules.length} 条)
                  </Button>
                )}
              </div>
              {showPresetPreview && presetRules.length > 0 && (
                <PresetRulesTable rules={presetRules} />
              )}
            </div>

            {provider.secret_fields.length > 0 && (
              <div className="grid gap-3 sm:grid-cols-2">
                <div className="space-y-1.5">
                  <Label htmlFor="enable-secret-scope" className="text-xs">
                    上游凭据模式
                  </Label>
                  <Select
                    value={secretScope}
                    onValueChange={(v) => handleScopeChange(v as SecretScope)}
                  >
                    <SelectTrigger id="enable-secret-scope" size="sm">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="shared">
                        团队共享（管理员录入）
                      </SelectItem>
                      <SelectItem value="personal">
                        成员个人（默认跨 Profile 复用）
                      </SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                <div className="space-y-1.5">
                  <Label htmlFor="enable-secret-name" className="text-xs">
                    凭据名称
                  </Label>
                  <Input
                    id="enable-secret-name"
                    value={secretName}
                    onChange={(e) => setSecretName(e.target.value)}
                    placeholder={
                      secretScope === "shared"
                        ? `${profileName}/${provider.id}`
                        : provider.id
                    }
                    className="h-8 font-mono text-xs"
                  />
                  {secretScope === "shared" && sharedSecrets.length > 0 && (
                    <div className="flex flex-wrap items-center gap-1 pt-0.5">
                      <span className="text-[11px] text-muted-foreground">
                        复用：
                      </span>
                      {sharedSecrets.slice(0, 5).map((s) => (
                        <button
                          key={s.name}
                          type="button"
                          onClick={() => setSecretName(s.name)}
                          className="rounded bg-muted px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground hover:text-foreground"
                        >
                          {s.name}
                        </button>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            )}

            {error && (
              <p className="text-xs text-destructive" role="alert">
                {error}
              </p>
            )}

            <div className="pt-1">
              <Button type="submit" size="sm" disabled={submitting}>
                <Plus />
                {submitting
                  ? "保存中…"
                  : isCustomHttp
                    ? `添加自定义 HTTP 到 ${profileName}`
                    : `启用 ${provider.name}`}
              </Button>
            </div>
          </form>
        )}
      </CardContent>
    </Card>
  )
}

function MountedPlatformWorkspace({
  profile,
  platform,
  providerMeta,
  isAdmin,
  encryptionReady,
  sharedSecrets,
  savingProfile,
  onSavePlatformSpec,
  onRemovePlatform,
}: {
  profile: ProfileDetail
  platform: PlatformDetail
  providerMeta: ProviderCatalogEntry | null
  isAdmin: boolean
  encryptionReady: boolean
  sharedSecrets: SecretMeta[]
  savingProfile: boolean
  onSavePlatformSpec: (nextSpec: PlatformSpec) => Promise<void>
  onRemovePlatform: () => void
}) {
  const [tab, setTab] = useState<"rules" | "secrets" | "params">("rules")
  const [draft, setDraft] = useState<PlatformSpec>(platform.spec)
  const [showPresetRules, setShowPresetRules] = useState(false)
  const [ruleDialogOpen, setRuleDialogOpen] = useState(false)
  const [editingRuleIndex, setEditingRuleIndex] = useState<number | null>(null)
  const [narrowHostsInput, setNarrowHostsInput] = useState(
    (platform.spec.routing.inject_hosts ?? []).join("\n")
  )

  useEffect(() => {
    setDraft(platform.spec)
    setNarrowHostsInput((platform.spec.routing.inject_hosts ?? []).join("\n"))
  }, [platform])

  const isDirty = useMemo(() => {
    const nextNarrow = narrowHostsInput
      .split("\n")
      .map((s) => s.trim())
      .filter(Boolean)
    const origNarrow = platform.spec.routing.inject_hosts ?? []
    const narrowChanged =
      JSON.stringify(nextNarrow) !== JSON.stringify(origNarrow)
    return (
      narrowChanged || JSON.stringify(draft) !== JSON.stringify(platform.spec)
    )
  }, [draft, narrowHostsInput, platform.spec])

  const presetNames = providerMeta ? Object.keys(providerMeta.presets) : []
  const previewPresetRules = useMemo(() => {
    if (!draft.preset) return []
    if (draft.preset === platform.spec.preset) return platform.preset_rules
    return providerMeta?.presets[draft.preset] ?? []
  }, [draft.preset, platform.spec.preset, platform.preset_rules, providerMeta])

  const isNamed = platform.spec.id === platform.spec.provider_id
  const primaryTitle = isNamed ? platform.provider_name : platform.spec.id
  const secondaryCode = isNamed
    ? platform.spec.id
    : `${platform.provider_name} · ${platform.spec.provider_id}`

  function buildSpecForSave(): PlatformSpec {
    const narrowed = narrowHostsInput
      .split("\n")
      .map((s) => s.trim())
      .filter(Boolean)
    return {
      ...draft,
      routing: {
        ...draft.routing,
        inject_hosts: narrowed.length > 0 ? narrowed : null,
      },
    }
  }

  async function handleSaveAll() {
    await onSavePlatformSpec(buildSpecForSave())
  }

  function handleRuleSubmit(rule: PolicyRule) {
    setDraft((prev) => {
      const nextRules = [...prev.rules]
      if (editingRuleIndex !== null) {
        nextRules[editingRuleIndex] = rule
      } else {
        nextRules.push(rule)
      }
      return { ...prev, rules: nextRules }
    })
  }

  function moveRule(index: number, delta: -1 | 1) {
    setDraft((prev) => {
      const target = index + delta
      if (target < 0 || target >= prev.rules.length) return prev
      const next = [...prev.rules]
      const [item] = next.splice(index, 1)
      next.splice(target, 0, item)
      return { ...prev, rules: next }
    })
  }

  function duplicateRule(index: number) {
    setDraft((prev) => {
      const copy = structuredClone(prev.rules[index])
      const next = [...prev.rules]
      next.splice(index + 1, 0, copy)
      return { ...prev, rules: next }
    })
  }

  function deleteRule(index: number) {
    setDraft((prev) => ({
      ...prev,
      rules: prev.rules.filter((_, i) => i !== index),
    }))
  }

  function updateSecretBinding(slot: string, scope: SecretScope, name: string) {
    setDraft((prev) => ({
      ...prev,
      secrets: {
        ...prev.secrets,
        [slot]: {
          source: "db",
          scope,
          name,
        },
      },
    }))
  }

  return (
    <Card className="min-w-0 shadow-xs">
      <CardHeader className="flex flex-col gap-3 border-b pb-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex min-w-0 items-start gap-3">
          <ProviderIcon
            icon={platform.provider_icon}
            providerId={platform.spec.provider_id}
            name={platform.provider_name}
            size="lg"
          />
          <div className="min-w-0 space-y-1">
            <div className="flex flex-wrap items-center gap-2">
              <CardTitle className="text-base font-semibold">
                {primaryTitle}
              </CardTitle>
              <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-[11px] text-muted-foreground">
                {secondaryCode}
              </code>
            </div>
            <CardDescription className="flex flex-wrap items-center gap-1.5 text-xs">
              {platform.inject_hosts.map((host) => (
                <code
                  key={host}
                  className="rounded bg-muted px-1.5 py-0.5 font-mono text-[11px] text-foreground"
                >
                  {host}
                </code>
              ))}
            </CardDescription>
          </div>
        </div>

        <div className="flex shrink-0 items-center gap-2">
          {isAdmin && isDirty && (
            <>
              <Button
                type="button"
                variant="ghost"
                size="sm"
                onClick={() => {
                  setDraft(platform.spec)
                  setNarrowHostsInput(
                    (platform.spec.routing.inject_hosts ?? []).join("\n")
                  )
                }}
                disabled={savingProfile}
              >
                放弃
              </Button>
              <Button
                type="button"
                size="sm"
                onClick={() => void handleSaveAll()}
                disabled={savingProfile}
              >
                <Save />
                {savingProfile ? "保存中…" : "保存变更"}
              </Button>
            </>
          )}
          {isAdmin && (
            <Button
              type="button"
              variant="ghost"
              size="icon-sm"
              aria-label={`停用或移除 ${primaryTitle}`}
              className="text-muted-foreground hover:text-destructive"
              onClick={onRemovePlatform}
              disabled={savingProfile}
            >
              <Trash2 className="size-4" />
            </Button>
          )}
        </div>
      </CardHeader>

      <CardContent className="space-y-5 pt-4">
        <Tabs
          value={tab}
          onValueChange={(v) => setTab(v as "rules" | "secrets" | "params")}
        >
          <TabsList>
            <TabsTrigger value="rules">
              访问规则 ({draft.rules.length})
            </TabsTrigger>
            <TabsTrigger value="secrets">
              上游凭据
              {platform.secrets.some((s) => !s.configured) && (
                <span className="ml-1.5 size-1.5 rounded-full bg-warning" />
              )}
            </TabsTrigger>
            <TabsTrigger value="params">参数与路由</TabsTrigger>
          </TabsList>

          {/* TAB 1: ACCESS RULES */}
          <TabsContent value="rules" className="mt-4 space-y-4">
            <div className="rounded-lg border bg-muted/20 p-3.5">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div className="flex items-center gap-3">
                  <Label htmlFor="platform-preset" className="text-xs font-medium">
                    策略预设
                  </Label>
                  {isAdmin ? (
                    <Select
                      value={draft.preset ?? "none"}
                      onValueChange={(v) =>
                        setDraft((prev) => ({
                          ...prev,
                          preset: v === "none" ? null : v,
                        }))
                      }
                    >
                      <SelectTrigger
                        id="platform-preset"
                        size="sm"
                        className="w-44 font-mono text-xs"
                      >
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {presetNames.map((p) => (
                          <SelectItem
                            key={p}
                            value={p}
                            className="font-mono text-xs"
                          >
                            {p}
                          </SelectItem>
                        ))}
                        <SelectItem value="none">不使用预设（默认拒绝）</SelectItem>
                      </SelectContent>
                    </Select>
                  ) : (
                    <code className="rounded bg-muted px-2 py-0.5 font-mono text-xs">
                      {draft.preset ?? "无预设"}
                    </code>
                  )}
                </div>

                {previewPresetRules.length > 0 && (
                  <Button
                    type="button"
                    variant="ghost"
                    size="xs"
                    className="text-xs text-muted-foreground"
                    onClick={() => setShowPresetRules((v) => !v)}
                  >
                    {showPresetRules ? (
                      <ChevronDown className="size-3.5" />
                    ) : (
                      <ChevronRight className="size-3.5" />
                    )}
                    预设内置规则 ({previewPresetRules.length} 条)
                  </Button>
                )}
              </div>

              {showPresetRules && previewPresetRules.length > 0 && (
                <PresetRulesTable rules={previewPresetRules} />
              )}
            </div>

            <div className="space-y-2.5">
              <div className="flex items-center justify-between gap-2">
                <div>
                  <h3 className="text-xs font-medium">自定义规则</h3>
                  <p className="text-[11px] text-muted-foreground">
                    与预设共同生效，显式拒绝始终优先于允许规则。
                  </p>
                </div>
                {isAdmin && (
                  <Button
                    type="button"
                    size="sm"
                    variant="outline"
                    onClick={() => {
                      setEditingRuleIndex(null)
                      setRuleDialogOpen(true)
                    }}
                  >
                    <Plus />
                    添加规则
                  </Button>
                )}
              </div>

              {draft.rules.length === 0 ? (
                <div className="rounded-lg border border-dashed py-8 text-center text-xs text-muted-foreground">
                  暂无自定义规则，当前完全按预设执行。
                </div>
              ) : (
                <div className="overflow-x-auto rounded-lg border">
                  <Table>
                    <TableHeader>
                      <TableRow className="bg-muted/30 hover:bg-muted/30">
                        <TableHead className="w-[44px] text-xs">#</TableHead>
                        <TableHead className="w-[84px] text-xs">动作</TableHead>
                        <TableHead className="w-[120px] text-xs">方法</TableHead>
                        <TableHead className="text-xs">主机</TableHead>
                        <TableHead className="text-xs">路径</TableHead>
                        {isAdmin && (
                          <TableHead className="w-[136px] text-right text-xs">
                            操作
                          </TableHead>
                        )}
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {draft.rules.map((rule, idx) => (
                        <TableRow key={idx}>
                          <TableCell className="font-mono text-xs text-muted-foreground tabular-nums">
                            {idx + 1}
                          </TableCell>
                          <TableCell>
                            <DecisionBadge decision={rule.effect} />
                          </TableCell>
                          <TableCell className="font-mono text-xs">
                            {rule.methods.join(", ") || "*"}
                          </TableCell>
                          <TableCell className="font-mono text-xs">
                            {rule.hosts.join(", ") || "*"}
                          </TableCell>
                          <TableCell className="font-mono text-xs text-muted-foreground">
                            {rule.paths.join(", ") || "/**"}
                          </TableCell>
                          {isAdmin && (
                            <TableCell className="text-right">
                              <div className="flex justify-end gap-0.5">
                                <Button
                                  type="button"
                                  variant="ghost"
                                  size="icon-xs"
                                  aria-label="上移"
                                  disabled={idx === 0}
                                  onClick={() => moveRule(idx, -1)}
                                >
                                  <ArrowUp className="size-3.5" />
                                </Button>
                                <Button
                                  type="button"
                                  variant="ghost"
                                  size="icon-xs"
                                  aria-label="下移"
                                  disabled={idx === draft.rules.length - 1}
                                  onClick={() => moveRule(idx, 1)}
                                >
                                  <ArrowDown className="size-3.5" />
                                </Button>
                                <Button
                                  type="button"
                                  variant="ghost"
                                  size="icon-xs"
                                  aria-label="复制规则"
                                  onClick={() => duplicateRule(idx)}
                                >
                                  <Copy className="size-3.5" />
                                </Button>
                                <Button
                                  type="button"
                                  variant="ghost"
                                  size="icon-xs"
                                  aria-label="编辑规则"
                                  onClick={() => {
                                    setEditingRuleIndex(idx)
                                    setRuleDialogOpen(true)
                                  }}
                                >
                                  <Pencil className="size-3.5" />
                                </Button>
                                <Button
                                  type="button"
                                  variant="ghost"
                                  size="icon-xs"
                                  aria-label="删除规则"
                                  className="hover:text-destructive"
                                  onClick={() => deleteRule(idx)}
                                >
                                  <Trash2 className="size-3.5" />
                                </Button>
                              </div>
                            </TableCell>
                          )}
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              )}
            </div>

            <PlatformSimulator
              presetName={draft.preset}
              presetRules={previewPresetRules}
              customRules={draft.rules}
              defaultHost={platform.inject_hosts[0] ?? ""}
            />
          </TabsContent>

          {/* TAB 2: UPSTREAM SECRETS */}
          <TabsContent value="secrets" className="mt-4 space-y-4">
            {!encryptionReady && (
              <Alert variant="destructive">
                <CircleAlert />
                <AlertDescription>
                  服务端未配置 <code className="font-mono">CX_MASTER_KEY</code>，当前无法加密保存数据库凭据。
                </AlertDescription>
              </Alert>
            )}

            {platform.secrets.length === 0 ? (
              <div className="rounded-lg border border-dashed py-8 text-center text-xs text-muted-foreground">
                此平台无需配置上游凭据。
              </div>
            ) : (
              platform.secrets.map((slotStatus) => {
                const draftBinding: SecretBinding | undefined =
                  draft.secrets[slotStatus.slot]
                const bindingScope: SecretScope =
                  draftBinding?.source === "db"
                    ? draftBinding.scope
                    : (slotStatus.scope ?? "shared")
                const bindingName =
                  draftBinding?.source === "db"
                    ? draftBinding.name
                    : (slotStatus.name ??
                      (bindingScope === "shared"
                        ? `${profile.name}/${platform.spec.id}`
                        : platform.spec.id))

                const savedDbName =
                  platform.spec.secrets[slotStatus.slot]?.source === "db"
                    ? (
                        platform.spec.secrets[slotStatus.slot] as Extract<
                          SecretBinding,
                          { source: "db" }
                        >
                      ).name
                    : null
                const savedDbScope =
                  platform.spec.secrets[slotStatus.slot]?.source === "db"
                    ? (
                        platform.spec.secrets[slotStatus.slot] as Extract<
                          SecretBinding,
                          { source: "db" }
                        >
                      ).scope
                    : null
                const bindingUnsaved =
                  savedDbName !== bindingName || savedDbScope !== bindingScope

                return (
                  <div
                    key={slotStatus.slot}
                    className="space-y-3 rounded-lg border p-4"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-sm font-medium">
                          {slotStatus.slot}
                        </span>
                        <span className="rounded bg-muted px-1.5 py-0.5 text-[11px] text-muted-foreground">
                          {bindingScope === "shared" ? "团队共享" : "成员个人"}
                        </span>
                      </div>
                      {slotStatus.name && (
                        <code className="font-mono text-xs text-muted-foreground">
                          {slotStatus.name}
                        </code>
                      )}
                    </div>

                    {isAdmin && (
                      <div className="grid gap-3 border-b pb-3 sm:grid-cols-2">
                        <div className="space-y-1">
                          <Label className="text-[11px] text-muted-foreground">
                            凭据范围
                          </Label>
                          <Select
                            value={bindingScope}
                            onValueChange={(v) => {
                              const nextScope = v as SecretScope
                              const nextName =
                                nextScope === "shared"
                                  ? `${profile.name}/${platform.spec.id}`
                                  : platform.spec.id
                              updateSecretBinding(
                                slotStatus.slot,
                                nextScope,
                                nextName
                              )
                            }}
                          >
                            <SelectTrigger size="sm">
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              <SelectItem value="shared">
                                团队共享（管理员维护）
                              </SelectItem>
                              <SelectItem value="personal">
                                成员个人（默认跨 Profile 复用）
                              </SelectItem>
                            </SelectContent>
                          </Select>
                        </div>

                        <div className="space-y-1">
                          <Label className="text-[11px] text-muted-foreground">
                            绑定名称
                          </Label>
                          <Input
                            value={bindingName}
                            onChange={(e) =>
                              updateSecretBinding(
                                slotStatus.slot,
                                bindingScope,
                                e.target.value
                              )
                            }
                            className="h-8 font-mono text-xs"
                          />
                          {bindingScope === "shared" &&
                            sharedSecrets.length > 0 && (
                              <div className="flex flex-wrap gap-1 pt-0.5">
                                {sharedSecrets.slice(0, 5).map((s) => (
                                  <button
                                    key={s.name}
                                    type="button"
                                    onClick={() =>
                                      updateSecretBinding(
                                        slotStatus.slot,
                                        "shared",
                                        s.name
                                      )
                                    }
                                    className="rounded bg-muted px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground hover:text-foreground"
                                  >
                                    {s.name}
                                  </button>
                                ))}
                              </div>
                            )}
                        </div>
                      </div>
                    )}

                    {bindingUnsaved ? (
                      <p className="text-xs text-muted-foreground">
                        凭据绑定已修改，请先点击右上角「保存变更」，再录入密钥值。
                      </p>
                    ) : slotStatus.can_edit && savedDbName && savedDbScope ? (
                      <SecretValueForm
                        secretName={savedDbName}
                        scope={savedDbScope}
                        field={slotStatus.field}
                        configured={slotStatus.configured}
                        updatedAt={slotStatus.updated_at}
                        encryptionReady={encryptionReady}
                      />
                    ) : (
                      <p className="text-xs text-muted-foreground">
                        {slotStatus.source === "db" &&
                        slotStatus.scope === "shared"
                          ? slotStatus.configured
                            ? "团队共享凭据已由管理员配置就绪。"
                            : "团队共享凭据尚未录入，请联系管理员配置。"
                          : slotStatus.configured
                            ? "凭据已就绪。"
                            : "凭据未配置。"}
                      </p>
                    )}
                  </div>
                )
              })
            )}
          </TabsContent>

          {/* TAB 3: PARAMS & ROUTING */}
          <TabsContent value="params" className="mt-4 space-y-4">
            {providerMeta && providerMeta.params.length > 0 && (
              <div className="space-y-3 rounded-lg border p-4">
                <h3 className="text-xs font-medium">平台参数</h3>
                <div className="grid gap-3 sm:grid-cols-2">
                  {providerMeta.params.map((p) => (
                    <div key={p.name} className="space-y-1">
                      <Label className="font-mono text-xs">
                        {p.name}
                        {p.required && (
                          <span className="ml-1 text-destructive">*</span>
                        )}
                      </Label>
                      <Input
                        value={draft.params[p.name] ?? p.default ?? ""}
                        disabled={!isAdmin}
                        onChange={(e) =>
                          setDraft((prev) => ({
                            ...prev,
                            params: { ...prev.params, [p.name]: e.target.value },
                          }))
                        }
                        className="h-8 font-mono text-xs"
                      />
                    </div>
                  ))}
                </div>
              </div>
            )}

            <div className="space-y-3 rounded-lg border p-4">
              <div className="space-y-0.5">
                <h3 className="text-xs font-medium">域名收窄（可选）</h3>
                <p className="text-[11px] text-muted-foreground">
                  留空表示启用平台默认注入域名；填写后仅允许列表中的子集域名注入凭据（每行一个）。
                </p>
              </div>
              <textarea
                rows={3}
                disabled={!isAdmin}
                value={narrowHostsInput}
                onChange={(e) => setNarrowHostsInput(e.target.value)}
                placeholder={platform.inject_hosts.join("\n")}
                className="w-full rounded-md border bg-background px-3 py-2 font-mono text-xs outline-none focus-visible:ring-2 focus-visible:ring-ring disabled:opacity-60"
              />
              {platform.server_tunnel_hosts.length > 0 && (
                <div className="flex flex-wrap items-center gap-1.5 pt-1 text-xs">
                  <span className="text-muted-foreground">L4 TLS 透传域名：</span>
                  {platform.server_tunnel_hosts.map((h) => (
                    <code
                      key={h}
                      className="rounded bg-muted px-1.5 py-0.5 font-mono text-[11px]"
                    >
                      {h}
                    </code>
                  ))}
                </div>
              )}
            </div>
          </TabsContent>
        </Tabs>
      </CardContent>

      <RuleEditorDialog
        open={ruleDialogOpen}
        rule={
          editingRuleIndex !== null ? draft.rules[editingRuleIndex] : undefined
        }
        suggestedHosts={platform.inject_hosts}
        onOpenChange={setRuleDialogOpen}
        onSubmitRule={handleRuleSubmit}
      />
    </Card>
  )
}

export function PlatformsPage({
  initialPlatform,
  openAdd,
}: PlatformsPageProps) {
  const { session } = useAuth()
  const { activeProfile, providers, sharedSecrets, setCreateDialogOpen } =
    useActiveProfile()
  const detailQuery = useProfileDetailQuery(activeProfile)
  const updateProfile = useUpdateProfileMutation(activeProfile)

  const namedProviders = useMemo(
    () => providers.filter((p) => !p.allow_multiple),
    [providers]
  )
  const genericProvider = useMemo(
    () => providers.find((p) => p.allow_multiple) ?? null,
    [providers]
  )

  const detail = detailQuery.data
  const mountedPlatforms = detail?.platforms ?? []
  const mountedById = useMemo(
    () => new Map(mountedPlatforms.map((p) => [p.spec.id, p])),
    [mountedPlatforms]
  )
  const customHttpInstances = useMemo(
    () =>
      mountedPlatforms.filter(
        (p) => genericProvider && p.spec.provider_id === genericProvider.id
      ),
    [mountedPlatforms, genericProvider]
  )

  const [selection, setSelection] = useState<Selection | null>(null)
  const [removeTarget, setRemoveTarget] = useState<PlatformDetail | null>(null)

  // Initialize / reconcile selection when profile, URL param, or catalog changes
  useEffect(() => {
    if (openAdd && genericProvider && session?.context.admin) {
      setSelection({ kind: "new_generic" })
      return
    }
    if (initialPlatform) {
      if (namedProviders.some((p) => p.id === initialPlatform)) {
        setSelection({ kind: "provider", providerId: initialPlatform })
        return
      }
      if (mountedById.has(initialPlatform)) {
        setSelection({ kind: "custom", platformId: initialPlatform })
        return
      }
    }
  }, [
    initialPlatform,
    openAdd,
    namedProviders,
    mountedById,
    genericProvider,
    session?.context.admin,
  ])

  const effectiveSelection = useMemo<Selection | null>(() => {
    if (selection) {
      if (
        selection.kind === "provider" &&
        namedProviders.some((p) => p.id === selection.providerId)
      ) {
        return selection
      }
      if (
        selection.kind === "custom" &&
        customHttpInstances.some((p) => p.spec.id === selection.platformId)
      ) {
        return selection
      }
      if (selection.kind === "new_generic" && genericProvider) {
        return selection
      }
    }
    // Default: prefer the first mounted named provider, else first mounted custom instance, else first available provider
    const firstMountedNamed = namedProviders.find((p) => mountedById.has(p.id))
    if (firstMountedNamed) {
      return { kind: "provider", providerId: firstMountedNamed.id }
    }
    if (customHttpInstances[0]) {
      return { kind: "custom", platformId: customHttpInstances[0].spec.id }
    }
    if (namedProviders[0]) {
      return { kind: "provider", providerId: namedProviders[0].id }
    }
    if (genericProvider) {
      return { kind: "new_generic" }
    }
    return null
  }, [
    selection,
    namedProviders,
    customHttpInstances,
    mountedById,
    genericProvider,
  ])

  if (!session) return null
  const isAdmin = session.context.admin

  if (!activeProfile) {
    return (
      <div className="flex flex-col gap-5">
        <PageHeader title="平台与规则" />
        <Card className="shadow-xs">
          <Empty className="border-0 py-14">
            <EmptyHeader>
              <EmptyMedia variant="icon">
                <Blocks />
              </EmptyMedia>
              <EmptyTitle className="text-base">请先创建或选择 Profile</EmptyTitle>
              <EmptyDescription>
                在左上角切换或新建 Profile 后即可查看所有可用平台并逐项配置。
              </EmptyDescription>
            </EmptyHeader>
            {isAdmin && (
              <EmptyContent>
                <Button size="sm" onClick={() => setCreateDialogOpen(true)}>
                  <Plus />
                  新建 Profile
                </Button>
              </EmptyContent>
            )}
          </Empty>
        </Card>
      </div>
    )
  }

  async function savePlatforms(nextPlatforms: PlatformSpec[], toastMsg: string) {
    if (!detail) return
    try {
      await updateProfile.mutateAsync({
        revision: detail.revision,
        description: detail.description,
        allowed_groups: detail.allowed_groups,
        allowed_users: detail.allowed_users,
        deny_hosts: detail.deny_hosts,
        fallback: detail.fallback,
        platforms: nextPlatforms,
      })
      toast.success(toastMsg)
    } catch (err) {
      toast.error(getErrorMessage(err))
      throw err
    }
  }

  async function handleAddOrEnablePlatform(newSpec: PlatformSpec) {
    if (!detail) return
    const next = [...detail.platforms.map((p) => p.spec), newSpec]
    const prov = providers.find((p) => p.id === newSpec.provider_id)
    const label =
      newSpec.id === newSpec.provider_id && prov ? prov.name : newSpec.id
    await savePlatforms(next, `已启用 ${label}`)
    if (genericProvider && newSpec.provider_id === genericProvider.id) {
      setSelection({ kind: "custom", platformId: newSpec.id })
    } else {
      setSelection({ kind: "provider", providerId: newSpec.provider_id })
    }
  }

  async function handleSaveSinglePlatform(updatedSpec: PlatformSpec) {
    if (!detail) return
    const next = detail.platforms.map((p) =>
      p.spec.id === updatedSpec.id ? updatedSpec : p.spec
    )
    const prov = providers.find((p) => p.id === updatedSpec.provider_id)
    const label =
      updatedSpec.id === updatedSpec.provider_id && prov
        ? prov.name
        : updatedSpec.id
    await savePlatforms(next, `已保存 ${label} 配置并生效`)
  }

  async function handleConfirmRemove() {
    if (!detail || !removeTarget) return
    const target = removeTarget
    const next = detail.platforms
      .map((p) => p.spec)
      .filter((p) => p.id !== target.spec.id)
    try {
      const label =
        target.spec.id === target.spec.provider_id
          ? target.provider_name
          : target.spec.id
      await savePlatforms(next, `已停用 ${label}`)
      setRemoveTarget(null)
      if (target.spec.id !== target.spec.provider_id) {
        setSelection(null)
      }
    } catch {
      // toast already displayed
    }
  }

  // Resolve right-hand panel content from effectiveSelection
  let selectedMounted: PlatformDetail | null = null
  let selectedUnmountedProvider: ProviderCatalogEntry | null = null
  let isNewGenericView = false

  if (effectiveSelection?.kind === "provider") {
    const mounted = mountedById.get(effectiveSelection.providerId)
    if (mounted) {
      selectedMounted = mounted
    } else {
      selectedUnmountedProvider =
        namedProviders.find((p) => p.id === effectiveSelection.providerId) ??
        null
    }
  } else if (effectiveSelection?.kind === "custom") {
    selectedMounted = mountedById.get(effectiveSelection.platformId) ?? null
  } else if (effectiveSelection?.kind === "new_generic" && genericProvider) {
    isNewGenericView = true
  }

  const selectedProviderMeta = selectedMounted
    ? (providers.find((p) => p.id === selectedMounted!.spec.provider_id) ??
      null)
    : null

  return (
    <div className="flex flex-col gap-5">
      <PageHeader
        title="平台与规则"
        actions={
          <Button
            variant="outline"
            size="sm"
            onClick={() => void detailQuery.refetch()}
            disabled={detailQuery.isFetching}
          >
            <RefreshCw
              className={detailQuery.isFetching ? "animate-spin" : undefined}
            />
            刷新
          </Button>
        }
      />

      {detailQuery.isError && (
        <Alert variant="destructive" role="alert">
          <CircleAlert />
          <AlertDescription>{getErrorMessage(detailQuery.error)}</AlertDescription>
        </Alert>
      )}

      {detailQuery.isLoading || !detail ? (
        <div className="grid gap-4 lg:grid-cols-[260px_minmax(0,1fr)]">
          <Skeleton className="h-64 rounded-xl" />
          <Skeleton className="h-96 rounded-xl" />
        </div>
      ) : (
        <div className="grid items-start gap-4 lg:grid-cols-[260px_minmax(0,1fr)]">
          {/* Unified All-Providers Rail */}
          <Card className="gap-0 p-2 shadow-xs">
            {/* Named Providers Catalog (all available, enabled + unmounted) */}
            <div className="flex items-center justify-between px-2 py-1.5">
              <span className="text-[11px] font-medium text-muted-foreground">
                可用平台 ({namedProviders.length})
              </span>
            </div>

            <div className="space-y-0.5">
              {namedProviders.map((prov) => {
                const mounted = mountedById.get(prov.id)
                const selected =
                  effectiveSelection?.kind === "provider" &&
                  effectiveSelection.providerId === prov.id
                const missingSecret = Boolean(
                  mounted?.secrets.some((s) => !s.configured)
                )
                return (
                  <button
                    key={prov.id}
                    type="button"
                    data-provider-id={prov.id}
                    onClick={() =>
                      setSelection({ kind: "provider", providerId: prov.id })
                    }
                    className={cn(
                      "flex w-full items-center gap-2.5 rounded-md px-2 py-2 text-left transition-colors",
                      selected
                        ? "bg-muted text-foreground"
                        : "hover:bg-muted/50",
                      !mounted && !selected && "text-muted-foreground"
                    )}
                  >
                    <ProviderIcon
                      icon={prov.icon}
                      providerId={prov.id}
                      name={prov.name}
                      size="sm"
                      className={!mounted ? "opacity-60" : undefined}
                    />
                    <div className="min-w-0 flex-1">
                      <div className="truncate text-xs font-medium leading-tight">
                        {prov.name}
                      </div>
                      <div className="truncate font-mono text-[11px] text-muted-foreground">
                        {prov.id}
                      </div>
                    </div>
                    <div className="flex shrink-0 items-center gap-1.5">
                      {missingSecret && (
                        <span
                          title="凭据尚未录入"
                          className="size-1.5 rounded-full bg-warning"
                        />
                      )}
                      <span
                        className={cn(
                          "text-[10px]",
                          mounted
                            ? "text-foreground/70"
                            : "text-muted-foreground/70"
                        )}
                      >
                        {mounted ? "已启用" : "未启用"}
                      </span>
                    </div>
                  </button>
                )
              })}
            </div>

            {/* Generic HTTP multi-instance section */}
            {genericProvider && (
              <>
                <Separator className="my-2" />
                <div className="flex items-center justify-between px-2 py-1">
                  <span className="text-[11px] font-medium text-muted-foreground">
                    {genericProvider.name}
                    {customHttpInstances.length > 0
                      ? ` (${customHttpInstances.length})`
                      : ""}
                  </span>
                  {isAdmin && (
                    <Button
                      type="button"
                      variant="ghost"
                      size="xs"
                      className="h-6 px-1.5 text-[11px] text-muted-foreground hover:text-foreground"
                      onClick={() => setSelection({ kind: "new_generic" })}
                    >
                      <Plus className="size-3" />
                      新增
                    </Button>
                  )}
                </div>

                <div className="space-y-0.5">
                  {customHttpInstances.map((plat) => {
                    const selected =
                      effectiveSelection?.kind === "custom" &&
                      effectiveSelection.platformId === plat.spec.id
                    const missingSecret = plat.secrets.some(
                      (s) => !s.configured
                    )
                    return (
                      <button
                        key={plat.spec.id}
                        type="button"
                        data-platform-id={plat.spec.id}
                        onClick={() =>
                          setSelection({
                            kind: "custom",
                            platformId: plat.spec.id,
                          })
                        }
                        className={cn(
                          "flex w-full items-center gap-2.5 rounded-md px-2 py-2 text-left transition-colors",
                          selected
                            ? "bg-muted text-foreground"
                            : "text-muted-foreground hover:bg-muted/50 hover:text-foreground"
                        )}
                      >
                        <ProviderIcon
                          icon={plat.provider_icon}
                          providerId={plat.spec.provider_id}
                          name={plat.provider_name}
                          size="sm"
                        />
                        <div className="min-w-0 flex-1">
                          <div className="truncate font-mono text-xs font-medium leading-tight text-foreground">
                            {plat.spec.id}
                          </div>
                          <div className="truncate font-mono text-[11px] text-muted-foreground">
                            {plat.inject_hosts[0] ?? plat.spec.provider_id}
                          </div>
                        </div>
                        {missingSecret && (
                          <span
                            title="凭据尚未录入"
                            className="size-1.5 shrink-0 rounded-full bg-warning"
                          />
                        )}
                      </button>
                    )
                  })}

                  {isAdmin && customHttpInstances.length === 0 && (
                    <button
                      type="button"
                      data-action={NEW_GENERIC_KEY}
                      onClick={() => setSelection({ kind: "new_generic" })}
                      className={cn(
                        "flex w-full items-center gap-2 rounded-md border border-dashed px-2.5 py-2 text-left text-xs transition-colors",
                        effectiveSelection?.kind === "new_generic"
                          ? "border-foreground/30 bg-muted text-foreground"
                          : "text-muted-foreground hover:bg-muted/40 hover:text-foreground"
                      )}
                    >
                      <Plus className="size-3.5 shrink-0" />
                      <span>添加自定义 HTTP 服务</span>
                    </button>
                  )}
                </div>
              </>
            )}
          </Card>

          {/* Right Workspace */}
          {selectedMounted ? (
            <MountedPlatformWorkspace
              key={`${detail.name}:mounted:${selectedMounted.spec.id}`}
              profile={detail}
              platform={selectedMounted}
              providerMeta={selectedProviderMeta}
              isAdmin={isAdmin}
              encryptionReady={session.context.encryption_ready}
              sharedSecrets={sharedSecrets}
              savingProfile={updateProfile.isPending}
              onSavePlatformSpec={handleSaveSinglePlatform}
              onRemovePlatform={() => setRemoveTarget(selectedMounted)}
            />
          ) : selectedUnmountedProvider ? (
            <EnableProviderPanel
              key={`${detail.name}:enable:${selectedUnmountedProvider.id}`}
              profileName={detail.name}
              provider={selectedUnmountedProvider}
              isAdmin={isAdmin}
              existingPlatformIds={detail.platforms.map((p) => p.spec.id)}
              sharedSecrets={sharedSecrets}
              submitting={updateProfile.isPending}
              onEnable={handleAddOrEnablePlatform}
            />
          ) : isNewGenericView && genericProvider ? (
            <EnableProviderPanel
              key={`${detail.name}:new_generic:${customHttpInstances.length}`}
              profileName={detail.name}
              provider={genericProvider}
              isAdmin={isAdmin}
              existingPlatformIds={detail.platforms.map((p) => p.spec.id)}
              sharedSecrets={sharedSecrets}
              submitting={updateProfile.isPending}
              onEnable={handleAddOrEnablePlatform}
            />
          ) : null}
        </div>
      )}

      <AlertDialog
        open={Boolean(removeTarget)}
        onOpenChange={(open) => !open && setRemoveTarget(null)}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>
              停用{" "}
              {removeTarget
                ? removeTarget.spec.id === removeTarget.spec.provider_id
                  ? removeTarget.provider_name
                  : removeTarget.spec.id
                : ""}
              ？
            </AlertDialogTitle>
            <AlertDialogDescription>
              停用后，{activeProfile} 将不再拦截或向该平台域名注入凭据（已保存的加密凭据本身不会被删除，随时可重新启用）。
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={updateProfile.isPending}>
              取消
            </AlertDialogCancel>
            <AlertDialogAction
              onClick={(e) => {
                e.preventDefault()
                void handleConfirmRemove()
              }}
              disabled={updateProfile.isPending}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {updateProfile.isPending ? "停用中…" : "确认停用"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}

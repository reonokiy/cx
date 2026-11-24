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
import { useI18n, type Locale } from "@/lib/i18n"
import { useActiveProfile } from "@/lib/profile-context"
import { cn } from "@/lib/utils"

const IDENTIFIER_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/
const NEW_GENERIC_KEY = "__new_generic__"

function displayProviderName(
  providerId: string,
  providerName: string,
  locale: Locale
): string {
  if (providerId === "generic-http" && locale === "en") {
    return "Custom HTTP"
  }
  return providerName
}

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
  const { t } = useI18n()
  return (
    <div className="mt-3 overflow-x-auto rounded-md border bg-background">
      <Table>
        <TableHeader>
          <TableRow className="bg-muted/30 hover:bg-muted/30">
            <TableHead className="w-[84px] text-xs">
              {t("platforms.colAction")}
            </TableHead>
            <TableHead className="w-[120px] text-xs">
              {t("platforms.colMethod")}
            </TableHead>
            <TableHead className="text-xs">{t("platforms.colHost")}</TableHead>
            <TableHead className="text-xs">{t("platforms.colPath")}</TableHead>
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
  const { locale, t } = useI18n()
  const upsertSecret = useUpsertSecretMutation()
  const [value, setValue] = useState("")
  const [revealed, setRevealed] = useState(false)

  async function handleSave(e: FormEvent) {
    e.preventDefault()
    if (!value.trim()) {
      toast.error(t("platforms.errEmptySecret", { field }))
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
      toast.success(t("platforms.toastSecretSaved", { name: secretName }))
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
            ? t("platforms.secretConfiguredAt", {
                time: formatDateTime(updatedAt, locale),
              })
            : configured
              ? t("platforms.secretConfiguredShort")
              : t("platforms.secretNotEntered")}
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
                ? t("platforms.secretPlaceholderOverwrite", { field })
                : t("platforms.secretPlaceholderNew", { field })
            }
            disabled={!encryptionReady || upsertSecret.isPending}
            autoComplete="off"
            className="pr-9 font-mono text-xs"
          />
          <Button
            type="button"
            variant="ghost"
            size="icon-xs"
            aria-label={revealed ? t("common.hide") : t("common.show")}
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
          {upsertSecret.isPending
            ? t("common.saving")
            : t("platforms.saveSecret")}
        </Button>
      </div>
    </form>
  )
}

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
  const { locale, t } = useI18n()
  const isCustomHttp = provider.allow_multiple
  const localizedName = displayProviderName(provider.id, provider.name, locale)
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
      setError(t("platforms.errId"))
      return
    }
    if (existingPlatformIds.includes(id)) {
      setError(t("platforms.errDuplicate", { id }))
      return
    }

    const cleanedParams: Record<string, string> = {}
    for (const paramDef of provider.params) {
      const val = (params[paramDef.name] ?? "").trim()
      if (paramDef.required && !val) {
        setError(t("platforms.errRequiredParam", { name: paramDef.name }))
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
            name={localizedName}
            size="lg"
          />
          <div className="min-w-0 flex-1 space-y-1">
            <div className="flex flex-wrap items-center gap-2">
              <CardTitle className="text-base font-semibold">
                {isCustomHttp
                  ? t("platforms.addCustomHttpTitle", { name: localizedName })
                  : localizedName}
              </CardTitle>
              <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-[11px] text-muted-foreground">
                {provider.id}
              </code>
              {!isCustomHttp && (
                <span className="rounded border px-1.5 py-0.5 text-[11px] text-muted-foreground">
                  {t("common.disabled")}
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
            <span className="text-muted-foreground">
              {t("platforms.defaultHosts")}
            </span>
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
            {t("platforms.notEnabledMember", { name: localizedName })}
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="space-y-4">
            {isCustomHttp && (
              <div className="space-y-1.5">
                <Label htmlFor="inline-custom-id" className="text-xs">
                  {t("platforms.customIdLabel")}
                </Label>
                <Input
                  id="inline-custom-id"
                  placeholder={t("platforms.customIdPlaceholder")}
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
                      placeholder={p.default ?? t("common.required")}
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
                    {t("platforms.preset")}
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
                      <SelectItem value="none">
                        {t("platforms.presetNone")}
                      </SelectItem>
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
                    {t("platforms.presetRules", { count: presetRules.length })}
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
                    {t("platforms.secretMode")}
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
                        {t("platforms.secretShared")}
                      </SelectItem>
                      <SelectItem value="personal">
                        {t("platforms.secretPersonal")}
                      </SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                <div className="space-y-1.5">
                  <Label htmlFor="enable-secret-name" className="text-xs">
                    {t("platforms.secretName")}
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
                        {t("platforms.reuse")}
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
                  ? t("common.saving")
                  : isCustomHttp
                    ? t("platforms.addCustomTo", { profile: profileName })
                    : t("platforms.enableNamed", { name: localizedName })}
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
  const { locale, t } = useI18n()
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

  const localizedProviderName = displayProviderName(
    platform.spec.provider_id,
    platform.provider_name,
    locale
  )
  const isNamed = platform.spec.id === platform.spec.provider_id
  const primaryTitle = isNamed ? localizedProviderName : platform.spec.id
  const secondaryCode = isNamed
    ? platform.spec.id
    : `${localizedProviderName} · ${platform.spec.provider_id}`

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
            name={localizedProviderName}
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
                {t("common.discard")}
              </Button>
              <Button
                type="button"
                size="sm"
                onClick={() => void handleSaveAll()}
                disabled={savingProfile}
              >
                <Save />
                {savingProfile ? t("common.saving") : t("common.saveChanges")}
              </Button>
            </>
          )}
          {isAdmin && (
            <Button
              type="button"
              variant="ghost"
              size="icon-sm"
              aria-label={t("platforms.removeAria", { name: primaryTitle })}
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
              {t("platforms.tabRules", { count: draft.rules.length })}
            </TabsTrigger>
            <TabsTrigger value="secrets">
              {t("platforms.tabSecrets")}
              {platform.secrets.some((s) => !s.configured) && (
                <span className="ml-1.5 size-1.5 rounded-full bg-warning" />
              )}
            </TabsTrigger>
            <TabsTrigger value="params">{t("platforms.tabParams")}</TabsTrigger>
          </TabsList>

          {/* TAB 1: ACCESS RULES */}
          <TabsContent value="rules" className="mt-4 space-y-4">
            <div className="rounded-lg border bg-muted/20 p-3.5">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div className="flex items-center gap-3">
                  <Label
                    htmlFor="platform-preset"
                    className="text-xs font-medium"
                  >
                    {t("platforms.preset")}
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
                        <SelectItem value="none">
                          {t("platforms.presetNone")}
                        </SelectItem>
                      </SelectContent>
                    </Select>
                  ) : (
                    <code className="rounded bg-muted px-2 py-0.5 font-mono text-xs">
                      {draft.preset ?? t("overview.noPreset")}
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
                    {t("platforms.presetRules", {
                      count: previewPresetRules.length,
                    })}
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
                  <h3 className="text-xs font-medium">
                    {t("platforms.customRules")}
                  </h3>
                  <p className="text-[11px] text-muted-foreground">
                    {t("platforms.customRulesDesc")}
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
                    {t("platforms.addRule")}
                  </Button>
                )}
              </div>

              {draft.rules.length === 0 ? (
                <div className="rounded-lg border border-dashed py-8 text-center text-xs text-muted-foreground">
                  {t("platforms.noCustomRules")}
                </div>
              ) : (
                <div className="overflow-x-auto rounded-lg border">
                  <Table>
                    <TableHeader>
                      <TableRow className="bg-muted/30 hover:bg-muted/30">
                        <TableHead className="w-[44px] text-xs">#</TableHead>
                        <TableHead className="w-[84px] text-xs">
                          {t("platforms.colAction")}
                        </TableHead>
                        <TableHead className="w-[120px] text-xs">
                          {t("platforms.colMethod")}
                        </TableHead>
                        <TableHead className="text-xs">
                          {t("platforms.colHost")}
                        </TableHead>
                        <TableHead className="text-xs">
                          {t("platforms.colPath")}
                        </TableHead>
                        {isAdmin && (
                          <TableHead className="w-[136px] text-right text-xs">
                            {t("platforms.colActions")}
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
                                  aria-label={t("platforms.moveUp")}
                                  disabled={idx === 0}
                                  onClick={() => moveRule(idx, -1)}
                                >
                                  <ArrowUp className="size-3.5" />
                                </Button>
                                <Button
                                  type="button"
                                  variant="ghost"
                                  size="icon-xs"
                                  aria-label={t("platforms.moveDown")}
                                  disabled={idx === draft.rules.length - 1}
                                  onClick={() => moveRule(idx, 1)}
                                >
                                  <ArrowDown className="size-3.5" />
                                </Button>
                                <Button
                                  type="button"
                                  variant="ghost"
                                  size="icon-xs"
                                  aria-label={t("platforms.duplicateRule")}
                                  onClick={() => duplicateRule(idx)}
                                >
                                  <Copy className="size-3.5" />
                                </Button>
                                <Button
                                  type="button"
                                  variant="ghost"
                                  size="icon-xs"
                                  aria-label={t("platforms.editRule")}
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
                                  aria-label={t("platforms.deleteRule")}
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
                  {t("platforms.masterKeyMissingBefore")}{" "}
                  <code className="font-mono">CX_MASTER_KEY</code>{" "}
                  {t("platforms.masterKeyMissingAfter")}
                </AlertDescription>
              </Alert>
            )}

            {platform.secrets.length === 0 ? (
              <div className="rounded-lg border border-dashed py-8 text-center text-xs text-muted-foreground">
                {t("platforms.noSecretsNeeded")}
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
                          {bindingScope === "shared"
                            ? t("platforms.secretSharedTag")
                            : t("platforms.secretPersonalTag")}
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
                            {t("platforms.secretScope")}
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
                                {t("platforms.secretSharedAdmin")}
                              </SelectItem>
                              <SelectItem value="personal">
                                {t("platforms.secretPersonal")}
                              </SelectItem>
                            </SelectContent>
                          </Select>
                        </div>

                        <div className="space-y-1">
                          <Label className="text-[11px] text-muted-foreground">
                            {t("platforms.bindingName")}
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
                        {t("platforms.bindingUnsaved")}
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
                            ? t("platforms.sharedReady")
                            : t("platforms.sharedMissing")
                          : slotStatus.configured
                            ? t("platforms.secretConfigured")
                            : t("platforms.secretUnconfigured")}
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
                <h3 className="text-xs font-medium">
                  {t("platforms.paramsTitle")}
                </h3>
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
                <h3 className="text-xs font-medium">
                  {t("platforms.narrowHostsTitle")}
                </h3>
                <p className="text-[11px] text-muted-foreground">
                  {t("platforms.narrowHostsDesc")}
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
                  <span className="text-muted-foreground">
                    {t("platforms.l4TunnelHosts")}
                  </span>
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
  const { locale, t } = useI18n()
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
        <PageHeader title={t("nav.platforms")} />
        <Card className="shadow-xs">
          <Empty className="border-0 py-14">
            <EmptyHeader>
              <EmptyMedia variant="icon">
                <Blocks />
              </EmptyMedia>
              <EmptyTitle className="text-base">
                {t("platforms.emptyTitle")}
              </EmptyTitle>
              <EmptyDescription>{t("platforms.emptyDesc")}</EmptyDescription>
            </EmptyHeader>
            {isAdmin && (
              <EmptyContent>
                <Button size="sm" onClick={() => setCreateDialogOpen(true)}>
                  <Plus />
                  {t("sidebar.newProfile")}
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
      newSpec.id === newSpec.provider_id && prov
        ? displayProviderName(prov.id, prov.name, locale)
        : newSpec.id
    await savePlatforms(next, t("platforms.toastEnabled", { label }))
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
        ? displayProviderName(prov.id, prov.name, locale)
        : updatedSpec.id
    await savePlatforms(next, t("platforms.toastSaved", { label }))
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
          ? displayProviderName(
              target.spec.provider_id,
              target.provider_name,
              locale
            )
          : target.spec.id
      await savePlatforms(next, t("platforms.toastDisabled", { label }))
      setRemoveTarget(null)
      if (target.spec.id !== target.spec.provider_id) {
        setSelection(null)
      }
    } catch {
      // toast already displayed
    }
  }

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

  const removeTargetLabel = removeTarget
    ? removeTarget.spec.id === removeTarget.spec.provider_id
      ? displayProviderName(
          removeTarget.spec.provider_id,
          removeTarget.provider_name,
          locale
        )
      : removeTarget.spec.id
    : ""

  return (
    <div className="flex flex-col gap-5">
      <PageHeader
        title={t("nav.platforms")}
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
            {t("common.refresh")}
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
            <div className="flex items-center justify-between px-2 py-1.5">
              <span className="text-[11px] font-medium text-muted-foreground">
                {t("platforms.available", { count: namedProviders.length })}
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
                          title={t("platforms.secretMissingTitle")}
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
                        {mounted ? t("common.enabled") : t("common.disabled")}
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
                    {displayProviderName(
                      genericProvider.id,
                      genericProvider.name,
                      locale
                    )}
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
                      {t("common.add")}
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
                            title={t("platforms.secretMissingTitle")}
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
                      <span>{t("platforms.addCustomHttp")}</span>
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
              {t("platforms.disableTitle", { name: removeTargetLabel })}
            </AlertDialogTitle>
            <AlertDialogDescription>
              {t("platforms.disableDesc", { profile: activeProfile })}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={updateProfile.isPending}>
              {t("common.cancel")}
            </AlertDialogCancel>
            <AlertDialogAction
              onClick={(e) => {
                e.preventDefault()
                void handleConfirmRemove()
              }}
              disabled={updateProfile.isPending}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {updateProfile.isPending
                ? t("platforms.disabling")
                : t("platforms.confirmDisable")}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}

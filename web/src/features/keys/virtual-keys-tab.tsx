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
import { useI18n, type MessageKey } from "@/lib/i18n"
import { useActiveProfile } from "@/lib/profile-context"

const TTL_PRESETS: { labelKey: MessageKey; seconds: string }[] = [
  { labelKey: "vkeys.ttl1h", seconds: "3600" },
  { labelKey: "vkeys.ttl24h", seconds: "86400" },
  { labelKey: "vkeys.ttl7d", seconds: "604800" },
  { labelKey: "vkeys.ttl30d", seconds: "2592000" },
]

export function VirtualKeysTab() {
  const { activeProfile, activeProfileMeta, canIssueKeys } = useActiveProfile()
  const { locale, t } = useI18n()
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
            <EmptyTitle className="text-base">
              {t("vkeys.cannotIssueTitle")}
            </EmptyTitle>
            <EmptyDescription>
              {activeProfile
                ? t("vkeys.cannotIssueDesc", { profile: activeProfile })
                : t("vkeys.selectProfile")}
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
            <EmptyTitle className="text-base">
              {t("vkeys.noPlatformsTitle")}
            </EmptyTitle>
            <EmptyDescription>
              {t("vkeys.noPlatformsDesc", { profile: activeProfile })}
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
      toast.success(
        t("vkeys.toastGenerated", {
          profile: activeProfile,
          platform: res.platform,
        })
      )
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
            {t("vkeys.title")}
          </CardTitle>
          <CardDescription className="text-xs">
            {t("vkeys.descBefore")}{" "}
            <code className="font-mono">cx exec</code> {t("vkeys.descMid")}{" "}
            <code className="font-mono">.env</code> {t("vkeys.descAfter")}
          </CardDescription>
        </CardHeader>

        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-1.5">
              <Label htmlFor="vk-platform" className="text-xs">
                {t("vkeys.targetPlatform")}
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
              <Label className="text-xs">{t("vkeys.ttl")}</Label>
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
                      {t(preset.labelKey)}
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
              {createKey.isPending
                ? t("vkeys.generating")
                : t("vkeys.generate")}
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
                <DialogTitle>{t("vkeys.dialogTitle")}</DialogTitle>
              </div>
              <DialogDescription>
                {t("vkeys.dialogDescBefore")}{" "}
                <code className="font-mono">cx exec</code>{" "}
                {t("vkeys.dialogDescAfter")}
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
                  variant="default"
                  size="sm"
                  showLabel
                />
              </div>
              <p className="text-xs text-muted-foreground tabular-nums">
                {t("vkeys.dialogMeta", {
                  profile: issued.profile,
                  platform: issued.platform,
                })}
                {issued.expires_at
                  ? t("vkeys.dialogExpires", {
                      time: formatDateTime(issued.expires_at, locale),
                    })
                  : ""}
              </p>
            </div>

            <DialogFooter>
              <Button size="sm" onClick={() => setIssued(null)}>
                {t("common.done")}
              </Button>
            </DialogFooter>
          </DialogContent>
        )}
      </Dialog>
    </>
  )
}

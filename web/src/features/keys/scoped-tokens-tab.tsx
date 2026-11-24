import { zodResolver } from "@hookform/resolvers/zod"
import { CircleAlert, KeySquare, ShieldCheck } from "lucide-react"
import { useMemo, useState } from "react"
import { useForm } from "react-hook-form"
import { toast } from "sonner"
import { z } from "zod"
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
import { CopyButton } from "@/components/shared/copy-button"
import { useCreateScopedTokenMutation } from "@/hooks/use-console-queries"
import { getErrorMessage, type CreateScopedTokenResponse } from "@/lib/api"
import { formatDateTime } from "@/lib/format"
import { useI18n, type MessageKey } from "@/lib/i18n"
import { useActiveProfile } from "@/lib/profile-context"

const PAT_TTLS: { labelKey: MessageKey; value: string }[] = [
  { labelKey: "tokens.ttl1d", value: "86400" },
  { labelKey: "tokens.ttl7d", value: "604800" },
  { labelKey: "tokens.ttl30d", value: "2592000" },
  { labelKey: "tokens.ttl90d", value: "7776000" },
  { labelKey: "tokens.ttl365d", value: "31536000" },
]

interface ScopedTokenFormValues {
  name: string
  ttlSecs: string
}

export function ScopedTokensTab() {
  const { activeProfile, canIssueKeys } = useActiveProfile()
  const { locale, t } = useI18n()
  const createToken = useCreateScopedTokenMutation()
  const [issued, setIssued] = useState<{
    res: CreateScopedTokenResponse
    name: string
    profile: string
  } | null>(null)
  const [submitError, setSubmitError] = useState("")

  const scopedTokenSchema = useMemo(
    () =>
      z.object({
        name: z
          .string()
          .trim()
          .min(2, t("tokens.errNameMin"))
          .max(64, t("tokens.errNameMax")),
        ttlSecs: z.string(),
      }),
    [t]
  )

  const form = useForm<ScopedTokenFormValues>({
    resolver: zodResolver(scopedTokenSchema),
    defaultValues: {
      name: "",
      ttlSecs: "2592000",
    },
  })

  if (!activeProfile || !canIssueKeys) {
    return (
      <Card className="shadow-xs">
        <Empty className="border-0 py-14">
          <EmptyHeader>
            <EmptyMedia variant="icon">
              <KeySquare />
            </EmptyMedia>
            <EmptyTitle className="text-base">
              {t("tokens.cannotIssueTitle")}
            </EmptyTitle>
            <EmptyDescription>
              {activeProfile
                ? t("tokens.cannotIssueDesc", { profile: activeProfile })
                : t("vkeys.selectProfile")}
            </EmptyDescription>
          </EmptyHeader>
        </Empty>
      </Card>
    )
  }

  async function onSubmit(values: ScopedTokenFormValues) {
    setSubmitError("")
    try {
      const res = await createToken.mutateAsync({
        name: values.name,
        profiles: [activeProfile],
        ttl_secs: Number(values.ttlSecs),
      })
      setIssued({ res, name: values.name, profile: activeProfile })
      form.reset({ name: "", ttlSecs: values.ttlSecs })
      toast.success(t("tokens.toastIssued", { profile: activeProfile }))
    } catch (err) {
      const msg = getErrorMessage(err)
      setSubmitError(msg)
      toast.error(msg)
    }
  }

  const cliCommand = issued ? `cx login --token "${issued.res.token}"` : ""

  return (
    <>
      <Card className="max-w-xl shadow-xs">
        <CardHeader>
          <CardTitle className="text-sm font-medium">
            {t("tokens.titleBefore")}{" "}
            <code className="font-mono">{activeProfile}</code>{" "}
            {t("tokens.titleAfter")}
          </CardTitle>
          <CardDescription className="text-xs">
            {t("tokens.desc")}
          </CardDescription>
        </CardHeader>

        <CardContent>
          <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
            <div className="grid gap-3 sm:grid-cols-2">
              <div className="space-y-1.5">
                <Label htmlFor="pat-name" className="text-xs">
                  {t("tokens.name")}
                </Label>
                <Input
                  id="pat-name"
                  placeholder={t("tokens.namePlaceholder")}
                  disabled={createToken.isPending}
                  {...form.register("name")}
                />
                {form.formState.errors.name && (
                  <p className="text-xs text-destructive">
                    {form.formState.errors.name.message}
                  </p>
                )}
              </div>

              <div className="space-y-1.5">
                <Label htmlFor="pat-ttl" className="text-xs">
                  {t("tokens.ttl")}
                </Label>
                <Select
                  value={form.watch("ttlSecs")}
                  onValueChange={(v) => form.setValue("ttlSecs", v)}
                  disabled={createToken.isPending}
                >
                  <SelectTrigger id="pat-ttl" className="w-full">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {PAT_TTLS.map((item) => (
                      <SelectItem key={item.value} value={item.value}>
                        {t(item.labelKey)}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>

            {submitError && (
              <Alert variant="destructive" role="alert">
                <CircleAlert />
                <AlertDescription>{submitError}</AlertDescription>
              </Alert>
            )}

            <Button type="submit" size="sm" disabled={createToken.isPending}>
              <KeySquare />
              {createToken.isPending ? t("tokens.issuing") : t("tokens.issue")}
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
                <DialogTitle>{t("tokens.dialogTitle")}</DialogTitle>
              </div>
              <DialogDescription>{t("tokens.dialogDesc")}</DialogDescription>
            </DialogHeader>

            <div className="space-y-3">
              <div className="flex items-center gap-2">
                <Input
                  id="issued-pat-value"
                  readOnly
                  value={issued.res.token}
                  onFocus={(e) => e.target.select()}
                  className="font-mono text-xs"
                />
                <CopyButton
                  value={issued.res.token}
                  variant="default"
                  size="sm"
                  showLabel
                />
              </div>

              <div className="flex items-center justify-between gap-2 rounded-md border bg-muted/40 px-3 py-2">
                <code className="truncate font-mono text-xs">{cliCommand}</code>
                <CopyButton
                  value={cliCommand}
                  label={t("tokens.copyCommand")}
                />
              </div>

              <p className="text-xs text-muted-foreground tabular-nums">
                {issued.name} · Profile:{" "}
                <code className="font-mono">{issued.profile}</code> ·{" "}
                {t("tokens.dialogExpires", {
                  time: formatDateTime(issued.res.expires_at, locale),
                })}
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

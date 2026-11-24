import { zodResolver } from "@hookform/resolvers/zod"
import { CircleAlert, KeySquare, ShieldCheck } from "lucide-react"
import { useState } from "react"
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
import { useActiveProfile } from "@/lib/profile-context"

const PAT_TTLS = [
  { label: "1 天", value: "86400" },
  { label: "7 天", value: "604800" },
  { label: "30 天", value: "2592000" },
  { label: "90 天", value: "7776000" },
  { label: "365 天", value: "31536000" },
] as const

const scopedTokenSchema = z.object({
  name: z
    .string()
    .trim()
    .min(2, "名称至少 2 个字符")
    .max(64, "名称不超过 64 个字符"),
  ttlSecs: z.string(),
})

type ScopedTokenFormValues = z.infer<typeof scopedTokenSchema>

export function ScopedTokensTab() {
  const { activeProfile, canIssueKeys } = useActiveProfile()
  const createToken = useCreateScopedTokenMutation()
  const [issued, setIssued] = useState<{
    res: CreateScopedTokenResponse
    name: string
    profile: string
  } | null>(null)
  const [submitError, setSubmitError] = useState("")

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
            <EmptyTitle className="text-base">无法签发限定令牌</EmptyTitle>
            <EmptyDescription>
              {activeProfile
                ? `当前账号无权为 ${activeProfile} 签发限定令牌。`
                : "请先选择一个 Profile。"}
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
      toast.success(`已为 ${activeProfile} 签发限定令牌`)
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
            为 <code className="font-mono">{activeProfile}</code> 签发限定令牌
          </CardTitle>
          <CardDescription className="text-xs">
            供 CI/CD 或脚本通过 CLI 访问当前 Profile，无法越权操作其他 Profile。
          </CardDescription>
        </CardHeader>

        <CardContent>
          <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4">
            <div className="grid gap-3 sm:grid-cols-2">
              <div className="space-y-1.5">
                <Label htmlFor="pat-name" className="text-xs">
                  名称
                </Label>
                <Input
                  id="pat-name"
                  placeholder="例如：github-actions"
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
                  有效期
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
                        {item.label}
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
              {createToken.isPending ? "签发中…" : "签发限定令牌"}
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
                <DialogTitle>限定令牌已签发</DialogTitle>
              </div>
              <DialogDescription>
                明文令牌仅显示一次，请立即保存。
              </DialogDescription>
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
                  label="复制"
                  variant="default"
                  size="sm"
                  showLabel
                />
              </div>

              <div className="flex items-center justify-between gap-2 rounded-md border bg-muted/40 px-3 py-2">
                <code className="truncate font-mono text-xs">{cliCommand}</code>
                <CopyButton value={cliCommand} label="复制命令" />
              </div>

              <p className="text-xs text-muted-foreground tabular-nums">
                {issued.name} · Profile：
                <code className="font-mono">{issued.profile}</code> · 到期：
                {formatDateTime(issued.res.expires_at)}
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

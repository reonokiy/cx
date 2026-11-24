import { zodResolver } from "@hookform/resolvers/zod"
import { CheckCircle2, Plus, ShieldAlert } from "lucide-react"
import { useEffect } from "react"
import { useForm } from "react-hook-form"
import { z } from "zod"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Label } from "@/components/ui/label"
import { Textarea } from "@/components/ui/textarea"
import type { PolicyEffect, PolicyRule } from "@/lib/api"
import { describePolicyRule } from "@/lib/policy-matcher"
import { cn } from "@/lib/utils"

const HTTP_METHODS = [
  "GET",
  "HEAD",
  "POST",
  "PUT",
  "PATCH",
  "DELETE",
  "OPTIONS",
  "*",
] as const

const PATH_PRESETS = ["/**", "/user", "/repos/**", "/v1/**"]

function splitLines(raw: string): string[] {
  return raw
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean)
}

const lineListSchema = z
  .string()
  .refine(
    (val) => splitLines(val).length <= 100,
    "每项最多填写 100 条匹配模式"
  )
  .refine(
    (val) => splitLines(val).every((item) => item.length <= 1024),
    "单条匹配模式长度不能超过 1024 个字符"
  )

const ruleFormSchema = z.object({
  effect: z.enum(["allow", "deny"]),
  methods: z.array(z.string()).max(100, "最多选择 100 个方法"),
  hostsText: lineListSchema,
  pathsText: lineListSchema,
})

type RuleFormValues = z.infer<typeof ruleFormSchema>

interface RuleEditorDialogProps {
  open: boolean
  rule?: PolicyRule
  suggestedHosts?: string[]
  onOpenChange: (open: boolean) => void
  onSubmitRule: (rule: PolicyRule) => void
}

export function RuleEditorDialog({
  open,
  rule,
  suggestedHosts = [],
  onOpenChange,
  onSubmitRule,
}: RuleEditorDialogProps) {
  const form = useForm<RuleFormValues>({
    resolver: zodResolver(ruleFormSchema),
    defaultValues: {
      effect: rule?.effect ?? "deny",
      methods: rule?.methods ?? [],
      hostsText: rule?.hosts.join("\n") ?? "",
      pathsText: rule?.paths.join("\n") ?? "",
    },
  })

  useEffect(() => {
    if (open) {
      form.reset({
        effect: rule?.effect ?? "deny",
        methods: rule?.methods ?? [],
        hostsText: rule?.hosts.join("\n") ?? "",
        pathsText: rule?.paths.join("\n") ?? "",
      })
    }
  }, [open, rule, form])

  const effect = form.watch("effect")
  const methods = form.watch("methods")
  const hostsText = form.watch("hostsText")
  const pathsText = form.watch("pathsText")

  const previewRule: PolicyRule = {
    effect,
    methods,
    hosts: splitLines(hostsText),
    paths: splitLines(pathsText),
  }

  function toggleMethod(method: string) {
    const current = form.getValues("methods")
    if (method === "*") {
      form.setValue("methods", current.includes("*") ? [] : ["*"], {
        shouldDirty: true,
      })
      return
    }
    const withoutStar = current.filter((m) => m !== "*")
    const next = withoutStar.includes(method)
      ? withoutStar.filter((m) => m !== method)
      : [...withoutStar, method]
    form.setValue("methods", next, { shouldDirty: true })
  }

  function appendLine(field: "hostsText" | "pathsText", value: string) {
    const existing = splitLines(form.getValues(field))
    if (existing.includes(value)) return
    form.setValue(field, [...existing, value].join("\n"), { shouldDirty: true })
  }

  function handleSave(values: RuleFormValues) {
    onSubmitRule({
      effect: values.effect as PolicyEffect,
      methods: values.methods.map((m) => m.toUpperCase()),
      hosts: splitLines(values.hostsText),
      paths: splitLines(values.pathsText),
    })
    onOpenChange(false)
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[90dvh] overflow-y-auto sm:max-w-xl">
        <DialogHeader>
          <DialogTitle>{rule ? "编辑访问规则" : "新建访问规则"}</DialogTitle>
          <DialogDescription>
            配置 HTTP 方法、目标主机和路径 Glob 模式。字段留空表示匹配任意值。
          </DialogDescription>
        </DialogHeader>

        <form onSubmit={form.handleSubmit(handleSave)} className="space-y-5">
          {/* Effect Selector Cards */}
          <div className="space-y-2">
            <Label>规则动作</Label>
            <div className="grid grid-cols-2 gap-3">
              <button
                type="button"
                onClick={() => form.setValue("effect", "deny")}
                className={cn(
                  "flex items-start gap-3 rounded-lg border p-3 text-left transition-all",
                  effect === "deny"
                    ? "border-destructive bg-destructive/8 ring-1 ring-destructive/30"
                    : "hover:bg-muted/50"
                )}
              >
                <ShieldAlert
                  className={cn(
                    "mt-0.5 size-4 shrink-0",
                    effect === "deny"
                      ? "text-destructive"
                      : "text-muted-foreground"
                  )}
                />
                <div className="space-y-0.5">
                  <div className="text-sm font-medium">拒绝 (Deny)</div>
                  <p className="text-xs text-muted-foreground">
                    最高优先级，命中即拦截
                  </p>
                </div>
              </button>

              <button
                type="button"
                onClick={() => form.setValue("effect", "allow")}
                className={cn(
                  "flex items-start gap-3 rounded-lg border p-3 text-left transition-all",
                  effect === "allow"
                    ? "border-success bg-success/8 ring-1 ring-success/30"
                    : "hover:bg-muted/50"
                )}
              >
                <CheckCircle2
                  className={cn(
                    "mt-0.5 size-4 shrink-0",
                    effect === "allow"
                      ? "text-success"
                      : "text-muted-foreground"
                  )}
                />
                <div className="space-y-0.5">
                  <div className="text-sm font-medium">允许 (Allow)</div>
                  <p className="text-xs text-muted-foreground">
                    未命中拒绝时放行请求
                  </p>
                </div>
              </button>
            </div>
          </div>

          {/* HTTP Method Chips */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <Label>HTTP 方法</Label>
              <span className="text-xs text-muted-foreground">
                {methods.length === 0 ? "未选即匹配任意方法" : `已选 ${methods.length} 项`}
              </span>
            </div>
            <div className="flex flex-wrap gap-1.5">
              {HTTP_METHODS.map((method) => {
                const active = methods.includes(method)
                return (
                  <Button
                    key={method}
                    type="button"
                    size="xs"
                    variant={active ? "default" : "outline"}
                    onClick={() => toggleMethod(method)}
                    className="font-mono text-xs"
                  >
                    {method === "*" ? "* (全部)" : method}
                  </Button>
                )
              })}
            </div>
          </div>

          {/* Target Hosts */}
          <div className="space-y-2">
            <div className="flex items-center justify-between gap-2">
              <Label htmlFor="rule-hosts">目标主机（每行一个）</Label>
              <span className="text-xs text-muted-foreground">
                支持精确域名或 *.example.com
              </span>
            </div>
            <Textarea
              id="rule-hosts"
              rows={3}
              className="font-mono text-xs"
              placeholder={"api.github.com\n*.githubusercontent.com"}
              {...form.register("hostsText")}
            />
            {form.formState.errors.hostsText && (
              <p className="text-xs text-destructive">
                {form.formState.errors.hostsText.message}
              </p>
            )}
            {suggestedHosts.length > 0 && (
              <div className="flex flex-wrap items-center gap-1.5">
                <span className="text-[11px] text-muted-foreground">
                  快速填入当前 Profile 域名：
                </span>
                {suggestedHosts.map((host) => (
                  <Badge
                    key={host}
                    variant="secondary"
                    asChild
                    className="cursor-pointer font-mono text-[11px] hover:bg-accent"
                  >
                    <button
                      type="button"
                      onClick={() => appendLine("hostsText", host)}
                    >
                      <Plus className="size-3" />
                      {host}
                    </button>
                  </Badge>
                ))}
              </div>
            )}
          </div>

          {/* Path Globs */}
          <div className="space-y-2">
            <div className="flex items-center justify-between gap-2">
              <Label htmlFor="rule-paths">路径 Glob（每行一个）</Label>
              <span className="text-xs text-muted-foreground">
                支持 *、**、? 通配符（不含查询参数）
              </span>
            </div>
            <Textarea
              id="rule-paths"
              rows={3}
              className="font-mono text-xs"
              placeholder={"/repos/my-org/**\n/user"}
              {...form.register("pathsText")}
            />
            {form.formState.errors.pathsText && (
              <p className="text-xs text-destructive">
                {form.formState.errors.pathsText.message}
              </p>
            )}
            <div className="flex flex-wrap items-center gap-1.5">
              <span className="text-[11px] text-muted-foreground">
                常用模板：
              </span>
              {PATH_PRESETS.map((pattern) => (
                <Badge
                  key={pattern}
                  variant="secondary"
                  asChild
                  className="cursor-pointer font-mono text-[11px] hover:bg-accent"
                >
                  <button
                    type="button"
                    onClick={() => appendLine("pathsText", pattern)}
                  >
                    <Plus className="size-3" />
                    {pattern}
                  </button>
                </Badge>
              ))}
            </div>
          </div>

          {/* Live Rule Preview */}
          <div className="rounded-lg border bg-muted/40 px-3.5 py-2.5 text-xs leading-relaxed text-muted-foreground">
            <span className="mr-1.5 font-medium text-foreground">规则预览：</span>
            {describePolicyRule(previewRule)}
          </div>

          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={() => onOpenChange(false)}
            >
              取消
            </Button>
            <Button type="submit">应用到草稿</Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

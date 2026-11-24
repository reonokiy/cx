import { CheckCircle2, Play, ShieldAlert } from "lucide-react"
import { useEffect, useMemo, useState } from "react"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import type { PolicyRule } from "@/lib/api"
import { simulatePlatformPolicy } from "@/lib/policy-matcher"
import { cn } from "@/lib/utils"

const METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"] as const

export function PlatformSimulator({
  presetName,
  presetRules,
  customRules,
  defaultHost,
}: {
  presetName: string | null
  presetRules: PolicyRule[]
  customRules: PolicyRule[]
  defaultHost: string
}) {
  const [method, setMethod] = useState("GET")
  const [host, setHost] = useState(defaultHost)
  const [path, setPath] = useState("/")

  useEffect(() => {
    setHost(defaultHost)
  }, [defaultHost])

  const result = useMemo(
    () =>
      simulatePlatformPolicy(presetName, presetRules, customRules, {
        method,
        host,
        path,
      }),
    [presetName, presetRules, customRules, method, host, path]
  )

  return (
    <div className="space-y-3 rounded-lg border bg-muted/20 p-4">
      <div className="flex items-center gap-1.5 text-xs font-medium">
        <Play className="size-3.5 text-muted-foreground" />
        <span>策略模拟（预设 + 自定义规则联合评估）</span>
      </div>

      <div className="grid gap-2.5 sm:grid-cols-[110px_minmax(0,1fr)_minmax(0,1.2fr)]">
        <div className="space-y-1">
          <Label className="text-[11px] text-muted-foreground">方法</Label>
          <Select value={method} onValueChange={setMethod}>
            <SelectTrigger size="sm" className="font-mono text-xs">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {METHODS.map((m) => (
                <SelectItem key={m} value={m} className="font-mono text-xs">
                  {m}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        <div className="space-y-1">
          <Label className="text-[11px] text-muted-foreground">目标主机</Label>
          <Input
            value={host}
            onChange={(e) => setHost(e.target.value)}
            placeholder="api.github.com"
            className="h-8 font-mono text-xs"
          />
        </div>

        <div className="space-y-1">
          <Label className="text-[11px] text-muted-foreground">请求路径</Label>
          <Input
            value={path}
            onChange={(e) => setPath(e.target.value)}
            placeholder="/repos/example/internal/secret"
            className="h-8 font-mono text-xs"
          />
        </div>
      </div>

      <div
        className={cn(
          "flex items-start gap-2 rounded-md border px-3 py-2 text-xs",
          result.decision === "allow"
            ? "border-border bg-background text-foreground"
            : "border-destructive/30 bg-destructive/5 text-destructive"
        )}
      >
        {result.decision === "allow" ? (
          <CheckCircle2 className="mt-0.5 size-3.5 shrink-0 text-success" />
        ) : (
          <ShieldAlert className="mt-0.5 size-3.5 shrink-0 text-destructive" />
        )}
        <div className="space-y-0.5">
          <span className="font-medium">
            {result.decision === "allow" ? "放行 (Allow)" : "拒绝 (Deny)"}
          </span>
          <span className="ml-2 text-muted-foreground">{result.reason}</span>
        </div>
      </div>
    </div>
  )
}

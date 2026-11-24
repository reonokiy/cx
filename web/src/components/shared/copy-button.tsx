import { Check, Copy } from "lucide-react"
import { useEffect, useRef, useState } from "react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip"
import { useI18n } from "@/lib/i18n"
import { cn } from "@/lib/utils"

interface CopyButtonProps {
  value: string
  label?: string
  toastMessage?: string
  variant?: "ghost" | "outline" | "secondary" | "default"
  size?: "icon-xs" | "icon-sm" | "icon" | "sm" | "xs"
  showLabel?: boolean
  className?: string
}

export function CopyButton({
  value,
  label,
  toastMessage,
  variant = "ghost",
  size = "icon-xs",
  showLabel = false,
  className,
}: CopyButtonProps) {
  const { t } = useI18n()
  const [copied, setCopied] = useState(false)
  const timerRef = useRef<number | null>(null)

  const resolvedLabel = label ?? t("common.copy")
  const resolvedToast = toastMessage ?? t("common.copiedToast")

  useEffect(() => {
    return () => {
      if (timerRef.current !== null) window.clearTimeout(timerRef.current)
    }
  }, [])

  async function handleCopy() {
    try {
      await navigator.clipboard.writeText(value)
      setCopied(true)
      toast.success(resolvedToast)
      if (timerRef.current !== null) window.clearTimeout(timerRef.current)
      timerRef.current = window.setTimeout(() => setCopied(false), 1800)
    } catch {
      toast.error(t("common.copyFailed"))
    }
  }

  const button = (
    <Button
      type="button"
      variant={variant}
      size={size}
      onClick={() => void handleCopy()}
      aria-label={resolvedLabel}
      className={cn(className)}
    >
      {copied ? (
        <Check className="text-success" />
      ) : (
        <Copy className="text-muted-foreground" />
      )}
      {showLabel && <span>{copied ? t("common.copied") : resolvedLabel}</span>}
    </Button>
  )

  if (showLabel) return button

  return (
    <Tooltip>
      <TooltipTrigger asChild>{button}</TooltipTrigger>
      <TooltipContent>{copied ? t("common.copied") : resolvedLabel}</TooltipContent>
    </Tooltip>
  )
}

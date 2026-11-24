import { Check, Copy } from "lucide-react"
import { useEffect, useRef, useState } from "react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip"
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
  label = "复制",
  toastMessage = "已复制到剪贴板",
  variant = "ghost",
  size = "icon-xs",
  showLabel = false,
  className,
}: CopyButtonProps) {
  const [copied, setCopied] = useState(false)
  const timerRef = useRef<number | null>(null)

  useEffect(() => {
    return () => {
      if (timerRef.current !== null) window.clearTimeout(timerRef.current)
    }
  }, [])

  async function handleCopy() {
    try {
      await navigator.clipboard.writeText(value)
      setCopied(true)
      toast.success(toastMessage)
      if (timerRef.current !== null) window.clearTimeout(timerRef.current)
      timerRef.current = window.setTimeout(() => setCopied(false), 1800)
    } catch {
      toast.error("复制失败，请手动选中并复制。")
    }
  }

  const button = (
    <Button
      type="button"
      variant={variant}
      size={size}
      onClick={() => void handleCopy()}
      aria-label={label}
      className={cn(className)}
    >
      {copied ? (
        <Check className="text-success" />
      ) : (
        <Copy className="text-muted-foreground" />
      )}
      {showLabel && <span>{copied ? "已复制" : label}</span>}
    </Button>
  )

  if (showLabel) return button

  return (
    <Tooltip>
      <TooltipTrigger asChild>{button}</TooltipTrigger>
      <TooltipContent>{copied ? "已复制" : label}</TooltipContent>
    </Tooltip>
  )
}

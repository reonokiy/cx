import { cn } from "@/lib/utils"

interface BrandMarkProps {
  className?: string
  showSubtitle?: boolean
  compact?: boolean
}

export function BrandMark({
  className,
  showSubtitle = true,
  compact = false,
}: BrandMarkProps) {
  return (
    <div className={cn("flex items-center gap-2.5", className)}>
      <div className="flex size-8 shrink-0 items-center justify-center rounded-lg bg-primary text-primary-foreground shadow-xs">
        <svg
          viewBox="0 0 24 24"
          fill="none"
          className="size-4"
          aria-hidden="true"
        >
          <path
            d="M12 2.75L4.5 6.25V12C4.5 16.4 7.6 20.1 12 21.25C16.4 20.1 19.5 16.4 19.5 12V6.25L12 2.75Z"
            stroke="currentColor"
            strokeWidth="1.9"
            strokeLinejoin="round"
          />
          <path
            d="M9.25 12L11.1 13.85L15 9.95"
            stroke="currentColor"
            strokeWidth="1.9"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
        </svg>
      </div>
      {!compact && (
        <div className="grid min-w-0 flex-1 text-left leading-tight">
          <span className="truncate text-sm font-semibold tracking-tight">
            CX Gateway
          </span>
          {showSubtitle && (
            <span className="truncate text-xs text-muted-foreground">
              Secretless Console
            </span>
          )}
        </div>
      )}
    </div>
  )
}

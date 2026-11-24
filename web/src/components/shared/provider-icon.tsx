import {
  Blocks,
  Bot,
  Cloud,
  Code2,
  Cpu,
  Database,
  Globe,
  KeyRound,
  Layers,
  Server,
  Shield,
  Terminal,
  Webhook,
} from "lucide-react"
import { cn } from "@/lib/utils"

function GitHubSvg({ className }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="currentColor"
      aria-hidden="true"
      className={className}
    >
      <path d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.53 1.032 1.53 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0 1 12 6.844a9.59 9.59 0 0 1 2.504.337c1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.02 10.02 0 0 0 22 12.017C22 6.484 17.522 2 12 2Z" />
    </svg>
  )
}

function OpenAISvg({ className }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="currentColor"
      aria-hidden="true"
      className={className}
    >
      <path d="M22.282 9.821a5.985 5.985 0 0 0-.516-4.91 6.046 6.046 0 0 0-6.51-2.9A6.065 6.065 0 0 0 4.981 4.18a5.985 5.985 0 0 0-3.998 2.9 6.046 6.046 0 0 0 .743 7.097 5.98 5.98 0 0 0 .51 4.911 6.051 6.051 0 0 0 6.515 2.9A5.985 5.985 0 0 0 13.26 24a6.056 6.056 0 0 0 5.772-4.206 5.99 5.99 0 0 0 3.997-2.9 6.056 6.056 0 0 0-.747-7.073ZM13.26 22.43a4.476 4.476 0 0 1-2.876-1.04l.141-.081 4.779-2.758a.795.795 0 0 0 .392-.681v-6.737l2.02 1.168a.071.071 0 0 1 .038.052v5.583a4.504 4.504 0 0 1-4.494 4.494ZM3.6 18.304a4.47 4.47 0 0 1-.535-3.014l.142.085 4.783 2.759a.771.771 0 0 0 .78 0l5.843-3.369v2.332a.08.08 0 0 1-.033.062L9.74 19.95a4.5 4.5 0 0 1-6.14-1.646ZM2.34 7.896a4.485 4.485 0 0 1 2.366-1.973V11.6a.766.766 0 0 0 .388.676l5.815 3.355-2.02 1.168a.076.076 0 0 1-.071 0l-4.83-2.786A4.504 4.504 0 0 1 2.34 7.896Zm16.597 3.855-5.833-3.387L15.119 7.2a.076.076 0 0 1 .071 0l4.83 2.791a4.494 4.494 0 0 1-.676 8.105v-5.678a.79.79 0 0 0-.407-.667Zm2.01-3.023-.141-.085-4.774-2.782a.776.776 0 0 0-.785 0L9.409 9.23V6.897a.066.066 0 0 1 .028-.061l4.83-2.787a4.5 4.5 0 0 1 6.68 4.66Zm-12.64 4.135-2.02-1.164a.08.08 0 0 1-.038-.057V6.075a4.5 4.5 0 0 1 7.375-3.453l-.142.08L8.704 5.46a.795.795 0 0 0-.393.681Zm1.097-2.365 2.602-1.5 2.607 1.5v2.999l-2.597 1.5-2.607-1.5Z" />
    </svg>
  )
}

function AnthropicSvg({ className }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="currentColor"
      aria-hidden="true"
      className={className}
    >
      <path d="M13.827 3.52h3.603L24 20.48h-3.603l-6.57-16.96zm-7.258 0h3.767L16.906 20.48h-3.674l-1.343-3.461H5.017l-1.344 3.46H0L6.57 3.522zm4.132 10.422L8.453 8.15l-2.248 5.792h4.496z" />
    </svg>
  )
}

function GitLabSvg({ className }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="currentColor"
      aria-hidden="true"
      className={className}
    >
      <path d="M22.65 14.39 12 22.13 1.35 14.39a.84.84 0 0 1-.3-.94l1.22-3.78 2.44-7.51A.42.42 0 0 1 4.82 2a.43.43 0 0 1 .58 0 .42.42 0 0 1 .11.18l2.44 7.49h8.1l2.44-7.51A.42.42 0 0 1 18.6 2a.43.43 0 0 1 .58 0 .42.42 0 0 1 .11.18l2.44 7.51L23 13.45a.84.84 0 0 1-.35.94z" />
    </svg>
  )
}

function CloudflareSvg({ className }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="currentColor"
      aria-hidden="true"
      className={className}
    >
      <path d="M16.51 15.84a2.88 2.88 0 0 0 2.85-2.9 2.9 2.9 0 0 0-2.16-2.8 4.92 4.92 0 0 0-9.42-1.24 3.63 3.63 0 0 0-4.28 3.57 3.66 3.66 0 0 0 3.66 3.66h9.35v-.29Z" />
    </svg>
  )
}

function StripeSvg({ className }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="currentColor"
      aria-hidden="true"
      className={className}
    >
      <path d="M13.976 9.15c-2.172-.806-3.356-1.426-3.356-2.409 0-.831.683-1.305 1.901-1.305 2.227 0 4.515.858 6.09 1.631l.89-5.494C18.252.975 15.697 0 12.165 0 9.667 0 7.589.654 6.104 1.872 4.56 3.147 3.757 4.992 3.757 7.218c0 4.039 2.467 5.76 6.476 7.219 2.585.92 3.445 1.574 3.445 2.583 0 .98-.84 1.545-2.354 1.545-1.875 0-4.965-.921-6.99-2.109l-.9 5.555C5.175 22.99 8.385 24 11.714 24c2.641 0 4.843-.624 6.328-1.813 1.664-1.305 2.525-3.236 2.525-5.732 0-4.128-2.524-5.851-6.591-7.305z" />
    </svg>
  )
}

const NAMED_ICONS: Record<string, React.ComponentType<{ className?: string }>> = {
  github: GitHubSvg,
  openai: OpenAISvg,
  anthropic: AnthropicSvg,
  claude: AnthropicSvg,
  gitlab: GitLabSvg,
  cloudflare: CloudflareSvg,
  stripe: StripeSvg,
  globe: Globe,
  "generic-http": Globe,
  http: Globe,
  server: Server,
  terminal: Terminal,
  key: KeyRound,
  cloud: Cloud,
  aws: Cloud,
  azure: Cloud,
  google: Cloud,
  database: Database,
  shield: Shield,
  webhook: Webhook,
  code: Code2,
  bot: Bot,
  blocks: Blocks,
  layers: Layers,
  cpu: Cpu,
}

const FRAME_SIZES = {
  xs: "size-5 rounded",
  sm: "size-6 rounded-md",
  md: "size-7 rounded-md",
  lg: "size-9 rounded-lg",
} as const

const GLYPH_SIZES = {
  xs: "size-3",
  sm: "size-3.5",
  md: "size-4",
  lg: "size-5",
} as const

export function ProviderIcon({
  icon,
  providerId,
  name,
  size = "md",
  framed = true,
  className,
}: {
  icon?: string | null
  providerId?: string
  name?: string
  size?: keyof typeof FRAME_SIZES
  framed?: boolean
  className?: string
}) {
  const token = (icon?.trim() || providerId?.trim() || "").toLowerCase()
  const rawIcon = icon?.trim() ?? ""
  const isDataImage = /^data:image\/(png|webp|jpeg|svg\+xml);base64,/i.test(
    rawIcon
  )
  const NamedComp = !isDataImage ? NAMED_ICONS[token] : undefined

  const inner = isDataImage ? (
    <img
      src={rawIcon}
      alt=""
      className={cn(GLYPH_SIZES[size], "object-contain")}
    />
  ) : NamedComp ? (
    <NamedComp className={GLYPH_SIZES[size]} />
  ) : rawIcon && rawIcon.length <= 4 ? (
    <span className="leading-none" aria-hidden="true">
      {rawIcon}
    </span>
  ) : (
    <span
      className="font-mono text-[11px] font-semibold uppercase leading-none"
      aria-hidden="true"
    >
      {(name || providerId || "?").slice(0, 1)}
    </span>
  )

  if (!framed) {
    return (
      <span
        className={cn(
          "inline-flex shrink-0 items-center justify-center text-foreground",
          className
        )}
      >
        {inner}
      </span>
    )
  }

  return (
    <span
      className={cn(
        "inline-flex shrink-0 items-center justify-center border bg-muted/60 text-foreground",
        FRAME_SIZES[size],
        className
      )}
    >
      {inner}
    </span>
  )
}

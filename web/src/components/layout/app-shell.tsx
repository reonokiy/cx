import { AlertCircle, Search } from "lucide-react"
import { useMemo, useState, type ReactNode } from "react"
import { Button } from "@/components/ui/button"
import { Separator } from "@/components/ui/separator"
import {
  SidebarInset,
  SidebarProvider,
  SidebarTrigger,
} from "@/components/ui/sidebar"
import { AppSidebar } from "@/components/layout/app-sidebar"
import { CommandMenu } from "@/components/layout/command-menu"
import { CreateProfileDialog } from "@/components/layout/create-profile-dialog"
import { LocaleToggle } from "@/components/layout/locale-toggle"
import { ThemeToggle } from "@/components/layout/theme-toggle"
import { useGatewayHealth } from "@/hooks/use-console-queries"
import type { AppRoute } from "@/hooks/use-hash-route"
import { useI18n, type MessageKey } from "@/lib/i18n"
import { useActiveProfile } from "@/lib/profile-context"

const ROUTE_TITLE_KEYS: Record<AppRoute, MessageKey> = {
  overview: "nav.overview",
  platforms: "nav.platforms",
  audit: "nav.audit",
  settings: "nav.settings",
}

interface AppShellProps {
  route: AppRoute
  onNavigate: (route: AppRoute, params?: Record<string, string>) => void
  children: ReactNode
}

export function AppShell({ route, onNavigate, children }: AppShellProps) {
  const [commandOpen, setCommandOpen] = useState(false)
  const { data: health } = useGatewayHealth()
  const { createDialogOpen, setCreateDialogOpen } = useActiveProfile()
  const { t } = useI18n()

  const shortcutLabel = useMemo(() => {
    if (typeof navigator !== "undefined" && /Mac|iPhone|iPad/i.test(navigator.platform || navigator.userAgent)) {
      return "⌘K"
    }
    return "Ctrl K"
  }, [])

  return (
    <SidebarProvider>
      <AppSidebar route={route} onNavigate={(next) => onNavigate(next)} />
      <SidebarInset className="min-w-0">
        <header className="sticky top-0 z-20 flex h-13 shrink-0 items-center gap-2 border-b bg-background/85 px-4 backdrop-blur-md">
          <div className="flex min-w-0 items-center gap-2">
            <SidebarTrigger className="-ml-1" aria-label={t("nav.toggleSidebar")} />
            <Separator
              orientation="vertical"
              className="mr-1 data-[orientation=vertical]:h-4"
            />
            <span className="truncate text-sm font-medium text-foreground">
              {t(ROUTE_TITLE_KEYS[route])}
            </span>
          </div>

          <div className="ml-auto flex items-center gap-1.5">
            {health && !health.ok && (
              <span
                className="inline-flex items-center gap-1.5 rounded-md border border-destructive/30 bg-destructive/10 px-2 py-1 text-xs text-destructive"
                role="status"
              >
                <AlertCircle className="size-3.5" />
                {t("app.controlPlaneError")}
              </span>
            )}

            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => setCommandOpen(true)}
              className="h-8 w-8 justify-center border-border/80 bg-muted/40 px-0 text-xs font-normal text-muted-foreground shadow-none hover:bg-muted/70 hover:text-foreground sm:w-48 sm:justify-between sm:px-2.5"
              aria-label={t("search.openPalette")}
            >
              <span className="flex items-center gap-2">
                <Search className="size-3.5 shrink-0" />
                <span className="hidden sm:inline">{t("search.placeholder")}</span>
              </span>
              <kbd className="pointer-events-none hidden h-5 items-center rounded border bg-background px-1.5 font-mono text-[10px] font-medium text-muted-foreground sm:inline-flex">
                {shortcutLabel}
              </kbd>
            </Button>

            <LocaleToggle />
            <ThemeToggle />
          </div>
        </header>

        <div
          data-slot="page-content"
          className="mx-auto flex w-full max-w-[1360px] flex-1 flex-col gap-5 p-4 sm:p-6 lg:p-8"
        >
          {children}
        </div>
      </SidebarInset>

      <CommandMenu
        open={commandOpen}
        onOpenChange={setCommandOpen}
        onNavigate={onNavigate}
      />

      <CreateProfileDialog
        open={createDialogOpen}
        onOpenChange={setCreateDialogOpen}
        onCreated={() => onNavigate("platforms")}
      />
    </SidebarProvider>
  )
}

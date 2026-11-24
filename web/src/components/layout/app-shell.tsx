import { AlertCircle, Search } from "lucide-react"
import { useState, type ReactNode } from "react"
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator,
} from "@/components/ui/breadcrumb"
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
import { ThemeToggle } from "@/components/layout/theme-toggle"
import { useGatewayHealth } from "@/hooks/use-console-queries"
import type { AppRoute } from "@/hooks/use-hash-route"
import { useActiveProfile } from "@/lib/profile-context"

const ROUTE_TITLES: Record<AppRoute, string> = {
  overview: "概览",
  platforms: "平台与规则",
  audit: "审计日志",
  settings: "设置与令牌",
}

interface AppShellProps {
  route: AppRoute
  onNavigate: (route: AppRoute, params?: Record<string, string>) => void
  children: ReactNode
}

export function AppShell({ route, onNavigate, children }: AppShellProps) {
  const [commandOpen, setCommandOpen] = useState(false)
  const { data: health } = useGatewayHealth()
  const { activeProfile, createDialogOpen, setCreateDialogOpen } =
    useActiveProfile()

  return (
    <SidebarProvider>
      <AppSidebar route={route} onNavigate={(next) => onNavigate(next)} />
      <SidebarInset className="min-w-0">
        <header className="sticky top-0 z-20 flex h-13 shrink-0 items-center gap-2 border-b bg-background/85 px-4 backdrop-blur-md">
          <div className="flex min-w-0 items-center gap-2">
            <SidebarTrigger className="-ml-1" aria-label="切换侧边栏" />
            <Separator
              orientation="vertical"
              className="mr-1 data-[orientation=vertical]:h-4"
            />
            <Breadcrumb>
              <BreadcrumbList>
                <BreadcrumbItem className="hidden sm:inline-flex">
                  <BreadcrumbLink
                    href="#/overview"
                    className={activeProfile ? "font-mono text-xs" : undefined}
                    onClick={(e) => {
                      e.preventDefault()
                      onNavigate("overview")
                    }}
                  >
                    {activeProfile || "CX Gateway"}
                  </BreadcrumbLink>
                </BreadcrumbItem>
                <BreadcrumbSeparator className="hidden sm:inline-flex" />
                <BreadcrumbItem>
                  <BreadcrumbPage>{ROUTE_TITLES[route]}</BreadcrumbPage>
                </BreadcrumbItem>
              </BreadcrumbList>
            </Breadcrumb>
          </div>

          <div className="ml-auto flex items-center gap-1.5">
            {health && !health.ok && (
              <span
                className="inline-flex items-center gap-1.5 rounded-md border border-destructive/30 bg-destructive/10 px-2 py-1 text-xs text-destructive"
                role="status"
              >
                <AlertCircle className="size-3.5" />
                控制面异常
              </span>
            )}

            <Button
              type="button"
              variant="ghost"
              size="sm"
              onClick={() => setCommandOpen(true)}
              className="h-8 gap-2 px-2 text-xs font-normal text-muted-foreground hover:text-foreground"
              aria-label="打开命令面板"
            >
              <Search className="size-3.5" />
              <kbd className="pointer-events-none hidden rounded border bg-muted px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground sm:inline-block">
                ⌘K
              </kbd>
            </Button>

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

import {
  Activity,
  Blocks,
  Check,
  ChevronsUpDown,
  Layers,
  LayoutDashboard,
  LogOut,
  Plus,
  SlidersHorizontal,
} from "lucide-react"
import { Avatar, AvatarFallback } from "@/components/ui/avatar"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarRail,
  useSidebar,
} from "@/components/ui/sidebar"
import type { AppRoute } from "@/hooks/use-hash-route"
import { useAuth } from "@/lib/auth"
import { getInitials } from "@/lib/format"
import { useActiveProfile } from "@/lib/profile-context"

interface AppSidebarProps {
  route: AppRoute
  onNavigate: (route: AppRoute) => void
}

function summarizePlatforms(platformIds: string[]): string {
  if (platformIds.length === 0) return "尚未挂载平台"
  if (platformIds.length <= 3) return platformIds.join(" · ")
  return `${platformIds.slice(0, 2).join(" · ")} +${platformIds.length - 2}`
}

export function AppSidebar({ route, onNavigate }: AppSidebarProps) {
  const { session, signOut } = useAuth()
  const {
    profiles,
    activeProfile,
    activeProfileMeta,
    setActiveProfile,
    setCreateDialogOpen,
  } = useActiveProfile()
  const { isMobile, setOpenMobile } = useSidebar()

  if (!session) return null
  const { context, user } = session
  const displayName = context.display_name || context.email
  const initials = getInitials(context.display_name, context.email)

  function handleSelectRoute(target: AppRoute) {
    onNavigate(target)
    setOpenMobile(false)
  }

  function handleSwitchProfile(name: string) {
    setActiveProfile(name)
    setOpenMobile(false)
  }

  const activePlatformSubtitle = activeProfileMeta
    ? summarizePlatforms(activeProfileMeta.platforms.map((p) => p.id))
    : "CX Gateway"

  return (
    <Sidebar variant="inset" collapsible="icon">
      {/* Top-Left Profile Workspace Switcher */}
      <SidebarHeader className="p-2">
        <SidebarMenu>
          <SidebarMenuItem>
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <SidebarMenuButton
                  size="lg"
                  aria-label="切换 Profile"
                  className="data-[state=open]:bg-sidebar-accent data-[state=open]:text-sidebar-accent-foreground"
                >
                  <div className="flex size-8 shrink-0 items-center justify-center rounded-lg bg-primary text-primary-foreground">
                    <Layers className="size-4" aria-hidden="true" />
                  </div>
                  <div className="grid min-w-0 flex-1 text-left text-sm leading-tight">
                    <span className="truncate font-mono font-semibold">
                      {activeProfile || "未选择 Profile"}
                    </span>
                    <span className="truncate text-xs text-muted-foreground">
                      {activePlatformSubtitle}
                    </span>
                  </div>
                  <ChevronsUpDown className="ml-auto size-4 text-muted-foreground" />
                </SidebarMenuButton>
              </DropdownMenuTrigger>
              <DropdownMenuContent
                className="w-64 rounded-lg"
                align="start"
                side={isMobile ? "bottom" : "right"}
                sideOffset={6}
              >
                <DropdownMenuLabel className="text-xs font-normal text-muted-foreground">
                  切换 Profile
                </DropdownMenuLabel>
                <DropdownMenuSeparator />
                {profiles.length === 0 ? (
                  <div className="px-2 py-3 text-center text-xs text-muted-foreground">
                    暂无可用 Profile
                  </div>
                ) : (
                  profiles.map((prof) => {
                    const selected = prof.name === activeProfile
                    return (
                      <DropdownMenuItem
                        key={prof.name}
                        onSelect={() => handleSwitchProfile(prof.name)}
                        className="justify-between gap-2 py-2"
                      >
                        <div className="min-w-0">
                          <div className="truncate font-mono text-xs font-medium">
                            {prof.name}
                          </div>
                          <div className="truncate text-[11px] text-muted-foreground">
                            {summarizePlatforms(prof.platforms.map((p) => p.id))}
                          </div>
                        </div>
                        {selected && <Check className="size-3.5 shrink-0" />}
                      </DropdownMenuItem>
                    )
                  })
                )}

                {context.admin && (
                  <>
                    <DropdownMenuSeparator />
                    <DropdownMenuItem
                      onSelect={() => {
                        setOpenMobile(false)
                        setCreateDialogOpen(true)
                      }}
                    >
                      <Plus className="size-3.5" />
                      <span>新建 Profile</span>
                    </DropdownMenuItem>
                  </>
                )}
              </DropdownMenuContent>
            </DropdownMenu>
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarHeader>

      <SidebarContent>
        <SidebarGroup>
          <SidebarGroupLabel>
            {activeProfile ? "当前 Profile" : "工作区"}
          </SidebarGroupLabel>
          <SidebarGroupContent>
            <SidebarMenu>
              <SidebarMenuItem>
                <SidebarMenuButton
                  tooltip="概览"
                  isActive={route === "overview"}
                  onClick={() => handleSelectRoute("overview")}
                >
                  <LayoutDashboard />
                  <span>概览</span>
                </SidebarMenuButton>
              </SidebarMenuItem>

              <SidebarMenuItem>
                <SidebarMenuButton
                  tooltip="平台与规则"
                  isActive={route === "platforms"}
                  onClick={() => handleSelectRoute("platforms")}
                >
                  <Blocks />
                  <span>平台与规则</span>
                </SidebarMenuButton>
              </SidebarMenuItem>

              <SidebarMenuItem>
                <SidebarMenuButton
                  tooltip="审计日志"
                  isActive={route === "audit"}
                  onClick={() => handleSelectRoute("audit")}
                >
                  <Activity />
                  <span>审计日志</span>
                </SidebarMenuButton>
              </SidebarMenuItem>

              <SidebarMenuItem>
                <SidebarMenuButton
                  tooltip="设置与令牌"
                  isActive={route === "settings"}
                  onClick={() => handleSelectRoute("settings")}
                >
                  <SlidersHorizontal />
                  <span>设置与令牌</span>
                </SidebarMenuButton>
              </SidebarMenuItem>
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>
      </SidebarContent>

      <SidebarFooter>
        <SidebarMenu>
          <SidebarMenuItem>
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <SidebarMenuButton
                  size="lg"
                  aria-label="账号菜单"
                  className="data-[state=open]:bg-sidebar-accent data-[state=open]:text-sidebar-accent-foreground"
                >
                  <Avatar className="size-8 rounded-lg">
                    <AvatarFallback className="rounded-lg bg-muted text-xs font-medium text-foreground">
                      {initials}
                    </AvatarFallback>
                  </Avatar>
                  <div className="grid min-w-0 flex-1 text-left text-sm leading-tight">
                    <span className="truncate font-medium">{displayName}</span>
                    <span className="truncate text-xs text-muted-foreground">
                      {context.email}
                    </span>
                  </div>
                  <ChevronsUpDown className="ml-auto size-4 text-muted-foreground" />
                </SidebarMenuButton>
              </DropdownMenuTrigger>
              <DropdownMenuContent
                className="w-60 rounded-lg"
                side={isMobile ? "bottom" : "right"}
                align="end"
                sideOffset={6}
              >
                <DropdownMenuLabel className="p-2.5 font-normal">
                  <div className="space-y-1">
                    <div className="flex items-center justify-between gap-2">
                      <span className="truncate text-sm font-medium">
                        {displayName}
                      </span>
                      <span className="text-[11px] text-muted-foreground">
                        {context.admin ? "管理员" : "成员"}
                      </span>
                    </div>
                    <p className="truncate text-xs text-muted-foreground">
                      {context.email}
                    </p>
                    {user && user.groups.length > 0 && (
                      <p className="truncate pt-0.5 font-mono text-[11px] text-muted-foreground">
                        {user.groups.join(" · ")}
                      </p>
                    )}
                  </div>
                </DropdownMenuLabel>
                <DropdownMenuSeparator />
                <DropdownMenuItem
                  onSelect={() => void signOut()}
                  className="text-destructive focus:text-destructive"
                >
                  <LogOut />
                  <span>退出登录</span>
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarFooter>

      <SidebarRail />
    </Sidebar>
  )
}

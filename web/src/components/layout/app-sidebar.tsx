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
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar"
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
import { useI18n } from "@/lib/i18n"
import { useActiveProfile } from "@/lib/profile-context"

interface AppSidebarProps {
  route: AppRoute
  onNavigate: (route: AppRoute) => void
}

export function AppSidebar({ route, onNavigate }: AppSidebarProps) {
  const { session, signOut } = useAuth()
  const {
    profiles,
    activeProfile,
    setActiveProfile,
    setCreateDialogOpen,
  } = useActiveProfile()
  const { isMobile, setOpenMobile } = useSidebar()
  const { t } = useI18n()

  if (!session) return null
  const { context, user } = session
  const displayName = context.display_name || context.email
  const avatarUrl = context.avatar_url || user?.avatar_url || undefined
  const initials = getInitials(context.display_name, context.email)

  function handleSelectRoute(target: AppRoute) {
    onNavigate(target)
    setOpenMobile(false)
  }

  function handleSwitchProfile(name: string) {
    setActiveProfile(name)
    setOpenMobile(false)
  }

  return (
    <Sidebar variant="inset" collapsible="icon">
      {/* Top-Left Profile Switcher */}
      <SidebarHeader className="p-2">
        <SidebarMenu>
          <SidebarMenuItem>
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <SidebarMenuButton
                  size="lg"
                  aria-label={t("sidebar.switchProfile")}
                  className="data-[state=open]:bg-sidebar-accent data-[state=open]:text-sidebar-accent-foreground"
                >
                  <div className="flex size-8 shrink-0 items-center justify-center rounded-lg bg-primary text-primary-foreground">
                    <Layers className="size-4" aria-hidden="true" />
                  </div>
                  <span className="min-w-0 flex-1 truncate text-left text-sm font-semibold">
                    {activeProfile || "default"}
                  </span>
                  <ChevronsUpDown className="ml-auto size-4 shrink-0 text-muted-foreground" />
                </SidebarMenuButton>
              </DropdownMenuTrigger>
              <DropdownMenuContent
                className="w-56 rounded-lg"
                align="start"
                side={isMobile ? "bottom" : "right"}
                sideOffset={6}
              >
                <DropdownMenuLabel className="text-xs font-normal text-muted-foreground">
                  {t("sidebar.switchProfile")}
                </DropdownMenuLabel>
                <DropdownMenuSeparator />
                {profiles.length === 0 ? (
                  <div className="px-2 py-3 text-center text-xs text-muted-foreground">
                    {t("sidebar.noProfiles")}
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
                        <span className="truncate font-mono text-xs font-medium">
                          {prof.name}
                        </span>
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
                      <span>{t("sidebar.newProfile")}</span>
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
            {activeProfile ? t("nav.currentProfile") : t("nav.workspace")}
          </SidebarGroupLabel>
          <SidebarGroupContent>
            <SidebarMenu>
              <SidebarMenuItem>
                <SidebarMenuButton
                  tooltip={t("nav.overview")}
                  isActive={route === "overview"}
                  onClick={() => handleSelectRoute("overview")}
                >
                  <LayoutDashboard />
                  <span>{t("nav.overview")}</span>
                </SidebarMenuButton>
              </SidebarMenuItem>

              <SidebarMenuItem>
                <SidebarMenuButton
                  tooltip={t("nav.platforms")}
                  isActive={route === "platforms"}
                  onClick={() => handleSelectRoute("platforms")}
                >
                  <Blocks />
                  <span>{t("nav.platforms")}</span>
                </SidebarMenuButton>
              </SidebarMenuItem>

              <SidebarMenuItem>
                <SidebarMenuButton
                  tooltip={t("nav.audit")}
                  isActive={route === "audit"}
                  onClick={() => handleSelectRoute("audit")}
                >
                  <Activity />
                  <span>{t("nav.audit")}</span>
                </SidebarMenuButton>
              </SidebarMenuItem>

              <SidebarMenuItem>
                <SidebarMenuButton
                  tooltip={t("nav.settings")}
                  isActive={route === "settings"}
                  onClick={() => handleSelectRoute("settings")}
                >
                  <SlidersHorizontal />
                  <span>{t("nav.settings")}</span>
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
                  aria-label={t("sidebar.accountMenu")}
                  className="data-[state=open]:bg-sidebar-accent data-[state=open]:text-sidebar-accent-foreground"
                >
                  <Avatar className="size-8 rounded-lg">
                    {avatarUrl && (
                      <AvatarImage
                        src={avatarUrl}
                        alt={displayName}
                        referrerPolicy="no-referrer"
                        className="rounded-lg object-cover"
                      />
                    )}
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
                  <div className="flex items-center gap-2.5">
                    <Avatar className="size-8 rounded-lg">
                      {avatarUrl && (
                        <AvatarImage
                          src={avatarUrl}
                          alt={displayName}
                          referrerPolicy="no-referrer"
                          className="rounded-lg object-cover"
                        />
                      )}
                      <AvatarFallback className="rounded-lg bg-muted text-xs font-medium text-foreground">
                        {initials}
                      </AvatarFallback>
                    </Avatar>
                    <div className="min-w-0 flex-1 space-y-0.5">
                      <div className="flex items-center justify-between gap-2">
                        <span className="truncate text-sm font-medium">
                          {displayName}
                        </span>
                        <span className="shrink-0 text-[11px] text-muted-foreground">
                          {context.admin
                            ? t("sidebar.roleAdmin")
                            : t("sidebar.roleMember")}
                        </span>
                      </div>
                      <p className="truncate text-xs text-muted-foreground">
                        {context.email}
                      </p>
                    </div>
                  </div>
                  {user && user.groups.length > 0 && (
                    <p className="mt-2 truncate font-mono text-[11px] text-muted-foreground">
                      {user.groups.join(" · ")}
                    </p>
                  )}
                </DropdownMenuLabel>
                <DropdownMenuSeparator />
                <DropdownMenuItem
                  onSelect={() => void signOut()}
                  className="text-destructive focus:text-destructive"
                >
                  <LogOut />
                  <span>{t("sidebar.signOut")}</span>
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

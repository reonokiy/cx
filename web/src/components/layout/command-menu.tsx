import {
  Activity,
  Blocks,
  Check,
  Languages,
  Layers,
  LayoutDashboard,
  LogOut,
  Moon,
  Plus,
  SlidersHorizontal,
  Sun,
} from "lucide-react"
import { useEffect } from "react"
import {
  CommandDialog,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
  CommandSeparator,
} from "@/components/ui/command"
import type { AppRoute } from "@/hooks/use-hash-route"
import { useAuth } from "@/lib/auth"
import { useI18n } from "@/lib/i18n"
import { useActiveProfile } from "@/lib/profile-context"
import { useTheme } from "@/lib/theme"

interface CommandMenuProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  onNavigate: (route: AppRoute, params?: Record<string, string>) => void
}

export function CommandMenu({
  open,
  onOpenChange,
  onNavigate,
}: CommandMenuProps) {
  const { session, signOut } = useAuth()
  const {
    profiles,
    activeProfile,
    setActiveProfile,
    setCreateDialogOpen,
  } = useActiveProfile()
  const { resolvedTheme, setTheme } = useTheme()
  const { locale, setLocale, t } = useI18n()

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault()
        onOpenChange(!open)
      }
    }
    window.addEventListener("keydown", onKeyDown)
    return () => window.removeEventListener("keydown", onKeyDown)
  }, [open, onOpenChange])

  if (!session) return null
  const { context } = session

  function go(route: AppRoute, params?: Record<string, string>) {
    onOpenChange(false)
    onNavigate(route, params)
  }

  return (
    <CommandDialog
      open={open}
      onOpenChange={onOpenChange}
      title={t("cmd.title")}
      description={t("cmd.description")}
    >
      <CommandInput placeholder={t("cmd.inputPlaceholder")} />
      <CommandList>
        <CommandEmpty>{t("cmd.empty")}</CommandEmpty>

        {(profiles.length > 0 || context.admin) && (
          <>
            <CommandGroup heading={t("cmd.groupProfiles")}>
              {profiles.map((prof) => (
                <CommandItem
                  key={`switch-${prof.name}`}
                  value={`profile ${prof.name}`}
                  keywords={[
                    prof.name,
                    "profile",
                    ...prof.platforms.map((p) => p.id),
                    ...prof.platforms.map((p) => p.provider_name),
                  ]}
                  onSelect={() => {
                    setActiveProfile(prof.name)
                    onOpenChange(false)
                  }}
                >
                  <Layers />
                  <span className="font-mono text-xs">{prof.name}</span>
                  {prof.platforms.length > 0 && (
                    <span className="ml-2 truncate text-xs text-muted-foreground">
                      {prof.platforms.map((p) => p.id).join(" · ")}
                    </span>
                  )}
                  {prof.name === activeProfile && (
                    <Check className="ml-auto size-3.5" />
                  )}
                </CommandItem>
              ))}
              {context.admin && (
                <CommandItem
                  value="new-profile"
                  keywords={["new", "create", "profile", "新建", "创建"]}
                  onSelect={() => {
                    onOpenChange(false)
                    setCreateDialogOpen(true)
                  }}
                >
                  <Plus />
                  <span>{t("cmd.newProfile")}</span>
                </CommandItem>
              )}
            </CommandGroup>
            <CommandSeparator />
          </>
        )}

        <CommandGroup heading={t("cmd.groupPages")}>
          <CommandItem
            value="overview"
            keywords={["overview", "dashboard", "home", "概览", "首页"]}
            onSelect={() => go("overview")}
          >
            <LayoutDashboard />
            <span>{t("nav.overview")}</span>
          </CommandItem>
          <CommandItem
            value="platforms"
            keywords={[
              "platforms",
              "providers",
              "rules",
              "policy",
              "secrets",
              "平台",
              "规则",
              "凭据",
            ]}
            onSelect={() => go("platforms")}
          >
            <Blocks />
            <span>{t("nav.platforms")}</span>
          </CommandItem>
          <CommandItem
            value="audit"
            keywords={["audit", "logs", "events", "审计", "日志"]}
            onSelect={() => go("audit")}
          >
            <Activity />
            <span>{t("nav.audit")}</span>
          </CommandItem>
          <CommandItem
            value="settings"
            keywords={[
              "settings",
              "tokens",
              "keys",
              "virtual",
              "pat",
              "设置",
              "令牌",
              "密钥",
            ]}
            onSelect={() => go("settings")}
          >
            <SlidersHorizontal />
            <span>{t("nav.settings")}</span>
          </CommandItem>
        </CommandGroup>

        <CommandSeparator />
        <CommandGroup heading={t("cmd.groupSystem")}>
          <CommandItem
            value="toggle-language"
            keywords={["language", "locale", "english", "chinese", "语言", "中文", "英文"]}
            onSelect={() => {
              setLocale(locale === "zh-CN" ? "en" : "zh-CN")
              onOpenChange(false)
            }}
          >
            <Languages />
            <span>{t("cmd.switchLanguage")}</span>
          </CommandItem>
          <CommandItem
            value="toggle-theme"
            keywords={["theme", "dark", "light", "主题", "深色", "浅色"]}
            onSelect={() => {
              setTheme(resolvedTheme === "dark" ? "light" : "dark")
              onOpenChange(false)
            }}
          >
            {resolvedTheme === "dark" ? <Sun /> : <Moon />}
            <span>
              {resolvedTheme === "dark"
                ? t("cmd.switchToLight")
                : t("cmd.switchToDark")}
            </span>
          </CommandItem>
          <CommandItem
            value="sign-out"
            keywords={["logout", "sign out", "退出", "登出"]}
            onSelect={() => {
              onOpenChange(false)
              void signOut()
            }}
          >
            <LogOut />
            <span>{t("sidebar.signOut")}</span>
          </CommandItem>
        </CommandGroup>
      </CommandList>
    </CommandDialog>
  )
}

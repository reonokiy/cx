import {
  Activity,
  Blocks,
  Check,
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
      title="快捷命令"
      description="切换 Profile 或跳转到页面"
    >
      <CommandInput placeholder="搜索 Profile、页面或操作…" />
      <CommandList>
        <CommandEmpty>未找到匹配项。</CommandEmpty>

        {profiles.length > 0 && (
          <>
            <CommandGroup heading="切换 Profile">
              {profiles.map((prof) => (
                <CommandItem
                  key={`switch-${prof.name}`}
                  onSelect={() => {
                    setActiveProfile(prof.name)
                    onOpenChange(false)
                  }}
                >
                  <Layers />
                  <span className="font-mono text-xs">{prof.name}</span>
                  <span className="ml-2 text-xs text-muted-foreground">
                    {prof.platforms.map((p) => p.id).join(" · ")}
                  </span>
                  {prof.name === activeProfile && (
                    <Check className="ml-auto size-3.5" />
                  )}
                </CommandItem>
              ))}
              {context.admin && (
                <CommandItem
                  onSelect={() => {
                    onOpenChange(false)
                    setCreateDialogOpen(true)
                  }}
                >
                  <Plus />
                  <span>新建 Profile</span>
                </CommandItem>
              )}
            </CommandGroup>
            <CommandSeparator />
          </>
        )}

        <CommandGroup heading="页面">
          <CommandItem onSelect={() => go("overview")}>
            <LayoutDashboard />
            <span>概览</span>
          </CommandItem>
          <CommandItem onSelect={() => go("platforms")}>
            <Blocks />
            <span>平台与规则</span>
          </CommandItem>
          <CommandItem onSelect={() => go("audit")}>
            <Activity />
            <span>审计日志</span>
          </CommandItem>
          <CommandItem onSelect={() => go("settings")}>
            <SlidersHorizontal />
            <span>设置与令牌</span>
          </CommandItem>
        </CommandGroup>

        <CommandSeparator />
        <CommandGroup heading="系统">
          <CommandItem
            onSelect={() => {
              setTheme(resolvedTheme === "dark" ? "light" : "dark")
              onOpenChange(false)
            }}
          >
            {resolvedTheme === "dark" ? <Sun /> : <Moon />}
            <span>{resolvedTheme === "dark" ? "浅色模式" : "深色模式"}</span>
          </CommandItem>
          <CommandItem
            onSelect={() => {
              onOpenChange(false)
              void signOut()
            }}
          >
            <LogOut />
            <span>退出登录</span>
          </CommandItem>
        </CommandGroup>
      </CommandList>
    </CommandDialog>
  )
}

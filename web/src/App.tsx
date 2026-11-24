import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { lazy, Suspense } from "react"
import { Skeleton } from "@/components/ui/skeleton"
import { Toaster } from "@/components/ui/sonner"
import { TooltipProvider } from "@/components/ui/tooltip"
import { AppShell } from "@/components/layout/app-shell"
import { LoginPage } from "@/features/auth/login-page"
import { useHashRoute } from "@/hooks/use-hash-route"
import { AuthProvider, useAuth } from "@/lib/auth"
import { ProfileProvider } from "@/lib/profile-context"
import { ThemeProvider } from "@/lib/theme"

const OverviewPage = lazy(() =>
  import("@/features/overview/overview-page").then((m) => ({
    default: m.OverviewPage,
  }))
)
const PlatformsPage = lazy(() =>
  import("@/features/platforms/platforms-page").then((m) => ({
    default: m.PlatformsPage,
  }))
)
const AuditPage = lazy(() =>
  import("@/features/audit/audit-page").then((m) => ({
    default: m.AuditPage,
  }))
)
const SettingsPage = lazy(() =>
  import("@/features/settings/settings-page").then((m) => ({
    default: m.SettingsPage,
  }))
)

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: false,
      refetchOnWindowFocus: false,
    },
  },
})

function PageFallback() {
  return (
    <div className="space-y-6">
      <div className="space-y-2">
        <Skeleton className="h-7 w-40" />
        <Skeleton className="h-4 w-72" />
      </div>
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {Array.from({ length: 4 }).map((_, i) => (
          <Skeleton key={i} className="h-28 rounded-xl" />
        ))}
      </div>
      <Skeleton className="h-80 rounded-xl" />
    </div>
  )
}

function AuthenticatedApp() {
  const { session, isRestoring } = useAuth()
  const { route, params, navigate } = useHashRoute()

  if (isRestoring) {
    return (
      <div className="flex min-h-svh items-center justify-center bg-background">
        <div className="flex flex-col items-center gap-3">
          <Skeleton className="size-10 rounded-xl" />
          <p className="text-xs text-muted-foreground">正在恢复控制台会话…</p>
        </div>
      </div>
    )
  }

  if (!session) {
    return <LoginPage />
  }

  return (
    <ProfileProvider requestedProfile={params.profile}>
      <AppShell route={route} onNavigate={navigate}>
        <Suspense fallback={<PageFallback />}>
          {route === "overview" && <OverviewPage onNavigate={navigate} />}
          {route === "platforms" && (
            <PlatformsPage
              initialPlatform={params.platform}
              openAdd={params.add === "1"}
            />
          )}
          {route === "audit" && (
            <AuditPage
              initialSearch={params.q}
              initialPlatform={params.platform}
            />
          )}
          {route === "settings" && (
            <SettingsPage
              initialTab={params.tab}
              onProfileDeleted={() => navigate("overview")}
            />
          )}
        </Suspense>
      </AppShell>
    </ProfileProvider>
  )
}

export function App() {
  return (
    <ThemeProvider>
      <QueryClientProvider client={queryClient}>
        <TooltipProvider delayDuration={200}>
          <AuthProvider>
            <AuthenticatedApp />
          </AuthProvider>
          <Toaster position="bottom-right" richColors closeButton />
        </TooltipProvider>
      </QueryClientProvider>
    </ThemeProvider>
  )
}

export default App

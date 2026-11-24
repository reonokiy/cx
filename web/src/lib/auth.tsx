import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react"
import { useQueryClient } from "@tanstack/react-query"
import {
  createApiClient,
  fetchConsoleAuthConfig,
  type ConsoleAuthConfig,
  type ConsoleContext,
  type CxApiClient,
  type UserSummary,
} from "@/lib/api"

export interface AuthSession {
  context: ConsoleContext
  user: UserSummary | null
}

interface AuthContextValue {
  session: AuthSession | null
  api: CxApiClient | null
  authConfig: ConsoleAuthConfig
  isRestoring: boolean
  sessionExpired: boolean
  oidcErrorCode: string | null
  signOut: () => Promise<void>
  refreshContext: () => Promise<void>
}

const AuthContext = createContext<AuthContextValue | null>(null)

function consumeOidcErrorFromUrl(): string | null {
  if (typeof window === "undefined") return null
  const params = new URLSearchParams(window.location.search)
  const code = params.get("auth_error")
  if (!code) return null
  params.delete("auth_error")
  const qs = params.toString()
  const cleanUrl = `${window.location.pathname}${qs ? `?${qs}` : ""}${window.location.hash}`
  window.history.replaceState(null, "", cleanUrl)
  return code
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient()
  const [session, setSession] = useState<AuthSession | null>(null)
  const [authConfig, setAuthConfig] = useState<ConsoleAuthConfig>({
    oidc_enabled: false,
    session_active: false,
  })
  const [isRestoring, setIsRestoring] = useState<boolean>(true)
  const [sessionExpired, setSessionExpired] = useState(false)
  const [oidcErrorCode] = useState<string | null>(() =>
    consumeOidcErrorFromUrl()
  )
  const sessionSeqRef = useRef(0)

  const handleUnauthorized = useCallback(
    (seq: number) => {
      if (sessionSeqRef.current !== seq) return
      sessionSeqRef.current += 1
      queryClient.clear()
      setSessionExpired(true)
      setSession(null)
    },
    [queryClient]
  )

  const loadSession = useCallback(
    async (signal?: AbortSignal): Promise<AuthSession> => {
      const client = createApiClient()
      const context = await client.getConsoleContext(signal)
      let user: UserSummary | null = null
      try {
        user = await client.getWhoAmI(signal)
      } catch {
        user = null
      }
      return { context, user }
    },
    []
  )

  useEffect(() => {
    const controller = new AbortController()
    let cancelled = false

    async function bootstrap() {
      const cfg = await fetchConsoleAuthConfig(controller.signal)
      if (!cancelled) setAuthConfig(cfg)

      if (cfg.session_active) {
        try {
          const active = await loadSession(controller.signal)
          if (!cancelled) {
            sessionSeqRef.current += 1
            setSession(active)
            setSessionExpired(false)
          }
        } catch {
          if (!cancelled) {
            setSessionExpired(true)
          }
        }
      }
    }

    bootstrap().finally(() => {
      if (!cancelled) setIsRestoring(false)
    })

    return () => {
      cancelled = true
      controller.abort()
    }
  }, [loadSession])

  const signOut = useCallback(async () => {
    sessionSeqRef.current += 1
    queryClient.clear()
    setSessionExpired(false)
    setSession(null)
    try {
      await createApiClient().logout()
    } catch {
      // Ignore network errors on logout cleanup
    }
  }, [queryClient])

  const refreshContext = useCallback(async () => {
    if (!session) return
    const seq = sessionSeqRef.current
    const next = await loadSession()
    if (sessionSeqRef.current === seq) {
      setSession(next)
    }
  }, [session, loadSession])

  const api = useMemo<CxApiClient | null>(() => {
    if (!session) return null
    const seq = sessionSeqRef.current
    return createApiClient(() => handleUnauthorized(seq))
  }, [session, handleUnauthorized])

  const value = useMemo<AuthContextValue>(
    () => ({
      session,
      api,
      authConfig,
      isRestoring,
      sessionExpired,
      oidcErrorCode,
      signOut,
      refreshContext,
    }),
    [
      session,
      api,
      authConfig,
      isRestoring,
      sessionExpired,
      oidcErrorCode,
      signOut,
      refreshContext,
    ]
  )

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext)
  if (!ctx) {
    throw new Error("useAuth must be used within an AuthProvider")
  }
  return ctx
}

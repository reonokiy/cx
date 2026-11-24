import { useCallback, useEffect, useState } from "react"

export type AppRoute = "overview" | "platforms" | "audit" | "settings"

const VALID_ROUTES = new Set<AppRoute>([
  "overview",
  "platforms",
  "audit",
  "settings",
])

export interface ParsedRoute {
  route: AppRoute
  params: Record<string, string>
}

function parseHash(hash: string): ParsedRoute {
  const cleaned = hash.replace(/^#\/?/, "")
  const [segmentRaw, queryRaw] = cleaned.split("?")
  const candidate = (segmentRaw || "overview") as AppRoute
  const route: AppRoute = VALID_ROUTES.has(candidate) ? candidate : "overview"
  const params: Record<string, string> = {}
  if (queryRaw) {
    const sp = new URLSearchParams(queryRaw)
    sp.forEach((value, key) => {
      if (value) params[key] = value
    })
  }
  return { route, params }
}

function serializeHash(
  route: AppRoute,
  params?: Record<string, string>
): string {
  const sp = new URLSearchParams()
  if (params) {
    for (const [k, v] of Object.entries(params)) {
      if (v) sp.set(k, v)
    }
  }
  const qs = sp.toString()
  return `#/${route}${qs ? `?${qs}` : ""}`
}

export function useHashRoute() {
  const [state, setState] = useState<ParsedRoute>(() =>
    parseHash(typeof window !== "undefined" ? window.location.hash : "")
  )

  useEffect(() => {
    const onHashChange = () => {
      setState(parseHash(window.location.hash))
    }
    window.addEventListener("hashchange", onHashChange)
    return () => window.removeEventListener("hashchange", onHashChange)
  }, [])

  const navigate = useCallback(
    (route: AppRoute, params?: Record<string, string>) => {
      const target = serializeHash(route, params)
      if (window.location.hash !== target) {
        window.location.hash = target
      } else {
        setState(parseHash(target))
      }
    },
    []
  )

  return {
    route: state.route,
    params: state.params,
    navigate,
  }
}

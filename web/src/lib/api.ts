import { getCurrentLocale, translate } from "@/lib/i18n"

export type SecretScope = "personal" | "shared"
export type DefaultRouteAction = "client_passthrough" | "deny"
export type PolicyEffect = "allow" | "deny"

export interface ConsoleAuthConfig {
  oidc_enabled: boolean
  session_active: boolean
}

export interface PolicyRule {
  effect: PolicyEffect
  methods: string[]
  hosts: string[]
  paths: string[]
}

export interface ProviderParamInfo {
  name: string
  required: boolean
  default: string | null
}

export interface ProviderCatalogEntry {
  id: string
  name: string
  icon: string | null
  version: string
  description: string
  allow_multiple: boolean
  params: ProviderParamInfo[]
  secret_fields: string[]
  default_inject_hosts: string[]
  default_passthrough_hosts: string[]
  presets: Record<string, PolicyRule[]>
}

export type SecretBinding =
  | { source: "db"; scope: SecretScope; name: string; field?: string | null }
  | { source: "env"; var: string }
  | { source: "inline"; value: string }

export interface SecretMeta {
  name: string
  scope: SecretScope
  updated_at: number
}

export interface SecretSlotStatus {
  slot: string
  source: "db" | "env" | "inline" | "unconfigured"
  scope: SecretScope | null
  name: string | null
  field: string
  configured: boolean
  updated_at: number | null
  can_edit: boolean
}

export interface PlatformRoutingOverride {
  inject_hosts?: string[] | null
  passthrough_hosts?: string[] | null
  passthrough_ports?: number[] | null
}

export interface PlatformSpec {
  id: string
  provider_id: string
  params: Record<string, string>
  secrets: Record<string, SecretBinding>
  virtual_key_override?: Record<string, unknown> | null
  preset: string | null
  rules: PolicyRule[]
  routing: PlatformRoutingOverride
  allow_insecure_http: boolean
}

export interface PlatformOverview {
  id: string
  provider_id: string
  provider_name: string
  provider_icon: string | null
  preset: string | null
  custom_rule_count: number
  inject_hosts: string[]
  server_tunnel_hosts: string[]
  secrets: SecretSlotStatus[]
}

export interface ProfileOverview {
  name: string
  description: string
  allowed_groups: string[]
  allowed_users: string[]
  fallback: DefaultRouteAction
  can_issue_keys: boolean
  revision: string
  updated_by: string
  updated_at: number
  platforms: PlatformOverview[]
}

export interface PlatformDetail {
  spec: PlatformSpec
  provider_name: string
  provider_icon: string | null
  inject_hosts: string[]
  server_tunnel_hosts: string[]
  preset_rules: PolicyRule[]
  secret_fields: string[]
  secrets: SecretSlotStatus[]
}

export interface ProfileDetail {
  name: string
  description: string
  allowed_groups: string[]
  allowed_users: string[]
  deny_hosts: string[]
  fallback: DefaultRouteAction
  can_issue_keys: boolean
  revision: string
  updated_by: string
  updated_at: number
  created_at: number
  platforms: PlatformDetail[]
}

export interface CreateProfileInput {
  name: string
  description: string
  allowed_groups: string[]
  allowed_users: string[]
  deny_hosts: string[]
  fallback: DefaultRouteAction
  platforms: PlatformSpec[]
}

export interface UpdateProfileInput {
  revision: string
  description: string
  allowed_groups: string[]
  allowed_users: string[]
  deny_hosts: string[]
  fallback: DefaultRouteAction
  platforms: PlatformSpec[]
}

export interface ConsoleContext {
  email: string
  display_name: string
  avatar_url?: string | null
  admin: boolean
  encryption_ready: boolean
  providers: ProviderCatalogEntry[]
  profiles: ProfileOverview[]
  shared_secrets: SecretMeta[]
}

export interface UserSummary {
  id: string
  email: string
  display_name: string
  avatar_url?: string | null
  groups: string[]
}

export interface AuditEntry {
  id: number
  occurred_at: number
  user_id?: string
  user_email: string
  session_id: string
  profile_name: string
  platform_id: string
  route_tier: string
  target_host: string
  target_port: number
  http_method: string | null
  http_path: string | null
  status_code: number | null
  decision: string
  deny_reason: string | null
  client_ip: string
  latency_ms: number
}

export interface AuditPage {
  events: AuditEntry[]
  next: number | null
}

export interface AuditQueryParams {
  profile?: string
  platform?: string
  decision?: string
  search?: string
  before?: number
}

export interface CreateVirtualKeyRequest {
  profile: string
  platform?: string
  ttl_secs?: number
}

export interface CreateVirtualKeyResponse {
  id: string
  virtual_key: string
  profile: string
  platform: string
  expires_at: number | null
}

export interface CreateScopedTokenRequest {
  name: string
  profiles: string[]
  ttl_secs?: number
}

export interface CreateScopedTokenResponse {
  id: string
  token: string
  expires_at: number
}

export interface UpsertSecretRequest {
  name: string
  scope: SecretScope
  fields: Record<string, string>
}

export class ApiError extends Error {
  readonly status: number
  readonly detail: string

  constructor(status: number, detail: string) {
    super(
      detail ||
        translate(getCurrentLocale(), "error.requestFailed", { status })
    )
    this.name = "ApiError"
    this.status = status
    this.detail = detail
  }
}

export function getErrorMessage(error: unknown): string {
  const locale = getCurrentLocale()
  if (error instanceof ApiError) {
    if (error.status === 401)
      return error.detail || translate(locale, "error.unauthorized")
    if (error.status === 403)
      return error.detail || translate(locale, "error.forbidden")
    if (error.status === 409)
      return error.detail || translate(locale, "error.conflict")
    return error.message
  }
  if (error instanceof Error) return error.message
  return translate(locale, "error.network")
}

export interface CxApiClient {
  request<T>(path: string, init?: RequestInit): Promise<T>
  getConsoleContext(signal?: AbortSignal): Promise<ConsoleContext>
  getWhoAmI(signal?: AbortSignal): Promise<UserSummary>
  getProfileDetail(profile: string, signal?: AbortSignal): Promise<ProfileDetail>
  createProfile(payload: CreateProfileInput): Promise<ProfileDetail>
  updateProfile(profile: string, payload: UpdateProfileInput): Promise<ProfileDetail>
  deleteProfile(profile: string): Promise<void>
  listAudit(params: AuditQueryParams, signal?: AbortSignal): Promise<AuditPage>
  upsertSecret(payload: UpsertSecretRequest): Promise<void>
  createVirtualKey(payload: CreateVirtualKeyRequest): Promise<CreateVirtualKeyResponse>
  createScopedToken(payload: CreateScopedTokenRequest): Promise<CreateScopedTokenResponse>
  revokeSession(sessionId: string): Promise<void>
  logout(): Promise<void>
}

export function createApiClient(onUnauthorized?: () => void): CxApiClient {
  async function request<T>(path: string, init?: RequestInit): Promise<T> {
    const headers = new Headers(init?.headers)
    headers.set("X-CX-Console", "1")
    if (init?.body && !headers.has("Content-Type")) {
      headers.set("Content-Type", "application/json")
    }

    const response = await fetch(path, {
      ...init,
      cache: "no-store",
      credentials: "same-origin",
      headers,
    })

    if (!response.ok) {
      if (response.status === 401) {
        onUnauthorized?.()
      }
      const contentType = response.headers.get("content-type") ?? ""
      let detail = ""
      if (contentType.startsWith("text/plain") || contentType.includes("json")) {
        const raw = (await response.text()).trim()
        if (contentType.includes("json")) {
          try {
            const parsed = JSON.parse(raw) as { message?: string; error?: string }
            detail = parsed.message || parsed.error || raw
          } catch {
            detail = raw
          }
        } else {
          detail = raw
        }
      }
      throw new ApiError(response.status, detail)
    }

    if (response.status === 204) {
      return undefined as T
    }
    return (await response.json()) as T
  }

  return {
    request,
    getConsoleContext: (signal) =>
      request<ConsoleContext>("/v1/console", { signal }),
    getWhoAmI: (signal) => request<UserSummary>("/v1/whoami", { signal }),
    getProfileDetail: (profile, signal) =>
      request<ProfileDetail>(
        `/v1/console/profiles/${encodeURIComponent(profile)}`,
        { signal }
      ),
    createProfile: (payload) =>
      request<ProfileDetail>("/v1/console/profiles", {
        method: "POST",
        body: JSON.stringify(payload),
      }),
    updateProfile: (profile, payload) =>
      request<ProfileDetail>(
        `/v1/console/profiles/${encodeURIComponent(profile)}`,
        {
          method: "PUT",
          body: JSON.stringify(payload),
        }
      ),
    deleteProfile: (profile) =>
      request<void>(`/v1/console/profiles/${encodeURIComponent(profile)}`, {
        method: "DELETE",
      }),
    listAudit: (params, signal) => {
      const search = new URLSearchParams()
      if (params.profile) search.set("profile", params.profile)
      if (params.platform) search.set("platform", params.platform)
      if (params.decision) search.set("decision", params.decision)
      if (params.search) search.set("search", params.search)
      if (params.before !== undefined) search.set("before", String(params.before))
      const qs = search.toString()
      return request<AuditPage>(`/v1/console/audit${qs ? `?${qs}` : ""}`, {
        signal,
      })
    },
    upsertSecret: (payload) =>
      request<void>("/v1/secrets", {
        method: "POST",
        body: JSON.stringify(payload),
      }),
    createVirtualKey: (payload) =>
      request<CreateVirtualKeyResponse>("/v1/virtual-keys", {
        method: "POST",
        body: JSON.stringify(payload),
      }),
    createScopedToken: (payload) =>
      request<CreateScopedTokenResponse>("/v1/tokens", {
        method: "POST",
        body: JSON.stringify(payload),
      }),
    revokeSession: (sessionId) =>
      request<void>(`/v1/sessions/${encodeURIComponent(sessionId)}`, {
        method: "DELETE",
      }),
    logout: () =>
      request<void>("/v1/console/auth/logout", {
        method: "POST",
      }),
  }
}

export async function fetchConsoleAuthConfig(
  signal?: AbortSignal
): Promise<ConsoleAuthConfig> {
  try {
    const response = await fetch("/v1/console/auth-config", {
      cache: "no-store",
      credentials: "same-origin",
      signal,
    })
    if (!response.ok) {
      return { oidc_enabled: false, session_active: false }
    }
    return (await response.json()) as ConsoleAuthConfig
  } catch {
    return { oidc_enabled: false, session_active: false }
  }
}

export async function checkGatewayHealth(
  signal?: AbortSignal
): Promise<{ ok: boolean; latencyMs: number }> {
  const started = performance.now()
  try {
    const response = await fetch("/healthz", { cache: "no-store", signal })
    const latencyMs = Math.max(1, Math.round(performance.now() - started))
    if (!response.ok) return { ok: false, latencyMs }
    const text = (await response.text()).trim()
    return { ok: text === "ok", latencyMs }
  } catch {
    return { ok: false, latencyMs: 0 }
  }
}

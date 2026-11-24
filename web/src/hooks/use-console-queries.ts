import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import {
  checkGatewayHealth,
  type AuditQueryParams,
  type CreateProfileInput,
  type CreateScopedTokenRequest,
  type CreateVirtualKeyRequest,
  type UpdateProfileInput,
  type UpsertSecretRequest,
} from "@/lib/api"
import { useAuth } from "@/lib/auth"

export const queryKeys = {
  health: ["gateway", "health"] as const,
  profileDetail: (profile: string) => ["console", "profile", profile] as const,
  audit: (params: AuditQueryParams) => ["console", "audit", params] as const,
  auditRecent: (profile?: string) =>
    ["console", "audit", "recent", profile ?? "all"] as const,
}

export function useGatewayHealth() {
  return useQuery({
    queryKey: queryKeys.health,
    queryFn: ({ signal }) => checkGatewayHealth(signal),
    refetchInterval: 30_000,
    staleTime: 15_000,
    retry: false,
  })
}

export function useProfileDetailQuery(profile: string, enabled = true) {
  const { api } = useAuth()
  return useQuery({
    queryKey: queryKeys.profileDetail(profile),
    queryFn: ({ signal }) => api!.getProfileDetail(profile, signal),
    enabled: !!api && !!profile && enabled,
    staleTime: 10_000,
  })
}

export function useCreateProfileMutation() {
  const { api, refreshContext } = useAuth()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (payload: CreateProfileInput) => api!.createProfile(payload),
    onSuccess: async (created) => {
      queryClient.setQueryData(queryKeys.profileDetail(created.name), created)
      await refreshContext()
    },
  })
}

export function useUpdateProfileMutation(profile: string) {
  const { api, refreshContext } = useAuth()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (payload: UpdateProfileInput) =>
      api!.updateProfile(profile, payload),
    onSuccess: async (updated) => {
      queryClient.setQueryData(queryKeys.profileDetail(profile), updated)
      await refreshContext()
    },
  })
}

export function useDeleteProfileMutation() {
  const { api, refreshContext } = useAuth()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (profile: string) => api!.deleteProfile(profile),
    onSuccess: async (_, deletedName) => {
      queryClient.removeQueries({
        queryKey: queryKeys.profileDetail(deletedName),
      })
      await refreshContext()
    },
  })
}

export function useRecentAuditQuery(profile?: string) {
  const { api } = useAuth()
  return useQuery({
    queryKey: queryKeys.auditRecent(profile),
    queryFn: ({ signal }) =>
      api!.listAudit(profile ? { profile } : {}, signal),
    enabled: !!api && !!profile,
    staleTime: 10_000,
  })
}

export function useAuditPageQuery(
  params: AuditQueryParams,
  options?: { autoRefresh?: boolean; enabled?: boolean }
) {
  const { api } = useAuth()
  return useQuery({
    queryKey: queryKeys.audit(params),
    queryFn: ({ signal }) => api!.listAudit(params, signal),
    enabled: !!api && (options?.enabled ?? true),
    refetchInterval: options?.autoRefresh ? 10_000 : false,
  })
}

export function useUpsertSecretMutation() {
  const { api, refreshContext } = useAuth()
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: (payload: UpsertSecretRequest) => api!.upsertSecret(payload),
    onSuccess: async () => {
      await refreshContext()
      await queryClient.invalidateQueries({ queryKey: ["console", "profile"] })
    },
  })
}

export function useCreateVirtualKeyMutation() {
  const { api } = useAuth()
  return useMutation({
    mutationFn: (payload: CreateVirtualKeyRequest) =>
      api!.createVirtualKey(payload),
  })
}

export function useCreateScopedTokenMutation() {
  const { api } = useAuth()
  return useMutation({
    mutationFn: (payload: CreateScopedTokenRequest) =>
      api!.createScopedToken(payload),
  })
}

export function useRevokeSessionMutation() {
  const { api } = useAuth()
  return useMutation({
    mutationFn: (sessionId: string) => api!.revokeSession(sessionId),
  })
}

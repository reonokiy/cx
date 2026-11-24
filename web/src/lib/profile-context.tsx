import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react"
import type {
  ProfileOverview,
  ProviderCatalogEntry,
  SecretMeta,
} from "@/lib/api"
import { useAuth } from "@/lib/auth"

const LAST_PROFILE_KEY = "cx-console-active-profile"

interface ProfileContextValue {
  profiles: ProfileOverview[]
  profileNames: string[]
  providers: ProviderCatalogEntry[]
  sharedSecrets: SecretMeta[]
  activeProfile: string
  activeProfileMeta: ProfileOverview | null
  canIssueKeys: boolean
  setActiveProfile: (profile: string) => void
  createDialogOpen: boolean
  setCreateDialogOpen: (open: boolean) => void
}

const ProfileContext = createContext<ProfileContextValue | null>(null)

function readSavedProfile(): string | null {
  try {
    return sessionStorage.getItem(LAST_PROFILE_KEY)
  } catch {
    return null
  }
}

function writeSavedProfile(profile: string) {
  try {
    sessionStorage.setItem(LAST_PROFILE_KEY, profile)
  } catch {
    // Ignore storage failures
  }
}

export function ProfileProvider({
  requestedProfile,
  children,
}: {
  requestedProfile?: string
  children: ReactNode
}) {
  const { session } = useAuth()
  const profiles = session?.context.profiles ?? []
  const providers = session?.context.providers ?? []
  const sharedSecrets = session?.context.shared_secrets ?? []
  const profileNames = useMemo(() => profiles.map((p) => p.name), [profiles])

  const defaultProfileName = useMemo(() => {
    if (profileNames.includes("default")) return "default"
    return profileNames[0] ?? ""
  }, [profileNames])

  const [createDialogOpen, setCreateDialogOpen] = useState(false)
  const [selected, setSelected] = useState<string>(() => {
    if (requestedProfile && profileNames.includes(requestedProfile)) {
      return requestedProfile
    }
    const saved = readSavedProfile()
    if (saved && profileNames.includes(saved)) return saved
    return defaultProfileName
  })

  useEffect(() => {
    if (requestedProfile && profileNames.includes(requestedProfile)) {
      setSelected(requestedProfile)
      writeSavedProfile(requestedProfile)
    }
  }, [requestedProfile, profileNames])

  const activeProfile = useMemo(() => {
    if (selected && profileNames.includes(selected)) return selected
    return defaultProfileName
  }, [selected, profileNames, defaultProfileName])

  const setActiveProfile = useCallback((next: string) => {
    setSelected(next)
    writeSavedProfile(next)
  }, [])

  const activeProfileMeta = useMemo(
    () => profiles.find((p) => p.name === activeProfile) ?? null,
    [profiles, activeProfile]
  )

  const canIssueKeys = Boolean(activeProfileMeta?.can_issue_keys)

  const value = useMemo<ProfileContextValue>(
    () => ({
      profiles,
      profileNames,
      providers,
      sharedSecrets,
      activeProfile,
      activeProfileMeta,
      canIssueKeys,
      setActiveProfile,
      createDialogOpen,
      setCreateDialogOpen,
    }),
    [
      profiles,
      profileNames,
      providers,
      sharedSecrets,
      activeProfile,
      activeProfileMeta,
      canIssueKeys,
      setActiveProfile,
      createDialogOpen,
      setCreateDialogOpen,
    ]
  )

  return (
    <ProfileContext.Provider value={value}>{children}</ProfileContext.Provider>
  )
}

export function useActiveProfile(): ProfileContextValue {
  const ctx = useContext(ProfileContext)
  if (!ctx) {
    throw new Error("useActiveProfile must be used within a ProfileProvider")
  }
  return ctx
}

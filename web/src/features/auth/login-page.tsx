import { ArrowRight, CircleAlert, LogIn } from "lucide-react"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { BrandMark } from "@/components/layout/brand-mark"
import { LocaleToggle } from "@/components/layout/locale-toggle"
import { ThemeToggle } from "@/components/layout/theme-toggle"
import { useGatewayHealth } from "@/hooks/use-console-queries"
import { useAuth } from "@/lib/auth"
import { useI18n, type MessageKey } from "@/lib/i18n"

const OIDC_ERROR_KEYS: Record<string, MessageKey> = {
  oidc_access_denied: "login.err.oidc_access_denied",
  oidc_not_configured: "login.err.oidc_not_configured",
  oidc_provider_unreachable: "login.err.oidc_provider_unreachable",
  oidc_expired: "login.err.oidc_expired",
  oidc_invalid_session: "login.err.oidc_invalid_session",
  oidc_verification_failed: "login.err.oidc_verification_failed",
  oidc_failed: "login.err.oidc_failed",
}

export function LoginPage() {
  const { sessionExpired, authConfig, oidcErrorCode } = useAuth()
  const { data: health } = useGatewayHealth()
  const { t } = useI18n()

  const bannerError = oidcErrorCode
    ? t(OIDC_ERROR_KEYS[oidcErrorCode] ?? "login.err.oidc_failed")
    : sessionExpired
      ? t("login.sessionExpired")
      : health && !health.ok
        ? t("login.controlPlaneUnavailable")
        : ""

  return (
    <div className="flex min-h-svh flex-col bg-muted/30">
      <header className="flex items-center justify-end gap-1.5 p-5">
        <LocaleToggle />
        <ThemeToggle />
      </header>

      <main className="flex flex-1 items-center justify-center px-5 pb-16">
        <div className="w-full max-w-[380px] space-y-6">
          <div className="flex justify-center">
            <BrandMark showSubtitle={false} />
          </div>

          <Card className="shadow-xs">
            <CardHeader className="space-y-1 text-center">
              <CardTitle
                role="heading"
                aria-level={1}
                className="text-xl tracking-tight"
              >
                {t("login.title")}
              </CardTitle>
              <CardDescription>{t("login.description")}</CardDescription>
            </CardHeader>

            <CardContent className="space-y-4">
              {bannerError && (
                <Alert variant="destructive" role="alert">
                  <CircleAlert />
                  <AlertDescription className="break-all">
                    {bannerError}
                  </AlertDescription>
                </Alert>
              )}

              {authConfig.oidc_enabled ? (
                <Button size="lg" className="w-full" asChild>
                  <a href="/v1/console/auth/oidc/start">
                    <LogIn />
                    <span>{t("login.oidcButton")}</span>
                    <ArrowRight className="ml-auto" />
                  </a>
                </Button>
              ) : (
                <>
                  <Alert variant="destructive">
                    <CircleAlert />
                    <AlertTitle>{t("login.oidcDisabledTitle")}</AlertTitle>
                    <AlertDescription>
                      {t("login.oidcDisabledDescBefore")}{" "}
                      <code className="rounded bg-muted px-1 py-0.5 font-mono text-[11px] text-foreground">
                        [oidc]
                      </code>{" "}
                      {t("login.oidcDisabledDescMid")}{" "}
                      <code className="rounded bg-muted px-1 py-0.5 font-mono text-[11px] text-foreground">
                        deploy/dev/
                      </code>{" "}
                      {t("login.oidcDisabledDescAfter")}
                    </AlertDescription>
                  </Alert>
                  <Button size="lg" className="w-full" disabled>
                    <LogIn />
                    <span>{t("login.oidcButton")}</span>
                  </Button>
                </>
              )}
            </CardContent>
          </Card>
        </div>
      </main>
    </div>
  )
}

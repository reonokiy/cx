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
import { ThemeToggle } from "@/components/layout/theme-toggle"
import { useGatewayHealth } from "@/hooks/use-console-queries"
import { useAuth } from "@/lib/auth"

const OIDC_ERROR_MESSAGES: Record<string, string> = {
  oidc_access_denied: "你已取消登录授权，或身份提供方拒绝了访问。",
  oidc_not_configured: "服务端尚未启用 OIDC 配置，请联系管理员。",
  oidc_provider_unreachable: "无法连接身份提供方，请稍后重试。",
  oidc_expired: "登录会话已超时或失效，请重新登录。",
  oidc_invalid_session: "登录状态校验失败，请重新发起登录。",
  oidc_verification_failed: "身份令牌校验失败，请联系管理员。",
  oidc_failed: "登录未完成，请重试。",
}

export function LoginPage() {
  const { sessionExpired, authConfig, oidcErrorCode } = useAuth()
  const { data: health } = useGatewayHealth()

  const bannerError = oidcErrorCode
    ? (OIDC_ERROR_MESSAGES[oidcErrorCode] ?? OIDC_ERROR_MESSAGES.oidc_failed)
    : sessionExpired
      ? "登录会话已失效，请重新登录。"
      : health && !health.ok
        ? "当前无法连接网关控制面，请稍后重试。"
        : ""

  return (
    <div className="flex min-h-svh flex-col bg-muted/30">
      <header className="flex items-center justify-end p-5">
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
                登录控制台
              </CardTitle>
              <CardDescription>
                使用组织 OIDC 账号继续访问 CX Gateway
              </CardDescription>
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
                    <span>使用 OIDC 单点登录</span>
                    <ArrowRight className="ml-auto" />
                  </a>
                </Button>
              ) : (
                <>
                  <Alert variant="destructive">
                    <CircleAlert />
                    <AlertTitle>服务端尚未启用 OIDC</AlertTitle>
                    <AlertDescription>
                      请在服务端配置{" "}
                      <code className="rounded bg-muted px-1 py-0.5 font-mono text-[11px] text-foreground">
                        [oidc]
                      </code>
                      ，本地开发可使用{" "}
                      <code className="rounded bg-muted px-1 py-0.5 font-mono text-[11px] text-foreground">
                        deploy/dev/
                      </code>{" "}
                      中的 Dex 配置。
                    </AlertDescription>
                  </Alert>
                  <Button size="lg" className="w-full" disabled>
                    <LogIn />
                    <span>使用 OIDC 单点登录</span>
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

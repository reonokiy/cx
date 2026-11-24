<img src="assets/icon.svg" width="64" height="64" alt="">

# cx

Secretless CLI credential-injecting proxy for Linux (`Rootless NetNS` + `smoltcp` + `QUIC` + `OIDC` + `PostgreSQL`).

Clients never see real upstream secrets—`cx` runs target CLIs (e.g. `gh`, `curl`, `git`) inside an unprivileged user/network/mount namespace with placeholder virtual keys, transparently intercepts matching HTTPS traffic via Fake-IP DNS + TLS SNI verification, and forwards it over an authenticated QUIC tunnel to `cx-server`, which enforces RBAC/L7 policy and injects the real secret server-side.

## Client Installation (`mise`)

### 1. From GitHub Releases (Recommended)

Once a tag (`v*`) is published by GitHub Actions:

```bash
# Latest stable release
mise use -g github:reonokiy/cx@latest

# Or pin a prerelease (e.g. v0.1.0-alpha.1)
# In ~/.config/mise/config.toml:
# "github:reonokiy/cx" = { version = "0.1.0-alpha.1", prerelease = "true" }
```

### 2. Local Source Build via `mise` (Before Releasing / Local Dev)

```bash
# Build release `cx` and register into mise as `http:cx@local` (zero-network local link)
mise run install-local

# Or register AND activate globally right away (`mise use -g http:cx@local`)
mise run install-local-global
```

Once you publish a GitHub Release, switch seamlessly to the GitHub backend:

```bash
mise unuse -g http:cx && mise use -g github:reonokiy/cx@latest
```

Verify your Linux Rootless NetNS environment:

```bash
cx --version
cx doctor
```

## Web 控制台

启动服务器后，访问 HTTP 控制面的 `/ui/`，例如 `http://127.0.0.1:8080/ui/`。通过反向代理对外部署时，使用 HTTPS。

- **OIDC 单点登录**：Web 控制台仅通过 **OIDC** 登录（复用 `{external_url}/v1/auth/oidc/callback` 回调地址，使用 PKCE S256、防登录 CSRF 事务 Cookie 及 `HttpOnly; SameSite=Lax` 会话 Cookie 鉴权，退出时在服务端吊销会话令牌）。
- **本地开发（内置 Dex）**：仓库提供开箱即用且可自定义的本地 Dex + PostgreSQL 开发配置（[`deploy/dev/`](deploy/dev/)），默认预置管理员 `admin@example.com`（`cx-admins`, `eng`）与普通成员 `dev@example.com`（`eng`），密码均为 `password`：
  ```bash
  mise run dev-server
  # 停止本地依赖容器：mise run dev-down
  ```
- **多平台 Profile 工作区（全量持久化到 PostgreSQL）**：在左上角切换或新建 `Profile`，每个 Profile 可同时挂载多个上游平台（具名平台如 `github` / `openai` 每 Profile 最多挂载一次；`generic-http` 可按不同标识添加多个自定义 HTTP 服务）。服务端在运行时严格按域名隔离各平台的虚拟密钥、访问策略与上游凭据。
- **平台与规则**：按平台独立管理策略预设（支持展开预览预设内置规则）、自定义 HTTP 允许/拒绝规则、策略模拟器、域名收窄，以及共享/个人加密凭据（后端返回配置状态但绝不回显明文；个人凭据默认按平台跨 Profile 复用）。修改保存后当前实例立即热生效。
- **审计日志**：自动限定到当前 Profile，支持按平台、允许或拒绝判定筛选、搜索主机/路径/用户/会话，并支持详情抽屉反查、会话吊销与 CSV/JSON 导出。普通用户查看自己的记录，管理员可查看全部记录。
- **设置与令牌**：支持管理员修改当前 Profile 的 OIDC 访问权限组、兜底出网策略与删除 Profile，以及按需为指定平台签发静态虚拟密钥或限定范围的个人访问令牌（`cx_pat_`）。

Docker 镜像会打包控制台。本地运行 Rust 服务时，先在仓库根目录构建前端资源。

```bash
npm --prefix web ci
npm --prefix web run build
```

服务默认从当前目录下的 `web/dist` 读取资源，也可通过 `CX_WEB_DIR` 指定。开发时可运行 `npm --prefix web run dev`，Vite 会把 API 请求转发到 `http://127.0.0.1:8080`，也可通过 `CX_API_ORIGIN` 修改目标。

## Server Deployment (Docker / GHCR)

Multi-arch images (`linux/amd64`, `linux/arm64`) are published to GHCR on every `v*` release:

```bash
docker pull ghcr.io/reonokiy/cx-server:latest
```

Or build locally:

```bash
# Fast local build (uses host Rust + debian:bookworm-slim, ~145MB)
mise run docker-build

# Or self-contained multi-stage Docker build (no host Rust required)
mise run docker-build-full
```

See [deploy/docker-compose.example.yml](deploy/docker-compose.example.yml), [deploy/server.docker.toml.example](deploy/server.docker.toml.example), and [deploy/nginx.conf.example](deploy/nginx.conf.example) for a complete PostgreSQL 17 + `cx-server` setup.

## Release Workflow

Push a semantic version tag to trigger [`.github/workflows/release.yml`](.github/workflows/release.yml):

```bash
git tag v0.1.0-alpha.1
git push origin v0.1.0-alpha.1
```

This automatically:
1. Builds native `x86_64-unknown-linux-gnu` and `aarch64-unknown-linux-gnu` CLI archives (`cx-<tag>-<target>.tar.gz` + `.sha256` + `SHA256SUMS.txt`) with build provenance attestations and publishes a GitHub Release ready for `mise use -g github:reonokiy/cx`.
2. Builds native `linux/amd64` and `linux/arm64` `cx-server` container images and publishes a multi-arch manifest to `ghcr.io/reonokiy/cx-server`.

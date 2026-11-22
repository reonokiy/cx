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

# Multi-stage build for cx-server (HTTP Control Plane + QUIC Data Plane)
ARG RUST_VERSION=1-slim-bookworm

FROM node:24-slim AS web-builder
WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM rust:${RUST_VERSION} AS builder

# `ring` compiles small C/asm primitives; no OpenSSL or libpq headers required
RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy workspace manifests, crates, migrations, and built-in provider manifests
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY providers ./providers

# Build only the server binary (release profile enables thin LTO + symbol stripping)
RUN cargo build --release --locked --bin cx-server

FROM debian:bookworm-slim AS runtime

ARG APP_VERSION=0.1.0
ARG GIT_SHA=unknown

LABEL org.opencontainers.image.title="cx-server" \
      org.opencontainers.image.description="Secretless CLI credential-injecting gateway server (HTTP control plane + QUIC data plane)" \
      org.opencontainers.image.source="https://github.com/reonokiy/cx" \
      org.opencontainers.image.version="${APP_VERSION}" \
      org.opencontainers.image.revision="${GIT_SHA}"

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates tzdata \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 --system cx \
    && useradd --uid 10001 --gid 10001 --system --home-dir /etc/cx --shell /usr/sbin/nologin cx \
    && mkdir -p /etc/cx/providers /etc/cx/profiles /etc/cx/certs /usr/share/cx/providers \
    && chown -R cx:cx /etc/cx

COPY --from=builder /app/target/release/cx-server /usr/local/bin/cx-server
COPY providers/ /usr/share/cx/providers/
COPY --from=web-builder /web/dist /usr/share/cx/web
ENV CX_WEB_DIR=/usr/share/cx/web

USER cx
WORKDIR /etc/cx

# 8080/tcp: HTTP Control Plane (behind L7 reverse proxy)
# 8443/udp: Native QUIC Data Plane (L4 UDP proxy or direct exposure)
EXPOSE 8080/tcp
EXPOSE 8443/udp

HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
    CMD ["cx-server", "healthcheck", "--url", "http://127.0.0.1:8080/healthz"]

ENTRYPOINT ["cx-server"]
CMD ["serve", "-c", "/etc/cx/server.toml"]

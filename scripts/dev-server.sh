#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

export CX_POSTGRES_PASSWORD="${CX_POSTGRES_PASSWORD:-cxdevpass}"
export CX_OIDC_CLIENT_SECRET="${CX_OIDC_CLIENT_SECRET:-cx-dev-oidc-secret}"

DEV_DIR="${ROOT_DIR}/.cx-dev"
CERT_DIR="${DEV_DIR}/certs"
MASTER_KEY_FILE="${DEV_DIR}/master.key"

mkdir -p "$CERT_DIR"

if [[ ! -f "${CERT_DIR}/quic-cert.pem" || ! -f "${CERT_DIR}/quic-key.pem" ]]; then
  echo "Generating local dev QUIC TLS certificate under ${CERT_DIR}..."
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout "${CERT_DIR}/quic-key.pem" \
    -out "${CERT_DIR}/quic-cert.pem" \
    -days 365 -nodes \
    -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
    >/dev/null 2>&1
fi

if [[ -z "${CX_MASTER_KEY:-}" ]]; then
  if [[ ! -f "$MASTER_KEY_FILE" ]]; then
    openssl rand -base64 32 > "$MASTER_KEY_FILE"
    chmod 600 "$MASTER_KEY_FILE"
  fi
  export CX_MASTER_KEY="$(cat "$MASTER_KEY_FILE")"
fi

wait_for_dex() {
  local url="http://127.0.0.1:${CX_DEV_DEX_PORT:-5556}/dex/.well-known/openid-configuration"
  for _ in $(seq 1 30); do
    if curl -fsS "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "ERROR: Dex OIDC provider did not become ready at ${url}" >&2
  return 1
}

if [[ "${1:-}" == "--deps-only" ]]; then
  docker compose -f deploy/dev/docker-compose.yml up -d --wait
  wait_for_dex
  echo "Dev dependencies ready:"
  echo "  PostgreSQL: 127.0.0.1:${CX_DEV_PG_PORT:-5432} (db=cx, user=cx)"
  echo "  Dex OIDC:   http://127.0.0.1:${CX_DEV_DEX_PORT:-5556}/dex"
  echo "  Dev users:  admin@example.com / dev@example.com (password: password)"
  exit 0
fi

docker compose -f deploy/dev/docker-compose.yml up -d --wait
wait_for_dex

if [[ ! -f "${ROOT_DIR}/web/dist/index.html" ]]; then
  echo "Building web console assets..."
  npm --prefix web ci
  npm --prefix web run build
fi

if ! command -v cargo >/dev/null 2>&1 && [[ -x "${HOME}/.cargo/bin/cargo" ]]; then
  export PATH="${HOME}/.cargo/bin:${PATH}"
fi

echo "Starting cx-server with Dex OIDC dev config..."
echo "  Console UI: http://127.0.0.1:8080/ui/"
echo "  Dex OIDC:   http://127.0.0.1:${CX_DEV_DEX_PORT:-5556}/dex"
echo "  Dev users:  admin@example.com (cx-admins, eng) / dev@example.com (eng) | password: password"

exec cargo run --bin cx-server -- serve -c deploy/dev/server.dev.toml --seed-dev

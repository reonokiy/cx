#!/usr/bin/env bash
set -euo pipefail

# Build the `cx-server` container image locally.
# Default mode (`--fast`): builds `cx-server` using the host Rust toolchain and packages it
# directly into `debian:bookworm-slim` (no 300MB+ rust Docker builder pull needed).
# Full mode (`--multi-stage`): runs the self-contained multi-stage root `Dockerfile`.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if ! (cargo --version >/dev/null 2>&1 && rustc --version >/dev/null 2>&1); then
  if [[ -x "${HOME}/.cargo/bin/cargo" ]]; then
    export PATH="${HOME}/.cargo/bin:${PATH}"
  fi
fi

MODE="fast"
TAG_LOCAL="cx-server:local"
TAG_GHCR="ghcr.io/reonokiy/cx-server:local"
SKIP_BUILD=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --multi-stage)
      MODE="multi-stage"
      shift
      ;;
    --fast)
      MODE="fast"
      shift
      ;;
    --skip-build)
      SKIP_BUILD=1
      shift
      ;;
    --tag)
      TAG_LOCAL="$2"
      shift 2
      ;;
    -h|--help)
      echo "Usage: $0 [--fast|--multi-stage] [--skip-build] [--tag cx-server:local]"
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

PKG_VERSION="$(awk -F'"' '/^\[workspace\.package\]/{in_pkg=1} in_pkg && /^version[[:space:]]*=/{print $2; exit}' Cargo.toml)"
GIT_SHA="$(git rev-parse --short HEAD 2>/dev/null || echo dev)"

if [[ "$MODE" == "multi-stage" ]]; then
  docker build \
    --build-arg "APP_VERSION=${PKG_VERSION}" \
    --build-arg "GIT_SHA=${GIT_SHA}" \
    -t "$TAG_LOCAL" \
    -t "$TAG_GHCR" \
    .
  exit 0
fi

if [[ "$SKIP_BUILD" -eq 0 ]]; then
  echo "Building cx-server (release) on host..."
  cargo build --release --locked --bin cx-server
fi

BIN_PATH="${ROOT_DIR}/target/release/cx-server"
if [[ ! -x "$BIN_PATH" ]]; then
  echo "ERROR: release binary not found: $BIN_PATH" >&2
  exit 1
fi

CTX_DIR="$(mktemp -d)"
trap 'rm -rf "$CTX_DIR"' EXIT

install -m 0755 "$BIN_PATH" "${CTX_DIR}/cx-server"
cp -r "${ROOT_DIR}/providers" "${CTX_DIR}/providers"
cp "${ROOT_DIR}/deploy/Dockerfile.prebuilt" "${CTX_DIR}/Dockerfile"

docker build \
  --build-arg "APP_VERSION=${PKG_VERSION}" \
  --build-arg "GIT_SHA=${GIT_SHA}" \
  -t "$TAG_LOCAL" \
  -t "$TAG_GHCR" \
  "$CTX_DIR"

docker image ls --format 'table {{.Repository}}\t{{.Tag}}\t{{.Size}}' "$TAG_LOCAL"

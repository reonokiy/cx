#!/usr/bin/env bash
set -euo pipefail

# Build `cx` locally and register it into `mise` via `mise link` (zero-network `http:cx@local`).
# Switch to official GitHub Releases anytime once a `v*` tag is published:
#   Local:   mise use -g http:cx@local
#   Release: mise unuse -g http:cx && mise use -g github:reonokiy/cx@latest

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if ! (cargo --version >/dev/null 2>&1 && rustc --version >/dev/null 2>&1); then
  if [[ -x "${HOME}/.cargo/bin/cargo" ]]; then
    export PATH="${HOME}/.cargo/bin:${PATH}"
  fi
fi

if ! command -v mise >/dev/null 2>&1; then
  echo "ERROR: 'mise' not found in PATH. Install mise first: https://mise.jdx.dev" >&2
  exit 1
fi

USE_GLOBAL=0
SKIP_BUILD=0
VERSION_TAG="local"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --global|-g)
      USE_GLOBAL=1
      shift
      ;;
    --skip-build)
      SKIP_BUILD=1
      shift
      ;;
    --version-tag)
      VERSION_TAG="$2"
      shift 2
      ;;
    -h|--help)
      echo "Usage: $0 [--global|-g] [--skip-build] [--version-tag local]"
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

PKG_VERSION="$(awk -F'"' '/^\[workspace\.package\]/{in_pkg=1} in_pkg && /^version[[:space:]]*=/{print $2; exit}' Cargo.toml)"
TOOL_REF="http:cx@${VERSION_TAG}"

if [[ "$SKIP_BUILD" -eq 0 ]]; then
  echo "Building cx (release)..."
  cargo build --release --locked --bin cx
fi

BIN_PATH="${ROOT_DIR}/target/release/cx"
if [[ ! -x "$BIN_PATH" ]]; then
  echo "ERROR: release binary not found: $BIN_PATH" >&2
  exit 1
fi

DATA_HOME="${XDG_DATA_HOME:-${HOME}/.local/share}"
INSTALL_DIR="${DATA_HOME}/cx/mise-local/${VERSION_TAG}"
mkdir -p "$INSTALL_DIR"

# Install atomically so replacing a running binary never fails with ETXTBSY
TMP_BIN="${INSTALL_DIR}/.cx.tmp.$$"
install -m 0755 "$BIN_PATH" "$TMP_BIN"
mv -f "$TMP_BIN" "${INSTALL_DIR}/cx"

COMMIT_SHA="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
HOST_TARGET="$(rustc -vV | awk '/^host:/{print $2}')"
RUSTC_VER="$(rustc --version)"
cat > "${INSTALL_DIR}/release.json" <<EOF
{
  "name": "cx",
  "version": "${PKG_VERSION}-${VERSION_TAG}",
  "commit": "${COMMIT_SHA}",
  "compiler": "${RUSTC_VER}",
  "artifact": "${HOST_TARGET}",
  "source": "local"
}
EOF

mise link -f "$TOOL_REF" "$INSTALL_DIR"

echo ""
echo "Linked local cx into mise:"
echo "  Tool: ${TOOL_REF}"
echo "  Path: ${INSTALL_DIR}/cx"

if [[ "$USE_GLOBAL" -eq 1 ]]; then
  mise use -g "$TOOL_REF"
  echo "Activated globally in ~/.config/mise/config.toml!"
  echo "Verify with: cx --version && cx doctor"
else
  echo ""
  echo "To activate globally:"
  echo "  mise use -g ${TOOL_REF}"
  echo "Or test once without modifying global config:"
  echo "  mise exec ${TOOL_REF} -- cx --version"
fi

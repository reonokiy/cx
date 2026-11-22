#!/usr/bin/env bash
set -euo pipefail

# Build and package `cx` CLI release archive compatible with `mise` (`github:reonokiy/cx`).
# Archive layout:
#   cx-<tag>-<target>.tar.gz
#   └── cx-<tag>-<target>/
#       ├── cx
#       ├── release.json
#       └── README.md

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

if ! (cargo --version >/dev/null 2>&1 && rustc --version >/dev/null 2>&1); then
  if [[ -x "${HOME}/.cargo/bin/cargo" ]]; then
    export PATH="${HOME}/.cargo/bin:${PATH}"
  fi
fi

TAG=""
TARGET=""
OUT_DIR="${ROOT_DIR}/dist"
PREBUILT_BIN=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tag)
      TAG="$2"
      shift 2
      ;;
    --target)
      TARGET="$2"
      shift 2
      ;;
    --out-dir)
      OUT_DIR="$2"
      shift 2
      ;;
    --bin)
      PREBUILT_BIN="$2"
      shift 2
      ;;
    -h|--help)
      echo "Usage: $0 [--tag v0.1.0] [--target x86_64-unknown-linux-gnu] [--out-dir dist] [--bin path/to/cx]"
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

PKG_VERSION="$(awk -F'"' '/^\[workspace\.package\]/{in_pkg=1} in_pkg && /^version[[:space:]]*=/{print $2; exit}' Cargo.toml)"
if [[ -z "$TAG" ]]; then
  TAG="v${PKG_VERSION}"
fi
VERSION="${TAG#v}"

HOST_TARGET="$(rustc -vV | awk '/^host:/{print $2}')"
if [[ -z "$TARGET" ]]; then
  TARGET="$HOST_TARGET"
fi

if [[ -n "$PREBUILT_BIN" ]]; then
  BIN_PATH="$PREBUILT_BIN"
else
  if [[ "$TARGET" == "$HOST_TARGET" ]]; then
    cargo build --release --locked --bin cx
    BIN_PATH="${ROOT_DIR}/target/release/cx"
  else
    cargo build --release --locked --target "$TARGET" --bin cx
    BIN_PATH="${ROOT_DIR}/target/${TARGET}/release/cx"
  fi
fi

if [[ ! -x "$BIN_PATH" ]]; then
  echo "ERROR: built binary not found or not executable: $BIN_PATH" >&2
  exit 1
fi

ARCHIVE_STEM="cx-${TAG}-${TARGET}"
STAGE_PARENT="$(mktemp -d)"
trap 'rm -rf "$STAGE_PARENT"' EXIT
STAGE_DIR="${STAGE_PARENT}/${ARCHIVE_STEM}"
mkdir -p "$STAGE_DIR" "$OUT_DIR"

install -m 0755 "$BIN_PATH" "${STAGE_DIR}/cx"
if [[ -f "${ROOT_DIR}/README.md" ]]; then
  cp "${ROOT_DIR}/README.md" "${STAGE_DIR}/README.md"
fi

COMMIT_SHA="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
RUSTC_VER="$(rustc --version)"
cat > "${STAGE_DIR}/release.json" <<EOF
{
  "name": "cx",
  "version": "${VERSION}",
  "tag": "${TAG}",
  "commit": "${COMMIT_SHA}",
  "compiler": "${RUSTC_VER}",
  "artifact": "${TARGET}"
}
EOF

ARCHIVE_NAME="${ARCHIVE_STEM}.tar.gz"
ARCHIVE_PATH="${OUT_DIR}/${ARCHIVE_NAME}"
tar -C "$STAGE_PARENT" -czf "$ARCHIVE_PATH" "$ARCHIVE_STEM"

(
  cd "$OUT_DIR"
  sha256sum "$ARCHIVE_NAME" > "${ARCHIVE_NAME}.sha256"
)

echo "Packaged: ${ARCHIVE_PATH}"
cat "${ARCHIVE_PATH}.sha256"

#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

for cmd in cargo node npm; do
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    echo "Missing required command: ${cmd}" >&2
    exit 1
  fi
done

detect_platform() {
  local os arch
  os="$(uname -s)"
  arch="$(uname -m)"

  case "${os}" in
    Linux)
      case "${arch}" in
        x86_64)
          TARGET_TRIPLE_DEFAULT="x86_64-unknown-linux-gnu"
          PLATFORM_PACKAGE_DEFAULT="corgea-cli-linux-x64"
          BINARY_NAME_DEFAULT="corgea"
          ;;
        aarch64|arm64)
          TARGET_TRIPLE_DEFAULT="aarch64-unknown-linux-gnu"
          PLATFORM_PACKAGE_DEFAULT="corgea-cli-linux-arm64"
          BINARY_NAME_DEFAULT="corgea"
          ;;
        *)
          echo "Unsupported Linux architecture: ${arch}" >&2
          exit 1
          ;;
      esac
      ;;
    Darwin)
      case "${arch}" in
        x86_64)
          TARGET_TRIPLE_DEFAULT="x86_64-apple-darwin"
          PLATFORM_PACKAGE_DEFAULT="corgea-cli-darwin-x64"
          BINARY_NAME_DEFAULT="corgea"
          ;;
        arm64)
          TARGET_TRIPLE_DEFAULT="aarch64-apple-darwin"
          PLATFORM_PACKAGE_DEFAULT="corgea-cli-darwin-arm64"
          BINARY_NAME_DEFAULT="corgea"
          ;;
        *)
          echo "Unsupported macOS architecture: ${arch}" >&2
          exit 1
          ;;
      esac
      ;;
    MINGW*|MSYS*|CYGWIN*)
      TARGET_TRIPLE_DEFAULT="x86_64-pc-windows-msvc"
      PLATFORM_PACKAGE_DEFAULT="corgea-cli-win32-x64"
      BINARY_NAME_DEFAULT="corgea.exe"
      ;;
    *)
      echo "Unsupported OS: ${os}" >&2
      exit 1
      ;;
  esac
}

detect_platform

TARGET_TRIPLE="${TARGET_TRIPLE:-${TARGET_TRIPLE_DEFAULT}}"
PLATFORM_PACKAGE="${PLATFORM_PACKAGE:-${PLATFORM_PACKAGE_DEFAULT}}"
BINARY_NAME="${BINARY_NAME:-${BINARY_NAME_DEFAULT}}"
PLATFORM_PACKAGE_DIR="packages/${PLATFORM_PACKAGE}"
VERSION="$(node -p "require('./package.json').version")"

if [[ ! -d "${PLATFORM_PACKAGE_DIR}" ]]; then
  echo "Missing platform package directory: ${PLATFORM_PACKAGE_DIR}" >&2
  exit 1
fi

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/corgea-npm-local-test.XXXXXX")"
NPM_CACHE_DIR="${TMP_DIR}/npm-cache"
TEST_PREFIX="${TEST_PREFIX:-${TMP_DIR}/npm-global}"
KEEP_TMP="${KEEP_TMP:-0}"

cleanup() {
  if [[ "${KEEP_TMP}" == "1" ]]; then
    echo "Keeping temp directory: ${TMP_DIR}"
    return
  fi
  rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

echo "Testing local npm install flow"
echo "  version:           ${VERSION}"
echo "  target triple:     ${TARGET_TRIPLE}"
echo "  platform package:  ${PLATFORM_PACKAGE}"
echo "  binary:            ${BINARY_NAME}"
echo "  test prefix:       ${TEST_PREFIX}"

echo "1/6 Building native binary..."
cargo build --release --target "${TARGET_TRIPLE}"

echo "2/6 Staging platform package..."
node scripts/npm/prepare-platform-package.js \
  "${PLATFORM_PACKAGE_DIR}" \
  "${TARGET_TRIPLE}" \
  "${BINARY_NAME}" \
  "${VERSION}"

echo "3/6 Packing platform package..."
(
  cd "${PLATFORM_PACKAGE_DIR}"
  NPM_CONFIG_CACHE="${NPM_CACHE_DIR}" npm pack --pack-destination "${TMP_DIR}" >/dev/null
)
PLATFORM_TARBALL="${TMP_DIR}/${PLATFORM_PACKAGE}-${VERSION}.tgz"

echo "4/6 Packing main package..."
NPM_CONFIG_CACHE="${NPM_CACHE_DIR}" npm pack --pack-destination "${TMP_DIR}" >/dev/null
MAIN_TARBALL="${TMP_DIR}/corgea-cli-${VERSION}.tgz"

if [[ ! -f "${PLATFORM_TARBALL}" ]]; then
  echo "Expected tarball not found: ${PLATFORM_TARBALL}" >&2
  exit 1
fi

if [[ ! -f "${MAIN_TARBALL}" ]]; then
  echo "Expected tarball not found: ${MAIN_TARBALL}" >&2
  exit 1
fi

echo "5/6 Installing tarballs into isolated prefix..."
mkdir -p "${TEST_PREFIX}"
NPM_CONFIG_CACHE="${NPM_CACHE_DIR}" npm install -g --prefix "${TEST_PREFIX}" --offline "${PLATFORM_TARBALL}" >/dev/null
# The platform package is installed explicitly above, so omit optional deps
# here to avoid unnecessary registry lookups during local/offline testing.
NPM_CONFIG_CACHE="${NPM_CACHE_DIR}" npm install -g --prefix "${TEST_PREFIX}" --offline --omit=optional "${MAIN_TARBALL}" >/dev/null

echo "6/6 Running corgea --version..."
CLI_PATH_UNIX="${TEST_PREFIX}/bin/corgea"
CLI_PATH_WIN="${TEST_PREFIX}/corgea.cmd"

if [[ -x "${CLI_PATH_UNIX}" ]]; then
  "${CLI_PATH_UNIX}" --version
elif [[ -f "${CLI_PATH_WIN}" ]]; then
  "${CLI_PATH_WIN}" --version
else
  echo "Could not find installed CLI entrypoint under ${TEST_PREFIX}" >&2
  exit 1
fi

echo
echo "Local npm package test passed."

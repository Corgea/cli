#!/usr/bin/env bash
# Publishes @corgea/cli with the correct dist-tag + safety guards.
# Env: PACKAGE_VERSION (e.g. 1.10.0-beta.1 | 1.10.0); DRY_RUN (true => --dry-run);
#      RESOLVE_ONLY (true => print decision and exit, no npm calls).
set -euo pipefail
PKG="@corgea/cli"
VERSION="${PACKAGE_VERSION:?PACKAGE_VERSION is required}"

if [[ "$VERSION" == *-* ]]; then DIST_TAG="beta"; PRE=1; else DIST_TAG="latest"; PRE=0; fi
# Safety: never cross the streams.
if [[ "$PRE" -eq 1 && "$DIST_TAG" == "latest" ]]; then echo "REFUSING: pre-release $VERSION -> latest" >&2; exit 1; fi
if [[ "$PRE" -eq 0 && "$DIST_TAG" == "beta"   ]]; then echo "REFUSING: final $VERSION -> beta" >&2; exit 1; fi
echo "version=$VERSION dist-tag=$DIST_TAG dry_run=${DRY_RUN:-false}"
[[ "${RESOLVE_ONLY:-false}" == "true" ]] && exit 0

# Idempotency: query the CORRECT scoped package at the exact version.
if npm view "${PKG}@${VERSION}" version >/dev/null 2>&1; then
  echo "${PKG}@${VERSION} already exists on npm, skipping."; exit 0
fi
ARGS=(publish --access public --tag "$DIST_TAG")
[[ "${DRY_RUN:-false}" == "true" ]] && ARGS+=(--dry-run)
npm "${ARGS[@]}"

#!/usr/bin/env bash
# Publishes @corgea/cli with the correct dist-tag + safety guards.
# Env: PACKAGE_VERSION (e.g. 1.10.0-beta.1 | 1.10.0); DRY_RUN (true => --dry-run);
#      RESOLVE_ONLY (true => print decision and exit, no npm calls).
set -euo pipefail
PKG="@corgea/cli"
VERSION="${PACKAGE_VERSION:?PACKAGE_VERSION is required}"
DRY_RUN="${DRY_RUN:-false}"

if [[ "$VERSION" == *-* ]]; then DIST_TAG="beta"; PRE=1; else DIST_TAG="latest"; PRE=0; fi
# Safety: never cross the streams.
if [[ "$PRE" -eq 1 && "$DIST_TAG" == "latest" ]]; then echo "REFUSING: pre-release $VERSION -> latest" >&2; exit 1; fi
if [[ "$PRE" -eq 0 && "$DIST_TAG" == "beta"   ]]; then echo "REFUSING: final $VERSION -> beta" >&2; exit 1; fi
echo "version=$VERSION dist-tag=$DIST_TAG dry_run=$DRY_RUN"
[[ "${RESOLVE_ONLY:-false}" == "true" ]] && exit 0

# Idempotency: if the exact version is already on npm, skip re-publishing — but
# still fall through to the dist-tag verification below, so dist-tag drift is
# caught instead of masked by an early exit. (The whole check is skipped under
# DRY_RUN so a rehearsal always exercises the real publish path.)
already=0
if [[ "$DRY_RUN" != "true" ]] && npm view "${PKG}@${VERSION}" version >/dev/null 2>&1; then
  echo "${PKG}@${VERSION} already on npm; skipping publish, verifying dist-tag."
  already=1
fi
if [[ "$already" -eq 0 ]]; then
  ARGS=(publish --access public --tag "$DIST_TAG")
  [[ "$DRY_RUN" == "true" ]] && ARGS+=(--dry-run)
  npm "${ARGS[@]}"
fi

# A dry-run writes nothing to verify.
[[ "$DRY_RUN" == "true" ]] && { echo "dry-run complete (nothing published)."; exit 0; }

# Post-publish gate: prove the registry has the version under the expected
# dist-tag, for a fresh publish AND the already-exists path (the latter catches
# dist-tag drift the idempotency skip would otherwise hide). A hard failure
# (e.g. @corgea/cli@1.9.0's E404 token-scope error) already fails `npm publish`
# above; this covers the quieter mode where npm exits 0 but the version is not
# live under the expected tag. We verify rather than `npm dist-tag add` to
# repair: re-pointing here would regress `latest` on a re-dispatch of an older tag.
echo "Verifying ${PKG}@${VERSION} is live with dist-tag ${DIST_TAG}..."
ok=0
for attempt in 1 2 3 4 5 6; do
  got="$(npm view "${PKG}" "dist-tags.${DIST_TAG}" 2>/dev/null || true)"
  if [[ "$got" == "$VERSION" ]]; then ok=1; break; fi
  echo "  dist-tag ${DIST_TAG}=${got:-<unset>} (attempt ${attempt}/6); waiting for registry..."
  sleep 10
done
if [[ "$ok" -ne 1 ]]; then
  echo "ERROR: ${PKG} dist-tag ${DIST_TAG} != ${VERSION}; the registry never confirmed the publish or the dist-tag has drifted." >&2
  exit 1
fi
echo "OK: ${PKG}@${VERSION} live; dist-tag ${DIST_TAG} -> ${VERSION}."

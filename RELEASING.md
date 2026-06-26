# Releasing the Corgea CLI

The `corgea` CLI ships to three channels, all driven by **one git tag**:

| Channel | Package | Install |
|---|---|---|
| npm | `@corgea/cli` (scoped, bundles native binaries) | `npm install -g @corgea/cli` |
| PyPI | `corgea-cli` (maturin-built wheels) | `pip install corgea-cli` |
| GitHub Release | `corgea-<target>.zip` (raw binaries) | download from the [Releases page](https://github.com/Corgea/cli/releases) |

Pushing an annotated `vX.Y.Z` tag to `main` fans out to three GitHub Actions workflows that build and publish all three. **Publishing is automated; the changelog is not** (see [Release notes](#release-notes)).

## Versioning

- **`Cargo.toml` `version` is the single source of truth.** Follow [SemVer](https://semver.org/).
- **PyPI** reads it automatically: `pyproject.toml` sets `dynamic = ["version"]`, so maturin takes the version from `Cargo.toml`.
- **npm** does *not* read `Cargo.toml`. `package.json` pins a placeholder (`0.0.0`); the real version is set from the **tag name** at publish time (`npm version <X.Y.Z> --no-git-tag-version` in `npm-publish.yml`).
- **The tag, `Cargo.toml`, and the published version must agree.** Bump `Cargo.toml` to `X.Y.Z` *before* tagging `vX.Y.Z`, or PyPI ships a different version than npm/GitHub.
- **Tags must be `v`-prefixed** (`v1.9.1`, not `1.9.1`). npm auto-publish keys off the tag starting with `v`; a non-`v` tag skips the npm publish entirely (this happened once with `1.8.8`).

## Prerequisites

- Write access to `Corgea/cli` and the [`gh`](https://cli.github.com/) CLI authenticated.
- These repository secrets are already configured in CI (no per-release action needed): `PYPI_API_TOKEN`, `NPM_TOKEN`, `GITHUB_TOKEN`.
- A clean checkout of `main` with all release-bound PRs already merged.

## Release procedure

1. **Land all changes on `main`** through reviewed PRs. Nothing ships that isn't on `main`.

2. **Bump the version.** Edit `Cargo.toml` `version = "X.Y.Z"` and merge it to `main`. This is the only manual version edit; PyPI and npm derive theirs from it and the tag.

3. **Gate on the merge commit.** From a clean `main`:
   ```bash
   git checkout main
   git pull --ff-only
   ./harness ci   # strict clippy (-D warnings), format check, dep audit, tests, coverage ≥ 13%
   ```
   Do not tag if `./harness ci` is red.

4. **Tag and push.** Two equivalent options:

   **a. Tag, then add notes (matches existing history):**
   ```bash
   git tag -a vX.Y.Z -m "vX.Y.Z"
   git push origin vX.Y.Z
   # after the release exists, fill notes (see below)
   ```

   **b. Create the GitHub Release + tag + notes in one step (recommended):**
   ```bash
   gh release create vX.Y.Z --target main --generate-notes
   ```
   `--generate-notes` produces the same "What's Changed / Full Changelog" body used by past releases. The tag push then triggers the publish workflows.

5. **Watch the workflows, in this order** (Actions tab):

   | # | Workflow | File | Publishes |
   |---|---|---|---|
   | 1 | **CI** | `release.yml` | wheels → **PyPI** (`corgea-cli`), on tag |
   | 2 | **Native Binary Release** | `release-binaries.yml` | 6 target zips → **GitHub Release** |
   | 3 | **Publish npm Package** | `npm-publish.yml` | bundles binaries → **npm** (`@corgea/cli`) |

   Workflow 3 is triggered by workflow 2 completing successfully (and only when the tag is `v`-prefixed). If it does not auto-start, dispatch it manually:
   ```bash
   gh workflow run npm-publish.yml -f tag=vX.Y.Z
   ```

## What gets built

- **PyPI wheels** (`release.yml`): Linux (x86_64, x86), Windows (x64, x86), macOS (x86_64, aarch64), plus an sdist. Asserts `manylinux2014` tags for broad Linux compatibility.
- **Native binaries** (`release-binaries.yml`): `x86_64-unknown-linux-gnu`, `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-gnu`, `x86_64-apple-darwin`, `aarch64-apple-darwin`, `x86_64-pc-windows-msvc`.
- **npm binary bundling** (`npm-publish.yml` → `scripts/npm/bundle-binaries.js`): downloads the GitHub Release zips and lays them out as `vendor/<target>/corgea/corgea`. At runtime `bin/corgea.js` selects the binary for the host OS/arch. npm ships 5 of the 6 targets (Linux x64 uses the musl build).

## Release notes

There is **no automated changelog** — no `CHANGELOG.md`, no release-please/git-cliff, and the workflows do not set `generate_release_notes`. `release-binaries.yml` creates the GitHub Release with an **empty body**.

Generate notes with GitHub's built-in feature, either via `gh release create … --generate-notes` (step 4b) or the **"Generate release notes"** button when editing the release. The established format is:

```
## What's Changed
* <PR title> by @<author> in <PR link>
...
**Full Changelog**: https://github.com/Corgea/cli/compare/<prev>...vX.Y.Z
```

Release notes live on the GitHub Release, not in the repository, so updating them needs **no PR**.

## Post-release verification

Smoke-test every channel:

```bash
# npm
npm install -g @corgea/cli@X.Y.Z
corgea --version

# PyPI (isolated)
python3 -m venv /tmp/corgea-smoke
/tmp/corgea-smoke/bin/pip install corgea-cli==X.Y.Z
/tmp/corgea-smoke/bin/corgea --version
```

Confirm registry state:

```bash
npm view @corgea/cli version dist-tags
python3 -m pip index versions corgea-cli
gh release view vX.Y.Z
```

## Rollback

Published package versions are **immutable** — you cannot overwrite `X.Y.Z` on npm or PyPI. **Roll forward:** fix, bump to the next patch (`X.Y.Z+1`), and release again. If a bad npm version must be discouraged, `npm deprecate '@corgea/cli@X.Y.Z' "reason"`.

## Known issues

- **npm idempotency guard checks the wrong name.** `npm-publish.yml` runs `npm view "corgea-cli@<version>"` (unscoped) to decide whether to skip, but the package is `@corgea/cli` (scoped). The guard never matches, so it never skips; re-running on an already-published version fails at `npm publish` instead of skipping cleanly. **Publishing itself is correct** (`npm publish` uses `package.json` → `@corgea/cli`), which is why releases succeed — only the skip optimization is broken. Fix: query `@corgea/cli`.
- **`bin/corgea.js` reinstall hint is wrong.** Its "binary missing" message says `npm install -g corgea-cli@latest`; the npm package is `@corgea/cli`. (`corgea-cli` is the *PyPI* name.)
- **npm auto-publish requires a `v`-prefixed tag.** Non-`v` tags build PyPI + binaries but skip npm; use the manual dispatch in step 5.

## Reference

- Workflows: `.github/workflows/release.yml`, `release-binaries.yml`, `npm-publish.yml`
- Quality gate: `./harness ci` (see `AGENTS.md`)
- Packaging: `Cargo.toml`, `pyproject.toml`, `package.json`, `bin/corgea.js`, `scripts/npm/bundle-binaries.js`

# Releasing the Corgea CLI

The CLI ships to three places off a single git tag `vX.Y.Z`:

- **npm** — `@corgea/cli` (native binaries bundled into `vendor/`)
- **PyPI** — `corgea-cli` (maturin wheels; version is dynamic from `Cargo.toml`)
- **GitHub Releases** — native binary zips for six targets

## Golden rule: the tag equals the `Cargo.toml` version

The npm publish derives its version from the **tag** (`tag minus the leading v`);
the PyPI publish derives its version from **`Cargo.toml`** (maturin). If those two
drift, npm and PyPI ship different versions off one tag. Two guards protect this:

- `version-guard` (`release.yml`, tag-gated) fails the **release** if the tag and
  `Cargo.toml` version disagree.
- `version-bump-check` (`test.yml`, PR-gated) fails a **PR** whose `Cargo.toml`
  version still equals the latest released tag — i.e. the version wasn't moved
  past what's already published. The first PR after each release must bump.

Get it right at the source:

1. Bump `[package].version` in `Cargo.toml`.
2. `cargo build` (refreshes `Cargo.lock`).
3. Commit, then tag `v<that exact version>` and push the tag.

## Stable vs beta

| Want | `Cargo.toml` version | Tag |
|---|---|---|
| Stable | `X.Y.Z` | `vX.Y.Z` |
| Beta | `X.Y.Z-beta.N` | `vX.Y.Z-beta.N` |

Betas are **curated**, not nightly: a maintainer bumps to `X.Y.Z-beta.N` and tags it
deliberately. `N` starts at `1` and increments per beta cut.

### What a beta tag publishes

| Channel | Stable (`vX.Y.Z`) | Beta (`vX.Y.Z-beta.N`) |
|---|---|---|
| npm dist-tag | `latest` | `beta` (never touches `latest`) |
| PyPI | normal install | only via `pip install --pre corgea-cli` |
| GitHub Release | normal | `prerelease: true` + beta disclaimer body |

The dist-tag decision lives in `scripts/npm/publish.sh`: any version containing a
`-` (a SemVer pre-release) maps to `beta`; everything else maps to `latest`. The
script refuses to cross the streams (pre-release → `latest`, or final → `beta`).

### SemVer vs PEP 440 spelling

SemVer (the tag) and PEP 440 (the Python wheel) spell pre-releases differently.
maturin performs the translation; **never hand-edit a wheel version**:

| `Cargo.toml` / tag (SemVer) | Wheel (PEP 440) |
|---|---|
| `1.10.0-beta.1` | `1.10.0b1` |
| `1.10.0-beta.2` | `1.10.0b2` |
| `1.10.0` | `1.10.0` |

`pip install --pre corgea-cli` resolves the beta; plain `pip install corgea-cli`
ignores pre-releases and stays on the latest stable.

## Cut sequence

1. `Cargo.toml` → target version (`X.Y.Z` or `X.Y.Z-beta.N`).
2. `cargo build` to update `Cargo.lock`; run `./harness ci` green.
3. For a stable release, move `CHANGELOG.md`'s `[Unreleased]` into a dated
   `[X.Y.Z]` section and open a fresh `[Unreleased]` (see CHANGELOG maintenance below).
4. Commit, tag `vX.Y.Z[-beta.N]`, push the tag.
5. `release-binaries.yml` (`push`) builds six zips, uploads them to the GitHub
   Release (flagged `prerelease` for betas), and the `finalize-release` job sets
   the notes/disclaimer once.
6. On its `completed` event, `npm-publish.yml` downloads those zips, bundles them
   into `vendor/`, and publishes `@corgea/cli` with the resolved dist-tag.
7. `release.yml` builds wheels + sdist and (tag-gated, after `version-guard`)
   publishes to PyPI.

### Verify a beta

```
npm dist-tag ls @corgea/cli          # latest unchanged; beta -> X.Y.Z-beta.N
pip install --pre corgea-cli         # resolves X.Y.Zb N; plain install stays stable
gh release view vX.Y.Z-beta.N --json isPrerelease,assets   # prerelease true + 6 zips
```

## npm dry-run dispatch contract

Rehearse the npm publish path without writing to the registry. It downloads an
**existing** release's six zips, bundles them, and runs `npm publish --dry-run`:

```
gh workflow run npm-publish.yml --ref <branch> -f tag=v1.9.0 -f dry_run=true
```

`dry_run` is empty on the automatic `workflow_run` trigger, where the script's
`DRY_RUN: ${{ inputs.dry_run || 'false' }}` resolves to `"false"` — so real
releases always publish. The beta dist-tag selection itself is unit-testable
locally with no network:

```
RESOLVE_ONLY=true PACKAGE_VERSION=1.10.0-beta.1 ./scripts/npm/publish.sh   # dist-tag=beta
RESOLVE_ONLY=true PACKAGE_VERSION=1.10.0        ./scripts/npm/publish.sh   # dist-tag=latest
```

## CHANGELOG maintenance

`CHANGELOG.md` is curated and follows Keep a Changelog. On each **stable** release,
rename `[Unreleased]` to a dated `[X.Y.Z]` section, add its compare link, and open a
fresh empty `[Unreleased]` pointing `vX.Y.Z...HEAD`. Betas need no changelog edit —
their notes come from the GitHub prerelease body and auto-generated commit notes.

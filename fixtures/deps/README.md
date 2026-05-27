# Deps dogfood fixtures

Sample apps for manually testing `corgea deps verify` and install wrappers (`corgea npm`, etc.) the way a customer would. Each subdirectory is a minimal project with pinned dependency manifests and lockfiles.

**Do not bump dependency versions** — pins are intentional and advisory-backed.

## Fixtures

| Directory | Ecosystem | Lockfile | Primary test |
|---|---|---|---|
| `npm/` | npm | `package-lock.json` | CVE scan (`--check-cve`), `corgea npm` |
| `npm-clean/` | npm | `package-lock.json` | CVE clean control (`lodash@4.17.21`, patched) |
| `npm-unpinned/` | npm | *(none)* | `--fail-unpinned` |
| `yarn/` | npm/yarn | `yarn.lock` | Yarn lockfile parser |
| `pnpm/` | npm/pnpm | `pnpm-lock.yaml` | pnpm lockfile parser |
| `python-requirements/` | Python | `requirements.txt` | `==`-pinned requirements |
| `python-poetry/` | Python | `poetry.lock` | Poetry lock discovery |
| `python-uv/` | Python | `uv.lock` | uv lock discovery |

## vuln-api e2e stub

Offline dogfood and GitHub Actions use [`vuln-api-stub.json`](vuln-api-stub.json) with the `vuln-api-stub` binary:

```bash
cargo build --release --bin vuln-api-stub --bin corgea
./target/release/vuln-api-stub --fixtures fixtures/deps/vuln-api-stub.json --print-url &
export CORGEA_VULN_API_URL=http://127.0.0.1:<port>
export CORGEA_TOKEN=ci-stub-token
export CORGEA_NPM_REGISTRY=http://127.0.0.1:1

./target/release/corgea deps verify --check-cve --fail-cve --path fixtures/deps/npm      # expect exit 1
./target/release/corgea deps verify --check-cve --fail-cve --path fixtures/deps/npm-clean # expect exit 0
```

Unlisted `(ecosystem, name, version)` keys in the fixture file default to **clean** responses.

## Manual dogfood

```bash
cd cli
cargo build --release
BIN=./target/release/corgea

# Baseline freshness scan
$BIN deps verify --path fixtures/deps/npm --threshold 2d

# Pinning enforcement (expect exit 1)
$BIN deps verify --path fixtures/deps/npm-unpinned --fail-unpinned

# CVE scan (needs CORGEA_VULN_API_URL + Corgea token)
$BIN deps verify --path fixtures/deps/npm --check-cve
$BIN deps verify --path fixtures/deps/python-requirements --ecosystem python --check-cve

# CI-gate shape
$BIN deps verify --path fixtures/deps/npm --threshold 2d --fail --fail-unpinned --check-cve

# JSON output
$BIN deps verify --path fixtures/deps/npm --check-cve --json

# Install wrapper (install-time tripwire)
cd fixtures/deps/npm
$BIN npm install --check-only --threshold 2d

cd ../python-uv
$BIN uv sync --check-only --threshold 2d
```

## Automated tests

```bash
cargo test deps_dogfood
```

Runs fixture discovery and stub-server CVE tests offline (no live registry or vuln-api required).

## Pin sources

npm pins adapted from `devex-testing-grounds/insecure-js`. Python pins adapted from `devex-testing-grounds/insecure-app/requirements.txt`.

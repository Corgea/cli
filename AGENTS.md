# AGENTS.md

Corgea developer CLI — Rust binary distributed three ways: native zip (GH releases), npm (`@corgea/cli`), pip (`corgea-cli` via maturin). The workspace `AGENTS.md` covers the monorepo; this file is cli-specific. `CLAUDE.md` is a symlink to this file.

## Commands

- After edits: `./harness check` — clippy fix, format, tests, suppression report
- Pre-commit: `./harness pre-commit` — staged Rust files only (auto via git hook)
- CI: `./harness ci` — strict clippy (`-D warnings`), format check, dep audit, tests + coverage gate (min 13%)
- Audit: `./harness audit` — `cargo audit` for known dep vulnerabilities
- Coverage: `./harness coverage [--min=N]` — cargo-llvm-cov; HTML report under `target/llvm-cov/`; fails if line coverage < N (default 13)
- Lint: `./harness lint` — clippy + format check, no fixes
- Test: `./harness test` — `cargo test`
- Fix: `./harness fix` — clippy fix + format
- Setup: `./harness setup-hooks` — install `.git/hooks/pre-commit`
- Auto-format: `./harness post-edit` — runs `cargo fmt` on changed Rust files (wire into your editor/agent's post-edit hook)

Add `--verbose` to stream raw command output instead of the quiet summary.

Coverage needs LLVM's `llvm-cov`/`llvm-profdata`. On a rustup toolchain, run
`rustup component add llvm-tools-preview`. On a non-rustup toolchain (e.g.
Homebrew Rust) those are missing, so point cargo-llvm-cov at a system LLVM:
`LLVM_COV="$(brew --prefix llvm)/bin/llvm-cov" LLVM_PROFDATA="$(brew --prefix llvm)/bin/llvm-profdata" ./harness coverage`.
CI uses its own toolchain and is unaffected.

## Layout

`src/main.rs` defines the clap `Commands` enum and dispatches. Each subcommand is its own module: `authorize.rs` (OAuth login), `scan.rs` + `scanners/{blast,fortify}.rs`, `scanners/parsers/{semgrep,sarif,checkmarx,coverity}.rs` for upload formats, `list.rs`, `inspect.rs`, `wait.rs`, `setup_hooks.rs`, `targets.rs` (path/glob/git selectors), `cicd.rs`. Shared infra in `utils/{api,terminal,generic}.rs` and `config.rs`.

User-facing reference lives in `skills/corgea/SKILL.md` — keep it in sync when adding/changing commands.

## Build

| Task | Command |
|---|---|
| Native build | `cargo build --release` → `./target/release/corgea` |
| Python wheel (dev) | `maturin develop` (needs venv + `pip install maturin`) |
| Local multi-target build | `./build_release.sh` (Darwin/Linux only; CI is the canonical path) |

<important if="you are adding a new subcommand">
- Add a variant to `Commands` in `src/main.rs`, a match arm in `main()`, and a new `mod` (declared at top of `main.rs`).
- Token-gated commands must call `verify_token_and_exit_when_fail(&corgea_config)` before doing work.
- Corgea API calls go through `utils::api` — do not build a `reqwest::Client` for them. Auth header is set via `utils::api::set_auth_token`; the client picks `Authorization: Bearer` for JWTs and `CORGEA-TOKEN` otherwise (`auth_headers` in `utils/api.rs`).
- Update `skills/corgea/SKILL.md` and `README.md` if user-visible.
</important>

<important if="you are bumping the version or cutting a release">
- `Cargo.toml` `version` is the source of truth. `pyproject.toml` is `dynamic = ["version"]` (maturin reads Cargo). `package.json` version is overwritten from the git tag by `npm-publish.yml`.
- Release flow: bump `Cargo.toml`, merge, push tag `v<version>`. That triggers `release.yml` (PyPI via maturin), `release-binaries.yml` (zips per target attached to the GH release), then `npm-publish.yml` (downloads those zips, runs `scripts/npm/bundle-binaries.js` to lay out `vendor/<target-triple>/corgea/<binary>`, publishes to npm).
- Supported npm/pip target triples are listed in `scripts/npm/bundle-binaries.js` and `bin/corgea.js` — keep them in lockstep with the CI matrix in `release-binaries.yml`.
</important>

<important if="you are touching auth, config, or the HTTP client">
- Config persists at `~/.corgea/config.toml` (`config.rs`). Env overrides: `CORGEA_TOKEN`, `CORGEA_URL`, `CORGEA_DEBUG`, `CORGEA_SOURCE`, `CORGEA_ACCEPT_CERT` (skip TLS verification, only honored when `https_proxy` is set), `CORGEA_NO_UPDATE_CHECK` (disable the new-release notice in `update_check.rs`).
- A single shared `reqwest::blocking::Client` lives in `utils/api.rs` with a 150s timeout and a process-wide cookie jar — reuse it for Corgea API calls. The vuln-api client (`vuln_api/mod.rs`), the update check (`update_check.rs`) and registry lookups (`verify_deps/registry.rs`) build their own clients.
- `corgea login` with no token launches a localhost OAuth callback (`authorize.rs`); with a token (or `CORGEA_TOKEN` env) it verifies and stores. `--scope` selects the tenant subdomain and overrides `--url`.
</important>

<important if="you are adding a new upload/report parser">
- New parsers live in `src/scanners/parsers/` and are wired in `mod.rs`. Dispatch happens in `scan.rs` (`read_file_report` / `read_stdin_report`); Fortify `.fpr` is special-cased in `main.rs` and goes through `scanners/fortify.rs`.
</important>

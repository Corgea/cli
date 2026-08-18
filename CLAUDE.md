# CLAUDE.md (cli/)

Corgea developer CLI — Rust binary distributed three ways: native zip (GH releases), npm (`@corgea/cli`), pip (`corgea-cli` via maturin). Parent `corgea/CLAUDE.md` covers the monorepo; this file is cli-specific.

## Layout

`src/main.rs` defines the clap `Commands` enum and dispatches. Each subcommand is its own module: `authorize.rs` (OAuth login), `scan.rs` + `scanners/{blast,fortify}.rs`, `scanners/parsers/{semgrep,sarif,checkmarx,coverity}.rs` for upload formats, `list.rs`, `inspect.rs`, `wait.rs`, `setup_hooks.rs`, `targets.rs` (path/glob/git selectors), `cicd.rs`. Shared infra in `utils/{api,terminal,generic}.rs` and `config.rs`.

User-facing reference lives in `skills/corgea/SKILL.md` — keep it in sync when adding/changing commands.

## Build / test / run

| Task | Command |
|---|---|
| Tests | `cargo test` (also runs in `.github/workflows/test.yml`) |
| Native build | `cargo build --release` → `./target/release/corgea` |
| Python wheel (dev) | `maturin develop` (needs venv + `pip install maturin`) |
| Local multi-target build | `./build_release.sh` (Darwin/Linux only; CI is the canonical path) |

<important if="you are adding a new subcommand">
- Add a variant to `Commands` in `src/main.rs`, a match arm in `main()`, and a new `mod` (declared at top of `main.rs`).
- Token-gated commands must call `verify_token_and_exit_when_fail(&corgea_config)` before doing work.
- HTTP calls go through `utils::api` — do not instantiate `reqwest::Client` directly. Auth header is set via `utils::api::set_auth_token`; the client picks `Authorization: Bearer` for JWTs and `CORGEA-TOKEN` otherwise (`utils/api.rs:22`).
- Update `skills/corgea/SKILL.md` and `README.md` if user-visible.
</important>

<important if="you are bumping the version or cutting a release">
- `Cargo.toml` `version` is the source of truth. `pyproject.toml` is `dynamic = ["version"]` (maturin reads Cargo). `package.json` version is overwritten from the git tag by `npm-publish.yml`.
- Release flow: bump `Cargo.toml`, merge, push tag `v<version>`. That triggers `release.yml` (PyPI via maturin), `release-binaries.yml` (zips per target attached to the GH release), then `npm-publish.yml` (downloads those zips, runs `scripts/npm/bundle-binaries.js` to lay out `vendor/<target-triple>/corgea/<binary>`, publishes to npm).
- Supported npm/pip target triples are listed in `scripts/npm/bundle-binaries.js` and `bin/corgea.js` — keep them in lockstep with the CI matrix in `release-binaries.yml`.
</important>

<important if="you are touching auth, config, or the HTTP client">
- Config persists at `~/.corgea/config.toml` (`config.rs`). Env overrides: `CORGEA_TOKEN`, `CORGEA_URL`, `CORGEA_DEBUG`, `CORGEA_SOURCE`, `CORGEA_ACCEPT_CERT` (skip TLS verification, only honored when `https_proxy` is set).
- A single shared `reqwest::blocking::Client` lives in `utils/api.rs` with a 150s timeout and a process-wide cookie jar — reuse it; do not build new clients per call.
- `corgea login` with no token launches a localhost OAuth callback (`authorize.rs`); with a token (or `CORGEA_TOKEN` env) it verifies and stores. `--scope` selects the tenant subdomain and overrides `--url`.
</important>

<important if="you are adding a new upload/report parser">
- New parsers live in `src/scanners/parsers/` and are wired in `mod.rs`. Dispatch happens in `scan.rs` (`read_file_report` / `read_stdin_report`); Fortify `.fpr` is special-cased in `main.rs` and goes through `scanners/fortify.rs`.
</important>

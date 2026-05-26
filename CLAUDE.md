# CLAUDE

Corgea developer CLI — Rust binary shipped via `maturin` to npm + pip.
Repo-root `/Users/juan/Code/corgea/CLAUDE.md` covers cross-codebase
conventions; this file covers cli-only specifics.

## Commands

- After edits: `./harness check` — clippy fix, format, tests, suppression report
- Pre-commit: `./harness pre-commit` — staged Rust files only (auto via git hook)
- CI: `./harness ci` — strict clippy (`-D warnings`), format check, dep audit, tests + coverage gate (min 41%)
- Audit: `./harness audit` — `cargo audit` for known dep vulnerabilities
- Coverage: `./harness coverage [--min=N]` — cargo-llvm-cov; HTML report under `target/llvm-cov/`; fails if line coverage < N (default 41)
- Lint: `./harness lint` — clippy + format check, no fixes
- Test: `./harness test` — `cargo test`
- Fix: `./harness fix` — clippy fix + format
- Setup: `./harness setup-hooks` — install `.git/hooks/pre-commit`
- Install: `./harness install` — `cargo install --path .` to `~/.cargo/bin/corgea`
- Auto-format: `./harness post-edit` runs via Claude Code Stop hook

Add `--verbose` to stream raw command output instead of the quiet summary.

## Source map

CLI entry is `src/main.rs` — clap-derived `Commands` enum dispatches to one module per subcommand.

| Path | Role |
|---|---|
| `authorize.rs` / `cicd.rs` | OAuth device flow + CI/CD token detection for `login` |
| `scanners/{blast,fortify,parsers}` | `scan` subcommand — blast (default), semgrep, snyk, Fortify FPR parsing |
| `scan.rs` / `wait.rs` / `list.rs` / `inspect.rs` | Upload, poll, list, inspect scans and issues against Corgea API |
| `verify_deps/` | `deps` subcommand — registry freshness + optional CVE check (npm + Python) |
| `precheck/` | `npm` / `yarn` / `pnpm` / `pip` / `uv` install wrappers |
| `vuln_api/` | Client for `vuln-api.corgea.app` (advisories); opt-in via `--check-cve` |
| `utils/{api,generic,terminal}` | HTTP, env helpers, TTY/color output |
| `config.rs` | `~/.corgea/config.toml` — url, token, optional `vuln_api_url` |

## Env vars

- `CORGEA_TOKEN`, `CORGEA_URL`, `CORGEA_DEBUG` — auth + endpoint override
- `CORGEA_VULN_API_URL` — override vuln-api host (default `https://vuln-api.corgea.app`)
- `CORGEA_NPM_REGISTRY`, `CORGEA_PYPI_REGISTRY` — alternate registries for `deps` and install wrappers

## Adding a subcommand

1. New module under `src/` (or `src/<name>/mod.rs` if multi-file).
2. Add a variant to `Commands` in `src/main.rs` with clap `#[arg]` help text — this is the user-facing doc.
3. Dispatch in the `match &cli.command` block; call `verify_token_and_exit_when_fail(&corgea_config)` only if the command hits the Corgea API.
4. Exit codes: `1` = expected failure (findings, auth, validation), `2` = bad CLI input.

## Dogfood fixtures

`fixtures/deps/` holds minimal npm/yarn/pnpm/pip/poetry/uv projects with pinned, advisory-backed manifests. Used by `cargo test deps_dogfood` (offline) and manual runs — see `fixtures/deps/README.md`. **Do not bump pins** — versions are chosen intentionally.

## Layer 2 (behavior contract)

Not wired. Commits, pushes, and arch-config edits are NOT gated by hooks in this subproject — follow the conventions in the repo-root CLAUDE.md.

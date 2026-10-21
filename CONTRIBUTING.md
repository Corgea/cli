# Contributing to Corgea CLI

Thanks for your interest in improving the Corgea CLI! This document covers everything you need to go from a fresh clone to a merged pull request.

The CLI is a Rust binary distributed three ways: native zips on [GitHub Releases](https://github.com/Corgea/cli/releases), npm (`@corgea/cli`), and pip (`corgea-cli`, built with [maturin](https://github.com/PyO3/maturin)).

## Ways to contribute

- **Report a bug** — open a [bug report](https://github.com/Corgea/cli/issues/new?template=bug_report.yml).
- **Request a feature** — open a [feature request](https://github.com/Corgea/cli/issues/new?template=feature_request.yml).
- **Ask a question** — use [Discussions](https://github.com/Corgea/cli/discussions); please don't open an issue for support.
- **Send a fix or feature** — see the workflow below. For anything non-trivial, open an issue first so we can agree on the approach before you invest time.

To report a **security vulnerability**, do *not* open a public issue — follow [SECURITY.md](SECURITY.md).

## Prerequisites

- **Rust** (stable) — install via [rustup](https://rustup.rs/). The crate targets edition 2021.
- **Python 3.8+** — only needed if you build or test the pip wheel.
- A C toolchain — required to build the vendored OpenSSL dependency on non-Windows platforms.

## Development setup

```bash
git clone https://github.com/Corgea/cli.git
cd cli
cargo build
```

### Build and run

| Task | Command |
|---|---|
| Build (debug) | `cargo build` |
| Build (release) | `cargo build --release` → `./target/release/corgea` |
| Run a subcommand | `cargo run -- scan --help` |
| Python wheel (dev) | `maturin develop` (needs a venv + `pip install maturin`) |
| Multi-target build | `./build_release.sh` (Darwin/Linux only; CI is the canonical path) |

After changing Rust code, re-run `maturin develop` to rebuild the Python wheel.

### Test, format, lint

```bash
cargo test                 # runs in CI on every push and PR
cargo fmt --all            # format before committing
cargo clippy --all-targets # catch common mistakes
```

CI currently runs `cargo test`. Please run `cargo fmt` and `cargo clippy` locally anyway — a clean, warning-free diff is much faster to review.

Run a single test with `cargo test <name>`.

## Project layout

`src/main.rs` defines the clap `Commands` enum and dispatches each subcommand. Every subcommand is its own module:

- `authorize.rs` — OAuth login
- `scan.rs` + `scanners/{blast,fortify}.rs` — scanning
- `scanners/parsers/{semgrep,sarif,checkmarx,coverity}.rs` — upload formats
- `list.rs`, `inspect.rs`, `wait.rs`, `setup_hooks.rs`, `targets.rs`, `cicd.rs`
- `utils/{api,terminal,generic}.rs`, `config.rs` — shared infrastructure

`CLAUDE.md` at the repo root has deeper notes on internal conventions.

### Adding a subcommand

1. Add a variant to the `Commands` enum in `src/main.rs`.
2. Add a match arm in `main()` and declare the new `mod` at the top of `main.rs`.
3. Put the implementation in its own module file.
4. Token-gated commands must call `verify_token_and_exit_when_fail(&corgea_config)` before doing work.
5. Make HTTP calls through `utils::api` — do not construct a `reqwest::Client` yourself. The shared client carries auth, cookies, and the standard timeout.
6. Update `skills/corgea/SKILL.md` and `README.md` if the change is user-visible.

### Adding an upload/report parser

New parsers live in `src/scanners/parsers/` and are wired in `mod.rs`. Dispatch happens in `scan.rs` (`read_file_report` / `read_stdin_report`); the Fortify `.fpr` format is special-cased in `main.rs` via `scanners/fortify.rs`.

## Pull request workflow

1. Fork the repo and create a branch from `main`.
2. Make your change. Keep PRs focused — one logical change per PR.
3. Add or update tests for behavior changes.
4. Run `cargo test`, `cargo fmt --all`, and `cargo clippy` — all clean.
5. Update `README.md` and `skills/corgea/SKILL.md` if you changed anything user-facing.
6. Open the PR against `main` and fill out the template. Link the issue it closes.

A maintainer will review. Please be responsive to feedback; stale PRs may be closed and can always be reopened.

### Commit messages

Write a concise, imperative summary line (e.g. "Support JWT tokens", "Fail on offset mismatch when uploading a report"). The PR title becomes the squashed commit, so make it descriptive.

## Releases

Maintainers cut releases. The flow:

1. Bump `version` in `Cargo.toml` (the single source of truth — `pyproject.toml` reads it via maturin, and `package.json` is overwritten from the git tag).
2. Merge, then push a tag `v<version>`.
3. The tag triggers the release workflows: PyPI (maturin), per-target zips attached to the GitHub Release, then the npm publish.

Contributors do not need to bump the version in feature PRs.

## License

By contributing, you agree that your contributions are licensed under the [GNU LGPL v2.1](LICENSE), the same license as the project.

## Code of conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). By participating, you agree to uphold it.
